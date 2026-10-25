//! wifi mitm: router session, DNS holds, and optional captive HTTP.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, IsTerminal, Write};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use infishark::protocol;
use infishark::wifi_mitm::{
    WifiDnsMode, WifiHttpMode, WifiMitmAction, WifiMitmOpts, WifiUpstream, append_ndjson,
    append_pcap,
};
use infishark::{Device, SavedNetwork, WifiScanOpts, pcap};

use crate::ui;

pub struct Opts {
    pub ssid: String,
    pub pass: String,
    pub steer: bool,
    pub pass_from_upstream: bool,
    pub hidden: bool,
    pub max_clients: u8,
    pub upstream: WifiUpstream,
    pub dns: Option<WifiDnsMode>,
    pub dns_server: Option<Ipv4Addr>,
    pub dns_log: bool,
    pub intercept: bool,
    pub intercept_ms: Option<u32>,
    pub http: WifiHttpMode,
    pub host_timeout_ms: u32,
    pub block: Vec<[u8; 6]>,
    pub rewrite: Vec<(String, Ipv4Addr)>,
    pub watch: Vec<(Ipv4Addr, u16, &'static str, &'static str)>,
    pub watch_bytes: u8,
    pub capture: Option<String>,
    pub verbose: bool,
    pub pcap_path: Option<String>,
}

enum UpChoice {
    Saved(SavedNetwork),
    Island,
}

pub struct Session {
    pub ssid: String,
    pub pass: String,
    pub upstream: WifiUpstream,
    pub steer: bool,
    pub pass_from_upstream: bool,
}

/// Fill in a SoftAP name, its WPA2 passphrase, and an upstream.
/// A missing name is typed, not scanned, unless the prompt is left blank.
pub fn resolve(
    dev: &mut Device,
    ssid: Option<String>,
    pass: Option<String>,
    upstream_index: Option<u8>,
    upstream_ssid: Option<String>,
    upstream_pass: Option<String>,
    upstream_none: bool,
    channel: Option<u8>,
    steer: bool,
    json: bool,
) -> Result<Session> {
    if channel.is_some() && !upstream_none {
        bail!("--channel is only used with --upstream-none");
    }
    let channel = channel.unwrap_or(1);
    let upstream_given = upstream_none || upstream_index.is_some() || upstream_ssid.is_some();
    if json && (ssid.is_none() || !upstream_given) {
        bail!("wifi mitm --json needs a SoftAP name and an upstream");
    }

    let mut ssid = match ssid {
        Some(s) => s,
        None => prompt_ap_name(dev)?,
    };
    let upstream = if upstream_none {
        WifiUpstream::None { channel }
    } else if let Some(index) = upstream_index {
        WifiUpstream::Saved(index)
    } else if let Some(name) = upstream_ssid {
        let pass = match upstream_pass {
            Some(p) => p,
            None => ui::prompt_password(&name)?,
        };
        WifiUpstream::Explicit { ssid: name, pass }
    } else {
        pick_upstream(dev, channel)?
    };
    let pass_given = pass.is_some();
    let mut pass = pass.unwrap_or_default();
    if ssid.is_empty() || ssid.len() > 32 {
        bail!("SoftAP name must be 1 to 32 characters");
    }
    let (steer, pass_from_upstream) =
        apply_steer(dev, &mut ssid, &mut pass, &upstream, steer, json)?;
    if !pass_given
        && !pass_from_upstream
        && pass.is_empty()
        && !json
        && std::io::stdin().is_terminal()
    {
        pass = ui::prompt_password(&ssid)?;
    }
    if !pass.is_empty() && !(8..=63).contains(&pass.len()) {
        bail!("SoftAP password must be empty or 8 to 63 characters");
    }
    Ok(Session {
        ssid,
        pass,
        upstream,
        steer,
        pass_from_upstream,
    })
}

fn prompt_ap_name(dev: &mut Device) -> Result<String> {
    let typed = ui::prompt_line("SoftAP name (blank scans): ")?;
    if typed.is_empty() {
        scan_ap_name(dev)
    } else {
        Ok(typed)
    }
}

fn apply_steer(
    dev: &mut Device,
    ssid: &mut String,
    pass: &mut String,
    upstream: &WifiUpstream,
    steer_flag: bool,
    json: bool,
) -> Result<(bool, bool)> {
    if matches!(upstream, WifiUpstream::None { .. }) {
        if steer_flag {
            bail!("--steer needs an upstream network");
        }
        return Ok((false, false));
    }
    let up_name = upstream_name(dev, upstream)?;
    if !names_match_for_deauth(ssid, &up_name) {
        if steer_flag {
            bail!("--steer needs the SoftAP name to match the upstream");
        }
        return Ok((false, false));
    }
    let interactive = !json && std::io::stdin().is_terminal();
    let want = if steer_flag {
        true
    } else if !interactive {
        false
    } else {
        ask(
            &format!(
                "Deauth {} and send its clients here?",
                ui::tty_text(&up_name)
            ),
            false,
        )?
    };
    if !want {
        return Ok((false, false));
    }
    let from_saved = pass.is_empty() && matches!(upstream, WifiUpstream::Saved(_));
    if pass.is_empty() {
        if let WifiUpstream::Explicit { pass: up, .. } = upstream {
            if !up.is_empty() {
                *pass = up.clone();
            }
        }
    } else if let WifiUpstream::Explicit { pass: up, .. } = upstream {
        if !up.is_empty() && up != pass {
            crate::log::warn(
                "SoftAP password does not match the upstream password; clients may not rejoin",
            );
        }
    } else if !pass.is_empty() {
        crate::log::warn("clients rejoin only if this password is the one saved on the upstream");
    }
    Ok((true, from_saved))
}

fn upstream_name(dev: &mut Device, upstream: &WifiUpstream) -> Result<String> {
    match upstream {
        WifiUpstream::None { .. } => Ok(String::new()),
        WifiUpstream::Explicit { ssid, .. } => Ok(ssid.clone()),
        WifiUpstream::Saved(index) => {
            let saved = dev.wifi_saved_list()?;
            Ok(saved
                .iter()
                .find(|n| n.index == *index)
                .map(|n| n.ssid.clone())
                .unwrap_or_default())
        }
    }
}

fn names_match_for_deauth(ssid: &str, upstream_ssid: &str) -> bool {
    !upstream_ssid.is_empty() && ssid == upstream_ssid
}

fn ask(prompt: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    let line = ui::prompt_line(&format!("{prompt} {hint} "))?;
    Ok(match line.trim() {
        "" => default_yes,
        "y" | "Y" | "yes" => true,
        _ => false,
    })
}

fn scan_ap_name(dev: &mut Device) -> Result<String> {
    let sp = ui::Spinner::start("scanning networks");
    let nets = dev.wifi_scan(&WifiScanOpts {
        active: true,
        ..WifiScanOpts::default()
    });
    sp.stop();
    let mut nets = nets?;
    nets.retain(|n| !n.ssid.is_empty());
    Ok(ui::pick_network(&mut nets)?.ssid)
}

fn pick_upstream(dev: &mut Device, channel: u8) -> Result<WifiUpstream> {
    let saved = dev.wifi_saved_list()?;
    let mut choices: Vec<UpChoice> = saved.into_iter().map(UpChoice::Saved).collect();
    choices.push(UpChoice::Island);
    let pick = ui::pick_from_list(&choices, "select upstream [n]: ", |c| match c {
        UpChoice::Saved(n) => format!("slot {}  {}", n.index, ui::tty_text(&n.ssid)),
        UpChoice::Island => "no upstream".into(),
    })?;
    match pick {
        UpChoice::Saved(n) => Ok(WifiUpstream::Saved(n.index)),
        UpChoice::Island => Ok(WifiUpstream::None { channel }),
    }
}

pub fn run(mut dev: Device, opts: Opts) -> Result<()> {
    let mut spec = WifiMitmOpts::new(opts.ssid, opts.upstream);
    spec.pass = opts.pass;
    spec.steer = opts.steer;
    spec.pass_from_upstream = opts.pass_from_upstream;
    spec.hidden = opts.hidden;
    spec.max_clients = opts.max_clients;
    spec.block = opts.block;
    spec.http = opts.http;
    spec.host_timeout_ms = opts.host_timeout_ms;
    spec.dns_log = opts.dns_log;
    spec.intercept_dns = opts.intercept;
    spec.dns_server = opts.dns_server;
    if let Some(mode) = opts.dns {
        spec.dns = mode;
    } else if spec.http == WifiHttpMode::Portal {
        spec.dns = WifiDnsMode::Captive;
    }
    if opts.intercept {
        spec.intercept_timeout_ms = opts.intercept_ms.unwrap_or(500);
    }

    spec.capture_flows = true;
    spec.diagnostics = opts.verbose;
    let stamp = local_stamp();

    dev.set_read_timeout(Duration::from_millis(300))?;
    crate::signals::install_sigint();
    crate::signals::RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    if opts.verbose {
        crate::log::info("starting Wi-Fi MITM (diagnostics enabled)");
    }
    let sp = (!opts.verbose).then(|| ui::Spinner::start("associating"));
    let started = dev.wifi_mitm_start(&spec, |v| {
        if opts.verbose && v.get("type").and_then(|t| t.as_str()) == Some("phase") {
            crate::log::info(event_line(&v));
        }
    });
    if let Some(sp) = sp {
        sp.stop();
    }
    let ident = match started {
        Ok(v) => v,
        Err(e) => {
            let _ = dev.stop_current_task();
            return Err(e.into());
        }
    };
    if let Err(e) = (|| -> Result<()> {
        for (name, addr) in &opts.rewrite {
            dev.wifi_mitm_control(&serde_json::json!({
                "op": "rewrite", "name": name, "a": addr.to_string()
            }))?;
        }
        for (ip, port, proto, dir) in &opts.watch {
            dev.wifi_mitm_control(&serde_json::json!({
                "op": "watch",
                "ip": ip.to_string(),
                "port": port,
                "proto": proto,
                "dir": dir,
                "bytes": opts.watch_bytes,
            }))?;
        }
        Ok(())
    })() {
        let _ = dev.stop_current_task();
        return Err(e);
    }
    let (pcap_path, pcap_writer) = match opts.pcap_path.as_deref() {
        Some(path) => open_pcap(path).map(|w| (path.to_string(), w)),
        None => reserve_pcap(&stamp),
    }
    .inspect_err(|_| {
        let _ = dev.stop_current_task();
    })?;
    let mut pcap_out = Some(pcap_writer);
    let mut capture = match opts.capture.as_ref() {
        Some(path) => match open_private(path) {
            Ok(file) => Some(BufWriter::new(file)),
            Err(e) => {
                let _ = dev.stop_current_task();
                return Err(e);
            }
        },
        None => None,
    };

    let ssid = ident.get("ap_ssid").and_then(|v| v.as_str()).unwrap_or("?");
    let ip = ident
        .get("ap_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("192.168.4.1");
    let dns = ident
        .get("dns")
        .and_then(|v| v.as_str())
        .unwrap_or(spec.dns.as_str());
    let auth = if ident
        .get("open")
        .and_then(|v| v.as_bool())
        .unwrap_or(spec.pass.is_empty() && !spec.pass_from_upstream)
    {
        "open"
    } else {
        "wpa2"
    };
    let steer = if spec.steer { "  deauth" } else { "" };

    let mut view = View {
        ssid: ssid.to_string(),
        ip: ip.to_string(),
        auth: format!("{auth}  dns={dns}{steer}"),
        channel: ident.get("channel").and_then(|n| n.as_u64()).unwrap_or(0),
        clients: 0,
        rx: 0,
        tx: 0,
        kbps: 0,
        prev_bytes: 0,
        prev_at: Instant::now(),
        last: String::new(),
        site: String::new(),
        pcap: Some(pcap_path.clone()),
        start: Instant::now(),
    };
    let mut status = ui::StatusBlock::new();
    let end = live(
        &mut dev,
        &mut view,
        &mut status,
        &mut capture,
        &mut pcap_out,
        opts.verbose,
    );
    status.clear();
    let _ = dev.stop_current_task();
    if let Ok(v) = dev.wifi_mitm_control(&serde_json::json!({"op": "status"})) {
        apply_status(&mut view, &v);
    }
    crate::log::ok(format!(
        "stopped  {}  {} clients  rx={} tx={}",
        fmt_rate(view.kbps),
        view.clients,
        view.rx,
        view.tx
    ));
    match pcap_out.as_mut().map(|w| w.flush()).transpose() {
        Ok(_) => eprintln!("saved to {}", ui::tty_text(&pcap_path)),
        Err(e) => crate::log::warn(ui::tty_text(&format!("{pcap_path}: {e}"))),
    }
    end
}

struct View {
    ssid: String,
    ip: String,
    auth: String,
    channel: u64,
    clients: u64,
    rx: u64,
    tx: u64,
    kbps: u64,
    prev_bytes: u64,
    prev_at: Instant,
    last: String,
    site: String,
    pcap: Option<String>,
    start: Instant,
}

fn tighten_private(file: &File, path: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| {
                    anyhow::anyhow!(
                        "{path}: mode is {mode:04o}, expected 0600, and it could not be changed"
                    )
                })?;
        }
    }
    let _ = path;
    Ok(())
}

fn open_private(path: &str) -> Result<File> {
    let file = ui::create_secure(path).map_err(|e| {
        let denied = e.chain().any(|c| {
            matches!(
                c.downcast_ref::<std::io::Error>().map(|io| io.kind()),
                Some(std::io::ErrorKind::PermissionDenied)
            )
        });
        if denied {
            anyhow::anyhow!("{path}: permission denied; the current directory is not writable")
        } else {
            e
        }
    })?;
    tighten_private(&file, path)?;
    Ok(file)
}

fn format_stamp(year: i32, month: i32, day: i32, hour: i32, min: i32, sec: i32) -> String {
    format!("{year:04}-{month:02}-{day:02}T{hour:02}{min:02}{sec:02}")
}

fn local_stamp() -> String {
    #[cfg(unix)]
    {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as libc::time_t)
            .unwrap_or(0);
        let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
        if !unsafe { libc::localtime_r(&secs, tm.as_mut_ptr()) }.is_null() {
            let tm = unsafe { tm.assume_init() };
            return format_stamp(
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
            );
        }
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day, hour, min, sec) = utc_parts(secs);
    format_stamp(year, month, day, hour, min, sec)
}

fn utc_parts(secs: u64) -> (i32, i32, i32, i32, i32, i32) {
    let ss = (secs % 60) as i32;
    let mm = ((secs / 60) % 60) as i32;
    let hh = ((secs / 3600) % 24) as i32;
    let z = (secs / 86400) as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as i32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as i32;
    let y = (if m <= 2 { y + 1 } else { y }) as i32;
    (y, m, d, hh, mm, ss)
}

fn reserve_pcap(stamp: &str) -> Result<(String, BufWriter<File>)> {
    for n in 1..1000 {
        let path = if n == 1 {
            format!("{stamp}.pcap")
        } else {
            format!("{stamp}-{n}.pcap")
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, pcap_writer(file)?)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(anyhow::anyhow!("creating PCAP: {e}")),
        }
    }
    bail!("too many PCAP files for this timestamp")
}

fn open_pcap(path: &str) -> Result<BufWriter<File>> {
    pcap_writer(open_private(path)?)
}

fn pcap_writer(file: File) -> Result<BufWriter<File>> {
    let mut w = BufWriter::new(file);
    pcap::write_global_header(&mut w, pcap::LINKTYPE_RAW)?;
    w.flush()?;
    Ok(w)
}

fn fmt_rate(kbps: u64) -> String {
    if kbps >= 1000 {
        format!("{:.1} Mbps", kbps as f64 / 1000.0)
    } else {
        format!("{kbps} kbps")
    }
}

fn apply_status(view: &mut View, v: &serde_json::Value) {
    if let Some(n) = v.get("clients").and_then(|n| n.as_u64()) {
        view.clients = n;
    }
    if let Some(n) = v.get("channel").and_then(|n| n.as_u64()) {
        view.channel = n;
    }
    let rx = v.pointer("/nat/rx_bytes").and_then(|n| n.as_u64());
    let tx = v.pointer("/nat/tx_bytes").and_then(|n| n.as_u64());
    if let (Some(rx), Some(tx)) = (rx, tx) {
        let total = rx.saturating_add(tx);
        let dt = view.prev_at.elapsed().as_secs_f64().max(0.05);
        if total >= view.prev_bytes {
            let bits = (total - view.prev_bytes) as f64 * 8.0;
            view.kbps = (bits / dt / 1000.0) as u64;
        }
        view.prev_bytes = total;
        view.prev_at = Instant::now();
        view.rx = v
            .pointer("/nat/rx_pkts")
            .and_then(|n| n.as_u64())
            .unwrap_or(view.rx);
        view.tx = v
            .pointer("/nat/tx_pkts")
            .and_then(|n| n.as_u64())
            .unwrap_or(view.tx);
    }
}

fn draw_view(status: &mut ui::StatusBlock, view: &View) {
    status.draw(&ui::status_frame(
        "mitm",
        view.start.elapsed(),
        &view_lines(view),
        None,
    ));
}

fn view_lines(view: &View) -> Vec<String> {
    let mut body = vec![
        format!(
            "{}  {}  {}  ch {}",
            view.ssid, view.ip, view.auth, view.channel
        ),
        format!("clients  {}", view.clients),
        format!(
            "speed    {}   rx {}   tx {}",
            fmt_rate(view.kbps),
            view.rx,
            view.tx
        ),
    ];
    if !view.site.is_empty() {
        body.push(format!("site     {}", view.site));
    }
    if let Some(path) = &view.pcap {
        body.push(format!("pcap     {path}"));
    }
    if !view.last.is_empty() {
        body.push(format!("last     {}", view.last));
    }
    body.into_iter().map(|line| ui::tty_text(&line)).collect()
}

fn diagnostic_line(v: &serde_json::Value) -> String {
    let text = |key| ui::tty_text(v.get(key).and_then(|x| x.as_str()).unwrap_or("?"));
    let num = |key| {
        v.get(key)
            .and_then(|x| x.as_u64())
            .map_or("?".into(), |n| n.to_string())
    };
    let count = |path| {
        v.pointer(path)
            .and_then(|x| x.as_u64())
            .map_or("?".into(), |n| n.to_string())
    };
    let signed = |path| {
        v.pointer(path)
            .and_then(|x| x.as_i64())
            .map_or("?".into(), |n| n.to_string())
    };
    format!(
        "phase={} upstream={} ssid={} ch={} ap={}/{} gw={} sta={} dhcp={} clients={}/{} denied={} dhcp_rx={} dhcp_tx={} dhcp_tx_fail={} dhcp_last_err={} heap_free={} heap_max_alloc={} rx={} tx={} tx_fail={}",
        text("phase"),
        text("upstream"),
        text("ap_ssid"),
        num("channel"),
        text("ap_ip_actual"),
        text("ap_netmask"),
        text("ap_gateway"),
        text("sta_ip"),
        text("dhcp"),
        num("clients"),
        num("max_clients"),
        num("denied"),
        count("/dhcp_packets/rx"),
        count("/dhcp_packets/tx"),
        count("/dhcp_packets/tx_fail"),
        signed("/dhcp_packets/last_err"),
        num("heap_free"),
        num("heap_max_alloc"),
        count("/nat/rx_pkts"),
        count("/nat/tx_pkts"),
        count("/nat/tx_fail")
    )
}

#[cfg(test)]
mod diagnostic_tests {
    use super::diagnostic_line;
    use clap::Parser;

    #[test]
    fn verbose_flag_parses() {
        let cli = crate::Cli::try_parse_from([
            "infishark",
            "wifi",
            "mitm",
            "test-ap",
            "--upstream-none",
            "--verbose",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(crate::Command::Wifi {
                action: crate::WifiCmd::Mitm { verbose: true, .. },
                ..
            })
        ));
    }

    #[test]
    fn deauth_only_when_the_softap_clones_the_upstream_name() {
        assert!(super::names_match_for_deauth(
            "Wi-Fi Network",
            "Wi-Fi Network"
        ));
        assert!(!super::names_match_for_deauth("ap", "Wi-Fi Network"));
        assert!(!super::names_match_for_deauth("Wi-Fi Network", ""));
        assert!(!super::names_match_for_deauth(
            "wi-fi network",
            "Wi-Fi Network"
        ));
    }

    #[test]
    fn concurrent_pcap_reservations_preserve_existing_captures() {
        use rand::RngCore;
        use std::sync::{Arc, Barrier};
        let mut random = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let dir = std::env::temp_dir().join(format!(
            "infishark-pcap-{}",
            infishark::hex::encode_lower(&random)
        ));
        std::fs::create_dir(&dir).unwrap();
        let stamp = super::format_stamp(1999, 12, 31, 23, 59, 59);
        assert_eq!(stamp, "1999-12-31T235959");
        let prefix = dir.join(stamp).to_str().unwrap().to_string();
        let existing = format!("{prefix}.pcap");
        std::fs::write(&existing, b"retained capture").unwrap();
        let start = Arc::new(Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let start = Arc::clone(&start);
                let prefix = prefix.clone();
                std::thread::spawn(move || {
                    start.wait();
                    let (path, writer) = super::reserve_pcap(&prefix).unwrap();
                    drop(writer);
                    path
                })
            })
            .collect();
        let mut paths: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        paths.sort();
        assert_eq!(
            paths,
            [format!("{prefix}-2.pcap"), format!("{prefix}-3.pcap")]
        );
        assert_eq!(std::fs::read(existing).unwrap(), b"retained capture");
        for path in paths {
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 24);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn remote_text_cannot_control_mitm_terminal_output() {
        let text = "remote\u{1b}]52;c;payload\u{7}\nnext";
        let event = serde_json::json!({ "type": "site", "name": text });
        assert!(!super::event_line(&event).chars().any(char::is_control));
        let diagnostic = serde_json::json!({ "phase": text, "ap_ssid": text });
        assert!(!diagnostic_line(&diagnostic).chars().any(char::is_control));
        let view = super::View {
            ssid: text.into(),
            ip: text.into(),
            auth: text.into(),
            channel: 1,
            clients: 0,
            rx: 0,
            tx: 0,
            kbps: 0,
            prev_bytes: 0,
            prev_at: std::time::Instant::now(),
            last: text.into(),
            site: text.into(),
            pcap: Some(text.into()),
            start: std::time::Instant::now(),
        };
        assert!(
            super::view_lines(&view)
                .iter()
                .all(|line| !line.chars().any(char::is_control))
        );
        assert_eq!(view.ssid, text);
        let mut capture = Vec::new();
        infishark::wifi_mitm::append_ndjson(&mut capture, &event).unwrap();
        let captured: serde_json::Value = serde_json::from_slice(&capture).unwrap();
        assert_eq!(captured["name"], text);
    }

    #[test]
    fn utc_parts_reads_the_unix_epoch() {
        assert_eq!(super::utc_parts(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(super::utc_parts(1_609_459_200), (2021, 1, 1, 0, 0, 0));
    }

    #[test]
    fn prints_dhcp_and_ap_state_without_other_status_fields() {
        let status = serde_json::json!({
            "phase": "active", "upstream": "up", "channel": 6,
            "ap_ip_actual": "192.168.4.1", "ap_gateway": "192.168.4.1",
            "ap_netmask": "255.255.255.0", "sta_ip": "192.168.0.2",
            "dhcp": "started", "clients": 1, "max_clients": 4,
            "dhcp_packets": {"rx": 3, "tx": 2, "tx_fail": 1, "last_err": -12},
            "heap_free": 32000, "heap_max_alloc": 10000,
            "nat": {"rx_pkts": 4, "tx_pkts": 1, "tx_fail": 0},
            "secret": "never-log-this"
        });
        let line = diagnostic_line(&status);
        assert!(line.contains("dhcp=started clients=1/4 denied=? dhcp_rx=3 dhcp_tx=2"));
        assert!(line.contains("ap=192.168.4.1/255.255.255.0"));
        assert!(line.contains("dhcp_last_err=-12 heap_free=32000 heap_max_alloc=10000"));
        assert!(!line.contains("never-log-this"));
        assert!(diagnostic_line(&serde_json::json!({})).contains("dhcp_rx=?"));
    }

    #[test]
    fn site_follows_lookup_then_later_packets_to_that_address() {
        let mut sites = super::SiteBook::default();
        let first = sites.observe(&serde_json::json!({
            "type": "site",
            "name": "example.com",
            "ip": "203.0.113.10"
        }));
        assert_eq!(first, Some("example.com"));
        assert!(
            sites
                .observe(&serde_json::json!({
                    "type": "site",
                    "name": "example.com",
                    "ip": "203.0.113.10"
                }))
                .is_none()
        );
        sites.observe(&serde_json::json!({"type": "site", "name": "example.net"}));
        let mut pkt = vec![0x45u8, 0, 0, 40];
        pkt.resize(20, 0);
        pkt[12..16].copy_from_slice(&[192, 168, 4, 3]);
        pkt[16..20].copy_from_slice(&[203, 0, 113, 10]);
        let hex: String = pkt.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            sites.observe(&serde_json::json!({"type": "flow", "hex": hex})),
            Some("example.com")
        );
    }
}

#[derive(Default)]
struct SiteBook {
    by_ip: HashMap<Ipv4Addr, String>,
    current: String,
}

fn ap_client(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 192 && o[1] == 168 && o[2] == 4
}

fn remote_ip(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() < 40 || !hex.is_ascii() {
        return None;
    }
    let mut b = [0u8; 20];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    if b[0] >> 4 != 4 {
        return None;
    }
    let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    if ap_client(src) && !ap_client(dst) {
        Some(dst)
    } else if ap_client(dst) && !ap_client(src) {
        Some(src)
    } else {
        None
    }
}

impl SiteBook {
    fn observe(&mut self, v: &serde_json::Value) -> Option<&str> {
        let mut next = None;
        match v.get("type").and_then(|t| t.as_str()) {
            Some("site" | "dns") => {
                if let Some(name) = v
                    .get("name")
                    .and_then(|n| n.as_str())
                    .filter(|s| !s.is_empty())
                {
                    if let Some(ip) = v
                        .get("ip")
                        .and_then(|s| s.as_str())
                        .and_then(|s| s.parse().ok())
                    {
                        if !ap_client(ip) {
                            if self.by_ip.len() >= 64 {
                                self.by_ip.clear();
                            }
                            self.by_ip.insert(ip, name.to_string());
                        }
                    }
                    next = Some(name.to_string());
                }
            }
            Some("flow") => {
                let from_field = v
                    .get("ip")
                    .and_then(|s| s.as_str())
                    .and_then(|s| s.parse().ok())
                    .filter(|ip: &Ipv4Addr| !ap_client(*ip));
                let ip = from_field
                    .or_else(|| v.get("hex").and_then(|s| s.as_str()).and_then(remote_ip));
                if let Some(ip) = ip {
                    if let Some(name) = self.by_ip.get(&ip) {
                        next = Some(name.clone());
                    }
                }
            }
            _ => {}
        }
        if let Some(name) = next {
            if name != self.current {
                self.current = name;
                return Some(self.current.as_str());
            }
        }
        None
    }
}

fn live(
    dev: &mut Device,
    view: &mut View,
    status: &mut ui::StatusBlock,
    capture: &mut Option<BufWriter<File>>,
    pcap_out: &mut Option<BufWriter<File>>,
    verbose: bool,
) -> Result<()> {
    let mut last_poll = Instant::now() - Duration::from_secs(1);
    let mut last_draw = last_poll;
    let mut last_diag = String::new();
    let mut last_diag_at = Instant::now() - Duration::from_secs(5);
    let mut sites = SiteBook::default();
    loop {
        if !crate::signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        if last_poll.elapsed() >= Duration::from_millis(500) {
            match dev.wifi_mitm_control(&serde_json::json!({"op": "status"})) {
                Ok(v) => {
                    apply_status(view, &v);
                    if verbose {
                        let line = diagnostic_line(&v);
                        if (line != last_diag && last_diag_at.elapsed() >= Duration::from_secs(1))
                            || last_diag_at.elapsed() >= Duration::from_secs(5)
                        {
                            crate::log::info(&line);
                            last_diag = line;
                            last_diag_at = Instant::now();
                        }
                    }
                }
                Err(e) if verbose && last_diag_at.elapsed() >= Duration::from_secs(5) => {
                    crate::log::warn(ui::tty_text(&format!("status poll failed: {e}")));
                    last_diag_at = Instant::now();
                }
                Err(_) => {}
            }
            last_poll = Instant::now();
        }
        if last_draw.elapsed() >= Duration::from_millis(200) {
            if !verbose {
                draw_view(status, view);
            }
            if let Some(w) = pcap_out.as_mut() {
                let _ = w.flush();
            }
            if let Some(w) = capture.as_mut() {
                let _ = w.flush();
            }
            last_draw = Instant::now();
        }
        match dev.next_event() {
            Ok((protocol::EVT_WIFI_MITM, payload)) => {
                let v: serde_json::Value = match serde_json::from_slice(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        crate::log::warn(format!("skipped a malformed MITM event: {e}"));
                        continue;
                    }
                };
                let line = event_line(&v);
                if !line.is_empty() {
                    view.last = line;
                }
                if let Some(name) = sites.observe(&v) {
                    view.site = name.to_string();
                    if verbose {
                        crate::log::info(format!("site {}", ui::tty_text(name)));
                    }
                }
                if verbose
                    && matches!(
                        v.get("type").and_then(|t| t.as_str()),
                        Some("phase" | "client")
                    )
                {
                    crate::log::info(&view.last);
                }
                if v.get("held").and_then(|h| h.as_bool()) == Some(true) {
                    if let Some(id) = v.get("id").and_then(|n| n.as_u64()) {
                        if let Err(e) = dev.wifi_mitm_action(id as u16, WifiMitmAction::Allow) {
                            if format!("{e}").contains("unknown id") {
                                view.last = format!("auto-allow {id}");
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                if let Some(w) = capture.as_mut() {
                    if let Err(e) = append_ndjson(w, &v) {
                        crate::log::warn(format!("capture write failed: {e}"));
                    }
                }
                if let Some(w) = pcap_out.as_mut() {
                    if let Err(e) = append_pcap(w, &v) {
                        crate::log::warn(format!("pcap write failed: {e}"));
                    }
                }
            }
            Ok((protocol::EVT_PORTAL_REQUEST, payload)) => {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    view.last = format!(
                        "http {} {}",
                        v.get("method").and_then(|m| m.as_str()).unwrap_or("?"),
                        v.get("path").and_then(|p| p.as_str()).unwrap_or("/")
                    );
                    if let Some(w) = capture.as_mut() {
                        append_ndjson(w, &v)?;
                    }
                }
            }
            Ok(_) => {}
            Err(infishark::Error::Timeout) => {}
            Err(infishark::Error::Interrupted) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
}

fn event_line(v: &serde_json::Value) -> String {
    ui::tty_text(&match v.get("type").and_then(|t| t.as_str()) {
        Some("phase") => format!(
            "phase {} {}",
            v.get("phase").and_then(|p| p.as_str()).unwrap_or("?"),
            v.get("reason").and_then(|p| p.as_str()).unwrap_or("")
        ),
        Some("client") => format!(
            "client {} {} {}",
            v.get("event").and_then(|p| p.as_str()).unwrap_or("?"),
            v.get("mac").and_then(|p| p.as_str()).unwrap_or("?"),
            v.get("ip").and_then(|p| p.as_str()).unwrap_or("")
        ),
        Some("dns") => format!(
            "dns {}",
            v.get("name").and_then(|n| n.as_str()).unwrap_or("?")
        ),
        Some("site") => {
            let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if name.is_empty() {
                String::new()
            } else {
                format!("site {name}")
            }
        }
        Some("flow") => format!(
            "flow {} {}:{}",
            v.get("proto").and_then(|p| p.as_str()).unwrap_or("?"),
            v.get("ip").and_then(|p| p.as_str()).unwrap_or("?"),
            v.get("dport").and_then(|p| p.as_u64()).unwrap_or(0)
        ),
        _ => String::new(),
    })
}

pub fn parse_block(text: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = text.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        bail!("block address must be six octets");
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).map_err(|_| anyhow::anyhow!("bad MAC {text}"))?;
    }
    Ok(mac)
}

pub fn parse_rewrite(text: &str) -> Result<(String, Ipv4Addr)> {
    let (name, addr) = text
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("rewrite must be name=a.b.c.d"))?;
    Ok((name.to_string(), addr.parse()?))
}

fn static_word(word: &str) -> Result<(&'static str, Option<&'static str>)> {
    Ok(match word {
        "tcp" => ("tcp", None),
        "udp" => ("udp", None),
        "in" => ("tcp", Some("in")),
        "out" => ("tcp", Some("out")),
        "both" => ("tcp", Some("both")),
        _ => bail!("watch must be ip:port[/tcp|udp][/in|out|both]"),
    })
}

pub fn parse_watch(text: &str) -> Result<(Ipv4Addr, u16, &'static str, &'static str)> {
    let mut bits = text.split('/');
    let hostport = bits
        .next()
        .ok_or_else(|| anyhow::anyhow!("watch must be ip:port[/tcp|udp][/in|out|both]"))?;
    let mut proto = "tcp";
    let mut dir = "both";
    if let Some(word) = bits.next() {
        let (p, d) = static_word(word)?;
        proto = p;
        if let Some(d) = d {
            dir = d;
        }
    }
    if let Some(word) = bits.next() {
        dir = match word {
            "in" => "in",
            "out" => "out",
            "both" => "both",
            _ => bail!("watch direction must be in, out, or both"),
        };
    }
    let (ip, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("watch must be ip:port[/tcp|udp][/in|out|both]"))?;
    Ok((ip.parse()?, port.parse()?, proto, dir))
}
