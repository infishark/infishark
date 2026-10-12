//! Deep Wi-Fi recon: lock a channel, sniff frames for one AP, and keep the
//! station, probe, and airtime tables current as frames arrive.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use console::style;
use infishark::ieee80211::{self, FrameType, mgmt_subtype};
use infishark::{Device, MonitorFilter, Network, oui};

use crate::signals;
use crate::ui;
use crate::wifi_analysis;

/// One associated (or strongly inferred) station.
#[derive(Debug, Clone)]
struct Station {
    mac: [u8; 6],
    frames: u64,
    data: u64,
    nulls: u64,
    best_rssi: i8,
    last_rssi: i8,
}

/// A client that probed for an SSID (may be unassociated).
#[derive(Debug, Clone)]
struct Prober {
    mac: [u8; 6],
    count: u64,
    /// Directed probe SSIDs seen (empty string = wildcard).
    ssids: Vec<String>,
    best_rssi: i8,
    last_rssi: i8,
}

#[derive(Debug, Default)]
struct ReconStats {
    frames: u64,
    beacons: u64,
    probe_req: u64,
    probe_resp: u64,
    data: u64,
    nulls: u64,
    ctrl: u64,
    mgmt_other: u64,
    eapol: u64,
    protected_data: u64,
    /// Latest RSSI from a frame the AP sent. The scan value stands in until
    /// then.
    ap_last_rssi: Option<i8>,
    stations: HashMap<[u8; 6], Station>,
    probers: HashMap<[u8; 6], Prober>,
}

/// Run deep recon against `net` for `secs` (0 = until Ctrl-C).
pub fn run(
    dev: &mut Device,
    net: &Network,
    secs: u64,
    oui_db: Option<&oui::Db>,
    as_json: bool,
) -> Result<()> {
    let bssid = ieee80211::parse_mac(&net.bssid)?;
    let channel = ieee80211::channel::require(net.channel)?;

    let filter = MonitorFilter::all();

    let label = if net.ssid.is_empty() {
        net.bssid.clone()
    } else {
        format!("{} ({})", net.ssid, net.bssid)
    };
    if !as_json {
        let dwell = if secs == 0 {
            "until Ctrl-C".to_string()
        } else {
            format!("for {secs}s (Ctrl-C to stop)")
        };
        eprintln!("recon {} ch{} {dwell}", style(&label).bold(), channel,);
    }

    dev.wifi_monitor_start(channel, &filter, None)?;
    signals::install_sigint();
    signals::RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = dev.set_read_timeout(Duration::from_millis(200));

    let mut stats = ReconStats::default();
    let start = Instant::now();
    let limit = (secs > 0).then(|| Duration::from_secs(secs));
    // Per-frame repaint flickers. 200 ms matches the other live views.
    const REDRAW: Duration = Duration::from_millis(200);
    let live = !as_json && std::io::stdout().is_terminal();
    let mut view = live.then(ui::StatusBlock::new);
    let mut last_draw: Option<Instant> = None;
    if let Some(v) = view.as_mut() {
        v.draw(&human_lines(&stats, net, Duration::ZERO, oui_db));
        last_draw = Some(Instant::now());
    }

    let result = loop {
        if !signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            break Ok(());
        }
        if let Some(lim) = limit {
            if start.elapsed() >= lim {
                break Ok(());
            }
        }
        match dev.next_wifi_frame_opt() {
            Ok(Some(payload)) if payload.len() >= 6 => {
                let rssi = payload[0] as i8;
                let frame = &payload[6..];
                ingest(&mut stats, bssid, &net.ssid, rssi, frame);
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(infishark::Error::Timeout) => {}
            Err(_) if !signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) => break Ok(()),
            Err(e) => break Err(e.into()),
        }
        let due = last_draw.is_none_or(|t| t.elapsed() >= REDRAW);
        if view.is_some() && due {
            let lines = human_lines(&stats, net, start.elapsed(), oui_db);
            if let Some(v) = view.as_mut() {
                v.draw(&lines);
            }
            last_draw = Some(Instant::now());
        }
    };
    if let Err(e) = result {
        if let Some(v) = view.as_mut() {
            v.clear();
        }
        return Err(e);
    }
    let _ = dev.stop_current_task();
    let elapsed = start.elapsed();

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stats_json(&stats, net, elapsed, oui_db))?
        );
    } else if let Some(v) = view.as_mut() {
        v.draw(&human_lines(&stats, net, elapsed, oui_db));
    } else {
        print_human(&stats, net, elapsed, oui_db);
    }
    Ok(())
}

fn ingest(stats: &mut ReconStats, bssid: [u8; 6], ap_ssid: &str, rssi: i8, raw: &[u8]) {
    let Some(fr) = ieee80211::parse_frame(raw) else {
        return;
    };
    let probe_ssid = (fr.ftype == FrameType::Mgmt && fr.subtype == mgmt_subtype::PROBE_REQ)
        .then(|| parse_ssid_ie(fr.body).unwrap_or_default());
    let for_ap = fr.bssid() == bssid
        || fr.addr1 == bssid
        || fr.addr2 == bssid
        || fr.addr3 == bssid
        || probe_ssid
            .as_deref()
            .is_some_and(|s| !ap_ssid.is_empty() && (s.is_empty() || s == ap_ssid));
    if !for_ap {
        return;
    }
    stats.frames += 1;
    if heard_from_ap(&fr, bssid) {
        stats.ap_last_rssi = Some(rssi);
    }

    match fr.ftype {
        FrameType::Mgmt => match fr.subtype {
            mgmt_subtype::BEACON => stats.beacons += 1,
            mgmt_subtype::PROBE_REQ => {
                stats.probe_req += 1;
                let ssid = probe_ssid.unwrap_or_default();
                touch_prober(stats, fr.addr2, rssi, ssid);
            }
            mgmt_subtype::PROBE_RESP => stats.probe_resp += 1,
            _ => stats.mgmt_other += 1,
        },
        FrameType::Ctrl => {
            stats.ctrl += 1;
            // PS-Poll: addr1 = BSSID, addr2 = STA.
            if fr.subtype == ieee80211::ctrl_subtype::PS_POLL && fr.addr1 == bssid {
                touch_station(stats, fr.addr2, rssi, false, true);
            }
        }
        FrameType::Data => {
            let is_null = matches!(
                fr.subtype,
                ieee80211::data_subtype::NULL | ieee80211::data_subtype::QOS_NULL
            );
            if is_null {
                stats.nulls += 1;
            } else {
                stats.data += 1;
            }
            if fr.protected {
                stats.protected_data += 1;
            }
            if is_eapol(&fr) {
                stats.eapol += 1;
            }
            // Infrastructure: station is the non-AP address.
            if fr.to_ds ^ fr.from_ds {
                let sta = fr.station();
                if sta != bssid && ieee80211::is_unicast(sta) {
                    touch_station(stats, sta, rssi, !is_null, is_null);
                }
            } else if !fr.to_ds && !fr.from_ds {
                for mac in [fr.addr1, fr.addr2] {
                    if mac != bssid && ieee80211::is_unicast(mac) {
                        touch_station(stats, mac, rssi, !is_null, is_null);
                    }
                }
            }
        }
        FrameType::Ext => {}
    }
}

/// Beacon, probe response, or FromDS data: the RSSI belongs to the AP.
fn heard_from_ap(fr: &ieee80211::Frame<'_>, bssid: [u8; 6]) -> bool {
    match fr.ftype {
        FrameType::Mgmt => {
            matches!(fr.subtype, mgmt_subtype::BEACON | mgmt_subtype::PROBE_RESP)
                && fr.addr2 == bssid
        }
        FrameType::Data => fr.from_ds && !fr.to_ds && fr.addr2 == bssid,
        _ => false,
    }
}

fn is_eapol(fr: &ieee80211::Frame<'_>) -> bool {
    if fr.ftype != FrameType::Data || fr.protected {
        return false;
    }
    // LLC/SNAP: AA AA 03 00 00 00 <ethertype>
    let et = ieee80211::ethertype::EAPOL.to_be_bytes();
    fr.body.len() >= 8
        && fr.body[0] == 0xaa
        && fr.body[1] == 0xaa
        && fr.body[2] == 0x03
        && fr.body[6] == et[0]
        && fr.body[7] == et[1]
}

/// SSID IE from a probe-request body (IEs start at offset 0).
fn parse_ssid_ie(body: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 2 <= body.len() {
        let id = body[i];
        let len = body[i + 1] as usize;
        i += 2;
        if i + len > body.len() {
            break;
        }
        if id == 0 {
            return Some(String::from_utf8_lossy(&body[i..i + len]).into_owned());
        }
        i += len;
    }
    None
}

fn touch_station(stats: &mut ReconStats, mac: [u8; 6], rssi: i8, data: bool, null: bool) {
    let e = stats.stations.entry(mac).or_insert(Station {
        mac,
        frames: 0,
        data: 0,
        nulls: 0,
        best_rssi: rssi,
        last_rssi: rssi,
    });
    e.frames += 1;
    if data {
        e.data += 1;
    }
    if null {
        e.nulls += 1;
    }
    e.last_rssi = rssi;
    if rssi > e.best_rssi {
        e.best_rssi = rssi;
    }
}

fn touch_prober(stats: &mut ReconStats, mac: [u8; 6], rssi: i8, ssid: String) {
    let e = stats.probers.entry(mac).or_insert(Prober {
        mac,
        count: 0,
        ssids: Vec::new(),
        best_rssi: rssi,
        last_rssi: rssi,
    });
    e.count += 1;
    e.last_rssi = rssi;
    if rssi > e.best_rssi {
        e.best_rssi = rssi;
    }
    if !e.ssids.iter().any(|s| s == &ssid) {
        e.ssids.push(ssid);
    }
}

fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn vendor_of(mac: &[u8; 6], db: Option<&oui::Db>) -> String {
    if mac[0] & 0x02 != 0 {
        return String::new();
    }
    let s = fmt_mac(mac);
    db.and_then(|d| d.lookup(&s).map(|v| v.to_string()))
        .unwrap_or_default()
}

fn print_human(stats: &ReconStats, net: &Network, elapsed: Duration, oui_db: Option<&oui::Db>) {
    for line in human_lines(stats, net, elapsed, oui_db) {
        println!("{line}");
    }
}

fn human_lines(
    stats: &ReconStats,
    net: &Network,
    elapsed: Duration,
    oui_db: Option<&oui::Db>,
) -> Vec<String> {
    let secs = elapsed.as_secs_f64().max(0.001);
    let mut lines = Vec::new();
    lines.push(String::new());
    lines.push(style("AP").bold().to_string());
    let mut rows: Vec<(String, String)> = vec![
        (
            "ssid".into(),
            if net.ssid.is_empty() {
                "<hidden>".into()
            } else {
                net.ssid.clone()
            },
        ),
        ("bssid".into(), net.bssid.clone()),
        ("channel".into(), net.channel.to_string()),
        (
            "rssi".into(),
            format!("{} dBm", stats.ap_last_rssi.unwrap_or(net.rssi)),
        ),
        ("encryption".into(), net.encryption.clone()),
        (
            "posture".into(),
            wifi_analysis::posture(net).as_str().into(),
        ),
    ];
    if let Some(v) = ap_vendor(net, oui_db) {
        rows.push(("vendor".into(), v));
    }
    for key in [
        "phy",
        "wps",
        "pairwise_cipher",
        "group_cipher",
        "bandwidth",
        "secondary",
        "country",
    ] {
        let s = if key == "wps" {
            if net.extra_bool(key) {
                "yes".into()
            } else {
                continue;
            }
        } else if key == "bandwidth" {
            net.extra_num(key)
        } else {
            net.extra_str(key).to_string()
        };
        if !s.is_empty() {
            rows.push((key.into(), s));
        }
    }
    push_detail(&mut lines, &rows);

    lines.push(String::new());
    lines.push(style("Airtime").bold().to_string());
    push_detail(
        &mut lines,
        &[
            ("dwell".to_string(), ui::fmt_elapsed(elapsed)),
            ("frames".into(), stats.frames.to_string()),
            (
                "rate".into(),
                format!("{:.1} fps", stats.frames as f64 / secs),
            ),
            ("beacons".into(), stats.beacons.to_string()),
            ("probe_req".into(), stats.probe_req.to_string()),
            ("probe_resp".into(), stats.probe_resp.to_string()),
            ("data".into(), stats.data.to_string()),
            ("nulls".into(), stats.nulls.to_string()),
            ("ctrl".into(), stats.ctrl.to_string()),
            ("eapol".into(), stats.eapol.to_string()),
            ("protected_data".into(), stats.protected_data.to_string()),
        ],
    );

    let stas = sorted_stations(stats);
    lines.push(String::new());
    lines.push(format!(
        "{}  {}",
        style("Stations").bold(),
        style(format!("({})", stas.len())).dim()
    ));
    if stas.is_empty() {
        lines.push("  (none seen - quiet channel or no client traffic during dwell)".into());
    } else {
        for (i, s) in stas.iter().enumerate() {
            lines.push(format!(
                "  {:>2}  {}  {:>4} dBm  {:>5} frames  data={} null={}{}",
                i,
                fmt_mac(&s.mac),
                s.last_rssi,
                s.frames,
                s.data,
                s.nulls,
                vendor_suffix(&s.mac, oui_db)
            ));
        }
    }

    let probes = sorted_probers(stats);
    lines.push(String::new());
    lines.push(format!(
        "{}  {}",
        style("Probe requests").bold(),
        style(format!("({})", probes.len())).dim()
    ));
    if probes.is_empty() {
        lines.push("  (none addressing this BSSID during dwell)".into());
    } else {
        for (i, p) in probes.iter().enumerate() {
            let ssids = if p.ssids.is_empty() {
                "*".into()
            } else {
                p.ssids
                    .iter()
                    .map(|s| if s.is_empty() { "*" } else { s.as_str() })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            lines.push(format!(
                "  {:>2}  {}  {:>4} dBm  {:>4}x  ssid=[{}]{}",
                i,
                fmt_mac(&p.mac),
                p.last_rssi,
                p.count,
                ssids,
                vendor_suffix(&p.mac, oui_db)
            ));
        }
    }
    lines
}

fn ap_vendor(net: &Network, oui_db: Option<&oui::Db>) -> Option<String> {
    net.vendor
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| oui_db.and_then(|db| db.lookup_ap(&net.bssid).map(str::to_string)))
}

fn push_detail(lines: &mut Vec<String>, rows: &[(String, String)]) {
    let w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in rows {
        lines.push(format!("  {}  {}", style(format!("{k:<w$}")).dim(), v));
    }
}

fn vendor_suffix(mac: &[u8; 6], db: Option<&oui::Db>) -> String {
    let vend = vendor_of(mac, db);
    if vend.is_empty() {
        String::new()
    } else {
        format!("  {vend}")
    }
}

fn sorted_stations(stats: &ReconStats) -> Vec<&Station> {
    let mut stas: Vec<&Station> = stats.stations.values().collect();
    stas.sort_by(|a, b| b.frames.cmp(&a.frames).then_with(|| a.mac.cmp(&b.mac)));
    stas
}

fn sorted_probers(stats: &ReconStats) -> Vec<&Prober> {
    let mut probes: Vec<&Prober> = stats.probers.values().collect();
    probes.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.mac.cmp(&b.mac)));
    probes
}

fn stats_json(
    stats: &ReconStats,
    net: &Network,
    elapsed: Duration,
    oui_db: Option<&oui::Db>,
) -> serde_json::Value {
    let stas = sorted_stations(stats);
    let probes = sorted_probers(stats);
    serde_json::json!({
        "ap": {
            "ssid": net.ssid,
            "bssid": net.bssid,
            "channel": net.channel,
            "rssi": stats.ap_last_rssi.unwrap_or(net.rssi),
            "encryption": net.encryption,
            "posture": wifi_analysis::posture(net).as_str(),
            "vendor": ap_vendor(net, oui_db),
        },
        "dwell_ms": elapsed.as_millis() as u64,
        "frames": stats.frames,
        "beacons": stats.beacons,
        "probe_req": stats.probe_req,
        "probe_resp": stats.probe_resp,
        "data": stats.data,
        "nulls": stats.nulls,
        "ctrl": stats.ctrl,
        "eapol": stats.eapol,
        "protected_data": stats.protected_data,
        "stations": stas.iter().map(|s| serde_json::json!({
            "mac": fmt_mac(&s.mac),
            "frames": s.frames,
            "data": s.data,
            "nulls": s.nulls,
            "best_rssi": s.best_rssi,
            "last_rssi": s.last_rssi,
            "vendor": vendor_of(&s.mac, oui_db),
        })).collect::<Vec<_>>(),
        "probers": probes.iter().map(|p| serde_json::json!({
            "mac": fmt_mac(&p.mac),
            "count": p.count,
            "ssids": p.ssids,
            "best_rssi": p.best_rssi,
            "last_rssi": p.last_rssi,
            "vendor": vendor_of(&p.mac, oui_db),
        })).collect::<Vec<_>>(),
    })
}

/// Row number from the last `wifi scan` / `wifi list` table.
pub fn wifi_scan_row(token: &str) -> Result<Network> {
    let nets = crate::LAST_WIFI.lock().unwrap().clone();
    if nets.is_empty() {
        bail!("no wifi scan yet; run `wifi scan` first");
    }
    resolve_from_cache(&nets, Some(token.trim()), None, None)
}

/// Resolve a recon/show target from the last scan cache.
pub fn resolve_from_cache(
    nets: &[Network],
    sel: Option<&str>,
    ssid: Option<&str>,
    bssid: Option<&str>,
) -> Result<Network> {
    if let Some(b) = bssid {
        let b = b.to_ascii_uppercase();
        return nets
            .iter()
            .find(|n| n.bssid.eq_ignore_ascii_case(&b))
            .cloned()
            .with_context(|| format!("BSSID {b} not in last scan; run `wifi scan` first"));
    }
    if let Some(s) = ssid {
        let mut matches: Vec<&Network> = nets.iter().filter(|n| n.ssid == s).collect();
        if matches.is_empty() {
            bail!("SSID {s:?} not in last scan; run `wifi scan` first");
        }
        matches.sort_by_key(|n| std::cmp::Reverse(n.rssi));
        return Ok(matches[0].clone());
    }
    if let Some(tok) = sel {
        // Prefer numeric index into the RSSI-sorted table (same order as print).
        if let Ok(idx) = tok.parse::<usize>() {
            if nets.iter().any(|n| n.ssid == tok) {
                return resolve_from_cache(nets, None, Some(tok), None);
            }
            let mut order: Vec<usize> = (0..nets.len()).collect();
            order.sort_by_key(|&i| std::cmp::Reverse(nets[i].rssi));
            return order.get(idx).map(|&i| nets[i].clone()).with_context(|| {
                format!(
                    "index {idx} out of range (0..{})",
                    nets.len().saturating_sub(1)
                )
            });
        }
        // Fall back: BSSID or exact SSID token.
        if tok.contains(':') || tok.contains('-') {
            return resolve_from_cache(nets, None, None, Some(tok));
        }
        return resolve_from_cache(nets, None, Some(tok), None);
    }
    bail!("specify a scan #, --ssid, --bssid, or pick interactively");
}

#[cfg(test)]
mod tests {
    use super::*;

    const BSSID: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const STA: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const SSID: &str = "lab";

    fn from_ds_data(bssid: [u8; 6], dest: [u8; 6], src: [u8; 6]) -> Vec<u8> {
        let mut f = vec![0x08, 0x02, 0, 0]; // data, FromDS
        f.extend_from_slice(&dest);
        f.extend_from_slice(&bssid);
        f.extend_from_slice(&src);
        f.extend_from_slice(&[0, 0]);
        f
    }

    #[test]
    fn multicast_dest_is_not_a_station() {
        let bssid = BSSID;
        let mut stats = ReconStats::default();
        ingest(
            &mut stats,
            bssid,
            "lab",
            -50,
            &from_ds_data(bssid, [0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA], [0x11; 6]),
        );
        ingest(
            &mut stats,
            bssid,
            "lab",
            -50,
            &from_ds_data(bssid, [0x33, 0x33, 0x00, 0x00, 0x00, 0xFB], [0x11; 6]),
        );
        assert!(
            stats.stations.is_empty(),
            "group dests counted as stations: {:?}",
            stats.stations.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn unicast_dest_is_a_station() {
        let bssid = BSSID;
        let sta = STA;
        let mut stats = ReconStats::default();
        ingest(
            &mut stats,
            bssid,
            "lab",
            -70,
            &from_ds_data(bssid, sta, [0x22; 6]),
        );
        assert!(stats.stations.contains_key(&sta));
    }

    fn beacon(bssid: [u8; 6]) -> Vec<u8> {
        let mut f = vec![0x80, 0x00, 0, 0];
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&bssid);
        f.extend_from_slice(&bssid);
        f.extend_from_slice(&[0, 0]);
        f
    }

    fn to_ds_data(bssid: [u8; 6], sta: [u8; 6]) -> Vec<u8> {
        let mut f = vec![0x08, 0x01, 0, 0];
        f.extend_from_slice(&bssid);
        f.extend_from_slice(&sta);
        f.extend_from_slice(&bssid);
        f.extend_from_slice(&[0, 0]);
        f
    }

    fn lab_net(rssi: i8) -> Network {
        serde_json::from_value(serde_json::json!({
            "bssid": "02:00:00:00:00:01",
            "ssid": SSID,
            "rssi": rssi,
            "channel": 1,
            "encryption": "WPA2_PSK"
        }))
        .unwrap()
    }

    #[test]
    fn ap_rssi_follows_frames_the_ap_sent() {
        let bssid = BSSID;
        let sta = STA;
        let mut stats = ReconStats::default();
        ingest(&mut stats, bssid, SSID, -20, &to_ds_data(bssid, sta));
        assert_eq!(stats.ap_last_rssi, None);
        ingest(&mut stats, bssid, SSID, -48, &beacon(bssid));
        ingest(&mut stats, bssid, SSID, -63, &beacon(bssid));
        assert_eq!(stats.ap_last_rssi, Some(-63));
        let text = human_lines(&stats, &lab_net(-55), Duration::from_secs(1), None).join("\n");
        assert!(text.contains("-63 dBm"), "{text}");
        assert!(!text.contains("-55"), "{text}");
        assert!(text.contains("-20 dBm"), "{text}");
        ingest(
            &mut stats,
            bssid,
            SSID,
            -30,
            &from_ds_data(bssid, sta, [0x22; 6]),
        );
        assert_eq!(stats.ap_last_rssi, Some(-30));
    }

    #[test]
    fn station_row_shows_latest_rssi() {
        let bssid = BSSID;
        let sta = STA;
        let mut stats = ReconStats::default();
        ingest(&mut stats, bssid, SSID, -41, &to_ds_data(bssid, sta));
        ingest(&mut stats, bssid, SSID, -77, &to_ds_data(bssid, sta));
        let text = human_lines(&stats, &lab_net(-55), Duration::from_secs(2), None).join("\n");
        assert!(text.contains("-77 dBm"), "{text}");
        assert!(!text.contains("-41"), "{text}");
        assert_eq!(stats.stations[&sta].best_rssi, -41);
    }
}
