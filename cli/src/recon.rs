//! Deep Wi-Fi recon: lock a channel, sniff frames for one AP, summarize
//! stations, probes, and airtime mix.

use std::collections::HashMap;
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
        eprintln!(
            "recon {} ch{} for {} (Ctrl-C to stop)",
            style(&label).bold(),
            channel,
            if secs == 0 {
                "until interrupt".into()
            } else {
                format!("{secs}s")
            }
        );
    }

    dev.wifi_monitor_start(channel, &filter, None)?;
    signals::install_sigint();
    signals::RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = dev.set_read_timeout(Duration::from_millis(200));

    let mut stats = ReconStats::default();
    let start = Instant::now();
    let limit = (secs > 0).then(|| Duration::from_secs(secs));

    loop {
        if !signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        if let Some(lim) = limit {
            if start.elapsed() >= lim {
                break;
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
            Err(_) if !signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) => break,
            Err(e) => return Err(e.into()),
        }
    }
    let _ = dev.stop_current_task();
    let elapsed = start.elapsed();

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stats_json(&stats, net, elapsed, oui_db))?
        );
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
    });
    e.count += 1;
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
    let secs = elapsed.as_secs_f64().max(0.001);
    println!();
    println!("{}", style("AP").bold());
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
        ("rssi".into(), format!("{} dBm", net.rssi)),
        ("encryption".into(), net.encryption.clone()),
        (
            "posture".into(),
            wifi_analysis::posture(net).as_str().into(),
        ),
    ];
    if let Some(v) = &net.vendor {
        rows.push(("vendor".into(), v.clone()));
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
    ui::detail_table(&rows);

    println!();
    println!("{}", style("Airtime").bold());
    ui::detail_table(&[
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
    ]);

    let mut stas: Vec<&Station> = stats.stations.values().collect();
    stas.sort_by(|a, b| b.frames.cmp(&a.frames));
    println!();
    println!(
        "{}  {}",
        style("Stations").bold(),
        style(format!("({})", stas.len())).dim()
    );
    if stas.is_empty() {
        println!("  (none seen - quiet channel or no client traffic during dwell)");
    } else {
        for (i, s) in stas.iter().enumerate() {
            let vend = vendor_of(&s.mac, oui_db);
            let vend = if vend.is_empty() {
                String::new()
            } else {
                format!("  {vend}")
            };
            println!(
                "  {:>2}  {}  {:>4} dBm  {:>5} frames  data={} null={}{}",
                i,
                fmt_mac(&s.mac),
                s.best_rssi,
                s.frames,
                s.data,
                s.nulls,
                vend
            );
        }
    }

    let mut probes: Vec<&Prober> = stats.probers.values().collect();
    probes.sort_by(|a, b| b.count.cmp(&a.count));
    println!();
    println!(
        "{}  {}",
        style("Probe requests").bold(),
        style(format!("({})", probes.len())).dim()
    );
    if probes.is_empty() {
        println!("  (none addressing this BSSID during dwell)");
    } else {
        for (i, p) in probes.iter().enumerate() {
            let vend = vendor_of(&p.mac, oui_db);
            let ssids = if p.ssids.is_empty() {
                "*".into()
            } else {
                p.ssids
                    .iter()
                    .map(|s| if s.is_empty() { "*" } else { s.as_str() })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let vend = if vend.is_empty() {
                String::new()
            } else {
                format!("  {vend}")
            };
            println!(
                "  {:>2}  {}  {:>4} dBm  {:>4}x  ssid=[{}]{}",
                i,
                fmt_mac(&p.mac),
                p.best_rssi,
                p.count,
                ssids,
                vend
            );
        }
    }
}

fn stats_json(
    stats: &ReconStats,
    net: &Network,
    elapsed: Duration,
    oui_db: Option<&oui::Db>,
) -> serde_json::Value {
    let mut stas: Vec<&Station> = stats.stations.values().collect();
    stas.sort_by(|a, b| b.frames.cmp(&a.frames));
    let mut probes: Vec<&Prober> = stats.probers.values().collect();
    probes.sort_by(|a, b| b.count.cmp(&a.count));
    serde_json::json!({
        "ap": {
            "ssid": net.ssid,
            "bssid": net.bssid,
            "channel": net.channel,
            "rssi": net.rssi,
            "encryption": net.encryption,
            "posture": wifi_analysis::posture(net).as_str(),
            "vendor": net.vendor,
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
            "vendor": vendor_of(&s.mac, oui_db),
        })).collect::<Vec<_>>(),
        "probers": probes.iter().map(|p| serde_json::json!({
            "mac": fmt_mac(&p.mac),
            "count": p.count,
            "ssids": p.ssids,
            "best_rssi": p.best_rssi,
            "vendor": vendor_of(&p.mac, oui_db),
        })).collect::<Vec<_>>(),
    })
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
    // Caller should interactive-pick when nothing is specified; keep a clear error
    // if someone hits this path without a selection.
    bail!("specify a scan #, --ssid, --bssid, or pick interactively");
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let bssid = [0xB0, 0xE4, 0xD5, 0x0A, 0xC7, 0xD2];
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
        let bssid = [0xB0, 0xE4, 0xD5, 0x0A, 0xC7, 0xD2];
        let sta = [0x94, 0xB3, 0xF7, 0xDB, 0x82, 0xF2];
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
}
