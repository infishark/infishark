//! Profile of an open GATT link: connection parameters, a few well-known
//! characteristics, and a live count of notifications.
//!
//! This is the connected device, not a sniffer. The radio does not see other
//! devices' packets once the link is up.

use std::io::IsTerminal;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use console::style;
use infishark::GattNotification;

use crate::gatt_names::sig_uuid16 as uuid16;
use crate::signals;
use crate::ui;

/// Identity reads, in display order. Only rows that advertise `read`.
const IDENTITY: &[u16] = &[
    0x2a00, 0x2a01, 0x2a29, 0x2a24, 0x2a25, 0x2a26, 0x2a27, 0x2a28, 0x2a50, 0x2a19, 0x2a4b,
];

const REDRAW: Duration = Duration::from_millis(200);
const POLL: Duration = Duration::from_millis(200);
/// Bytes of a notification shown on the traffic line.
const HEX_CAP: usize = 8;

struct Link {
    addr: String,
    addr_type: u8,
    rssi: i32,
    /// 1.25 ms units.
    interval: u16,
    latency: u16,
    /// 10 ms units.
    timeout: u16,
    mtu: u16,
    encrypted: bool,
    bonded: bool,
    key_size: u8,
}

struct Ident {
    label: &'static str,
    uuid16: u16,
    handle: u16,
    value: String,
    error: Option<String>,
}

struct Traffic {
    row: Option<usize>,
    handle: u16,
    name: String,
    kind: &'static str,
    count: u64,
    last_hex: String,
}

struct Profile {
    name: String,
    address: String,
    link: Option<Link>,
    identity: Vec<Ident>,
    traffic: Vec<Traffic>,
    elapsed: Duration,
}

struct Prepared {
    profile: Profile,
    rows: Vec<ui::GattRow>,
    link_supported: bool,
}

/// Listen until Ctrl-C, or for `seconds` when that is non-zero.
///
/// Ctrl-C during the initial read is a cancel. Ctrl-C during the listen keeps
/// the last profile. Subscriptions stay enabled, same as `ble gatt subscribe`.
pub(crate) fn run(cli: &crate::Cli, dev: &mut infishark::Device, seconds: u64) -> Result<()> {
    signals::install_sigint();
    signals::RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);

    let sp = ui::Spinner::start("reading profile");
    let prepared = prepare(cli, dev);
    sp.stop();
    let Prepared {
        mut profile,
        rows,
        link_supported,
    } = prepared?;
    if !link_supported {
        crate::log::warn("link details need a newer firmware; showing GATT only");
    }

    if !cli.json {
        let dwell = if seconds == 0 {
            "until Ctrl-C".to_string()
        } else {
            format!("for {seconds}s (Ctrl-C to stop)")
        };
        eprintln!("recon {} {dwell}", style(title(&profile)).bold());
    }

    let _ = dev.set_read_timeout(POLL);
    let start = Instant::now();
    let limit = (seconds > 0).then(|| Duration::from_secs(seconds));
    let live = !cli.json && std::io::stdout().is_terminal();
    let mut view = live.then(ui::StatusBlock::new);
    let mut last_draw: Option<Instant> = None;
    let mut last_link = Instant::now();
    paint(&mut view, &mut profile, start, &mut last_draw);

    let result = loop {
        if !signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            break Ok(());
        }
        if limit.is_some_and(|lim| start.elapsed() >= lim) {
            break Ok(());
        }
        if link_supported && last_link.elapsed() >= Duration::from_secs(1) {
            match refresh_link(dev, &mut profile) {
                Ok(()) => {}
                Err(infishark::Error::Interrupted) => break Ok(()),
                // The peer dropped. Keep the profile we already have.
                Err(e) if e.to_string().contains("not connected") => break Ok(()),
                Err(_) => {}
            }
            last_link = Instant::now();
        }
        match dev.poll_notification() {
            Ok(Some(n)) => apply_note(&mut profile, &rows, &n),
            Ok(None) => {}
            Err(infishark::Error::Timeout) | Err(infishark::Error::Json(_)) => {}
            Err(infishark::Error::Interrupted) => break Ok(()),
            Err(_) if !signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) => break Ok(()),
            Err(e) => break Err(e),
        }
        if last_draw.is_none_or(|t| t.elapsed() >= REDRAW) {
            paint(&mut view, &mut profile, start, &mut last_draw);
        }
    };

    if let Err(e) = result {
        if let Some(v) = view.as_mut() {
            v.clear();
        }
        return Err(e.into());
    }
    profile.elapsed = start.elapsed();
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&profile_json(&profile))?);
    } else if let Some(v) = view.as_mut() {
        v.draw(&human_lines(&profile));
    } else {
        for line in human_lines(&profile) {
            println!("{line}");
        }
    }
    Ok(())
}

fn paint(
    view: &mut Option<ui::StatusBlock>,
    profile: &mut Profile,
    start: Instant,
    last_draw: &mut Option<Instant>,
) {
    profile.elapsed = start.elapsed();
    if let Some(v) = view.as_mut() {
        v.draw(&human_lines(profile));
        *last_draw = Some(Instant::now());
    }
}

fn refresh_link(dev: &mut infishark::Device, profile: &mut Profile) -> infishark::Result<()> {
    let _ = dev.set_read_timeout(Duration::from_millis(1000));
    let got = dev.gatt_link();
    let _ = dev.set_read_timeout(POLL);
    match got {
        Ok(v) => {
            let link = parse_link(&v);
            if profile.address.is_empty() {
                profile.address = link.addr.clone();
            }
            profile.link = Some(link);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn prepare(cli: &crate::Cli, dev: &mut infishark::Device) -> Result<Prepared> {
    still_running()?;
    let services = match dev.gatt_enum() {
        Ok(s) => s,
        Err(infishark::Error::Interrupted) => return Err(infishark::Error::Interrupted.into()),
        Err(e) if e.to_string().contains("not connected") => {
            bail!("not connected; run `ble gatt connect` first");
        }
        Err(e) => return Err(e.into()),
    };
    let rows = ui::gatt_rows(&services);
    *crate::LAST_GATT.lock().unwrap() = rows.clone();

    still_running()?;
    let (link, link_supported) = match dev.gatt_link() {
        Ok(v) => (Some(parse_link(&v)), true),
        Err(infishark::Error::Interrupted) => return Err(infishark::Error::Interrupted.into()),
        Err(infishark::Error::Device { code, .. })
            if code == infishark::protocol::ERR_UNKNOWN_COMMAND =>
        {
            (None, false)
        }
        Err(e) if e.to_string().contains("not connected") => {
            bail!("not connected; run `ble gatt connect` first");
        }
        Err(e) => return Err(e.into()),
    };

    let mut profile = Profile {
        name: String::new(),
        address: link.as_ref().map(|l| l.addr.clone()).unwrap_or_default(),
        link,
        identity: Vec::new(),
        traffic: Vec::new(),
        elapsed: Duration::ZERO,
    };
    // Name lookup takes the scan cache lock. Do not hold it across a GATT call.
    if profile.name.is_empty() && !profile.address.is_empty() {
        if let Some(n) = crate::ble_cached_name(&profile.address) {
            profile.name = n;
        }
    }

    still_running()?;
    profile.identity = read_identity(cli, dev, &rows)?;
    if let Some(n) = profile
        .identity
        .iter()
        .find(|r| r.uuid16 == 0x2a00 && r.error.is_none())
    {
        profile.name = n.value.clone();
    }

    still_running()?;
    profile.traffic = subscribe_traffic(cli, dev, &rows)?;
    Ok(Prepared {
        profile,
        rows,
        link_supported,
    })
}

fn still_running() -> Result<()> {
    if signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
        Ok(())
    } else {
        Err(signals::cancelled())
    }
}

fn read_identity(
    cli: &crate::Cli,
    dev: &mut infishark::Device,
    rows: &[ui::GattRow],
) -> Result<Vec<Ident>> {
    let mut out = Vec::new();
    for uuid in IDENTITY {
        for row in rows {
            if uuid16(&row.uuid) != Some(*uuid) || !has_prop(&row.props, "read") {
                continue;
            }
            still_running()?;
            let handle = (row.handle != 0).then_some(row.handle);
            match dev.gatt_read_at_with(&row.uuid, handle, |v| crate::watch_pair(cli, v)) {
                Ok(bytes) => {
                    let value = decode_known(*uuid, &bytes).unwrap_or_default();
                    if value.is_empty() {
                        continue;
                    }
                    out.push(Ident {
                        label: identity_label(*uuid),
                        uuid16: *uuid,
                        handle: row.handle,
                        value,
                        error: None,
                    });
                }
                Err(infishark::Error::Interrupted) => {
                    return Err(infishark::Error::Interrupted.into());
                }
                Err(e) => out.push(Ident {
                    label: identity_label(*uuid),
                    uuid16: *uuid,
                    handle: row.handle,
                    value: String::new(),
                    error: Some(short_reason(&e)),
                }),
            }
        }
    }
    Ok(out)
}

fn subscribe_traffic(
    cli: &crate::Cli,
    dev: &mut infishark::Device,
    rows: &[ui::GattRow],
) -> Result<Vec<Traffic>> {
    let tokens = vec!["all".to_string()];
    let sel = match ui::select_gatt(rows, &tokens, ui::GattOp::Subscribe { indicate: false }) {
        Ok(sel) => sel,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("no notifiable") || msg.contains("no gatt table") {
                return Ok(Vec::new());
            }
            return Err(e);
        }
    };
    let mut traffic = Vec::new();
    for t in &sel.targets {
        match dev.gatt_subscribe_at(&t.uuid, t.handle, t.indicate) {
            Ok(()) => traffic.push(Traffic {
                row: t.row,
                handle: t.handle.unwrap_or(0),
                name: t.name.clone(),
                kind: if t.indicate { "indicate" } else { "notify" },
                count: 0,
                last_hex: String::new(),
            }),
            Err(infishark::Error::Interrupted) => {
                return Err(infishark::Error::Interrupted.into());
            }
            Err(e) => crate::report_target_err(cli, t, &short_reason(&e)),
        }
    }
    Ok(traffic)
}

fn short_reason(e: &infishark::Error) -> String {
    if let infishark::Error::Device { message, .. } = e {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(message) {
            for key in ["reason", "error"] {
                if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
        }
    }
    e.to_string()
        .lines()
        .next()
        .unwrap_or("read failed")
        .chars()
        .take(80)
        .collect()
}

fn parse_link(v: &serde_json::Value) -> Link {
    Link {
        addr: v
            .get("addr")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_ascii_lowercase(),
        addr_type: u_field(v, "addr_type", u8::MAX as u64) as u8,
        rssi: v.get("rssi").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        interval: u_field(v, "interval", u16::MAX as u64) as u16,
        latency: u_field(v, "latency", u16::MAX as u64) as u16,
        timeout: u_field(v, "timeout", u16::MAX as u64) as u16,
        mtu: u_field(v, "mtu", u16::MAX as u64) as u16,
        encrypted: v
            .get("encrypted")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        bonded: v.get("bonded").and_then(|x| x.as_bool()).unwrap_or(false),
        key_size: u_field(v, "key_size", u8::MAX as u64) as u8,
    }
}

fn u_field(v: &serde_json::Value, key: &str, max: u64) -> u64 {
    v.get(key).and_then(|x| x.as_u64()).unwrap_or(0).min(max)
}

fn apply_note(profile: &mut Profile, rows: &[ui::GattRow], n: &GattNotification) {
    if n.handle == 0 {
        return;
    }
    if let Some(t) = profile.traffic.iter_mut().find(|t| t.handle == n.handle) {
        t.count += 1;
        t.last_hex = n.hex.clone();
        t.kind = if n.is_notify { "notify" } else { "indicate" };
    } else {
        let found = rows.iter().enumerate().find(|(_, r)| r.handle == n.handle);
        profile.traffic.push(Traffic {
            row: found.map(|(i, _)| i),
            handle: n.handle,
            name: found
                .map(|(_, r)| r.name.clone())
                .unwrap_or_else(|| char_label(&n.characteristic)),
            kind: if n.is_notify { "notify" } else { "indicate" },
            count: 1,
            last_hex: n.hex.clone(),
        });
    }
    if let Some(id) = profile
        .identity
        .iter_mut()
        .find(|r| r.handle == n.handle && r.uuid16 == 0x2a19 && r.error.is_none())
    {
        if let Some(b) = first_byte(&n.hex) {
            id.value = format!("{b}%");
        }
    }
}

fn char_label(uuid: &str) -> String {
    crate::gatt_names::characteristic(uuid)
        .unwrap_or("<unknown>")
        .to_string()
}

fn has_prop(props: &str, name: &str) -> bool {
    props.split(',').any(|p| p == name)
}

fn identity_label(uuid: u16) -> &'static str {
    match uuid {
        0x2a00 => "name",
        0x2a01 => "appearance",
        0x2a29 => "manufacturer",
        0x2a24 => "model",
        0x2a25 => "serial",
        0x2a26 => "firmware",
        0x2a27 => "hardware",
        0x2a28 => "software",
        0x2a50 => "pnp",
        0x2a19 => "battery",
        0x2a4b => "report map",
        _ => "value",
    }
}

fn decode_known(uuid: u16, bytes: &[u8]) -> Option<String> {
    Some(match uuid {
        0x2a00 | 0x2a24 | 0x2a25 | 0x2a26 | 0x2a27 | 0x2a28 | 0x2a29 => utf8_text(bytes),
        0x2a01 => {
            if bytes.len() < 2 {
                return None;
            }
            let v = u16::from_le_bytes([bytes[0], bytes[1]]);
            appearance_words(v)
        }
        0x2a19 => {
            if bytes.is_empty() {
                return None;
            }
            format!("{}%", bytes[0])
        }
        0x2a50 => pnp_text(bytes)?,
        0x2a4b => format!("{} bytes", bytes.len()),
        _ => return None,
    })
}

fn utf8_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn appearance_words(v: u16) -> String {
    if (0x03C1..=0x03C5).contains(&v) {
        return crate::hid::appearance_label(v).to_string();
    }
    let cat = match v & 0xFFC0 {
        0x0000 => "unknown",
        0x0040 => "phone",
        0x0080 => "computer",
        0x00C0 => "watch",
        0x0100 => "clock",
        0x0140 => "display",
        0x0180 => "remote",
        0x01C0 => "eyewear",
        0x0200 => "tag",
        0x0240 => "keyring",
        0x0280 => "media player",
        0x02C0 => "barcode",
        0x0300 => "thermometer",
        0x0340 => "heart rate",
        0x0380 => "blood pressure",
        0x03C0 => "hid",
        0x0440 => "glucose",
        0x0480 => "running",
        0x04C0 => "cycling",
        0x0540 => "pulse oximeter",
        0x0580 => "weight scale",
        0x07C0 => "outdoor",
        _ => return format!("0x{v:04x}"),
    };
    if v & 0x3F == 0 {
        cat.to_string()
    } else {
        format!("{cat} 0x{v:04x}")
    }
}

fn pnp_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 7 {
        return None;
    }
    let source = match bytes[0] {
        1 => "bluetooth",
        2 => "usb",
        _ => "vendor",
    };
    let vid = u16::from_le_bytes([bytes[1], bytes[2]]);
    let pid = u16::from_le_bytes([bytes[3], bytes[4]]);
    let ver = u16::from_le_bytes([bytes[5], bytes[6]]);
    Some(format!("{source} {vid:04x}:{pid:04x} {ver:04x}"))
}

fn title(p: &Profile) -> String {
    match (p.name.is_empty(), p.address.is_empty()) {
        (false, false) => format!("{}  {}", ui::tty_text(&p.name), ui::tty_text(&p.address)),
        (false, true) => ui::tty_text(&p.name),
        (true, false) => ui::tty_text(&p.address),
        (true, true) => "connected".into(),
    }
}

fn link_flags(link: &Link) -> String {
    let mut parts = Vec::new();
    parts.push(if link.encrypted { "encrypted" } else { "open" });
    if link.bonded {
        parts.push("bonded");
    }
    let mut line = format!("{}, rssi {} dBm", parts.join(", "), link.rssi);
    if link.encrypted && link.key_size > 0 {
        line.push_str(&format!(", key {}", link.key_size));
    }
    line
}

fn interval_text(units: u16) -> String {
    format!("{} ms", trim_number(f64::from(units) * 1.25))
}

fn timeout_text(units: u16) -> String {
    let ms = u32::from(units) * 10;
    if ms >= 10_000 {
        format!("{} s", trim_number(f64::from(ms) / 1000.0))
    } else {
        format!("{ms} ms")
    }
}

fn trim_number(n: f64) -> String {
    format!("{n:.2}")
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

fn dwell_text(elapsed: Duration) -> String {
    format!("{:.1}s", elapsed.as_secs_f64())
}

fn human_lines(p: &Profile) -> Vec<String> {
    let mut lines = vec![style(title(p)).bold().to_string()];
    if let Some(link) = &p.link {
        lines.push(format!("{:<8}  {}", "link", link_flags(link)));
        lines.push(format!(
            "{:<8}  {}   latency {}   timeout {}   mtu {}",
            "interval",
            interval_text(link.interval),
            link.latency,
            timeout_text(link.timeout),
            link.mtu
        ));
    }
    lines.push(String::new());
    lines.push(style("identity").bold().to_string());
    lines.extend(identity_lines(&p.identity));
    lines.push(String::new());
    lines.push(format!(
        "{}  {}",
        style("traffic").bold(),
        style(dwell_text(p.elapsed)).dim()
    ));
    lines.extend(traffic_lines(&p.traffic));
    lines
}

fn identity_lines(rows: &[Ident]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["  (none)".into()];
    }
    let w = rows.iter().map(|r| r.label.len()).max().unwrap_or(0);
    rows.iter()
        .map(|r| {
            let value = match &r.error {
                Some(err) => format!("skipped ({})", ui::tty_text(err)),
                None => ui::tty_text(&r.value),
            };
            format!("  {:<w$}  {value}", r.label)
        })
        .collect()
}

fn traffic_lines(traffic: &[Traffic]) -> Vec<String> {
    if traffic.is_empty() {
        return vec!["  (quiet)".into()];
    }
    let rows = sorted_traffic(traffic);
    let name_w = rows.iter().map(|t| t.name.len()).max().unwrap_or(0);
    let count_w = rows
        .iter()
        .map(|t| t.count.to_string().len())
        .max()
        .unwrap_or(1);
    rows.into_iter()
        .map(|t| {
            let n = match t.row {
                Some(i) => format!("{i:>3}"),
                None => "   ".into(),
            };
            let hex = if t.count == 0 {
                String::new()
            } else {
                let h = hex_capped(&t.last_hex);
                if h.is_empty() {
                    String::new()
                } else {
                    format!("  {h}")
                }
            };
            format!(
                "{n}  {:<name_w$}  {:<9}  {:>count_w$}{hex}",
                ui::tty_text(&t.name),
                t.kind,
                t.count
            )
        })
        .collect()
}

fn sorted_traffic(traffic: &[Traffic]) -> Vec<&Traffic> {
    let mut rows: Vec<&Traffic> = traffic.iter().collect();
    rows.sort_by_key(|t| (t.row.unwrap_or(usize::MAX), t.handle));
    rows
}

fn compact_hex(hex: &str) -> String {
    hex.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn hex_capped(hex: &str) -> String {
    let raw = compact_hex(hex);
    let bytes = raw.len() / 2;
    let show = bytes.min(HEX_CAP);
    let mut parts = Vec::with_capacity(show);
    for i in 0..show {
        parts.push(&raw[i * 2..i * 2 + 2]);
    }
    let mut s = parts.join(" ");
    if bytes > show {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str("...");
    }
    s
}

fn first_byte(hex: &str) -> Option<u8> {
    let raw = compact_hex(hex);
    if raw.len() < 2 {
        return None;
    }
    u8::from_str_radix(&raw[..2], 16).ok()
}

fn profile_json(p: &Profile) -> serde_json::Value {
    let traffic = sorted_traffic(&p.traffic);
    serde_json::json!({
        "name": p.name,
        "address": p.address,
        "seconds": (p.elapsed.as_secs_f64() * 10.0).round() / 10.0,
        "link": p.link.as_ref().map(link_json),
        "identity": p.identity.iter().map(ident_json).collect::<Vec<_>>(),
        "traffic": traffic.iter().copied().map(traffic_json).collect::<Vec<_>>(),
    })
}

fn link_json(l: &Link) -> serde_json::Value {
    serde_json::json!({
        "addr": l.addr,
        "addr_type": l.addr_type,
        "rssi": l.rssi,
        "interval": l.interval,
        "interval_ms": f64::from(l.interval) * 1.25,
        "latency": l.latency,
        "timeout": l.timeout,
        "timeout_ms": u32::from(l.timeout) * 10,
        "mtu": l.mtu,
        "encrypted": l.encrypted,
        "bonded": l.bonded,
        "key_size": l.key_size,
    })
}

fn ident_json(r: &Ident) -> serde_json::Value {
    let mut v = serde_json::json!({
        "label": r.label,
        "uuid": format!("{:04x}", r.uuid16),
        "handle": r.handle,
    });
    if let Some(err) = &r.error {
        v["error"] = err.clone().into();
    } else {
        v["value"] = r.value.clone().into();
    }
    v
}

fn traffic_json(t: &Traffic) -> serde_json::Value {
    serde_json::json!({
        "n": t.row,
        "name": t.name,
        "handle": t.handle,
        "kind": t.kind,
        "count": t.count,
        "hex": compact_hex(&t.last_hex),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic stand-in. Not a device from a scan.
    const FIXTURE_ADDR: &str = "aa:bb:cc:00:00:01";

    fn row(uuid: &str, handle: u16, name: &str, props: &str) -> ui::GattRow {
        ui::GattRow {
            uuid: uuid.into(),
            handle,
            name: name.into(),
            service: String::new(),
            props: props.into(),
        }
    }

    fn sample_link() -> Link {
        Link {
            addr: FIXTURE_ADDR.into(),
            addr_type: 1,
            rssi: -62,
            interval: 9,
            latency: 0,
            timeout: 72,
            mtu: 128,
            encrypted: true,
            bonded: true,
            key_size: 16,
        }
    }

    #[test]
    fn identity_values_are_words_not_a_dump() {
        assert_eq!(
            decode_known(0x2a00, b"Example Keyboard"),
            Some("Example Keyboard".into())
        );
        assert_eq!(
            decode_known(0x2a25, b"SN-EXAMPLE\0SECRET"),
            Some("SN-EXAMPLE".into())
        );
        assert_eq!(
            decode_known(0x2a01, &0x03C1u16.to_le_bytes()),
            Some("keyboard".into())
        );
        assert_eq!(
            decode_known(0x2a01, &0x0040u16.to_le_bytes()),
            Some("phone".into())
        );
        assert_eq!(decode_known(0x2a19, &[0x36]), Some("54%".into()));
        assert_eq!(decode_known(0x2a29, b"Example"), Some("Example".into()));
        assert_eq!(
            decode_known(0x2a50, &[0x02, 0x34, 0x12, 0x01, 0x00, 0x00, 0x01]),
            Some("usb 1234:0001 0100".into())
        );
        let map = [0x05, 0x01, 0x09, 0x06];
        assert_eq!(decode_known(0x2a4b, &map), Some("4 bytes".into()));
        let shown = decode_known(0x2a4b, &map).unwrap();
        assert!(!shown.contains("0501"));
    }

    #[test]
    fn human_profile_does_not_emit_remote_terminal_controls() {
        let value = "name\u{1b}]52;c;payload\u{7}\nnext";
        let profile = Profile {
            name: value.into(),
            address: FIXTURE_ADDR.into(),
            link: None,
            identity: vec![
                Ident {
                    label: "name",
                    uuid16: 0x2a00,
                    handle: 3,
                    value: value.into(),
                    error: None,
                },
                Ident {
                    label: "manufacturer",
                    uuid16: 0x2a29,
                    handle: 4,
                    value: String::new(),
                    error: Some(value.into()),
                },
            ],
            traffic: Vec::new(),
            elapsed: Duration::ZERO,
        };
        let shown = human_lines(&profile).join("\n");
        assert!(!shown.contains("]52;c;payload\u{7}"), "{shown:?}");
        for line in human_lines(&profile) {
            let plain = console::strip_ansi_codes(&line);
            assert!(!plain.chars().any(char::is_control), "{plain:?}");
        }
        assert_eq!(profile_json(&profile)["name"], value);
        assert_eq!(profile_json(&profile)["identity"][0]["value"], value);
    }

    #[test]
    fn link_json_keeps_the_fixture_address() {
        let v = serde_json::json!({
            "addr": "AA:BB:CC:00:00:01",
            "addr_type": 1,
            "rssi": -62,
            "interval": 9,
            "latency": 0,
            "timeout": 72,
            "mtu": 128,
            "encrypted": true,
            "bonded": true,
            "key_size": 16
        });
        let link = parse_link(&v);
        assert_eq!(link.addr, FIXTURE_ADDR);
        assert_eq!(interval_text(link.interval), "11.25 ms");
        assert_eq!(timeout_text(link.timeout), "720 ms");
        assert_eq!(link_flags(&link), "encrypted, bonded, rssi -62 dBm, key 16");
    }

    #[test]
    fn profile_lines_use_the_fixture_and_cap_the_hex() {
        let profile = Profile {
            name: "Example Keyboard".into(),
            address: FIXTURE_ADDR.into(),
            link: Some(sample_link()),
            identity: vec![
                Ident {
                    label: "name",
                    uuid16: 0x2a00,
                    handle: 3,
                    value: "Example Keyboard".into(),
                    error: None,
                },
                Ident {
                    label: "appearance",
                    uuid16: 0x2a01,
                    handle: 5,
                    value: "keyboard".into(),
                    error: None,
                },
                Ident {
                    label: "manufacturer",
                    uuid16: 0x2a29,
                    handle: 22,
                    value: "Example".into(),
                    error: None,
                },
                Ident {
                    label: "serial",
                    uuid16: 0x2a25,
                    handle: 26,
                    value: String::new(),
                    error: Some("peer requires pairing".into()),
                },
                Ident {
                    label: "battery",
                    uuid16: 0x2a19,
                    handle: 50,
                    value: "54%".into(),
                    error: None,
                },
                Ident {
                    label: "report map",
                    uuid16: 0x2a4b,
                    handle: 40,
                    value: "4 bytes".into(),
                    error: None,
                },
            ],
            traffic: vec![
                Traffic {
                    row: Some(2),
                    handle: 8,
                    name: "Service Changed".into(),
                    kind: "indicate",
                    count: 0,
                    last_hex: String::new(),
                },
                Traffic {
                    row: Some(12),
                    handle: 24,
                    name: "Report".into(),
                    kind: "notify",
                    count: 86,
                    last_hex: "a101000000".into(),
                },
                Traffic {
                    row: Some(13),
                    handle: 50,
                    name: "Battery Level".into(),
                    kind: "notify",
                    count: 2,
                    last_hex: "00112233445566778899".into(),
                },
            ],
            elapsed: Duration::from_millis(14200),
        };
        let text = human_lines(&profile).join("\n");
        assert!(text.contains("Example Keyboard"), "{text}");
        assert_eq!(text.matches(FIXTURE_ADDR).count(), 1, "{text}");
        assert!(
            text.contains("encrypted, bonded, rssi -62 dBm, key 16"),
            "{text}"
        );
        assert!(text.contains("11.25 ms"), "{text}");
        assert!(text.contains("720 ms"), "{text}");
        assert!(text.contains("mtu 128"), "{text}");
        assert!(text.contains("keyboard"), "{text}");
        assert!(text.contains("54%"), "{text}");
        assert!(text.contains("skipped (peer requires pairing)"), "{text}");
        assert!(text.contains("4 bytes"), "{text}");
        assert!(text.contains("14.2s"), "{text}");
        assert!(text.contains("a1 01 00 00 00"), "{text}");
        assert!(text.contains("..."), "{text}");
        assert!(!text.contains("88 99"), "{text}");
        assert!(!text.contains("0501"), "{text}");
        let service = text.find("Service Changed").unwrap();
        let report = text.find("Report").unwrap();
        let battery = text.find("Battery Level").unwrap();
        assert!(service < report && report < battery, "{text}");

        let doc = profile_json(&profile);
        assert_eq!(doc["address"], FIXTURE_ADDR);
        assert_eq!(doc["link"]["interval_ms"], 11.25);
        assert_eq!(doc["traffic"][1]["handle"], 24);
        assert_eq!(doc["traffic"][1]["count"], 86);
        assert_eq!(doc["identity"][3]["error"], "peer requires pairing");
    }

    #[test]
    fn two_hid_reports_tally_by_handle_and_battery_follows_the_note() {
        let rows = vec![
            row("2a4d", 20, "Report", "read,write"),
            row("2a4d", 24, "Report", "read,notify"),
            row("2a19", 50, "Battery Level", "read,notify"),
        ];
        let mut profile = Profile {
            name: "Example Keyboard".into(),
            address: FIXTURE_ADDR.into(),
            link: None,
            identity: vec![Ident {
                label: "battery",
                uuid16: 0x2a19,
                handle: 50,
                value: "54%".into(),
                error: None,
            }],
            traffic: vec![
                Traffic {
                    row: Some(1),
                    handle: 24,
                    name: "Report".into(),
                    kind: "notify",
                    count: 0,
                    last_hex: String::new(),
                },
                Traffic {
                    row: Some(2),
                    handle: 50,
                    name: "Battery Level".into(),
                    kind: "notify",
                    count: 0,
                    last_hex: String::new(),
                },
            ],
            elapsed: Duration::ZERO,
        };
        apply_note(&mut profile, &rows, &notify(24, "a101"));
        apply_note(&mut profile, &rows, &notify(24, "a102"));
        apply_note(&mut profile, &rows, &notify(20, "b1"));
        apply_note(&mut profile, &rows, &notify(50, "32"));
        assert_eq!(profile.traffic[0].count, 2);
        assert_eq!(profile.traffic[0].last_hex, "a102");
        assert_eq!(
            profile
                .traffic
                .iter()
                .find(|t| t.handle == 20)
                .unwrap()
                .count,
            1
        );
        assert_eq!(profile.traffic[1].count, 1);
        assert_eq!(profile.identity[0].value, "50%");
        let text = human_lines(&profile).join("\n");
        assert!(text.contains("50%"), "{text}");
        assert!(!text.contains("aa:bb:cc:dd:ee"), "{text}");
    }

    #[test]
    fn missing_link_omits_the_link_block() {
        let profile = Profile {
            name: "Example Keyboard".into(),
            address: String::new(),
            link: None,
            identity: vec![],
            traffic: vec![],
            elapsed: Duration::ZERO,
        };
        let text = human_lines(&profile).join("\n");
        assert!(text.contains("Example Keyboard"), "{text}");
        assert!(!text.contains("rssi"), "{text}");
        assert!(!text.contains(FIXTURE_ADDR), "{text}");
        assert!(text.contains("(none)"), "{text}");
        assert!(text.contains("(quiet)"), "{text}");
        assert!(profile_json(&profile)["link"].is_null());
    }

    fn notify(handle: u16, hex: &str) -> GattNotification {
        GattNotification {
            characteristic: "00002a4d-0000-1000-8000-00805f9b34fb".into(),
            handle,
            is_notify: true,
            hex: hex.into(),
        }
    }
}
