//! Shared terminal UI: network table, picker, status block, spinner.

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use console::{Term, style};
use infishark::ir::IrCapture;
use infishark::{BleDevice, GattService, Network, SavedNetwork};
use serde_json::Value;

fn is_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Format a duration as m:ss.
pub fn fmt_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    format!("{}:{:02}", s / 60, s % 60)
}

/// Paired/saved devices first, then nearby by RSSI.
fn ble_display_order(devs: &[BleDevice]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..devs.len()).collect();
    idx.sort_by_key(|&i| {
        let d = &devs[i];
        (if d.paired { 0u8 } else { 1 }, std::cmp::Reverse(d.rssi))
    });
    idx
}

/// Same order as the `#` column of [`ble_table`].
pub(crate) fn ble_in_display_order(devs: &[BleDevice]) -> Vec<BleDevice> {
    ble_display_order(devs)
        .into_iter()
        .map(|i| devs[i].clone())
        .collect()
}

pub(crate) fn is_mac_token(token: &str) -> bool {
    let t = token.trim();
    if t.contains(':') || t.contains('-') {
        return true;
    }
    t.len() == 12 && t.chars().all(|c| c.is_ascii_hexdigit())
}

/// Decimal row number, not a MAC.
pub(crate) fn is_row_index(token: &str) -> bool {
    let t = token.trim();
    !t.is_empty() && !is_mac_token(t) && t.parse::<usize>().is_ok()
}

// Item indices ordered by strongest signal first.
fn order_by_rssi<T, R: Ord + Copy>(items: &[T], rssi: impl Fn(&T) -> R) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..items.len()).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(rssi(&items[i])));
    idx
}

// 256-color grey ramp: white at strong signal, fading to grey when weak.
fn rssi_shade(rssi: impl Into<i64>) -> u8 {
    let rssi = rssi.into();
    240 + ((rssi + 90).clamp(0, 50) * 15 / 50) as u8
}

struct Col {
    head: &'static str,
    width: usize,
    right: bool,
}

struct Row {
    shade: u8,
    cells: Vec<String>,
}

fn cell(c: &Col, s: &str, last: bool) -> String {
    if last {
        s.to_string() // last column: no trailing padding or truncation
    } else if c.right {
        format!("{s:>w$}", w = c.width)
    } else {
        format!("{s:<w$.w$}", w = c.width)
    }
}

// Borderless table: dim header, name column (index 1) shaded by signal.
fn table(cols: &[Col], rows: &[Row]) {
    let color = is_tty();
    let last = cols.len().saturating_sub(1);
    let header = cols
        .iter()
        .enumerate()
        .map(|(i, c)| cell(c, c.head, i == last))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", style(header).dim());
    for r in rows {
        let line = cols
            .iter()
            .zip(&r.cells)
            .enumerate()
            .map(|(i, (c, v))| {
                let s = cell(c, v, i == last);
                if i == 1 && color {
                    style(s).color256(r.shade).to_string()
                } else {
                    s
                }
            })
            .collect::<Vec<_>>()
            .join("  ");
        println!("{line}");
    }
}

fn wifi_cols(verbose: bool) -> Vec<Col> {
    let mut cols = vec![
        Col {
            head: "#",
            width: 3,
            right: true,
        },
        Col {
            head: "SSID",
            width: 20,
            right: false,
        },
        Col {
            head: "BSSID",
            width: 17,
            right: false,
        },
        Col {
            head: "ch",
            width: 2,
            right: true,
        },
        Col {
            head: "rssi",
            width: 4,
            right: true,
        },
        Col {
            head: "enc",
            width: 14,
            right: false,
        },
        Col {
            head: "posture",
            width: 10,
            right: false,
        },
        Col {
            head: "phy",
            width: 5,
            right: false,
        },
        Col {
            head: "wps",
            width: 3,
            right: false,
        },
    ];
    if verbose {
        cols.extend([
            Col {
                head: "cipher",
                width: 9,
                right: false,
            },
            Col {
                head: "g-cipher",
                width: 9,
                right: false,
            },
            Col {
                head: "bw",
                width: 2,
                right: true,
            },
            Col {
                head: "sec",
                width: 5,
                right: false,
            },
            Col {
                head: "cc",
                width: 2,
                right: false,
            },
            Col {
                head: "flags",
                width: 16,
                right: false,
            },
        ]);
    }
    cols.push(Col {
        head: "vendor",
        width: 16,
        right: false,
    });
    cols
}

pub(crate) fn tty_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Shared table for textual records, with terminal control bytes removed.
pub(crate) fn text_table(header: &[&str], rows: &[Vec<String>]) {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(|cell| tty_text(cell)).collect())
        .collect();
    let aligned = align_table(header, &rows);
    println!("{}", style(aligned.header).dim());
    for row in aligned.rows {
        println!("{row}");
    }
}

fn ssid_label(n: &Network) -> String {
    if n.ssid.is_empty() {
        "<hidden>".to_string()
    } else {
        tty_text(&n.ssid)
    }
}

fn wifi_rows(nets: &[Network], order: &[usize], verbose: bool) -> Vec<Row> {
    order
        .iter()
        .enumerate()
        .map(|(row, &i)| {
            let n = &nets[i];
            let mut cells = vec![
                row.to_string(),
                ssid_label(n),
                n.bssid.clone(),
                n.channel.to_string(),
                n.rssi.to_string(),
                n.encryption.clone(),
                crate::wifi_analysis::posture(n).as_str().to_string(),
                n.extra_str("phy").to_string(),
                if n.extra_bool("wps") {
                    "yes".into()
                } else {
                    "-".into()
                },
            ];
            if verbose {
                cells.extend([
                    n.extra_str("pairwise_cipher").to_string(),
                    n.extra_str("group_cipher").to_string(),
                    n.extra_num("bandwidth"),
                    n.extra_str("secondary").to_string(),
                    n.extra_str("country").to_string(),
                    crate::wifi_analysis::risk_flags(n).join(","),
                ]);
            }
            cells.push(tty_text(&n.vendor.clone().unwrap_or_default()));
            Row {
                shade: rssi_shade(n.rssi),
                cells,
            }
        })
        .collect()
}

/// Borderless network table, strongest first. `verbose` adds
/// ciphers/bandwidth/flags.
pub fn network_table(nets: &mut [Network], verbose: bool) {
    crate::vendors::fill_wifi(nets);
    if nets.is_empty() {
        println!("no networks found");
        return;
    }
    let order = order_by_rssi(nets, |n| n.rssi);
    table(&wifi_cols(verbose), &wifi_rows(nets, &order, verbose));
    if verbose {
        print_hidden_correlations(nets);
    }
    print_scan_summary(nets);
}

/// Host-only post-table notes: hidden SSIDs that likely share a radio with a
/// named AP.
fn print_hidden_correlations(nets: &[Network]) {
    let hits = crate::wifi_analysis::hidden_correlations(nets, 8);
    if hits.is_empty() {
        return;
    }
    println!();
    println!("{}", style("Hidden SSID correlations").bold());
    for h in hits {
        let ch = if h.same_channel {
            "same ch".to_string()
        } else {
            "adj ch".to_string()
        };
        println!(
            "  {}  ~  {} ({})  {} dB, {}",
            style(&h.hidden_bssid).dim(),
            tty_text(&h.named_ssid),
            style(&h.named_bssid).dim(),
            h.rssi_delta,
            ch
        );
    }
}

/// Host-only aggregate footer (not on the device wire).
fn print_scan_summary(nets: &[Network]) {
    let s = crate::wifi_analysis::scan_summary(nets);
    if s.total == 0 {
        return;
    }
    println!();
    let mut parts = vec![format!("{} APs", s.total)];
    if s.open > 0 {
        parts.push(format!("{} open", s.open));
    }
    if s.wep > 0 {
        parts.push(format!("{} wep", s.wep));
    }
    if s.wpa2 > 0 {
        parts.push(format!("{} wpa2", s.wpa2));
    }
    if s.wpa3 > 0 {
        parts.push(format!("{} wpa3", s.wpa3));
    }
    if s.enterprise > 0 {
        parts.push(format!("{} enterprise", s.enterprise));
    }
    if s.wps > 0 {
        parts.push(format!("{} wps", s.wps));
    }
    if s.hidden > 0 {
        parts.push(format!("{} hidden", s.hidden));
    }
    println!("{}", style(parts.join(" / ")).dim());
    if !s.by_channel.is_empty() {
        let chs: Vec<String> = s
            .by_channel
            .iter()
            .map(|(c, n)| format!("ch{c}:{n}"))
            .collect();
        println!("{}", style(format!("channels  {}", chs.join("  "))).dim());
    }
}

/// Full detail for one AP from a scan (fixed fields + every extra key).
pub fn network_detail(n: &mut Network) {
    crate::vendors::fill_wifi(std::slice::from_mut(n));
    let mut rows: Vec<(String, String)> = vec![
        ("ssid".into(), ssid_label(n)),
        ("bssid".into(), n.bssid.clone()),
        ("rssi".into(), format!("{} dBm", n.rssi)),
        ("channel".into(), n.channel.to_string()),
        ("encryption".into(), n.encryption.clone()),
        (
            "posture".into(),
            crate::wifi_analysis::posture(n).as_str().into(),
        ),
    ];
    let flags = crate::wifi_analysis::risk_flags(n);
    if !flags.is_empty() {
        rows.push(("flags".into(), flags.join(", ")));
    }
    if let Some(v) = &n.vendor {
        rows.push(("vendor".into(), v.clone()));
    }
    for (k, v) in &n.extra {
        rows.push((k.clone(), value_str(v)));
    }
    detail_table(&rows);
}

/// Borderless BLE device table, strongest first, name shaded by signal.
pub fn ble_table(devs: &mut [BleDevice]) {
    crate::vendors::fill_ble(devs);
    if devs.is_empty() {
        println!("no devices found");
        return;
    }
    let cols = [
        Col {
            head: "#",
            width: 3,
            right: true,
        },
        Col {
            head: "name",
            width: 22,
            right: false,
        },
        Col {
            head: "address",
            width: 17,
            right: false,
        },
        Col {
            head: "rssi",
            width: 6,
            right: true,
        },
        Col {
            head: "vendor",
            width: 24,
            right: false,
        },
    ];
    let rows: Vec<Row> = ble_display_order(devs)
        .iter()
        .enumerate()
        .map(|(row, &i)| {
            let d = &devs[i];
            let name = d.name.clone().unwrap_or_else(|| "<unknown>".to_string());
            let vendor = d
                .vendor
                .clone()
                .or_else(|| d.company.clone())
                .unwrap_or_default();
            let rssi = if d.paired && d.rssi == 0 {
                "saved".to_string()
            } else {
                d.rssi.to_string()
            };
            Row {
                shade: rssi_shade(d.rssi),
                cells: vec![row.to_string(), name, d.address.clone(), rssi, vendor],
            }
        })
        .collect();
    table(&cols, &rows);
}

/// Full detail for one BLE device: fixed fields then every extra scan field.
pub fn ble_detail(d: &mut BleDevice) {
    crate::vendors::fill_ble(std::slice::from_mut(d));
    let mut rows: Vec<(String, String)> = vec![
        (
            "name".into(),
            d.name.clone().unwrap_or_else(|| "<unknown>".into()),
        ),
        (
            "address".into(),
            format!("{}  {}", d.address, addr_kind(d.addr_type)),
        ),
        ("rssi".into(), d.rssi.to_string()),
    ];
    if let Some(v) = &d.vendor {
        rows.push(("vendor".into(), v.clone()));
    }
    if let Some(c) = &d.company {
        rows.push(("company".into(), c.clone()));
    }
    if let Some(id) = d.company_id {
        rows.push(("company_id".into(), format!("{id:#06x}")));
    }
    for (k, v) in &d.extra {
        rows.push((k.clone(), value_str(v)));
    }
    detail_table(&rows);
}

fn addr_kind(t: Option<u8>) -> &'static str {
    match t {
        Some(0) => "public",
        Some(1) => "random",
        Some(2) => "public-id",
        Some(3) => "random-id",
        _ => "",
    }
}

pub fn value_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Render a dim-key / value detail block, keys left-aligned to the widest.
pub fn detail_table<K: AsRef<str>, V: AsRef<str>>(rows: &[(K, V)]) {
    let w = rows
        .iter()
        .map(|(k, _)| k.as_ref().len())
        .max()
        .unwrap_or(0);
    for (k, v) in rows {
        println!(
            "  {}  {}",
            style(format!("{:<w$}", k.as_ref())).dim(),
            v.as_ref()
        );
    }
}

/// Render a flat JSON object as a detail block; non-object values print as-is.
pub fn value_detail(v: &Value) {
    match v.as_object() {
        Some(obj) => {
            let rows: Vec<(String, String)> = obj
                .iter()
                .map(|(k, val)| (k.clone(), value_str(val)))
                .collect();
            detail_table(&rows);
        }
        None => println!("{v}"),
    }
}

/// List saved networks (slot + SSID).
pub fn saved_networks(nets: &[SavedNetwork]) {
    if nets.is_empty() {
        println!("no saved networks");
        return;
    }
    for n in nets {
        println!(
            "  {}  {}",
            style(format!("[slot {}]", n.index)).dim(),
            n.ssid
        );
    }
}

/// One characteristic row from `ble gatt enum`, in table order.
#[derive(Clone)]
pub(crate) struct GattRow {
    pub uuid: String,
    pub handle: u16,
    pub name: String,
    pub service: String,
    pub props: String,
}

/// What `read` / `write` / `subscribe` / `unsubscribe` is about to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GattOp {
    Read,
    Write,
    Subscribe { indicate: bool },
    Unsubscribe,
}

/// One characteristic a GATT command should touch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GattTarget {
    pub uuid: String,
    /// Set when the row came from the last enum. Absent for a UUID that is
    /// not in the table. Zero is never sent.
    pub handle: Option<u16>,
    pub name: String,
    pub row: Option<usize>,
    /// Subscribe only: notifications when false, indications when true.
    pub indicate: bool,
}

/// An explicit row this operation cannot use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GattRejection {
    pub row: Option<usize>,
    pub name: String,
    pub reason: &'static str,
}

/// Resolved arguments for one GATT command.
#[derive(Clone, Debug)]
pub(crate) struct GattSelection {
    pub targets: Vec<GattTarget>,
    pub rejected: Vec<GattRejection>,
    /// `all`, or more than one characteristic. Results are labeled.
    pub bulk: bool,
}

pub(crate) fn gatt_target_label(t: &GattTarget) -> String {
    match t.row {
        Some(n) => format!("{n}  {}", t.name),
        None => t.name.clone(),
    }
}

pub(crate) fn gatt_rejection_line(r: &GattRejection) -> String {
    match r.row {
        Some(n) => format!("{n}  {} is {}", r.name, r.reason),
        None => format!("{} is {}", r.name, r.reason),
    }
}

/// Characteristics in the order `gatt_services` numbers them.
pub(crate) fn gatt_rows(services: &[GattService]) -> Vec<GattRow> {
    let mut out = Vec::new();
    for s in services {
        let service = crate::gatt_names::service(&s.uuid)
            .map(str::to_string)
            .unwrap_or_else(|| compact_uuid(&s.uuid));
        for c in &s.characteristics {
            out.push(GattRow {
                uuid: c.uuid.clone(),
                handle: c.handle,
                name: crate::gatt_names::characteristic(&c.uuid)
                    .unwrap_or("<unknown>")
                    .to_string(),
                service: service.clone(),
                props: c.properties.join(","),
            });
        }
    }
    out
}

fn prop_has(props: &str, name: &str) -> bool {
    props.split(',').any(|p| p == name)
}

fn same_char(row_uuid: &str, token: &str) -> bool {
    match (
        infishark::hex::bluetooth_uuid(row_uuid),
        infishark::hex::bluetooth_uuid(token),
    ) {
        (Ok(a), Ok(b)) => a.eq_ignore_ascii_case(&b),
        _ => row_uuid.eq_ignore_ascii_case(token),
    }
}

fn char_name(uuid: &str) -> String {
    let name = crate::gatt_names::characteristic(uuid).unwrap_or("<unknown>");
    if name == "<unknown>" {
        uuid.to_string()
    } else {
        name.to_string()
    }
}

fn from_row(index: usize, row: &GattRow, indicate: bool) -> GattTarget {
    GattTarget {
        uuid: row.uuid.clone(),
        handle: (row.handle != 0).then_some(row.handle),
        name: row.name.clone(),
        row: Some(index),
        indicate,
    }
}

/// `Ok(indicate)` when this row can do `op`. The error is the reason it cannot.
fn fit(row: &GattRow, op: GattOp) -> std::result::Result<bool, &'static str> {
    let notify = prop_has(&row.props, "notify");
    let indicate = prop_has(&row.props, "indicate");
    match op {
        GattOp::Read => {
            if prop_has(&row.props, "read") {
                Ok(false)
            } else {
                Err("not readable")
            }
        }
        GattOp::Write => {
            if prop_has(&row.props, "write") || prop_has(&row.props, "write_no_resp") {
                Ok(false)
            } else {
                Err("not writable")
            }
        }
        GattOp::Unsubscribe => Ok(false),
        GattOp::Subscribe { indicate: true } => {
            if indicate {
                Ok(true)
            } else {
                Err("not indicatable")
            }
        }
        GattOp::Subscribe { indicate: false } => {
            if notify {
                Ok(false)
            } else if indicate {
                Ok(true)
            } else {
                Err("not notifiable")
            }
        }
    }
}

fn loose_uuid(token: &str, op: GattOp) -> GattTarget {
    GattTarget {
        uuid: token.to_string(),
        handle: None,
        name: char_name(token),
        row: None,
        indicate: matches!(op, GattOp::Subscribe { indicate: true }),
    }
}

enum One {
    Use(GattTarget),
    Skip(GattRejection),
}

fn resolve_one(rows: &[GattRow], token: &str, op: GattOp) -> Result<One> {
    if let Ok(n) = token.parse::<usize>() {
        if let Some(row) = rows.get(n) {
            return Ok(match fit(row, op) {
                Ok(indicate) => One::Use(from_row(n, row, indicate)),
                Err(reason) => One::Skip(GattRejection {
                    row: Some(n),
                    name: row.name.clone(),
                    reason,
                }),
            });
        }
        if infishark::hex::bluetooth_uuid(token).is_ok() {
            return Ok(One::Use(loose_uuid(token, op)));
        }
        if rows.is_empty() {
            bail!("no gatt table yet; run `ble gatt enum` first (or pass a UUID)");
        }
        bail!(
            "index {n} out of range (0..{}); numbers match the last `ble gatt enum`",
            rows.len() - 1
        );
    }
    let hits: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| same_char(&row.uuid, token))
        .map(|(i, _)| i)
        .collect();
    match hits.as_slice() {
        [] => Ok(One::Use(loose_uuid(token, op))),
        [i] => {
            let row = &rows[*i];
            Ok(match fit(row, op) {
                Ok(indicate) => One::Use(from_row(*i, row, indicate)),
                Err(reason) => One::Skip(GattRejection {
                    row: Some(*i),
                    name: row.name.clone(),
                    reason,
                }),
            })
        }
        many => {
            let mut msg = format!("{token} matches more than one row; pass a row number");
            for i in many {
                let row = &rows[*i];
                msg.push_str(&format!(
                    "\n{i}  {}  {:#06x}  {}",
                    row.name, row.handle, row.props
                ));
            }
            bail!(msg)
        }
    }
}

fn select_all(rows: &[GattRow], op: GattOp) -> Result<GattSelection> {
    if rows.is_empty() {
        bail!("no gatt table yet; run `ble gatt enum` first");
    }
    match op {
        GattOp::Write => bail!("`write all` is not supported"),
        GattOp::Unsubscribe => bail!("`unsubscribe all` is not supported"),
        GattOp::Read | GattOp::Subscribe { .. } => {}
    }
    let mut targets = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        if let Ok(indicate) = fit(row, op) {
            targets.push(from_row(i, row, indicate));
        }
    }
    if targets.is_empty() {
        bail!(match op {
            GattOp::Read => "no readable characteristics",
            GattOp::Subscribe { indicate: true } => "no indicatable characteristics",
            _ => "no notifiable characteristics",
        });
    }
    Ok(GattSelection {
        targets,
        rejected: Vec::new(),
        bulk: true,
    })
}

/// `all` is every row this operation can use. A row number or a unique UUID
/// carries that row's handle. An ambiguous UUID asks for the row number.
pub(crate) fn select_gatt(
    rows: &[GattRow],
    tokens: &[String],
    op: GattOp,
) -> Result<GattSelection> {
    let tokens: Vec<&str> = tokens
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        bail!("pass a row number or a characteristic UUID");
    }
    if tokens.iter().any(|t| *t == "*") {
        bail!("`*` is not a selector; use `all`");
    }
    if tokens.iter().any(|t| t.eq_ignore_ascii_case("all")) {
        if tokens.len() != 1 {
            bail!("`all` stands alone");
        }
        return select_all(rows, op);
    }
    let mut targets = Vec::new();
    let mut rejected = Vec::new();
    for token in &tokens {
        match resolve_one(rows, token, op)? {
            One::Use(t) => targets.push(t),
            One::Skip(r) => rejected.push(r),
        }
    }
    if targets.is_empty() && rejected.len() == 1 {
        bail!("{}", gatt_rejection_line(&rejected[0]));
    }
    Ok(GattSelection {
        targets,
        rejected,
        bulk: tokens.len() > 1,
    })
}

/// SIG UUIDs as `2a19`. Other 128-bit values stay in canonical form.
fn compact_uuid(uuid: &str) -> String {
    let Ok(full) = infishark::hex::bluetooth_uuid(uuid) else {
        return uuid.to_string();
    };
    let hex: String = full.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let Some(assigned) = hex.strip_suffix("00001000800000805f9b34fb") else {
        return full;
    };
    let short = assigned.trim_start_matches('0');
    if short.is_empty() {
        "0".to_string()
    } else if short.len() <= 4 {
        short.to_string()
    } else {
        assigned.to_string()
    }
}

fn service_heading(s: &GattService) -> String {
    let name = crate::gatt_names::service(&s.uuid)
        .map(|n| format!("  {n}"))
        .unwrap_or_default();
    format!(
        "svc {}  [{:#06x}-{:#06x}]{name}",
        compact_uuid(&s.uuid),
        s.handle,
        s.end_handle
    )
}

/// Numbered characteristic table. Each service is a section header.
/// `#` matches `ble gatt read N` and stays continuous across services.
pub fn gatt_services(services: &[GattService]) {
    if services.is_empty() {
        println!("no services");
        return;
    }
    let mut n = 0usize;
    let mut sections: Vec<(String, Vec<Vec<String>>)> = Vec::new();
    for s in services {
        let mut rows = Vec::new();
        for c in &s.characteristics {
            rows.push(vec![
                n.to_string(),
                format!("{:#06x}", c.handle),
                compact_uuid(&c.uuid),
                c.properties.join(","),
                crate::gatt_names::characteristic(&c.uuid)
                    .unwrap_or("<unknown>")
                    .to_string(),
            ]);
            n += 1;
        }
        sections.push((service_heading(s), rows));
    }
    if n == 0 {
        for (heading, _) in &sections {
            println!("{}", style(heading).dim());
        }
        return;
    }
    let header = ["#", "handle", "uuid", "props", "characteristic"];
    let body: Vec<Vec<String>> = sections.iter().flat_map(|(_, rows)| rows.clone()).collect();
    let lines = align_table(&header, &body);
    println!("{}", style(&lines.header).dim());
    let mut offset = 0;
    for (heading, rows) in &sections {
        println!("{}", style(heading).dim());
        for line in &lines.rows[offset..offset + rows.len()] {
            println!("{line}");
        }
        offset += rows.len();
    }
}

struct Aligned {
    header: String,
    rows: Vec<String>,
}

fn align_table(header: &[&str], rows: &[Vec<String>]) -> Aligned {
    let mut width: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = width.get_mut(i) {
                *w = (*w).max(cell.len());
            }
        }
    }
    let line = |cells: &[String]| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = width.get(i).copied().unwrap_or(0);
                if i + 1 == cells.len() {
                    cell.clone()
                } else if i == 0 {
                    format!("{cell:>w$}")
                } else {
                    format!("{cell:<w$}")
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let head: Vec<String> = header.iter().map(|s| (*s).to_string()).collect();
    Aligned {
        header: line(&head),
        rows: rows.iter().map(|row| line(row)).collect(),
    }
}

pub fn require_interactive(hint: &str) -> Result<()> {
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    bail!("{hint}");
}

/// Show the shared Wi-Fi table (same columns as `wifi scan`) and return the
/// operator's selection. Multi-select: `n | n,n | a`.
pub fn pick_networks(nets: &mut [Network]) -> Result<Vec<Network>> {
    require_interactive("pass --ssid or --bssid to choose a target")?;
    let order = wifi_picker_table(nets)?;
    let picks = parse_selection(
        &prompt_line("select target(s) [n | n,n | a]: ")?,
        order.len(),
    )?;
    Ok(picks.iter().map(|&p| nets[order[p]].clone()).collect())
}

/// Same table as [`pick_networks`], single choice (for save / join flows).
pub fn pick_network(nets: &mut [Network]) -> Result<Network> {
    require_interactive("pass --ssid or --bssid to choose a network")?;
    let order = wifi_picker_table(nets)?;
    let picks = parse_selection(&prompt_line("select network [n]: ")?, order.len())?;
    if picks.len() != 1 {
        bail!("select a single network");
    }
    Ok(nets[order[picks[0]]].clone())
}

fn wifi_picker_table(nets: &mut [Network]) -> Result<Vec<usize>> {
    crate::vendors::fill_wifi(nets);
    if nets.is_empty() {
        bail!("scan found no networks");
    }
    let order = order_by_rssi(nets, |n| n.rssi);
    table(&wifi_cols(false), &wifi_rows(nets, &order, false));
    Ok(order)
}

fn parse_selection(input: &str, len: usize) -> Result<Vec<usize>> {
    let input = input.trim();
    if input.eq_ignore_ascii_case("a") {
        return Ok((0..len).collect());
    }
    let mut out = Vec::new();
    for tok in input.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let i: usize = tok
            .parse()
            .map_err(|_| anyhow::anyhow!("bad selection '{tok}'"))?;
        if i >= len {
            bail!("selection {i} is out of range");
        }
        out.push(i);
    }
    if out.is_empty() {
        bail!("nothing selected");
    }
    Ok(out)
}

pub(crate) fn create_secure(path: &str) -> Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
        o.mode(0o600);
    }
    o.open(path)
        .with_context(|| format!("creating {path} (refusing to follow a symlink)"))
}

/// Prompt on stderr and read one line from the terminal; EOF is empty.
pub fn prompt_line(prompt: &str) -> Result<String> {
    Ok(prompt_line_eof(prompt)?.unwrap_or_default())
}

/// Prompt on stderr; distinguish EOF from an empty submitted line.
pub fn prompt_line_eof(prompt: &str) -> Result<Option<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    #[cfg(unix)]
    {
        if let Ok(tty) = std::fs::File::open("/dev/tty") {
            use std::os::unix::io::AsRawFd;
            return read_fd_line(tty.as_raw_fd());
        }
    }
    read_stdin_line()
}

/// One line from stdin. `Ok(None)` is end of input.
pub fn read_stdin_line() -> Result<Option<String>> {
    #[cfg(unix)]
    {
        read_fd_line(libc::STDIN_FILENO)
    }
    #[cfg(not(unix))]
    {
        let mut s = String::new();
        let n = std::io::stdin().read_line(&mut s)?;
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(s.trim_end_matches(['\n', '\r']).to_string()))
        }
    }
}

#[cfg(not(unix))]
fn read_stdin_blocking() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
}

#[cfg(unix)]
fn read_fd_line(fd: std::os::unix::io::RawFd) -> Result<Option<String>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        if !crate::signals::RUNNING.load(Ordering::SeqCst) {
            return Err(crate::signals::cancelled());
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 50) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        if rc == 0 {
            continue;
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
            && pfd.revents & libc::POLLIN == 0
        {
            return Ok(finished_line(&buf));
        }
        let n = unsafe { libc::read(fd, tmp.as_mut_ptr().cast::<libc::c_void>(), tmp.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        if n == 0 {
            return Ok(finished_line(&buf));
        }
        buf.extend_from_slice(&tmp[..n as usize]);
        if buf.contains(&b'\n') {
            return Ok(finished_line(&buf));
        }
    }
}

#[cfg(unix)]
fn finished_line(buf: &[u8]) -> Option<String> {
    if buf.is_empty() {
        return None;
    }
    Some(
        String::from_utf8_lossy(buf)
            .trim_end_matches(['\n', '\r'])
            .to_string(),
    )
}

/// Passwords must never be echoed or accepted as argv. Email codes use
/// prompt_code.
pub fn prompt_secret(prompt: &str) -> Result<String> {
    require_interactive("account secrets require an interactive terminal")?;
    let term = Term::stderr();
    if !term.is_term() {
        bail!("account secrets require an interactive terminal on stderr");
    }
    term.write_str(prompt)?;
    term.read_secure_line().context("read account secret")
}

/// Prompt for a Wi-Fi password (blank = open network).
pub fn prompt_password(ssid: &str) -> Result<String> {
    prompt_line(&format!("Password for {ssid:?} (blank = open): "))
}

/// Resolve a numeric token to an item by index.
pub fn parse_index<'a, T>(items: &'a [T], tok: &str) -> Result<&'a T> {
    let idx: usize = tok
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("'{tok}' is not a number"))?;
    items
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("index {idx} out of range"))
}

#[derive(Debug)]
pub(crate) enum BleToken {
    Row(BleDevice),
    Address(String),
}

impl BleToken {
    pub(crate) fn address(&self) -> &str {
        match self {
            BleToken::Row(d) => &d.address,
            BleToken::Address(a) => a,
        }
    }

    pub(crate) fn addr_type(&self) -> Option<u8> {
        match self {
            BleToken::Row(d) => d.addr_type,
            BleToken::Address(_) => None,
        }
    }
}

fn same_mac(a: &str, b: &str) -> bool {
    match (
        infishark::ieee80211::parse_mac(a),
        infishark::ieee80211::parse_mac(b),
    ) {
        (Ok(x), Ok(y)) => x == y,
        _ => a.eq_ignore_ascii_case(b),
    }
}

pub(crate) struct ResolvedBle {
    pub address: String,
    pub addr_type: u8,
    /// Set when the type came from `--addr-type` or from a table row.
    pub type_known: bool,
}

fn hid_uuid(s: &str) -> bool {
    let hex: String = s
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .flat_map(|c| c.to_lowercase())
        .collect();
    let trimmed = hex.trim_start_matches('0');
    trimmed == "1812" || (hex.starts_with("00001812") && hex.len() == 32)
}

/// Keyboard, mouse, and other HID advertisements. Those peers can type a PIN.
pub(crate) fn ble_prefers_passkey(d: &BleDevice) -> bool {
    if let Some(app) = d.extra.get("appearance").and_then(|v| v.as_u64()) {
        if (0x03C0..=0x03FF).contains(&app) {
            return true;
        }
    }
    d.extra
        .get("services")
        .and_then(|v| v.as_array())
        .is_some_and(|svcs| svcs.iter().any(|v| v.as_str().is_some_and(hid_uuid)))
}

/// Scan flag. `None` when this record never reported it (a saved bond, or a
/// typed address we have not scanned).
pub(crate) fn ble_connectable(d: &BleDevice) -> Option<bool> {
    d.extra.get("connectable").and_then(|v| v.as_bool())
}

/// Error when every sighting of `address` said it is not connectable. One
/// `true` allows the attempt, same as the sticky scan merge. No flag at all
/// means try: a saved peer may not be advertising yet.
pub(crate) fn refuse_unconnectable(
    rows: &[BleDevice],
    scan: &[BleDevice],
    address: &str,
) -> Result<()> {
    let mut saw_false = false;
    let mut name = None;
    for d in rows
        .iter()
        .chain(scan.iter())
        .filter(|d| same_mac(&d.address, address))
    {
        if name.is_none() {
            name = d.name.clone().filter(|s| !s.is_empty());
        }
        match ble_connectable(d) {
            Some(true) => return Ok(()),
            Some(false) => saw_false = true,
            None => {}
        }
    }
    if !saw_false {
        return Ok(());
    }
    let label = match name {
        Some(n) => format!("{n} ({address})"),
        None => address.to_string(),
    };
    bail!("{label} is not connectable")
}

pub(crate) fn resolve_ble_target(
    rows: &[BleDevice],
    token: &str,
    explicit_type: Option<u8>,
) -> Result<ResolvedBle> {
    let tok = resolve_ble_token(rows, token)?;
    let (addr_type, type_known) = match explicit_type {
        Some(t) => (t, true),
        None => match tok.addr_type() {
            Some(t) => (t, true),
            None => (0, false),
        },
    };
    Ok(ResolvedBle {
        address: tok.address().to_string(),
        addr_type,
        type_known,
    })
}

pub(crate) fn resolve_ble_token(rows: &[BleDevice], token: &str) -> Result<BleToken> {
    let token = token.trim();
    if token.is_empty() {
        bail!("pass a row number or a BLE address");
    }
    if !is_mac_token(token) {
        let Ok(idx) = token.parse::<usize>() else {
            bail!("'{token}' is not a row number or a BLE address");
        };
        if rows.is_empty() {
            bail!("no ble table yet; run `ble scan` or `ble bonds` first");
        }
        let d = rows.get(idx).ok_or_else(|| {
            anyhow::anyhow!(
                "index {idx} out of range (0..{}); numbers match the last ble table",
                rows.len() - 1
            )
        })?;
        return Ok(BleToken::Row(d.clone()));
    }
    infishark::ieee80211::parse_mac(token)
        .map_err(|_| anyhow::anyhow!("bad BLE address '{token}'"))?;
    if let Some(d) = rows.iter().find(|d| same_mac(&d.address, token)) {
        return Ok(BleToken::Row(d.clone()));
    }
    Ok(BleToken::Address(token.to_string()))
}

/// Print a numbered list and return the item the operator picks by index.
pub fn pick_from_list<'a, T>(
    items: &'a [T],
    prompt: &str,
    label: impl Fn(&T) -> String,
) -> Result<&'a T> {
    require_interactive("pass an explicit argument; need a terminal to pick")?;
    if items.is_empty() {
        bail!("nothing to choose from");
    }
    for (i, item) in items.iter().enumerate() {
        eprintln!("  [{i}] {}", label(item));
    }
    let choice = prompt_line(prompt)?;
    parse_index(items, &choice)
}

/// Show the BLE device table and return the operator's single selection.
pub fn pick_ble_device(devs: &mut [BleDevice]) -> Result<BleDevice> {
    require_interactive("pass a BLE address; need a terminal to pick")?;
    if devs.is_empty() {
        bail!("scan found no devices; pass an address");
    }
    let order = ble_display_order(devs);
    ble_table(devs);
    let picks = parse_selection(&prompt_line("select device [n]: ")?, order.len())?;
    Ok(devs[order[picks[0]]].clone())
}

/// Shared attack status lines: title/state/elapsed, targets, frame counters.
pub fn status_frame(
    title: &str,
    elapsed: Duration,
    body: &[String],
    warning: Option<&str>,
) -> Vec<String> {
    let mut lines = vec![format!(
        "{}  {}  {}",
        style(title).bold(),
        style("running").red(),
        fmt_elapsed(elapsed)
    )];
    lines.extend(body.iter().cloned());
    if let Some(w) = warning {
        lines.push(style(w).red().to_string());
    }
    lines.push(style("ctrl-c to stop").dim().to_string());
    lines
}

pub fn attack_status_lines(
    title: &str,
    targets: &str,
    sent: u64,
    failed: u64,
    elapsed: Duration,
) -> Vec<String> {
    let rate = (sent as f64 / elapsed.as_secs_f64().max(0.001)) as u64;
    let fail = if failed > 0 {
        style(format!("{failed} fail")).red().to_string()
    } else {
        "0 fail".to_string()
    };
    status_frame(
        title,
        elapsed,
        &[
            format!("targets  {targets}"),
            format!("frames   {sent} sent   {fail}   {rate}/s"),
        ],
        None,
    )
}

/// A fixed block of lines redrawn in place on a TTY, silent when piped.
pub struct StatusBlock {
    term: Term,
    tty: bool,
    lines: usize,
    drawn: bool,
}

impl StatusBlock {
    pub fn new() -> Self {
        StatusBlock {
            term: Term::stdout(),
            tty: is_tty(),
            lines: 0,
            drawn: false,
        }
    }

    pub fn draw(&mut self, lines: &[String]) {
        if !self.tty {
            return;
        }
        if self.drawn {
            self.term.clear_last_lines(self.lines).ok();
        }
        let width = self.term.size().1.max(20) as usize;
        for l in lines {
            self.term
                .write_line(&console::truncate_str(l, width, "\u{2026}"))
                .ok();
        }
        self.lines = lines.len();
        self.drawn = true;
    }

    pub fn clear(&mut self) {
        if self.tty && self.drawn {
            self.term.clear_last_lines(self.lines).ok();
            self.drawn = false;
        }
    }
}

/// One row of the device file table.
pub struct FileRow {
    pub size: u64,
    pub path: String,
    pub read: bool,
    pub write: bool,
    pub deletable: bool,
}

impl FileRow {
    // r pull, w push, d delete ('-' where denied).
    fn perms(&self) -> String {
        let flag = |on, c| if on { c } else { '-' };
        format!(
            "{}{}{}",
            flag(self.read, 'r'),
            flag(self.write, 'w'),
            flag(self.deletable, 'd')
        )
    }
}

/// Human-readable byte size (K at/above 1 KiB, else raw bytes).
pub fn fmt_size(bytes: u64) -> String {
    if bytes >= 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

pub fn file_table(rows: &[FileRow]) {
    if rows.is_empty() {
        println!("no files");
        return;
    }
    let cols = [
        Col {
            head: "#",
            width: 3,
            right: true,
        },
        Col {
            head: "perm",
            width: 4,
            right: false,
        },
        Col {
            head: "size",
            width: 9,
            right: true,
        },
        Col {
            head: "path",
            width: 0,
            right: false,
        },
    ];
    let trows: Vec<Row> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| Row {
            shade: 255,
            cells: vec![
                (i + 1).to_string(),
                r.perms(),
                fmt_size(r.size),
                r.path.clone(),
            ],
        })
        .collect();
    table(&cols, &trows);
}

/// Dim IR capture table header (live stream prints rows one at a time).
pub fn ir_header(verbose: bool) {
    let cols = ir_cols(verbose);
    let last = cols.len().saturating_sub(1);
    let header = cols
        .iter()
        .enumerate()
        .map(|(i, c)| cell(c, c.head, i == last))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", style(header).dim());
}

/// One live IR capture row (`n` is 1-based).
pub fn ir_row(n: usize, cap: &IrCapture, verbose: bool) {
    let cols = ir_cols(verbose);
    let last = cols.len().saturating_sub(1);
    let cells = ir_cells(n, cap, verbose);
    let line = cols
        .iter()
        .zip(&cells)
        .enumerate()
        .map(|(i, (c, v))| cell(c, v, i == last))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{line}");
}

/// Full detail for one cached capture (for `ir show`).
pub fn ir_detail(cap: &IrCapture) {
    match cap {
        IrCapture::Code(c) => {
            let rows = [
                ("kind", "code".into()),
                ("protocol", c.protocol.name().into()),
                ("data", format!("0x{:X}", c.data)),
                ("bits", c.bits.to_string()),
            ];
            detail_table(&rows);
        }
        IrCapture::Raw(r) => {
            let csv = r
                .timings
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let rows = [
                ("kind", "raw".into()),
                ("khz", r.khz.to_string()),
                ("samples", r.timings.len().to_string()),
                ("timings", csv.clone()),
            ];
            detail_table(&rows);
            println!();
            println!("  replay: ir raw --khz {} --timings {csv}", r.khz);
        }
    }
}

fn ir_cols(verbose: bool) -> Vec<Col> {
    let mut cols = vec![
        Col {
            head: "protocol",
            width: 12,
            right: false,
        },
        Col {
            head: "data",
            width: 16,
            right: false,
        },
        Col {
            head: "bits",
            width: 20,
            right: true,
        },
        Col {
            head: "kind",
            width: 8,
            right: false,
        },
    ];
    if verbose {
        cols.push(Col {
            head: "timings",
            width: 24,
            right: false,
        });
    }
    cols
}

fn ir_cells(n: usize, cap: &IrCapture, verbose: bool) -> Vec<String> {
    let mut cells = match cap {
        IrCapture::Code(c) => vec![
            n.to_string(),
            c.protocol.name().into(),
            format!("0x{:X}", c.data),
            c.bits.to_string(),
            "code".into(),
        ],
        IrCapture::Raw(r) => vec![
            n.to_string(),
            "raw".into(),
            "-".into(),
            "-".into(),
            format!("raw/{}", r.timings.len()),
        ],
    };
    if verbose {
        let t = match cap {
            IrCapture::Code(_) => "-".into(),
            IrCapture::Raw(r) => r
                .timings
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(","),
        };
        cells.push(t);
    }
    cells
}

/// One-line spinner for a blocking device op; silent when piped.
pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Spinner {
    pub fn start(msg: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let handle = is_tty().then(|| {
            let stop = Arc::clone(&stop);
            let msg = msg.to_string();
            std::thread::spawn(move || {
                let term = Term::stdout();
                let frames = ['|', '/', '-', '\\'];
                let start = Instant::now();
                let mut i = 0usize;
                while !stop.load(Ordering::SeqCst) {
                    term.clear_line().ok();
                    let f = frames[i % frames.len()];
                    term.write_str(&format!("{f} {msg} ({}s)", start.elapsed().as_secs()))
                        .ok();
                    i += 1;
                    std::thread::sleep(Duration::from_millis(120));
                }
                term.clear_line().ok();
            })
        });
        Spinner { stop, handle }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            h.join().ok();
        }
    }
}
#[cfg(all(test, unix))]
mod prompt_tests {
    use super::read_fd_line;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    static LOCK: Mutex<()> = Mutex::new(());

    fn pty_pair() -> (i32, std::fs::File) {
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(
                master >= 0,
                "posix_openpt: {}",
                std::io::Error::last_os_error()
            );
            assert_eq!(libc::grantpt(master), 0);
            assert_eq!(libc::unlockpt(master), 0);
            let mut name = [0u8; 64];
            let rc = libc::ptsname_r(master, name.as_mut_ptr().cast::<libc::c_char>(), name.len());
            assert_eq!(rc, 0, "ptsname_r");
            let slave = libc::open(
                name.as_ptr().cast::<libc::c_char>(),
                libc::O_RDWR | libc::O_NOCTTY,
            );
            assert!(
                slave >= 0,
                "open slave: {}",
                std::io::Error::last_os_error()
            );
            (master, std::fs::File::from_raw_fd(slave))
        }
    }

    #[test]
    fn line_comes_back_without_waiting_out_a_timeout() {
        let _guard = LOCK.lock().unwrap();
        let (master, slave) = pty_pair();
        let fd = slave.as_raw_fd();
        let msg = b"7\n";
        let n = unsafe { libc::write(master, msg.as_ptr().cast(), msg.len()) };
        assert_eq!(n, msg.len() as isize);
        crate::signals::RUNNING.store(true, Ordering::SeqCst);
        let line = read_fd_line(fd).unwrap();
        unsafe { libc::close(master) };
        assert_eq!(line.as_deref(), Some("7"));
    }

    #[test]
    fn ctrl_c_flag_returns_before_enter() {
        let _guard = LOCK.lock().unwrap();
        let (master, slave) = pty_pair();
        let fd = slave.as_raw_fd();
        crate::signals::RUNNING.store(true, Ordering::SeqCst);
        let worker = std::thread::spawn(move || read_fd_line(fd));
        std::thread::sleep(std::time::Duration::from_millis(20));
        crate::signals::RUNNING.store(false, Ordering::SeqCst);
        let err = worker.join().unwrap().unwrap_err();
        crate::signals::RUNNING.store(true, Ordering::SeqCst);
        unsafe { libc::close(master) };
        assert!(crate::signals::is_cancel(&err), "{err:#}");
    }
}

#[cfg(test)]
mod ble_token_tests {
    use super::{BleToken, ble_in_display_order, resolve_ble_token};
    use infishark::BleDevice;

    fn dev(addr: &str, rssi: i64, paired: bool, addr_type: Option<u8>) -> BleDevice {
        BleDevice {
            address: addr.into(),
            name: None,
            rssi,
            addr_type,
            company_id: None,
            vendor: None,
            company: None,
            paired,
            extra: Default::default(),
        }
    }

    #[test]
    fn paired_rows_sort_ahead_of_stronger_adverts() {
        let rows = ble_in_display_order(&[
            dev("aa:aa:aa:aa:aa:01", -40, false, Some(0)),
            dev("bb:bb:bb:bb:bb:02", 0, true, Some(1)),
        ]);
        assert_eq!(rows[0].address, "bb:bb:bb:bb:bb:02");
        assert_eq!(rows[1].address, "aa:aa:aa:aa:aa:01");
    }

    #[test]
    fn row_number_uses_table_order_and_keeps_addr_type() {
        let rows = ble_in_display_order(&[
            dev("aa:aa:aa:aa:aa:01", -40, false, Some(0)),
            dev("bb:bb:bb:bb:bb:02", 0, true, Some(1)),
        ]);
        match resolve_ble_token(&rows, "0").unwrap() {
            BleToken::Row(d) => {
                assert_eq!(d.address, "bb:bb:bb:bb:bb:02");
                assert_eq!(d.addr_type, Some(1));
            }
            BleToken::Address(a) => panic!("{a}"),
        }
        match resolve_ble_token(&rows, "1").unwrap() {
            BleToken::Row(d) => assert_eq!(d.address, "aa:aa:aa:aa:aa:01"),
            BleToken::Address(a) => panic!("{a}"),
        }
    }

    #[test]
    fn mac_hits_the_row_ignoring_case_and_separators() {
        let rows = [dev("DD:CC:BB:AA:EE:FF", -50, false, Some(1))];
        match resolve_ble_token(&rows, "ddccbbaaeeff").unwrap() {
            BleToken::Row(d) => {
                assert_eq!(d.address, "DD:CC:BB:AA:EE:FF");
                assert_eq!(d.addr_type, Some(1));
            }
            BleToken::Address(a) => panic!("{a}"),
        }
    }

    #[test]
    fn unknown_mac_is_passed_through() {
        match resolve_ble_token(&[], "aa:bb:cc:dd:ee:ff").unwrap() {
            BleToken::Address(a) => assert_eq!(a, "aa:bb:cc:dd:ee:ff"),
            BleToken::Row(_) => panic!("row"),
        }
    }

    #[test]
    fn known_row_keeps_its_type_and_an_unknown_mac_does_not() {
        let rows = [dev("aa:bb:cc:00:00:01", -52, false, Some(1))];
        let row = super::resolve_ble_target(&rows, "0", None).unwrap();
        assert_eq!(row.address, "aa:bb:cc:00:00:01");
        assert_eq!(row.addr_type, 1);
        assert!(row.type_known);
        let mac = super::resolve_ble_target(&rows, "aa:bb:cc:00:00:01", None).unwrap();
        assert!(mac.type_known);
        assert_eq!(mac.addr_type, 1);
        let fresh = super::resolve_ble_target(&[], "aa:bb:cc:dd:ee:ff", None).unwrap();
        assert!(!fresh.type_known);
        assert_eq!(fresh.addr_type, 0);
        let forced = super::resolve_ble_target(&rows, "0", Some(0)).unwrap();
        assert!(forced.type_known);
        assert_eq!(forced.addr_type, 0);
    }

    #[test]
    fn unconnectable_scan_refuses_and_a_later_true_allows() {
        let mut beacon = dev("aa:bb:cc:dd:ee:ff", -60, false, Some(1));
        beacon
            .extra
            .insert("connectable".into(), serde_json::json!(false));
        let err =
            super::refuse_unconnectable(&[], &[beacon.clone()], "AA-BB-CC-DD-EE-FF").unwrap_err();
        assert!(err.to_string().contains("is not connectable"), "{err}");

        let mut named = beacon.clone();
        named.name = Some("Tile".into());
        let err = super::refuse_unconnectable(&[named], &[], "aa:bb:cc:dd:ee:ff").unwrap_err();
        assert!(
            err.to_string()
                .contains("Tile (aa:bb:cc:dd:ee:ff) is not connectable"),
            "{err}"
        );

        let mut later = dev("aa:bb:cc:dd:ee:ff", -40, false, Some(1));
        later
            .extra
            .insert("connectable".into(), serde_json::json!(true));
        super::refuse_unconnectable(&[beacon], &[later], "aa:bb:cc:dd:ee:ff").unwrap();
    }

    #[test]
    fn missing_connectable_flag_still_tries() {
        let saved = dev("aa:bb:cc:dd:ee:01", 0, true, Some(0));
        super::refuse_unconnectable(&[saved], &[], "aa:bb:cc:dd:ee:01").unwrap();
        super::refuse_unconnectable(&[], &[], "aa:bb:cc:dd:ee:02").unwrap();
    }

    #[test]
    fn hid_appearance_or_service_wants_a_passkey() {
        let mut keyboard = dev("aa:aa:aa:aa:aa:01", -40, false, Some(1));
        keyboard
            .extra
            .insert("appearance".into(), serde_json::json!(0x03C1));
        assert!(super::ble_prefers_passkey(&keyboard));
        let mut band = dev("aa:aa:aa:aa:aa:02", -40, false, Some(1));
        band.extra
            .insert("services".into(), serde_json::json!(["180d"]));
        assert!(!super::ble_prefers_passkey(&band));
        let mut hogp = dev("aa:aa:aa:aa:aa:03", -40, false, Some(1));
        hogp.extra.insert(
            "services".into(),
            serde_json::json!(["00001812-0000-1000-8000-00805f9b34fb"]),
        );
        assert!(super::ble_prefers_passkey(&hogp));
    }

    #[test]
    fn index_without_a_table_names_the_commands() {
        let msg = format!("{}", resolve_ble_token(&[], "4").unwrap_err());
        assert!(msg.contains("ble scan"), "{msg}");
    }

    #[test]
    fn index_past_the_table_says_the_range() {
        let rows = [dev("aa:aa:aa:aa:aa:01", -40, false, Some(0))];
        let msg = format!("{}", resolve_ble_token(&rows, "4").unwrap_err());
        assert!(msg.contains("out of range"), "{msg}");
    }

    #[test]
    fn garbage_is_rejected() {
        let msg = format!("{}", resolve_ble_token(&[], "keyboard").unwrap_err());
        assert!(msg.contains("not a row number"), "{msg}");
        let msg = format!("{}", resolve_ble_token(&[], "not-a-device").unwrap_err());
        assert!(msg.contains("bad BLE address"), "{msg}");
    }
}

#[cfg(test)]
mod gatt_row_tests {
    use super::{GattOp, gatt_rows, select_gatt, service_heading};
    use infishark::{GattChar, GattService};

    fn ch(uuid: &str, handle: u16, props: &[&str]) -> GattChar {
        GattChar {
            uuid: uuid.into(),
            handle,
            properties: props.iter().map(|p| (*p).to_string()).collect(),
        }
    }

    fn sample() -> Vec<GattService> {
        vec![
            GattService {
                uuid: "180f".into(),
                handle: 12,
                end_handle: 16,
                characteristics: vec![
                    ch("2a19", 14, &["read", "notify"]),
                    ch("f00d", 16, &["write"]),
                ],
            },
            GattService {
                uuid: "0000180a-0000-1000-8000-00805f9b34fb".into(),
                handle: 20,
                end_handle: 24,
                characteristics: vec![ch("2a29", 22, &["read"])],
            },
        ]
    }

    #[test]
    fn rows_follow_service_order_and_keep_names() {
        let rows = gatt_rows(&sample());
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].uuid, "2a19");
        assert_eq!(rows[0].name, "Battery Level");
        assert_eq!(rows[0].service, "Battery");
        assert_eq!(rows[0].props, "read,notify");
        assert_eq!(rows[0].handle, 14);
        assert_eq!(rows[1].uuid, "f00d");
        assert_eq!(rows[1].name, "<unknown>");
        assert_eq!(rows[1].service, "Battery");
        assert_eq!(rows[2].name, "Manufacturer Name String");
        assert_eq!(rows[2].service, "Device Information");
    }

    #[test]
    fn service_heading_names_the_section_and_rows_stay_continuous() {
        let services = vec![
            GattService {
                uuid: "1800".into(),
                handle: 1,
                end_handle: 6,
                characteristics: vec![ch("2a00", 3, &["read"]), ch("2a01", 5, &["read"])],
            },
            GattService {
                uuid: "180f".into(),
                handle: 15,
                end_handle: 18,
                characteristics: vec![ch("2a19", 17, &["read"])],
            },
        ];
        assert_eq!(
            service_heading(&services[0]),
            "svc 1800  [0x0001-0x0006]  GAP"
        );
        assert_eq!(
            service_heading(&services[1]),
            "svc 180f  [0x000f-0x0012]  Battery"
        );
        let rows = gatt_rows(&services);
        assert_eq!(rows[0].service, "GAP");
        assert_eq!(rows[2].uuid, "2a19");
        assert_eq!(rows[2].service, "Battery");
    }

    fn tok(s: &str) -> Vec<String> {
        vec![s.into()]
    }

    #[test]
    fn row_number_resolves_and_a_uuid_passes_through() {
        let rows = gatt_rows(&sample());
        let hit = select_gatt(&rows, &tok("0"), GattOp::Read).unwrap();
        assert_eq!(hit.targets[0].uuid, "2a19");
        assert_eq!(hit.targets[0].handle, Some(14));
        assert_eq!(hit.targets[0].row, Some(0));
        let hit = select_gatt(&rows, &tok("2"), GattOp::Read).unwrap();
        assert_eq!(hit.targets[0].uuid, "2a29");
        assert_eq!(hit.targets[0].handle, Some(22));
        let hit = select_gatt(&rows, &tok("2a19"), GattOp::Read).unwrap();
        assert_eq!(hit.targets[0].handle, Some(14));
        let full = "00002a19-0000-1000-8000-00805f9b34fb";
        let hit = select_gatt(&rows, &tok(full), GattOp::Read).unwrap();
        assert_eq!(hit.targets[0].row, Some(0));
        assert_eq!(hit.targets[0].handle, Some(14));
        let other = "00002a37-0000-1000-8000-00805f9b34fb";
        let hit = select_gatt(&rows, &tok(other), GattOp::Read).unwrap();
        assert_eq!(hit.targets[0].uuid, other);
        assert_eq!(hit.targets[0].handle, None);
        // 2902 is the CCCD UUID and also a decimal. It is not a row here.
        let hit = select_gatt(&rows, &tok("2902"), GattOp::Read).unwrap();
        assert_eq!(hit.targets[0].uuid, "2902");
        assert_eq!(hit.targets[0].handle, None);
        let err = select_gatt(&rows, &tok("9"), GattOp::Read).unwrap_err();
        assert!(err.to_string().contains("ble gatt enum"), "{err}");
        let err = select_gatt(&[], &tok("0"), GattOp::Read).unwrap_err();
        assert!(err.to_string().contains("ble gatt enum"), "{err}");
    }

    fn hid() -> Vec<super::GattRow> {
        gatt_rows(&[
            GattService {
                uuid: "1812".into(),
                handle: 16,
                end_handle: 40,
                characteristics: vec![
                    ch("2a4d", 20, &["read", "write"]),
                    ch("2a4d", 24, &["read", "notify"]),
                ],
            },
            GattService {
                uuid: "180f".into(),
                handle: 48,
                end_handle: 52,
                characteristics: vec![ch("2a19", 50, &["read", "notify"])],
            },
            GattService {
                uuid: "1801".into(),
                handle: 1,
                end_handle: 5,
                characteristics: vec![ch("2a05", 3, &["indicate"])],
            },
        ])
    }

    #[test]
    fn read_all_skips_rows_without_read_and_keeps_handles() {
        let rows = gatt_rows(&sample());
        let sel = select_gatt(&rows, &tok("all"), GattOp::Read).unwrap();
        assert!(sel.bulk);
        let got: Vec<_> = sel
            .targets
            .iter()
            .map(|t| (t.row, t.handle, t.uuid.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![(Some(0), Some(14), "2a19"), (Some(2), Some(22), "2a29")]
        );
        let err = select_gatt(&rows, &tok("1"), GattOp::Read).unwrap_err();
        assert!(err.to_string().contains("not readable"), "{err}");
    }

    #[test]
    fn subscribe_all_picks_notify_and_indicate_only_rows() {
        let rows = hid();
        let sel = select_gatt(&rows, &tok("all"), GattOp::Subscribe { indicate: false }).unwrap();
        let got: Vec<_> = sel
            .targets
            .iter()
            .map(|t| (t.row, t.handle, t.indicate, t.name.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (Some(1), Some(24), false, "Report"),
                (Some(2), Some(50), false, "Battery Level"),
                (Some(3), Some(3), true, "Service Changed"),
            ]
        );
        let only = select_gatt(&rows, &tok("all"), GattOp::Subscribe { indicate: true }).unwrap();
        assert_eq!(only.targets.len(), 1);
        assert_eq!(only.targets[0].name, "Service Changed");
        assert!(only.targets[0].indicate);
        let one = select_gatt(&rows, &tok("3"), GattOp::Subscribe { indicate: false }).unwrap();
        assert!(one.targets[0].indicate);
        assert!(!one.bulk);
        let err = select_gatt(&rows, &tok("0"), GattOp::Subscribe { indicate: false }).unwrap_err();
        assert!(err.to_string().contains("not notifiable"), "{err}");
    }

    #[test]
    fn a_repeated_uuid_asks_for_the_row() {
        let rows = hid();
        let err = select_gatt(&rows, &tok("2a4d"), GattOp::Read).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pass a row number"), "{msg}");
        assert!(msg.contains("0x0014"), "{msg}");
        assert!(msg.contains("0x0018"), "{msg}");
        let second = select_gatt(&rows, &tok("1"), GattOp::Subscribe { indicate: false }).unwrap();
        assert_eq!(second.targets[0].handle, Some(24));
        assert!(!second.targets[0].indicate);
        let both = vec!["0".into(), "1".into()];
        let sel = select_gatt(&rows, &both, GattOp::Subscribe { indicate: false }).unwrap();
        assert!(sel.bulk);
        assert_eq!(sel.targets.len(), 1);
        assert_eq!(sel.targets[0].row, Some(1));
        assert_eq!(sel.rejected.len(), 1);
        assert_eq!(sel.rejected[0].reason, "not notifiable");
    }

    #[test]
    fn star_and_combined_all_are_rejected() {
        let rows = gatt_rows(&sample());
        let err = select_gatt(&rows, &tok("*"), GattOp::Read).unwrap_err();
        assert!(err.to_string().contains("use `all`"), "{err}");
        let err = select_gatt(
            &rows,
            &["all".into(), "0".into()],
            GattOp::Subscribe { indicate: false },
        )
        .unwrap_err();
        assert!(err.to_string().contains("stands alone"), "{err}");
        let err = select_gatt(&rows, &tok("all"), GattOp::Write).unwrap_err();
        assert!(err.to_string().contains("write all"), "{err}");
        let err = select_gatt(&[], &tok("all"), GattOp::Read).unwrap_err();
        assert!(err.to_string().contains("ble gatt enum"), "{err}");
    }
}
