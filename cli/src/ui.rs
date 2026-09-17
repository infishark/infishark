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

fn tty_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
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

/// Borderless network table, strongest first. `verbose` adds ciphers/bandwidth/flags.
pub fn network_table(nets: &[Network], verbose: bool) {
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

/// Host-only post-table notes: hidden SSIDs that likely share a radio with a named AP.
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
pub fn network_detail(n: &Network) {
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
pub fn ble_table(devs: &[BleDevice]) {
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
            width: 4,
            right: true,
        },
        Col {
            head: "vendor",
            width: 24,
            right: false,
        },
    ];
    let rows: Vec<Row> = order_by_rssi(devs, |d| d.rssi)
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
            Row {
                shade: rssi_shade(d.rssi),
                cells: vec![
                    row.to_string(),
                    name,
                    d.address.clone(),
                    d.rssi.to_string(),
                    vendor,
                ],
            }
        })
        .collect();
    table(&cols, &rows);
}

/// Full detail for one BLE device: fixed fields then every extra scan field.
pub fn ble_detail(d: &BleDevice) {
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

/// List GATT services and their characteristics.
pub fn gatt_services(services: &[GattService]) {
    if services.is_empty() {
        println!("no services");
        return;
    }
    for s in services {
        println!(
            "{}  {}",
            style(format!("svc {}", s.uuid)).bold(),
            style(format!("[{:#06x}-{:#06x}]", s.handle, s.end_handle)).dim()
        );
        for c in &s.characteristics {
            let props = if c.properties.is_empty() {
                String::new()
            } else {
                format!("  ({})", c.properties.join(","))
            };
            println!(
                "  {}  {}{}",
                c.uuid,
                style(format!("{:#06x}", c.handle)).dim(),
                props
            );
        }
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
pub fn pick_networks(nets: &[Network]) -> Result<Vec<Network>> {
    require_interactive("pass --ssid or --bssid to choose a target")?;
    let order = wifi_picker_table(nets)?;
    let picks = parse_selection(
        &prompt_line("select target(s) [n | n,n | a]: ")?,
        order.len(),
    )?;
    Ok(picks.iter().map(|&p| nets[order[p]].clone()).collect())
}

/// Same table as [`pick_networks`], single choice (for save / join flows).
pub fn pick_network(nets: &[Network]) -> Result<Network> {
    require_interactive("pass --ssid or --bssid to choose a network")?;
    let order = wifi_picker_table(nets)?;
    let picks = parse_selection(&prompt_line("select network [n]: ")?, order.len())?;
    if picks.len() != 1 {
        bail!("select a single network");
    }
    Ok(nets[order[picks[0]]].clone())
}

fn wifi_picker_table(nets: &[Network]) -> Result<Vec<usize>> {
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

/// Prompt on stderr and read one trimmed line from stdin.
pub fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut s = String::new();
    #[cfg(unix)]
    {
        if let Ok(tty) = std::fs::File::open("/dev/tty") {
            use std::io::BufRead;
            std::io::BufReader::new(tty).read_line(&mut s)?;
            return Ok(s.trim_end_matches(['\n', '\r']).to_string());
        }
    }
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
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
pub fn pick_ble_device(devs: &[BleDevice]) -> Result<BleDevice> {
    require_interactive("pass a BLE address; need a terminal to pick")?;
    if devs.is_empty() {
        bail!("scan found no devices; pass an address");
    }
    let order = order_by_rssi(devs, |d| d.rssi);
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
