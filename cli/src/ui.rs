//! Shared terminal UI: network table, picker, status block, spinner.

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
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
fn order_by_rssi<T>(items: &[T], rssi: impl Fn(&T) -> i64) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..items.len()).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(rssi(&items[i])));
    idx
}

// 256-color grey ramp: white at strong signal, fading to grey when weak.
fn rssi_shade(rssi: i64) -> u8 {
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

fn wifi_cols() -> Vec<Col> {
    vec![
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
            width: 15,
            right: false,
        },
        Col {
            head: "cipher",
            width: 9,
            right: false,
        },
        Col {
            head: "phy",
            width: 5,
            right: false,
        },
        Col {
            head: "vendor",
            width: 16,
            right: false,
        },
    ]
}

fn extra_str(n: &Network, key: &str) -> String {
    n.extra
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn wifi_rows(nets: &[Network], order: &[usize]) -> Vec<Row> {
    order
        .iter()
        .enumerate()
        .map(|(row, &i)| {
            let n = &nets[i];
            let name = if n.ssid.is_empty() {
                "<hidden>".to_string()
            } else {
                n.ssid.clone()
            };
            Row {
                shade: rssi_shade(n.rssi),
                cells: vec![
                    row.to_string(),
                    name,
                    n.bssid.clone(),
                    n.channel.to_string(),
                    n.rssi.to_string(),
                    n.encryption.clone(),
                    extra_str(n, "pairwise_cipher"),
                    extra_str(n, "phy"),
                    n.vendor.clone().unwrap_or_default(),
                ],
            }
        })
        .collect()
}

/// Borderless network table, strongest first.
pub fn network_table(nets: &[Network]) {
    if nets.is_empty() {
        println!("no networks found");
        return;
    }
    let order = order_by_rssi(nets, |n| n.rssi);
    table(&wifi_cols(), &wifi_rows(nets, &order));
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

fn value_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Render a dim-key / value detail block, keys left-aligned to the widest.
pub fn detail_table<K: AsRef<str>, V: AsRef<str>>(rows: &[(K, V)]) {
    let w = rows.iter().map(|(k, _)| k.as_ref().len()).max().unwrap_or(0);
    for (k, v) in rows {
        println!("  {}  {}", style(format!("{:<w$}", k.as_ref())).dim(), v.as_ref());
    }
}

/// Render a flat JSON object as a detail block; non-object values print as-is.
pub fn value_detail(v: &Value) {
    match v.as_object() {
        Some(obj) => {
            let rows: Vec<(String, String)> =
                obj.iter().map(|(k, val)| (k.clone(), value_str(val))).collect();
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
        println!("  {}  {}", style(format!("[slot {}]", n.index)).dim(), n.ssid);
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
            println!("  {}  {}{}", c.uuid, style(format!("{:#06x}", c.handle)).dim(), props);
        }
    }
}

/// Show the network table and return the operator's selection (n | n,n | a).
pub fn pick_networks(nets: &[Network]) -> Result<Vec<Network>> {
    if nets.is_empty() {
        bail!("scan found no networks");
    }
    let order = order_by_rssi(nets, |n| n.rssi);
    table(&wifi_cols(), &wifi_rows(nets, &order));
    let picks = parse_selection(
        &prompt_line("select target(s) [n | n,n | a]: ")?,
        order.len(),
    )?;
    Ok(picks.iter().map(|&p| nets[order[p]].clone()).collect())
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

/// Prompt on stderr and read one trimmed line from stdin.
pub fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut s = String::new();
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
