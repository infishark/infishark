//! Interactive reedline shell over the command tree; one device per session.
//! `ble gatt subscribe` keeps that device open and prints notifications above
//! the prompt.

use std::borrow::Cow;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::{Arg, Command, CommandFactory, Parser};
use console::style;
use infishark::Device;
use infishark::model::GattNotification;
use reedline::{Color, Prompt, PromptEditMode, PromptHistorySearch, Reedline, Signal};

use crate::ports::{DeviceIdent, PortEntry};
use crate::signals::{RUNNING, install_sigint};
use crate::{BleCmd, Cli, Command as CliCommand, DbOpts, GattCmd, dispatch, ports};

const LISTEN_MS: u64 = 200;

const SHARK: &str = include_str!("art/shark.txt");
const WORDMARK: &str = include_str!("art/wordmark.txt");
const MARGIN: &str = "   ";

pub fn run(base: &Cli) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("the interactive shell needs a terminal; run `infishark <command>` directly");
    }
    let mut sh = Shell::new();
    install_sigint();
    sh.banner(utf8_locale() && !base.no_banner);
    let account = crate::ctf_account::startup_status();
    println!("{MARGIN}{}\n", style(account.message()).dim());
    if account.is_pending() {
        sh.account_status = Some(account);
    }
    sh.repl()
}

fn utf8_locale() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"].iter().any(|k| {
        std::env::var(k)
            .map(|v| v.to_ascii_uppercase().replace('-', "").contains("UTF8"))
            .unwrap_or(false)
    })
}

fn fmt_uptime(secs: u64) -> String {
    let (h, m) = (secs / 3600, (secs % 3600) / 60);
    if h > 0 {
        format!("{h}h{m:02}m")
    } else {
        format!("{m}m")
    }
}

fn port_exists(name: &str) -> bool {
    serialport::available_ports()
        .map(|ps| ps.iter().any(|p| p.port_name == name))
        .unwrap_or(false)
}

struct Listen {
    dev: Arc<Mutex<Device>>,
    port: String,
    stop: Arc<AtomicBool>,
    // Pause listener reads while a command owns the port.
    pause: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

struct Unpause(Arc<AtomicBool>);

impl Drop for Unpause {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

struct Shell {
    devices: Vec<PortEntry>,
    selected: Option<String>,
    peripheral: Option<&'static str>,
    listen: Option<Listen>,
    account_status: Option<crate::ctf_account::StartupCheck>,
    // Queued by the listen thread. The shell owns the prompt and prints these.
    notes_tx: SyncSender<String>,
    notes_rx: Receiver<String>,
}

impl Shell {
    fn new() -> Self {
        let (notes_tx, notes_rx) = sync_channel(64);
        let mut sh = Shell {
            devices: vec![],
            selected: None,
            peripheral: None,
            listen: None,
            account_status: None,
            notes_tx,
            notes_rx,
        };
        sh.refresh();
        sh.selected = sh.devices.first().map(|d| d.name.clone());
        sh
    }

    fn refresh(&mut self) {
        self.devices = ports::list(false)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.device.is_some())
            .collect();
    }

    fn index_of(&self, port: &str) -> Option<usize> {
        self.devices.iter().position(|d| d.name == port)
    }

    fn label(&self) -> String {
        let base = match &self.selected {
            None => "infishark".to_string(),
            Some(p) => match self.index_of(p) {
                Some(i) => format!("nano{i}"),
                None => "nano".to_string(),
            },
        };
        match self.peripheral {
            Some(p) => format!("{base} ({p})"),
            None => base,
        }
    }

    fn banner(&self, big: bool) {
        let art = if big { SHARK } else { WORDMARK };
        println!();
        for line in art.lines() {
            println!("{MARGIN}{}", style(line).white());
        }
        println!();
        let n = self.devices.len();
        println!(
            "{MARGIN}{} {}   {}",
            style("infishark").white().bold(),
            style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim(),
            style(format!(
                "{n} device{} connected",
                if n == 1 { "" } else { "s" }
            ))
            .dim(),
        );
        println!();
        for (i, d) in self.devices.iter().enumerate() {
            let id = d.device.as_ref().unwrap();
            let head = format!("nano{i}  {}  {}", id.serial, d.name);
            if self.selected.as_deref() == Some(d.name.as_str()) {
                println!("{MARGIN}{}", style(head).white().bold());
            } else {
                println!("{MARGIN}{}", style(head).white());
            }
            if let Some(stats) = stats(&d.name, id) {
                println!("{MARGIN}{}", style(stats).dim());
            }
            if infishark::fw::is_outdated(&id.version) {
                println!(
                    "{MARGIN}{}",
                    style(format!(
                        "firmware {} is outdated (need {}); infishark device update",
                        id.version,
                        infishark::RECOMMENDED_FIRMWARE
                    ))
                    .yellow()
                );
            }
        }
        if self.devices.is_empty() {
            println!("{MARGIN}{}", style("no Nano connected").dim());
        }
        println!();
        println!(
            "{MARGIN}{}   {}",
            style("https://docs.infishark.com").dim(),
            style("help for commands, !cmd runs a shell command, exit or :q quits").dim()
        );
        println!();
    }

    fn repl(&mut self) -> Result<()> {
        let mut editor = Reedline::create();
        loop {
            self.flush_notes();
            // Reedline repaints the prompt, which would hide a line printed
            // while it owns the screen. Wait here until a key arrives.
            if self.listen.is_some() || self.account_status.is_some() {
                self.idle_until_key()?;
            }
            let prompt = NanoPrompt(self.label());
            match editor.read_line(&prompt) {
                Ok(Signal::Success(line)) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if is_quit(line) {
                        self.stop_listen();
                        break;
                    }
                    if let Some(cmd) = host_command(line) {
                        self.stop_listen();
                        self.account_status = None;
                        run_host(cmd);
                        continue;
                    }
                    if !self.builtin(line) {
                        self.exec(line);
                    }
                }
                Ok(Signal::CtrlC) => continue,
                Ok(Signal::CtrlD) => {
                    self.stop_listen();
                    break;
                }
                Err(e) => {
                    self.stop_listen();
                    crate::log::err(format!("input: {e}"));
                    break;
                }
            }
        }
        Ok(())
    }

    // Handle shell-only verbs; returns true when the line was one.
    fn builtin(&mut self, line: &str) -> bool {
        let mut toks = line.split_whitespace();
        match toks.next().unwrap_or("") {
            "help" | "?" | "--help" | "-h" => {
                let rest: Vec<String> = toks.map(str::to_string).collect();
                if rest.is_empty() {
                    self.help();
                } else {
                    let root = Cli::command();
                    match resolve(&root, &rest) {
                        Some(cmd) => render_help(cmd, &rest),
                        None => crate::log::err("no such command"),
                    }
                }
            }
            "clear" => {
                let _ = console::Term::stdout().clear_screen();
            }
            "select" => self.select(toks.next()),
            _ => return false,
        }
        true
    }

    fn select(&mut self, arg: Option<&str>) {
        self.refresh();
        let Some(arg) = arg else {
            for (i, d) in self.devices.iter().enumerate() {
                let mark = if self.selected.as_deref() == Some(d.name.as_str()) {
                    "*"
                } else {
                    " "
                };
                println!("{mark} nano{i}  {}", d.name);
            }
            return;
        };
        let idx = arg
            .parse::<usize>()
            .ok()
            .or_else(|| arg.strip_prefix("nano")?.parse().ok());
        if let Some(i) = idx.filter(|&i| i < self.devices.len()) {
            self.stop_listen();
            self.selected = Some(self.devices[i].name.clone());
        } else if self.index_of(arg).is_some() || port_exists(arg) {
            self.stop_listen();
            self.selected = Some(arg.to_string());
        } else {
            crate::log::err(format!("no such device '{arg}' (try 'ports' or 'select')"));
        }
    }

    // Track the fire-and-forget peripheral so the prompt can show it.
    fn track_peripheral(&mut self, path: &[String]) {
        match path
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["ble", "adv"] => self.peripheral = Some("adv"),
            ["ble", "gatt", "subscribe"] => self.peripheral = Some("gatt"),
            ["ble", "gatt", "disconnect"] | ["ble", "stop"] => self.peripheral = None,
            _ => {}
        }
    }

    fn exec(&mut self, line: &str) {
        let Some(toks) = shlex::split(line) else {
            crate::log::err("unbalanced quotes");
            return;
        };
        let is_help = toks.iter().any(|t| matches!(t.as_str(), "--help" | "-h"));
        if !is_help && line.contains(['|', '>', '<']) {
            self.stop_listen();
            self.account_status = None;
            self.run_external(line);
            return;
        }

        let root = Cli::command();

        if is_help {
            let path: Vec<String> = toks
                .iter()
                .take_while(|t| !matches!(t.as_str(), "--help" | "-h"))
                .filter(|t| !t.starts_with('-'))
                .cloned()
                .collect();
            match resolve(&root, &path) {
                Some(cmd) => render_help(cmd, &path),
                None => crate::log::err("no such command"),
            }
            return;
        }
        // A bare group (e.g. `ble`) lists its subcommands rather than running.
        if let Some(cmd) = resolve(&root, &toks) {
            if cmd.get_subcommands().next().is_some() {
                render_help(cmd, &toks);
                return;
            }
        }

        let path = command_path(&root, &toks);
        let mut argv = vec!["infishark".to_string()];
        argv.extend(toks);
        match Cli::try_parse_from(argv) {
            Ok(mut cli) => {
                if cli.port.is_none() {
                    cli.port = self.selected.clone();
                }
                if let Some(command) = &cli.command {
                    if matches!(
                        command,
                        CliCommand::Ctf {
                            action: crate::CtfCmd::Account { .. }
                        }
                    ) {
                        // Login/logout may replace or remove the saved session.
                        // A startup probe must not print a stale account afterward.
                        self.account_status = None;
                    }
                    RUNNING.store(true, Ordering::SeqCst);
                    let result = match command {
                        CliCommand::Ble {
                            db,
                            action: BleCmd::Gatt { action },
                        } => self.gatt_cmd(&cli, db, action),
                        CliCommand::Ir {
                            action: crate::IrCmd::Save { .. },
                        } => dispatch(&cli, command),
                        _ => {
                            self.stop_listen();
                            dispatch(&cli, command)
                        }
                    };
                    match result {
                        Ok(()) => self.track_peripheral(&path),
                        Err(e) if crate::signals::is_cancel(&e) => {
                            let _ = writeln!(std::io::stderr());
                        }
                        Err(e) => crate::log::err(format!("{e:#}")),
                    }
                }
            }
            Err(e) => {
                // Missing subcommand/argument shows our help, not clap's usage.
                let missing = matches!(
                    e.kind(),
                    clap::error::ErrorKind::MissingRequiredArgument
                        | clap::error::ErrorKind::MissingSubcommand
                );
                if let Some(cmd) = resolve(&root, &path).filter(|_| missing) {
                    render_help(cmd, &path);
                } else {
                    print!("{}", e.to_string().replace("infishark ", ""));
                }
            }
        }
    }

    fn run_external(&self, line: &str) {
        let Ok(exe) = std::env::current_exe() else {
            crate::log::err("cannot locate the infishark binary");
            return;
        };
        let port = match &self.selected {
            Some(p) if !line.contains("--port") => {
                format!("--port {} ", sh_quote(p))
            }
            _ => String::new(),
        };
        let cmd = format!("{} {port}{line}", sh_quote(&exe.display().to_string()));
        RUNNING.store(true, Ordering::SeqCst);
        if let Err(e) = std::process::Command::new(crate::privs::tool_path("sh"))
            .arg("-c")
            .arg(cmd)
            .status()
        {
            crate::log::err(format!("failed to run: {e}"));
        }
    }

    fn help(&self) {
        render_help(&Cli::command(), &[]);
        println!("{}", style("shell").bold());
        help_row("select", Some("switch active device (N | port)".into()), 6);
        help_row("clear", Some("clear the screen".into()), 6);
        help_row("!cmd", Some("run a shell command".into()), 6);
        help_row("exit", Some("leave the shell (quit, :q)".into()), 6);
    }

    fn gatt_cmd(&mut self, cli: &Cli, db: &DbOpts, action: &GattCmd) -> Result<()> {
        if let (Some(listen), Some(port)) = (&self.listen, cli.port.as_deref()) {
            if listen.port != port {
                self.stop_listen();
            }
        }
        match action {
            GattCmd::Subscribe { uuids, indicate } => self.start_listen(cli, uuids, *indicate),
            GattCmd::Disconnect if self.listen.is_some() => {
                let r = self.run_gatt(cli, db, action);
                self.stop_listen();
                r
            }
            _ if self.listen.is_some() => self.run_gatt(cli, db, action),
            _ => crate::cmd_gatt(cli, db, action),
        }
    }

    fn start_listen(&mut self, cli: &Cli, uuids: &[String], indicate: bool) -> Result<()> {
        let sel = crate::gatt_subscribe_selection(uuids, indicate)?;
        if sel.targets.is_empty() {
            crate::report_selection_misses(cli, &sel);
            anyhow::bail!("subscribe failed");
        }
        let fresh = self.listen.is_none();
        self.ensure_listen(cli)?;
        let subscribed = self.run_on_dev(cli.timeout_ms.max(12_000), |dev| {
            crate::apply_gatt_subscribe(cli, dev, &sel)
        });
        match subscribed {
            Ok(()) => {
                if cli.json {
                    crate::print_ok(true)
                } else {
                    crate::log::info("listening");
                    Ok(())
                }
            }
            Err(e) => {
                if fresh {
                    self.stop_listen();
                }
                Err(e)
            }
        }
    }

    fn ensure_listen(&mut self, cli: &Cli) -> Result<()> {
        if self.listen.is_some() {
            return Ok(());
        }
        let mut dev = cli.open(cli.timeout_ms.max(12_000))?;
        let port = dev.port().to_string();
        dev.set_read_timeout(Duration::from_millis(LISTEN_MS))?;
        let dev = Arc::new(Mutex::new(dev));
        let stop = Arc::new(AtomicBool::new(false));
        let pause = Arc::new(AtomicBool::new(false));
        let d2 = Arc::clone(&dev);
        let s2 = Arc::clone(&stop);
        let p2 = Arc::clone(&pause);
        let tx = self.notes_tx.clone();
        let thread = std::thread::spawn(move || listen_loop(d2, s2, p2, tx));
        self.listen = Some(Listen {
            dev,
            port,
            stop,
            pause,
            thread: Some(thread),
        });
        Ok(())
    }

    fn run_gatt(&mut self, cli: &Cli, db: &DbOpts, action: &GattCmd) -> Result<()> {
        self.run_on_dev(crate::gatt_timeout(cli, action), |dev| {
            crate::gatt_on(cli, db, action, dev)
        })
    }

    fn run_on_dev(
        &mut self,
        timeout_ms: u64,
        f: impl FnOnce(&mut Device) -> Result<()>,
    ) -> Result<()> {
        let listen = self
            .listen
            .as_ref()
            .ok_or_else(|| anyhow!("not listening"))?;
        // Unlock the device before clearing pause, or the listener can steal the port.
        listen.pause.store(true, Ordering::SeqCst);
        let _unpause = Unpause(Arc::clone(&listen.pause));
        let mut dev = listen
            .dev
            .lock()
            .map_err(|_| anyhow!("device lock poisoned"))?;
        dev.set_read_timeout(Duration::from_millis(timeout_ms))?;
        let r = f(&mut dev);
        let _ = dev.set_read_timeout(Duration::from_millis(1));
        // Drain queued notifications until quiet so a stream cannot hold the prompt.
        for _ in 0..32 {
            match dev.poll_notification() {
                Ok(Some(n)) => println!("{}", notify_line(&n)),
                Err(infishark::Error::Json(e)) => {
                    println!("notify: {e}");
                    break;
                }
                _ => break,
            }
        }
        let _ = dev.set_read_timeout(Duration::from_millis(LISTEN_MS));
        r
    }

    fn stop_listen(&mut self) {
        let Some(mut l) = self.listen.take() else {
            return;
        };
        l.stop.store(true, Ordering::Relaxed);
        if let Some(t) = l.thread.take() {
            let _ = t.join();
        }
        if self.peripheral == Some("gatt") {
            self.peripheral = None;
        }
    }

    fn flush_notes(&mut self) {
        while let Ok(line) = self.notes_rx.try_recv() {
            println!("{line}");
        }
        if let Some(line) = self.account_update() {
            println!("{MARGIN}{}", style(line).dim());
        }
    }

    fn account_update(&mut self) -> Option<String> {
        let check = self.account_status.as_mut()?;
        let update = check.poll_update();
        if !check.is_pending() {
            self.account_status = None;
        }
        update
    }

    fn idle_until_key(&mut self) -> Result<()> {
        crossterm::terminal::enable_raw_mode()?;
        let label = self.label();
        paint_prompt(&label);
        loop {
            while let Ok(line) = self.notes_rx.try_recv() {
                paint_above(&label, &line);
            }
            if let Some(line) = self.account_update() {
                paint_above(&label, &style(line).dim().to_string());
            }
            if self.listen.is_none() && self.account_status.is_none() {
                erase_line();
                return Ok(());
            }
            #[cfg(unix)]
            let pending = stdin_pending(40);
            #[cfg(not(unix))]
            let pending =
                crossterm::event::poll(Duration::from_millis(40)).map_err(anyhow::Error::from);
            match pending {
                Ok(true) => {
                    erase_line();
                    // Leave raw mode on so reedline reads the key that woke us.
                    return Ok(());
                }
                Ok(false) => continue,
                Err(e) => {
                    let _ = crossterm::terminal::disable_raw_mode();
                    return Err(e);
                }
            }
        }
    }
}

fn notify_line(n: &GattNotification) -> String {
    let kind = if n.is_notify { "notify" } else { "indicate" };
    let id = brief_uuid(&n.characteristic);
    // Handle distinguishes two characteristics that share a UUID (HID Report).
    if n.handle == 0 {
        format!("[{kind}] {id}  {}", n.hex)
    } else {
        format!("[{kind}] {:#06x}  {id}  {}", n.handle, n.hex)
    }
}

fn brief_uuid(uuid: &str) -> String {
    let u = uuid.trim().to_ascii_lowercase();
    if let Some(body) = u.strip_suffix("-0000-1000-8000-00805f9b34fb") {
        if let Some(short) = body.strip_prefix("0000") {
            if short.len() == 4 && short.bytes().all(|b| b.is_ascii_hexdigit()) {
                return format!("0x{short}");
            }
        }
    }
    u
}

fn listen_loop(
    dev: Arc<Mutex<Device>>,
    stop: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    tx: SyncSender<String>,
) {
    while !stop.load(Ordering::Relaxed) {
        if pause.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }
        let line = {
            let Ok(mut d) = dev.lock() else {
                break;
            };
            // Recheck after the lock so a command is not stuck behind another read.
            if pause.load(Ordering::Acquire) || stop.load(Ordering::Relaxed) {
                None
            } else {
                match d.poll_notification() {
                    Ok(Some(n)) => Some(notify_line(&n)),
                    Ok(None) => None,
                    Err(infishark::Error::Timeout) | Err(infishark::Error::Interrupted) => None,
                    Err(infishark::Error::Json(e)) => Some(format!("notify: {e}")),
                    Err(e) => {
                        let _ = tx.try_send(format!("notify: {e}"));
                        break;
                    }
                }
            }
        };
        if let Some(line) = line {
            // A full queue drops the line. A blocking send would stall quit.
            let _ = tx.try_send(line);
        }
    }
}

#[cfg(unix)]
fn stdin_pending(timeout_ms: i32) -> Result<bool> {
    let mut fd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let rc = unsafe { libc::poll(&mut fd, 1, timeout_ms) };
        if rc >= 0 {
            return Ok(rc > 0);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err.into());
    }
}

fn paint_prompt(label: &str) {
    let mut out = std::io::stdout();
    let head = style(label).white();
    let ind = style("> ").dim();
    let _ = write!(out, "\r\x1b[2K{head}{ind}");
    let _ = out.flush();
}

fn paint_above(label: &str, line: &str) {
    let mut out = std::io::stdout();
    let _ = write!(out, "\r\x1b[2K{line}\r\n");
    let _ = out.flush();
    paint_prompt(label);
}

fn erase_line() {
    let mut out = std::io::stdout();
    let _ = write!(out, "\r\x1b[2K");
    let _ = out.flush();
}

fn stats(port: &str, id: &DeviceIdent) -> Option<String> {
    let s = Device::open(Some(port), 2000).ok()?.system_status().ok()?;
    let field = |k: &str| s.get(k).and_then(|v| v.as_u64());
    let mut parts = vec![format!("fw {}", id.version)];
    if let Some(b) = field("battery_pct") {
        parts.push(format!("batt {b}%"));
    }
    if let Some(h) = field("heap_free") {
        parts.push(format!("heap {}KB", h / 1024));
    }
    if let Some(u) = field("uptime_s") {
        parts.push(format!("up {}", fmt_uptime(u)));
    }
    if let Some(m) = s
        .get("mesh")
        .and_then(|m| m.get("enabled"))
        .and_then(|v| v.as_bool())
    {
        parts.push(format!("mesh {}", if m { "on" } else { "off" }));
    }
    Some(parts.join("  "))
}

fn resolve<'a>(root: &'a Command, path: &[String]) -> Option<&'a Command> {
    let mut cur = root;
    for name in path {
        cur = cur.find_subcommand(name)?;
    }
    Some(cur)
}

// Leading tokens that form a valid command path.
fn command_path(root: &Command, toks: &[String]) -> Vec<String> {
    let mut cur = root;
    let mut path = Vec::new();
    for t in toks {
        match cur.find_subcommand(t) {
            Some(sub) => {
                path.push(t.clone());
                cur = sub;
            }
            None => break,
        }
    }
    path
}

// One consistent help renderer for the whole tree: subcommands for a group,
// non-global options for a leaf.
fn render_help(cmd: &Command, path: &[String]) {
    if !path.is_empty() {
        if let Some(about) = cmd.get_about() {
            println!("{}\n", style(about.to_string()).white());
        }
    }
    let subs: Vec<&Command> = cmd
        .get_subcommands()
        .filter(|s| s.get_name() != "help")
        .collect();
    let kind = if subs.is_empty() {
        "options"
    } else {
        "commands"
    };
    if path.is_empty() {
        println!("{}", style(kind).bold());
    } else {
        println!(
            "{} {}",
            style(path.join(" ")).white().bold(),
            style(kind).bold()
        );
    }
    if subs.is_empty() {
        let args: Vec<&Arg> = cmd
            .get_arguments()
            .filter(|a| !a.is_global_set() && a.get_id() != "help")
            .collect();
        if args.is_empty() {
            println!("  {}", style("(no options)").dim());
            return;
        }
        let w = args.iter().map(|a| arg_label(a).len()).max().unwrap_or(8);
        for a in args {
            help_row(&arg_label(a), Some(arg_help(a)), w);
        }
    } else {
        let w = subs.iter().map(|s| s.get_name().len()).max().unwrap_or(8);
        for s in subs {
            help_row(s.get_name(), s.get_about().map(|a| a.to_string()), w);
        }
    }
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn is_quit(line: &str) -> bool {
    matches!(line, "exit" | "quit" | ":q" | ":q!")
}

/// A leading `!` runs the rest in the host shell; `Some("")` means a bare `!`.
fn host_command(line: &str) -> Option<&str> {
    line.strip_prefix('!').map(str::trim_start)
}

enum CdPlan {
    NotCd,
    Home,
    Path(String),
    RunShell,
}

fn cd_plan(cmd: &str) -> CdPlan {
    let Some(toks) = shlex::split(cmd) else {
        return CdPlan::RunShell;
    };
    if toks.first().map(String::as_str) != Some("cd") {
        return CdPlan::NotCd;
    }
    match toks.len() {
        1 => CdPlan::Home,
        2 => {
            let path = &toks[1];
            // `~user` is the shell's job. `~` and `~/...` stick via set_current_dir.
            if path.starts_with('~') && path != "~" && !path.starts_with("~/") {
                CdPlan::RunShell
            } else {
                CdPlan::Path(path.clone())
            }
        }
        _ => CdPlan::RunShell,
    }
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
}

fn expand_cd_path(raw: &str) -> Result<std::path::PathBuf, &'static str> {
    if raw == "~" {
        return home_dir().ok_or("home directory is not set");
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = home_dir().ok_or("home directory is not set")?;
        return Ok(home.join(rest));
    }
    Ok(std::path::PathBuf::from(raw))
}

fn apply_cd(path: Option<&str>) {
    let dest = match path {
        None => match home_dir() {
            Some(p) => p,
            None => {
                eprintln!("cd: home directory is not set");
                return;
            }
        },
        Some(raw) => match expand_cd_path(raw) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cd: {e}");
                return;
            }
        },
    };
    if let Err(e) = std::env::set_current_dir(&dest) {
        eprintln!("cd: {}: {e}", dest.display());
    }
}

fn run_host(cmd: &str) {
    if cmd.is_empty() {
        eprintln!("usage: !<command>");
        return;
    }
    match cd_plan(cmd) {
        CdPlan::Home => apply_cd(None),
        CdPlan::Path(path) => apply_cd(Some(&path)),
        CdPlan::NotCd | CdPlan::RunShell => spawn_sh(cmd),
    }
}

fn spawn_sh(cmd: &str) {
    RUNNING.store(true, Ordering::SeqCst);
    let result = std::process::Command::new(crate::privs::tool_path("sh"))
        .arg("-c")
        .arg(cmd)
        .status();
    // Reset RUNNING after child Ctrl-C so the next command does not stop
    // immediately.
    RUNNING.store(true, Ordering::SeqCst);
    if let Err(e) = result {
        eprintln!("failed to run: {e}");
    }
}

fn arg_label(a: &Arg) -> String {
    match a.get_long() {
        Some(l) => format!("--{l}"),
        None => format!("<{}>", a.get_id()),
    }
}

fn arg_help(a: &Arg) -> String {
    let mut s = a.get_help().map(|h| h.to_string()).unwrap_or_default();
    let vals: Vec<String> = a
        .get_possible_values()
        .into_iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| v.get_name().to_string())
        .collect();
    if !vals.is_empty() {
        let list = vals.join(", ");
        if s.is_empty() {
            s = format!("[{list}]");
        } else {
            s = format!("{s} [{list}]");
        }
    }
    s
}

fn help_row(name: &str, about: Option<String>, w: usize) {
    println!(
        "  {}  {}",
        style(format!("{name:<w$}")).white().bold(),
        style(about.unwrap_or_default()).dim()
    );
}

struct NanoPrompt(String);

impl Prompt for NanoPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Owned(self.0.clone())
    }
    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
    fn render_prompt_indicator(&self, _: PromptEditMode) -> Cow<'_, str> {
        Cow::Borrowed("> ")
    }
    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("... ")
    }
    fn render_prompt_history_search_indicator(&self, _: PromptHistorySearch) -> Cow<'_, str> {
        Cow::Borrowed("(search) ")
    }
    fn get_prompt_color(&self) -> Color {
        Color::White
    }
    fn get_indicator_color(&self) -> Color {
        Color::Grey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig_uuid_is_shown_short() {
        assert_eq!(brief_uuid("00002A19-0000-1000-8000-00805F9B34FB"), "0x2a19");
        assert_eq!(
            brief_uuid("deadbeef-1234-5678-9abc-000000000000"),
            "deadbeef-1234-5678-9abc-000000000000"
        );
    }

    #[test]
    fn notify_line_shows_the_handle_beside_a_shared_uuid() {
        let n = GattNotification {
            characteristic: "00002a4d-0000-1000-8000-00805f9b34fb".into(),
            handle: 24,
            is_notify: true,
            hex: "a1".into(),
        };
        assert_eq!(notify_line(&n), "[notify] 0x0018  0x2a4d  a1");
    }
    #[test]
    fn account_status_does_not_change_device_or_peripheral_prompts() {
        let (notes_tx, notes_rx) = sync_channel(1);
        let port = "/dev/fake-nano".to_string();
        let mut sh = Shell {
            devices: vec![PortEntry {
                name: port.clone(),
                kind: "USB".into(),
                vid: None,
                pid: None,
                serial_number: None,
                manufacturer: None,
                product: None,
                device: None,
            }],
            selected: Some(port),
            peripheral: None,
            listen: None,
            account_status: None,
            notes_tx,
            notes_rx,
        };
        assert_eq!(sh.label(), "nano0");
        sh.peripheral = Some("BLE");
        assert_eq!(sh.label(), "nano0 (BLE)");
        let prompt = NanoPrompt(sh.label());
        assert_eq!(prompt.render_prompt_left(), "nano0 (BLE)");
        assert_eq!(
            prompt.render_prompt_indicator(PromptEditMode::Default),
            "> "
        );
        sh.selected = None;
        sh.peripheral = None;
        assert_eq!(sh.label(), "infishark");
    }

    #[test]
    fn quit_lines() {
        assert!(is_quit("exit"));
        assert!(is_quit("quit"));
        assert!(is_quit(":q"));
        assert!(is_quit(":q!"));
        assert!(!is_quit(":wq"));
        assert!(!is_quit("q"));
        assert!(!is_quit("exit now"));
    }

    #[test]
    fn bang_strips_once() {
        assert_eq!(host_command("ls"), None);
        assert_eq!(host_command("!ls"), Some("ls"));
        assert_eq!(host_command("! ls -la"), Some("ls -la"));
        assert_eq!(host_command("!"), Some(""));
        assert_eq!(host_command("!   "), Some(""));
        assert_eq!(host_command("wifi !scan"), None);
    }

    #[test]
    fn cd_plan_cases() {
        assert!(matches!(cd_plan("ls"), CdPlan::NotCd));
        assert!(matches!(cd_plan("cd"), CdPlan::Home));
        assert!(matches!(cd_plan("cd /tmp"), CdPlan::Path(p) if p == "/tmp"));
        assert!(matches!(cd_plan("cd \"a b\""), CdPlan::Path(p) if p == "a b"));
        assert!(matches!(cd_plan("cd foo && ls"), CdPlan::RunShell));
        assert!(matches!(cd_plan("cd ~/x"), CdPlan::Path(p) if p == "~/x"));
        assert!(matches!(cd_plan("cd ~root"), CdPlan::RunShell));
        assert!(matches!(cd_plan("cd \"unclosed"), CdPlan::RunShell));
    }
}
