//! Interactive reedline shell over the command tree; one device per session.

use std::borrow::Cow;
use std::io::IsTerminal;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::{Arg, Command, CommandFactory, Parser};
use console::style;
use infishark::Device;
use reedline::{Color, Prompt, PromptEditMode, PromptHistorySearch, Reedline, Signal};

use crate::ports::{DeviceIdent, PortEntry};
use crate::signals::{RUNNING, install_sigint};
use crate::{Cli, dispatch, ports};

const SHARK: &str = include_str!("art/shark.txt");
const WORDMARK: &str = include_str!("art/wordmark.txt");
const MARGIN: &str = "   ";

// A rotating line under the banner: mostly useful tips, a little dry humor.
const TIPS: &[&str] = &[
    "tip: 'select N' switches device; '--port' still overrides per command.",
    "tip: add '--help' to any command to see its options.",
    "tip: bare 'wifi deauth' scans, then lets you pick targets.",
    "tip: 'wifi scan' and 'ble scan' share the same live table.",
    "the 'S' in IoT stands for security.",
    "security is like an airbag: ignored until the moment you need it.",
    "there are two kinds of networks: compromised, and not yet.",
    "a firewall is only as sharp as the rule someone forgot to write.",
];

pub fn run(base: &Cli) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("the interactive shell needs a terminal; run `infishark <command>` directly");
    }
    let mut sh = Shell::new();
    install_sigint();
    sh.banner(utf8_locale() && !base.no_banner);
    sh.repl()
}

fn utf8_locale() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"].iter().any(|k| {
        std::env::var(k)
            .map(|v| v.to_ascii_uppercase().replace('-', "").contains("UTF8"))
            .unwrap_or(false)
    })
}

fn tip() -> &'static str {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as usize)
        .unwrap_or(0);
    TIPS[n % TIPS.len()]
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

// Commands that grab host resources (tun, uinput/hidraw) and need root.
fn needs_sudo(line: &str) -> bool {
    let t: Vec<&str> = line.split_whitespace().collect();
    matches!(
        t.as_slice(),
        ["wifi", "adapter", ..] | ["ble", "hid", "bridge", ..]
    )
}

struct Shell {
    devices: Vec<PortEntry>,
    selected: Option<String>,
    peripheral: Option<&'static str>,
}

impl Shell {
    fn new() -> Self {
        let mut sh = Shell {
            devices: vec![],
            selected: None,
            peripheral: None,
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
        }
        if self.devices.is_empty() {
            println!("{MARGIN}{}", style("no Nano connected").dim());
        }
        println!();
        println!("{MARGIN}{}", style(tip()).dim());
        println!(
            "{MARGIN}{}   {}",
            style("https://docs.infishark.com").dim(),
            style("'help' for commands, 'exit' to quit").dim()
        );
        println!();
    }

    fn repl(&mut self) -> Result<()> {
        let mut editor = Reedline::create();
        loop {
            let prompt = NanoPrompt(self.label());
            match editor.read_line(&prompt) {
                Ok(Signal::Success(line)) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if matches!(line, "exit" | "quit") {
                        break;
                    }
                    if !self.builtin(line) {
                        self.exec(line);
                    }
                }
                Ok(Signal::CtrlC) => continue,
                Ok(Signal::CtrlD) => break,
                Err(e) => {
                    eprintln!("input error: {e}");
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
            "help" | "?" | "--help" | "-h" => self.help(),
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
            self.selected = Some(self.devices[i].name.clone());
        } else if self.index_of(arg).is_some() || port_exists(arg) {
            self.selected = Some(arg.to_string());
        } else {
            eprintln!("no such device '{arg}' (try 'ports' or 'select')");
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
            ["ble", "stop"] => self.peripheral = None,
            _ => {}
        }
    }

    fn exec(&mut self, line: &str) {
        let is_help = line
            .split_whitespace()
            .last()
            .map(|t| matches!(t, "--help" | "-h" | "help"))
            .unwrap_or(false);
        // Pipes/redirects and root commands run through the system shell.
        if !is_help {
            let sudo = needs_sudo(line);
            let piped = line.contains(['|', '>', '<']);
            if sudo && piped {
                eprintln!("a root command can't be piped");
                return;
            }
            if piped {
                self.run_external(line, false);
                return;
            }
            if sudo {
                self.run_external(line, true);
                return;
            }
        }

        let Some(toks) = shlex::split(line) else {
            eprintln!("unbalanced quotes");
            return;
        };
        let root = Cli::command();

        // Any help request renders in our own style, at any depth.
        if is_help {
            let path = &toks[..toks.len().saturating_sub(1)];
            match resolve(&root, path) {
                Some(cmd) => render_help(cmd, path),
                None => eprintln!("no such command"),
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
                    RUNNING.store(true, Ordering::SeqCst);
                    match dispatch(&cli, command) {
                        Ok(()) => self.track_peripheral(&path),
                        Err(e) => eprintln!("{}", style(format!("error: {e:#}")).red()),
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

    // Re-run through the system shell so pipes work and sudo can prompt.
    fn run_external(&self, line: &str, sudo: bool) {
        let Ok(exe) = std::env::current_exe() else {
            eprintln!("cannot locate the infishark binary");
            return;
        };
        let port = match &self.selected {
            Some(p) if !line.contains("--port") => format!("--port '{p}' "),
            _ => String::new(),
        };
        let prefix = if sudo { "sudo " } else { "" };
        let cmd = format!("{prefix}'{}' {port}{line}", exe.display());
        RUNNING.store(true, Ordering::SeqCst);
        if let Err(e) = std::process::Command::new("sh").arg("-c").arg(cmd).status() {
            eprintln!("failed to run: {e}");
        }
    }

    fn help(&self) {
        render_help(&Cli::command(), &[]);
        println!("{}", style("shell").bold());
        help_row("select", Some("switch active device (N | port)".into()), 6);
        help_row("clear", Some("clear the screen".into()), 6);
        help_row("exit", Some("leave the shell".into()), 6);
    }
}

// Best-effort live stats for a device (opens it briefly for `device status`).
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
            help_row(&arg_label(a), a.get_help().map(|h| h.to_string()), w);
        }
    } else {
        let w = subs.iter().map(|s| s.get_name().len()).max().unwrap_or(8);
        for s in subs {
            help_row(s.get_name(), s.get_about().map(|a| a.to_string()), w);
        }
    }
}

fn arg_label(a: &Arg) -> String {
    match a.get_long() {
        Some(l) => format!("--{l}"),
        None => format!("<{}>", a.get_id()),
    }
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
