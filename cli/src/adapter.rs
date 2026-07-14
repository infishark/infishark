//! run the device as a USB Wi-Fi adapter. The device joins a saved network and NAPTs the host's IP
//! traffic over a SLIP tunnel on the USB serial link. Currently, it is only implemented for Linux.
//! Other OSes are planned.

use anyhow::Result;
use infishark::{AdapterConfig, AdapterTarget, Device};

pub struct AdapterOpts {
    pub ifname: String,
    pub mtu: u32,
    pub mss: u32,
    pub route_all: bool,
    pub no_oled: bool,
}

pub fn run(
    dev: Device,
    target: AdapterTarget,
    config: AdapterConfig,
    opts: AdapterOpts,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run(dev, target, config, opts)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dev, target, config, opts);
        anyhow::bail!("`wifi adapter` supports Linux only for now (needs a tun device)")
    }
}

// SLIP framing - check https://www.rfc-editor.org/info/rfc1055/
const SLIP_END: u8 = 0xC0;
const SLIP_ESC: u8 = 0xDB;
const SLIP_ESC_END: u8 = 0xDC;
const SLIP_ESC_ESC: u8 = 0xDD;

// Device control opcodes on the SLIP channel (stop, OLED toggle).
const CTRL_MAGIC: u8 = 0xB5;
const CTRL_STOP: u8 = 0x00;
const CTRL_OLED: u8 = 0x01;

fn slip_encode(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.push(SLIP_END);
    for &b in payload {
        match b {
            SLIP_END => out.extend_from_slice(&[SLIP_ESC, SLIP_ESC_END]),
            SLIP_ESC => out.extend_from_slice(&[SLIP_ESC, SLIP_ESC_ESC]),
            _ => out.push(b),
        }
    }
    out.push(SLIP_END);
    out
}

/// Incremental SLIP decoder: bytes arrive split across serial reads, so state (partial frame +
/// pending escape) persists between feeds.
struct SlipDecoder {
    buf: Vec<u8>,
    esc: bool,
}

impl SlipDecoder {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(2048),
            esc: false,
        }
    }

    /// Feed raw bytes; call `on_frame` for each completed (un-escaped) frame.
    fn feed(&mut self, data: &[u8], mut on_frame: impl FnMut(&[u8])) {
        for &b in data {
            if self.esc {
                self.esc = false;
                match b {
                    SLIP_ESC_END => self.buf.push(SLIP_END),
                    SLIP_ESC_ESC => self.buf.push(SLIP_ESC),
                    other => self.buf.push(other), // invalid escape sequence; keep the byte
                }
                continue;
            }
            match b {
                SLIP_END => {
                    if !self.buf.is_empty() {
                        on_frame(&self.buf);
                        self.buf.clear();
                    }
                }
                SLIP_ESC => self.esc = true,
                _ => self.buf.push(b),
            }
            if self.buf.len() > 4096 {
                self.buf.clear(); // runaway guard: never seen for MTU 1400
                self.esc = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(chunks: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut dec = SlipDecoder::new();
        let mut frames = Vec::new();
        for c in chunks {
            dec.feed(c, |f| frames.push(f.to_vec()));
        }
        frames
    }

    #[test]
    fn encode_escapes_end_and_esc() {
        // END and ESC in the payload must be escaped; framed by END delimiters.
        assert_eq!(
            slip_encode(&[0x01, SLIP_END, SLIP_ESC, 0x02]),
            vec![
                SLIP_END,
                0x01,
                SLIP_ESC,
                SLIP_ESC_END,
                SLIP_ESC,
                SLIP_ESC_ESC,
                0x02,
                SLIP_END
            ]
        );
    }

    #[test]
    fn roundtrip_recovers_the_payload() {
        let pkt: Vec<u8> = (0u16..600).map(|i| (i & 0xff) as u8).collect(); // spans 0xC0/0xDB
        let frames = decode_all(&[&slip_encode(&pkt)]);
        assert_eq!(frames, vec![pkt]);
    }

    #[test]
    fn decoder_reassembles_a_frame_split_across_reads() {
        let wire = slip_encode(&[0x45, 0x00, SLIP_END, SLIP_ESC, 0x99]);
        let (a, b) = wire.split_at(3);
        assert_eq!(
            decode_all(&[a, b]),
            vec![vec![0x45, 0x00, SLIP_END, SLIP_ESC, 0x99]]
        );
    }

    #[test]
    fn decoder_yields_two_back_to_back_frames_and_skips_empties() {
        let mut wire = slip_encode(&[0xB5, 0x00]); // control frame
        wire.push(SLIP_END); // stray delimiter -> no empty frame emitted
        wire.extend(slip_encode(&[0x45, 0x11]));
        assert_eq!(
            decode_all(&[&wire]),
            vec![vec![0xB5, 0x00], vec![0x45, 0x11]]
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use infishark::Device;
    use serialport::SerialPort;

    use crate::signals::{RUNNING, install_sigint};

    use super::{
        AdapterConfig, AdapterOpts, AdapterTarget, CTRL_MAGIC, CTRL_OLED, CTRL_STOP, SlipDecoder,
        slip_encode,
    };

    // Host end of the /30; the device's slip netif is 192.168.7.1.
    const HOST_CIDR: &str = "192.168.7.2/30";
    const DEVICE_GW: &str = "192.168.7.1";

    pub fn run(
        mut dev: Device,
        target: AdapterTarget,
        config: AdapterConfig,
        opts: AdapterOpts,
    ) -> Result<()> {
        eprintln!("Starting adapter on {target} (BLE goes down while active)...");
        let up = dev.wifi_adapter_start(target, &config)?;
        if let Some(ip) = up.get("sta_ip").and_then(|v| v.as_str()) {
            eprintln!("Device associated (STA {ip}). Tunnel is live.");
        }
        let port = dev.into_port();
        pump(port, opts)
    }

    fn pump(port: Box<dyn SerialPort>, opts: AdapterOpts) -> Result<()> {
        let (tun_read, ifname) = open_tun(&opts.ifname)?;
        let tun_write = tun_read.try_clone().context("cloning tun fd")?;

        setup_iface(&ifname, opts.mtu)?;
        add_mss_clamp(&ifname, opts.mss)?;
        let saved_default = if opts.route_all {
            let saved = current_default();
            set_default_route(&ifname)?;
            eprintln!(
                "Routing all traffic through {ifname}. (DNS: if your resolver was on the old LAN, set a public one.)"
            );
            saved
        } else {
            eprintln!(
                "Interface {ifname} is up. To route traffic through it:\n  sudo ip route add <dest> via {DEVICE_GW} dev {ifname}\nor re-run with --route-all."
            );
            None
        };

        install_sigint();

        // Serial writer is shared (tun pump, Ctrl-C stop, OLED toggle); the mutex keeps SLIP frames from interleaving on the wire.
        let reader = port.try_clone().context("cloning serial port")?;
        let writer = Arc::new(Mutex::new(port));

        let t_out = spawn_tun_to_serial(tun_read, Arc::clone(&writer));
        let t_in = spawn_serial_to_tun(reader, tun_write);

        let saved_tty = enable_raw_stdin();
        let mut oled_on = !opts.no_oled;
        if opts.no_oled {
            send_oled(&writer, false);
        }
        if saved_tty.is_some() {
            eprintln!("Adapter running. [d] toggles the device screen, Ctrl-C stops.");
        } else {
            eprintln!("Adapter running. Ctrl-C stops.");
        }

        while RUNNING.load(Ordering::SeqCst) {
            if saved_tty.is_some() && stdin_ready(150) {
                let mut b = [0u8; 1];
                let nr = unsafe { libc::read(0, b.as_mut_ptr() as *mut libc::c_void, 1) };
                if nr == 1 && (b[0] == b'd' || b[0] == b'D') {
                    oled_on = !oled_on;
                    send_oled(&writer, oled_on);
                    eprintln!("device screen {}", if oled_on { "on" } else { "off" });
                }
            } else if saved_tty.is_none() {
                std::thread::sleep(Duration::from_millis(150));
            }
        }
        restore_stdin(&saved_tty);

        // Best-effort clean teardown: tell the device to stop
        eprintln!("\nStopping adapter...");
        if let Ok(mut w) = writer.lock() {
            let _ = w.write_all(&slip_encode(&[CTRL_MAGIC, CTRL_STOP]));
            let _ = w.flush();
        }
        std::thread::sleep(Duration::from_millis(150));
        restore_default(&saved_default);
        del_mss_clamp(&ifname, opts.mss);
        drop(t_out);
        drop(t_in);
        Ok(())
    }

    fn spawn_tun_to_serial(
        mut tun: std::fs::File,
        writer: Arc<Mutex<Box<dyn SerialPort>>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while RUNNING.load(Ordering::SeqCst) {
                match tun.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let frame = slip_encode(&buf[..n]);
                        if let Ok(mut w) = writer.lock() {
                            if w.write_all(&frame).and_then(|_| w.flush()).is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            RUNNING.store(false, Ordering::SeqCst);
        })
    }

    fn spawn_serial_to_tun(
        mut reader: Box<dyn SerialPort>,
        mut tun: std::fs::File,
    ) -> std::thread::JoinHandle<()> {
        // Short read timeout so the loop can notice a Ctrl-C between frames.
        let _ = reader.set_timeout(Duration::from_millis(250));
        std::thread::spawn(move || {
            let mut dec = SlipDecoder::new();
            let mut buf = [0u8; 2048];
            while RUNNING.load(Ordering::SeqCst) {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut err = false;
                        dec.feed(&buf[..n], |pkt| {
                            if tun.write_all(pkt).is_err() {
                                err = true;
                            }
                        });
                        if err {
                            break;
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(_) => break,
                }
            }
            RUNNING.store(false, Ordering::SeqCst);
        })
    }

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x400454ca; // _IOW('T', 202, int)

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    /// Create a tun interface. Non-persistent, so closing the fd (at exit) also
    /// removes the interface and its addresses/routes.
    fn open_tun(name: &str) -> Result<(std::fs::File, String)> {
        if name.len() >= libc::IFNAMSIZ {
            bail!("interface name '{name}' too long");
        }
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("opening /dev/net/tun (needs root / CAP_NET_ADMIN)");
        }
        let mut req: IfReq = unsafe { std::mem::zeroed() };
        for (dst, &b) in req.name.iter_mut().zip(name.as_bytes()) {
            *dst = b as libc::c_char;
        }
        req.flags = IFF_TUN | IFF_NO_PI;
        let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &mut req) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e).with_context(|| format!("TUNSETIFF on {name}"));
        }
        let actual: String = req
            .name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok((file, actual))
    }

    fn send_oled(writer: &Arc<Mutex<Box<dyn SerialPort>>>, on: bool) {
        if let Ok(mut w) = writer.lock() {
            let _ = w.write_all(&slip_encode(&[CTRL_MAGIC, CTRL_OLED, on as u8]));
            let _ = w.flush();
        }
    }

    // Put stdin into cbreak mode (single keypresses, no echo) but keep ISIG so our Ctrl-C still
    // works.
    fn enable_raw_stdin() -> Option<libc::termios> {
        unsafe {
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut orig) != 0 {
                return None;
            }
            let mut raw = orig;
            raw.c_lflag &= !(libc::ICANON | libc::ECHO);
            libc::tcsetattr(0, libc::TCSANOW, &raw);
            Some(orig)
        }
    }

    fn restore_stdin(saved: &Option<libc::termios>) {
        if let Some(orig) = saved {
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, orig);
            }
        }
    }

    fn stdin_ready(timeout_ms: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) > 0 && (pfd.revents & libc::POLLIN) != 0 }
    }

    fn setup_iface(ifname: &str, mtu: u32) -> Result<()> {
        run_cmd("ip", &["addr", "add", HOST_CIDR, "dev", ifname])?;
        run_cmd(
            "ip",
            &["link", "set", ifname, "mtu", &mtu.to_string(), "up"],
        )
    }

    // Clamp advertised TCP MSS on SYNs leaving the tunnel; otherwise PMTUD blackholes silently drop oversized packets. Applied on the interface, independent of routes.
    fn mss_clamp_args<'a>(op: &'a str, ifname: &'a str, mss: &'a str) -> [&'a str; 15] {
        [
            "-t",
            "mangle",
            op,
            "POSTROUTING",
            "-o",
            ifname,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--set-mss",
            mss,
        ]
    }

    fn add_mss_clamp(ifname: &str, mss: u32) -> Result<()> {
        run_cmd("iptables", &mss_clamp_args("-A", ifname, &mss.to_string()))
    }

    fn del_mss_clamp(ifname: &str, mss: u32) {
        let _ = run_cmd("iptables", &mss_clamp_args("-D", ifname, &mss.to_string()));
    }

    fn current_default() -> Option<String> {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
    }

    fn set_default_route(ifname: &str) -> Result<()> {
        run_cmd(
            "ip",
            &[
                "route", "replace", "default", "via", DEVICE_GW, "dev", ifname,
            ],
        )
    }

    fn restore_default(saved: &Option<String>) {
        if let Some(line) = saved {
            let mut args = vec!["route", "replace"];
            args.extend(line.split_whitespace());
            let _ = run_cmd("ip", &args);
        }
    }

    fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
        eprintln!("+ {prog} {}", args.join(" "));
        let status = std::process::Command::new(prog)
            .args(args)
            .status()
            .with_context(|| format!("running `{prog}` (is it installed / are you root?)"))?;
        if !status.success() {
            bail!("`{prog} {}` failed ({status})", args.join(" "));
        }
        Ok(())
    }
}
