//! ble hid bridge: grab host HID inputs (keyboard / mouse / gamepad / tablet /
//! system control), merge them into one composite BLE HID device, and stream
//! reports to whatever is paired to the Nano so the host drives a remote device
//! over BLE. Exclusive grab (the host stops seeing the input) with a
//! configurable release hotkey. Linux only (evdev; needs /dev/input access).
//! But other platforms are WIP.

use anyhow::Result;
use infishark::Device;

pub struct BridgeOpts {
    pub release: String,
    pub devices: Vec<String>,
    pub all: bool,
    pub no_start: bool,
}

pub fn run(dev: Device, opts: BridgeOpts) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run(dev, opts)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dev, opts);
        anyhow::bail!("`ble hid bridge` supports Linux only for now (needs evdev)")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::BridgeOpts;
    use crate::hid::{HidClass, input_report};
    use crate::signals::{RUNNING, install_sigint};
    use anyhow::{Context, Result, bail};
    use infishark::Device;
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    // ioctl(fd, EVIOCGRAB, 1|0): claim/release exclusive access to a device.
    const EVIOCGRAB: libc::c_ulong = 0x4004_4590;
    // EVIOCGABS(axis) = 0x80184540 + axis: read an absolute axis' min/max.
    const EVIOCGABS_BASE: libc::c_ulong = 0x8018_4540;
    const EVIOCGABS_MT_X: libc::c_ulong = 0x8018_4575; // ABS_MT_POSITION_X (0x35)
    const EVIOCGABS_MT_Y: libc::c_ulong = 0x8018_4576; // ABS_MT_POSITION_Y (0x36)

    const EV_SYN: u16 = 0x00;
    const EV_KEY: u16 = 0x01;
    const EV_REL: u16 = 0x02;
    const EV_ABS: u16 = 0x03;
    const REL_X: u16 = 0x00;
    const REL_Y: u16 = 0x01;
    const REL_WHEEL: u16 = 0x08;
    const ABS_X: u16 = 0x00;
    const ABS_Y: u16 = 0x01;
    const ABS_MT_SLOT: u16 = 0x2f;
    const ABS_MT_POSITION_X: u16 = 0x35;
    const ABS_MT_POSITION_Y: u16 = 0x36;
    const ABS_MT_TRACKING_ID: u16 = 0x39; // -1 = finger up, >=0 = finger down
    const BTN_LEFT: u16 = 0x110;
    const BTN_RIGHT: u16 = 0x111;
    const BTN_MIDDLE: u16 = 0x112;
    const BTN_TOUCH: u16 = 0x14a;
    const BTN_TOOL_DOUBLETAP: u16 = 0x14d; // two fingers on the pad = scroll
    const BTN_JOYSTICK: u16 = 0x120; // BTN_TRIGGER
    const BTN_GAMEPAD_LO: u16 = 0x130; // BTN_SOUTH .. BTN_THUMBR
    const BTN_GAMEPAD_HI: u16 = 0x13f;
    const BTN_TOOL_FINGER: u16 = 0x145; // present on touchpads
    const BTN_TOOL_PEN: u16 = 0x140; // present on pen digitizers
    const KEY_A: u16 = 30;
    const KEY_Z: u16 = 44;
    const KEY_POWER: u16 = 116;
    const KEY_SLEEP: u16 = 142;
    const KEY_WAKEUP: u16 = 143;
    const EVENT_SIZE: usize = 24; // struct input_event on 64-bit: timeval(16)+type+code+value

    // ioctl request builder for the EVIOCG* reads (direction READ, type 'E').
    const IOC_READ: libc::c_ulong = 2;
    fn ioc(typ: u8, nr: u8, size: usize) -> libc::c_ulong {
        (IOC_READ << 30)
            | ((size as libc::c_ulong) << 16)
            | ((typ as libc::c_ulong) << 8)
            | nr as libc::c_ulong
    }

    fn abs_minmax(fd: RawFd, req: libc::c_ulong) -> Option<(i32, i32)> {
        let mut info = [0i32; 6]; // value, min, max, fuzz, flat, resolution
        if unsafe { libc::ioctl(fd, req, info.as_mut_ptr()) } < 0 {
            return None;
        }
        (info[2] > info[1]).then_some((info[1], info[2]))
    }

    // Read the supported-code bitmap for event type ev (EVIOCGBIT).
    fn eviocgbit(fd: RawFd, ev: u16, buf: &mut [u8]) {
        let req = ioc(b'E', 0x20 + ev as u8, buf.len());
        unsafe { libc::ioctl(fd, req, buf.as_mut_ptr()) };
    }

    fn has_bit(buf: &[u8], bit: usize) -> bool {
        buf.get(bit / 8).is_some_and(|b| b & (1 << (bit % 8)) != 0)
    }

    fn device_name(fd: RawFd) -> String {
        let mut buf = [0u8; 256];
        let r = unsafe { libc::ioctl(fd, ioc(b'E', 0x06, buf.len()), buf.as_mut_ptr()) };
        if r <= 0 {
            return String::new();
        }
        let n = (r as usize).min(buf.len()).saturating_sub(1);
        String::from_utf8_lossy(&buf[..n])
            .trim_end_matches('\0')
            .to_string()
    }

    fn classify_fd(fd: RawFd) -> Option<InputKind> {
        let mut evbits = [0u8; 4]; // EV_CNT = 0x20
        eviocgbit(fd, 0, &mut evbits);
        let has_rel = has_bit(&evbits, EV_REL as usize);
        let has_abs = has_bit(&evbits, EV_ABS as usize);

        let mut keys = [0u8; 96]; // KEY_CNT = 0x300
        if has_bit(&evbits, EV_KEY as usize) {
            eviocgbit(fd, EV_KEY, &mut keys);
        }
        let key = |b: u16| has_bit(&keys, b as usize);

        if has_abs && key(BTN_GAMEPAD_LO) {
            Some(InputKind::Gamepad)
        } else if has_abs && key(BTN_JOYSTICK) {
            Some(InputKind::Joystick)
        } else if has_abs && key(BTN_TOOL_PEN) {
            Some(InputKind::Tablet)
        } else if has_abs && key(BTN_TOOL_FINGER) {
            Some(InputKind::Touchpad)
        } else if has_rel && key(BTN_LEFT) {
            Some(InputKind::Mouse)
        } else if key(KEY_A) && key(KEY_Z) {
            Some(InputKind::Keyboard)
        } else if key(KEY_POWER) || key(KEY_SLEEP) || key(KEY_WAKEUP) {
            // After the keyboard check: a full keyboard also carries these keys.
            Some(InputKind::System)
        } else {
            None
        }
    }

    #[derive(Clone)]
    struct InputDev {
        path: String,
        name: String,
        kind: InputKind,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum InputKind {
        Keyboard,
        Mouse,
        Touchpad,
        Gamepad,
        Joystick,
        Tablet,
        System,
    }

    impl InputKind {
        fn label(self) -> &'static str {
            match self {
                InputKind::Keyboard => "keyboard",
                InputKind::Mouse => "mouse",
                InputKind::Touchpad => "touchpad",
                InputKind::Gamepad => "gamepad",
                InputKind::Joystick => "joystick",
                InputKind::Tablet => "tablet",
                InputKind::System => "system",
            }
        }
        fn class(self) -> HidClass {
            match self {
                InputKind::Keyboard => HidClass::Keyboard,
                InputKind::Mouse | InputKind::Touchpad => HidClass::Mouse,
                InputKind::Gamepad | InputKind::Joystick => HidClass::Gamepad,
                InputKind::Tablet => HidClass::Tablet,
                InputKind::System => HidClass::System,
            }
        }
    }

    struct Grab {
        file: fs::File,
        class: HidClass,
    }

    impl Drop for Grab {
        fn drop(&mut self) {
            unsafe { libc::ioctl(self.file.as_raw_fd(), EVIOCGRAB, 0) };
        }
    }

    pub fn run(mut dev: Device, opts: BridgeOpts) -> Result<()> {
        let hotkey = parse_hotkey(&opts.release)?;
        let selected = resolve_devices(&opts)?;

        let mut grabs: Vec<Grab> = Vec::new();
        for d in &selected {
            let file = fs::OpenOptions::new()
                .read(true)
                .open(&d.path)
                .with_context(|| format!("opening {} (need root?)", d.path))?;
            grabs.push(Grab {
                file,
                class: d.kind.class(),
            });
        }

        // wait until every key is released before grabbing
        let fds: Vec<RawFd> = grabs.iter().map(|g| g.file.as_raw_fd()).collect();
        wait_all_keys_up(&fds);

        let mut tp_range: Option<(i32, i32)> = None; // touchpad ABS X/Y span
        for (g, d) in grabs.iter().zip(&selected) {
            let fd = g.file.as_raw_fd();
            if unsafe { libc::ioctl(fd, EVIOCGRAB, 1) } != 0 {
                bail!("failed to grab {} (another process holding it?)", d.path);
            }
            if d.kind == InputKind::Touchpad {
                let rx = abs_minmax(fd, EVIOCGABS_BASE + ABS_X as libc::c_ulong)
                    .or_else(|| abs_minmax(fd, EVIOCGABS_MT_X));
                let ry = abs_minmax(fd, EVIOCGABS_BASE + ABS_Y as libc::c_ulong)
                    .or_else(|| abs_minmax(fd, EVIOCGABS_MT_Y));
                if let (Some((_, mx)), Some((_, my))) = (rx, ry) {
                    tp_range = Some((mx, my));
                }
            }
            eprintln!("grabbed {}  [{}]  {}", d.path, d.kind.label(), d.name);
        }

        // Which classes are active decides the composite map + report IDs
        let classes: Vec<HidClass> = selected.iter().map(|d| d.kind.class()).collect();
        let assigned = crate::hid::assign(&classes);
        let id_of = |c: HidClass| assigned.iter().find(|(x, _)| *x == c).map(|(_, id)| *id);

        if !opts.no_start {
            let (map, reports, appearance) = crate::hid::composite(&classes);
            let spec = serde_json::json!({
                "report_map": map, "reports": reports, "appearance": appearance,
            });
            dev.ble_hid_start(&spec)?;
        }

        let mut kb = KeyboardState::new(id_of(HidClass::Keyboard).unwrap_or(1));
        let mut ms = MouseState::new(id_of(HidClass::Mouse).unwrap_or(2), tp_range);
        let mut gp = GamepadState::new(id_of(HidClass::Gamepad).unwrap_or(3), &grabs);
        let mut tb = TabletState::new(id_of(HidClass::Tablet).unwrap_or(4), &grabs);
        let mut sy = SystemState::new(id_of(HidClass::System).unwrap_or(5));
        let has_kbd = id_of(HidClass::Keyboard).is_some();
        let has_mouse = id_of(HidClass::Mouse).is_some();
        let has_gp = id_of(HidClass::Gamepad).is_some();
        let has_tablet = id_of(HidClass::Tablet).is_some();
        let has_system = id_of(HidClass::System).is_some();

        eprintln!(
            "Bridging {} -> BLE HID. Release with [{}] (or Ctrl-C).",
            assigned
                .iter()
                .map(|(c, _)| c.label())
                .collect::<Vec<_>>()
                .join("+"),
            opts.release
        );

        let mut pressed: BTreeSet<u16> = BTreeSet::new();
        let mut pollfds: Vec<libc::pollfd> = grabs
            .iter()
            .map(|g| libc::pollfd {
                fd: g.file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let mut buf = [0u8; EVENT_SIZE * 64];

        install_sigint();
        'ev: loop {
            if !RUNNING.load(Ordering::SeqCst) {
                break 'ev;
            }
            let n = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 200) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            if n == 0 {
                if has_mouse {
                    ms.flush(&mut dev, true)?; // idle tick: emit any pending motion
                }
                continue;
            }
            for i in 0..pollfds.len() {
                if pollfds[i].revents & libc::POLLIN == 0 {
                    continue;
                }
                let src = grabs[i].class;
                let read = unsafe {
                    libc::read(
                        pollfds[i].fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if read <= 0 {
                    continue;
                }
                for ev in buf[..read as usize].chunks_exact(EVENT_SIZE) {
                    let etype = u16::from_ne_bytes([ev[16], ev[17]]);
                    let code = u16::from_ne_bytes([ev[18], ev[19]]);
                    let value = i32::from_ne_bytes([ev[20], ev[21], ev[22], ev[23]]);
                    match etype {
                        EV_KEY
                            if src == HidClass::Mouse
                                && (BTN_LEFT..=BTN_MIDDLE).contains(&code)
                                && has_mouse =>
                        {
                            ms.button(code, value != 0);
                        }
                        EV_KEY if src == HidClass::Mouse && code == BTN_TOUCH && has_mouse => {
                            ms.touch(value != 0)
                        }
                        EV_KEY
                            if src == HidClass::Mouse
                                && code == BTN_TOOL_DOUBLETAP
                                && has_mouse =>
                        {
                            ms.two_finger(value != 0);
                        }
                        EV_KEY
                            if src == HidClass::Gamepad
                                && (BTN_GAMEPAD_LO..=BTN_GAMEPAD_HI).contains(&code)
                                && has_gp =>
                        {
                            gp.button(code, value != 0);
                        }
                        EV_KEY
                            if src == HidClass::Tablet
                                && (code == BTN_TOUCH || code == BTN_TOOL_PEN)
                                && has_tablet =>
                        {
                            tb.key(code, value != 0);
                        }
                        EV_KEY
                            if src == HidClass::System
                                && matches!(code, KEY_POWER | KEY_SLEEP | KEY_WAKEUP)
                                && has_system =>
                        {
                            sy.key(code, value != 0);
                        }
                        EV_KEY => {
                            if value == 1 {
                                pressed.insert(code);
                                if hotkey.iter().all(|k| pressed.contains(k)) {
                                    break 'ev;
                                }
                            } else if value == 0 {
                                pressed.remove(&code);
                            }
                            if has_kbd && value != 2 && kb.apply(code, value == 1) {
                                dev.ble_hid_send(&kb.report_json())?;
                            }
                        }
                        EV_REL if src == HidClass::Mouse && has_mouse => ms.rel(code, value),
                        EV_ABS if src == HidClass::Gamepad && has_gp => gp.axis(code, value),
                        EV_ABS if src == HidClass::Tablet && has_tablet => tb.abs(code, value),
                        EV_ABS if src == HidClass::Mouse && has_mouse => ms.abs(code, value),
                        EV_SYN if code == 0 => match src {
                            HidClass::Gamepad if has_gp => gp.flush(&mut dev)?,
                            HidClass::Tablet if has_tablet => tb.flush(&mut dev)?,
                            HidClass::System if has_system => sy.flush(&mut dev)?,
                            _ if has_mouse => {
                                ms.apply_touch();
                                ms.flush(&mut dev, false)?;
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }
        // Reached on the release hotkey or Ctrl-C: leave nothing held on the central.
        if has_kbd {
            dev.ble_hid_send(&kb.release_json())?;
        }
        if has_mouse {
            dev.ble_hid_send(&ms.release_json())?;
        }
        if has_gp {
            dev.ble_hid_send(&gp.release_json())?;
        }
        if has_tablet {
            dev.ble_hid_send(&tb.release_json())?;
        }
        if has_system {
            dev.ble_hid_send(&sy.release_json())?;
        }
        Ok(())
    }

    fn any_key_down(fd: RawFd) -> bool {
        let mut keys = [0u8; 96]; // KEY_CNT (0x300) / 8
        let req = ioc(b'E', 0x18, keys.len()); // EVIOCGKEY
        if unsafe { libc::ioctl(fd, req, keys.as_mut_ptr()) } < 0 {
            return false;
        }
        keys.iter().any(|&b| b != 0)
    }

    fn wait_all_keys_up(fds: &[RawFd]) {
        let deadline = Instant::now() + Duration::from_millis(3000);
        while fds.iter().any(|&fd| any_key_down(fd)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(30));
        }
        std::thread::sleep(Duration::from_millis(50)); // let the compositor process the ups
    }

    fn resolve_devices(opts: &BridgeOpts) -> Result<Vec<InputDev>> {
        let detected = detect_inputs()?;
        if !opts.devices.is_empty() {
            return opts
                .devices
                .iter()
                .map(|tok| resolve_one(&detected, tok))
                .collect();
        }
        if detected.is_empty() {
            bail!("no supported input devices found");
        }
        // "all" (the flag or typed at the prompt) grabs every input except the power
        // button, which would swallow the host's own power key. It stays
        // explicitly selectable by number.
        let grab_all = || -> Vec<InputDev> {
            detected
                .iter()
                .filter(|d| d.kind != InputKind::System)
                .cloned()
                .collect()
        };
        if opts.all {
            return Ok(grab_all());
        }
        eprintln!("Detected HID inputs:");
        for (i, d) in detected.iter().enumerate() {
            eprintln!("  [{i}] {:9} {}", d.kind.label(), d.name);
        }
        let line = crate::ui::prompt_line("Pick inputs to bridge (comma-separated, or 'all'): ")?;
        let t = line.trim();
        if t.eq_ignore_ascii_case("all") {
            return Ok(grab_all());
        }
        let mut out = Vec::new();
        for tok in t.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            out.push(crate::ui::parse_index(&detected, tok)?.clone());
        }
        if out.is_empty() {
            bail!("no inputs selected");
        }
        Ok(out)
    }

    // Resolve one --device token: a picker number, an exact /dev/input/eventN path,
    // or a case-insensitive name/label substring.
    fn resolve_one(detected: &[InputDev], tok: &str) -> Result<InputDev> {
        if let Ok(i) = tok.parse::<usize>() {
            if let Some(d) = detected.get(i) {
                return Ok(d.clone());
            }
        }
        if let Some(d) = detected.iter().find(|d| d.path == *tok) {
            return Ok(d.clone());
        }
        let needle = tok.to_ascii_lowercase();
        let mut hits = detected.iter().filter(|d| {
            d.name.to_ascii_lowercase().contains(needle.as_str())
                || d.kind.label().contains(needle.as_str())
        });
        match (hits.next(), hits.next()) {
            (Some(d), None) => Ok(d.clone()),
            (Some(_), Some(_)) => {
                bail!(
                    "--device {tok:?} matches more than one device; use its number or /dev/input/eventN path"
                )
            }
            (None, _) => bail!(
                "{tok:?} is not a recognized input device (use its number, name, or /dev/input/eventN path)"
            ),
        }
    }

    // Classify each /dev/input/event*; unrecognized nodes (power buttons, etc.) are
    // skipped.
    fn detect_inputs() -> Result<Vec<InputDev>> {
        let mut paths: Vec<String> = fs::read_dir("/dev/input")
            .context("reading /dev/input")?
            .flatten()
            .filter_map(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with("event").then(|| format!("/dev/input/{n}"))
            })
            .collect();
        paths.sort_by_key(|p| {
            p.rsplit("event")
                .next()
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or(0)
        });
        let mut out = Vec::new();
        for path in paths {
            let Ok(file) = fs::OpenOptions::new().read(true).open(&path) else {
                continue;
            };
            let fd = file.as_raw_fd();
            let Some(kind) = classify_fd(fd) else {
                continue;
            };
            out.push(InputDev {
                path,
                name: device_name(fd),
                kind,
            });
        }
        Ok(out)
    }

    struct KeyboardState {
        id: u8,
        modifiers: u8,
        keys: Vec<u8>, // HID usages currently down (non-modifier), max 6
    }

    impl KeyboardState {
        fn new(id: u8) -> Self {
            Self {
                id,
                modifiers: 0,
                keys: Vec::new(),
            }
        }
        fn apply(&mut self, code: u16, down: bool) -> bool {
            if let Some(bit) = linux_modifier_bit(code) {
                let before = self.modifiers;
                if down {
                    self.modifiers |= bit;
                } else {
                    self.modifiers &= !bit;
                }
                return self.modifiers != before;
            }
            let Some(usage) = linux_to_hid_usage(code) else {
                return false;
            };
            if down {
                if self.keys.contains(&usage) || self.keys.len() >= 6 {
                    return false;
                }
                self.keys.push(usage);
            } else if let Some(pos) = self.keys.iter().position(|&u| u == usage) {
                self.keys.remove(pos);
            } else {
                return false;
            }
            true
        }

        fn report_json(&self) -> serde_json::Value {
            let mut r = [0u8; 8];
            r[0] = self.modifiers;
            for (i, &u) in self.keys.iter().take(6).enumerate() {
                r[2 + i] = u;
            }
            input_report(self.id, &r)
        }

        fn release_json(&self) -> serde_json::Value {
            input_report(self.id, &[0u8; 8])
        }
    }

    struct MouseState {
        id: u8,
        buttons: u8,
        dx: i32,
        dy: i32,
        wheel: i32,
        last_sent_buttons: u8,
        last_flush: Instant,
        // Touchpad (EV_ABS) -> relative motion. tp_range = pad's (X,Y) span.
        tp_range: Option<(i32, i32)>,
        tp_x: i32,
        tp_y: i32,
        tp_last_x: i32,
        tp_last_y: i32,
        tp_touching: bool,
        tp_fresh: bool, // first frame after touch-down: seed last, no delta
        tp_acc_x: i32,
        tp_acc_y: i32,
        mt_slot: i32,       // active ABS_MT slot; we only track slot 0
        two_finger: bool,   // two contacts down -> scroll instead of pointer
        tp_scroll_acc: i32, // accumulated vertical counts toward the next wheel tick
    }

    impl MouseState {
        fn new(id: u8, tp_range: Option<(i32, i32)>) -> Self {
            Self {
                id,
                buttons: 0,
                dx: 0,
                dy: 0,
                wheel: 0,
                last_sent_buttons: 0,
                last_flush: Instant::now(),
                tp_range,
                tp_x: 0,
                tp_y: 0,
                tp_last_x: 0,
                tp_last_y: 0,
                tp_touching: false,
                tp_fresh: false,
                tp_acc_x: 0,
                tp_acc_y: 0,
                mt_slot: 0,
                two_finger: false,
                tp_scroll_acc: 0,
            }
        }
        fn rel(&mut self, code: u16, value: i32) {
            match code {
                REL_X => self.dx += value,
                REL_Y => self.dy += value,
                REL_WHEEL => self.wheel += value,
                _ => {}
            }
        }
        fn abs(&mut self, code: u16, value: i32) {
            match code {
                ABS_MT_SLOT => self.mt_slot = value,
                ABS_X => self.tp_x = value,
                ABS_Y => self.tp_y = value,
                ABS_MT_POSITION_X if self.mt_slot == 0 => self.tp_x = value,
                ABS_MT_POSITION_Y if self.mt_slot == 0 => self.tp_y = value,
                ABS_MT_TRACKING_ID if self.mt_slot == 0 => self.touch(value != -1),
                _ => {}
            }
        }
        fn touch(&mut self, down: bool) {
            self.tp_touching = down;
            self.tp_fresh = down;
        }
        // Two contacts -> scroll mode. Re-seed on the change so the switch between
        // pointer and scroll doesn't emit a jump.
        fn two_finger(&mut self, on: bool) {
            if on != self.two_finger {
                self.two_finger = on;
                self.tp_fresh = true;
                self.tp_scroll_acc = 0;
            }
        }
        fn apply_touch(&mut self) {
            let Some((rx, ry)) = self.tp_range else {
                return;
            };
            if !self.tp_touching {
                return;
            }
            if self.tp_fresh {
                self.tp_last_x = self.tp_x;
                self.tp_last_y = self.tp_y;
                self.tp_fresh = false;
                return;
            }
            let ddx = self.tp_x - self.tp_last_x;
            let ddy = self.tp_y - self.tp_last_y;
            self.tp_last_x = self.tp_x;
            self.tp_last_y = self.tp_y;
            if self.two_finger {
                self.tp_scroll_acc += ddy;
                let step = (ry / 15).max(1);
                let ticks = self.tp_scroll_acc / step;
                self.tp_scroll_acc -= ticks * step;
                self.wheel -= ticks;
            } else {
                self.tp_acc_x += ddx * 1000;
                self.tp_acc_y += ddy * 1000;
                let ox = self.tp_acc_x / rx.max(1);
                let oy = self.tp_acc_y / ry.max(1);
                self.tp_acc_x -= ox * rx.max(1);
                self.tp_acc_y -= oy * ry.max(1);
                self.dx += ox;
                self.dy += oy;
            }
        }
        fn button(&mut self, code: u16, down: bool) {
            let bit = match code {
                BTN_LEFT => 0x01,
                BTN_RIGHT => 0x02,
                BTN_MIDDLE => 0x04,
                _ => return,
            };
            if down {
                self.buttons |= bit;
            } else {
                self.buttons &= !bit;
            }
        }
        // Emit a report on button changes immediately, motion at <=125 Hz.
        fn flush(&mut self, dev: &mut Device, idle: bool) -> Result<()> {
            let btn_changed = self.buttons != self.last_sent_buttons;
            let motion = self.dx != 0 || self.dy != 0 || self.wheel != 0;
            if !btn_changed
                && (!motion || (!idle && self.last_flush.elapsed() < Duration::from_millis(8)))
            {
                return Ok(());
            }
            let clamp = |v: i32| v.clamp(-127, 127) as i8 as u8;
            let r = [
                self.buttons,
                clamp(self.dx),
                clamp(self.dy),
                clamp(self.wheel),
            ];
            dev.ble_hid_send(&input_report(self.id, &r))?;
            self.dx = 0;
            self.dy = 0;
            self.wheel = 0;
            self.last_sent_buttons = self.buttons;
            self.last_flush = Instant::now();
            Ok(())
        }

        fn release_json(&self) -> serde_json::Value {
            input_report(self.id, &[0u8; 4])
        }
    }

    struct GamepadState {
        id: u8,
        buttons: u16,
        axes: [i8; 4],           // X, Y, Z, Rz
        ranges: [(i32, i32); 4], // per-axis (min, max)
        dirty: bool,
    }

    impl GamepadState {
        // Read the axis ranges from the first grabbed gamepad (for scaling).
        fn new(id: u8, grabs: &[Grab]) -> Self {
            let mut ranges = [(0i32, 255i32); 4];
            if let Some(g) = grabs.iter().find(|g| g.class == HidClass::Gamepad) {
                let fd = g.file.as_raw_fd();
                for (i, axis) in [0u16, 1, 2, 5].into_iter().enumerate() {
                    if let Some(mm) = abs_minmax(fd, EVIOCGABS_BASE + axis as libc::c_ulong) {
                        ranges[i] = mm;
                    }
                }
            }
            Self {
                id,
                buttons: 0,
                axes: [0; 4],
                ranges,
                dirty: false,
            }
        }
        fn button(&mut self, code: u16, down: bool) {
            let bit = code - BTN_GAMEPAD_LO;
            if bit >= 16 {
                return;
            }
            let mask = 1u16 << bit;
            if down {
                self.buttons |= mask;
            } else {
                self.buttons &= !mask;
            }
            self.dirty = true;
        }
        fn axis(&mut self, code: u16, value: i32) {
            let idx = match code {
                0 => 0, // ABS_X
                1 => 1, // ABS_Y
                2 => 2, // ABS_Z
                5 => 3, // ABS_RZ
                _ => return,
            };
            let (min, max) = self.ranges[idx];
            let scaled = if max > min {
                let n = (value - min) as f32 / (max - min) as f32; // 0..1
                (n * 254.0 - 127.0).round().clamp(-127.0, 127.0) as i8
            } else {
                0
            };
            if self.axes[idx] != scaled {
                self.axes[idx] = scaled;
                self.dirty = true;
            }
        }
        fn flush(&mut self, dev: &mut Device) -> Result<()> {
            if !self.dirty {
                return Ok(());
            }
            let r = [
                (self.buttons & 0xff) as u8,
                (self.buttons >> 8) as u8,
                self.axes[0] as u8,
                self.axes[1] as u8,
                self.axes[2] as u8,
                self.axes[3] as u8,
            ];
            dev.ble_hid_send(&input_report(self.id, &r))?;
            self.dirty = false;
            Ok(())
        }

        fn release_json(&self) -> serde_json::Value {
            input_report(self.id, &[0u8; 6])
        }
    }

    struct TabletState {
        id: u8,
        x: u16,
        y: u16,
        tip: bool,
        in_range: bool,
        rx: (i32, i32),
        ry: (i32, i32),
        dirty: bool,
    }

    impl TabletState {
        // Read the pen's absolute X/Y range from the first grabbed tablet (to scale
        // into 0..32767).
        fn new(id: u8, grabs: &[Grab]) -> Self {
            let mut rx = (0, 32767);
            let mut ry = (0, 32767);
            if let Some(g) = grabs.iter().find(|g| g.class == HidClass::Tablet) {
                let fd = g.file.as_raw_fd();
                if let Some(mm) = abs_minmax(fd, EVIOCGABS_BASE + ABS_X as libc::c_ulong) {
                    rx = mm;
                }
                if let Some(mm) = abs_minmax(fd, EVIOCGABS_BASE + ABS_Y as libc::c_ulong) {
                    ry = mm;
                }
            }
            Self {
                id,
                x: 0,
                y: 0,
                tip: false,
                in_range: false,
                rx,
                ry,
                dirty: false,
            }
        }
        fn scale(v: i32, (min, max): (i32, i32)) -> u16 {
            if max <= min {
                return 0;
            }
            ((v.clamp(min, max) as i64 - min as i64) * 32767 / (max as i64 - min as i64)) as u16
        }
        fn abs(&mut self, code: u16, value: i32) {
            match code {
                ABS_X => {
                    self.x = Self::scale(value, self.rx);
                    self.dirty = true;
                }
                ABS_Y => {
                    self.y = Self::scale(value, self.ry);
                    self.dirty = true;
                }
                _ => {}
            }
        }
        fn key(&mut self, code: u16, down: bool) {
            match code {
                BTN_TOUCH => {
                    self.tip = down;
                    self.dirty = true;
                }
                BTN_TOOL_PEN => {
                    self.in_range = down;
                    self.dirty = true;
                }
                _ => {}
            }
        }
        fn flush(&mut self, dev: &mut Device) -> Result<()> {
            if !self.dirty {
                return Ok(());
            }
            let flags = (self.tip as u8) | ((self.in_range as u8) << 1);
            let [xl, xh] = self.x.to_le_bytes();
            let [yl, yh] = self.y.to_le_bytes();
            dev.ble_hid_send(&input_report(self.id, &[flags, xl, xh, yl, yh]))?;
            self.dirty = false;
            Ok(())
        }
        fn release_json(&self) -> serde_json::Value {
            input_report(self.id, &[0u8; 5])
        }
    }

    struct SystemState {
        id: u8,
        bits: u8,
        last_sent: u8,
    }

    impl SystemState {
        fn new(id: u8) -> Self {
            Self {
                id,
                bits: 0,
                last_sent: 0,
            }
        }
        fn key(&mut self, code: u16, down: bool) {
            let bit = match code {
                KEY_POWER => 0x01,
                KEY_SLEEP => 0x02,
                KEY_WAKEUP => 0x04,
                _ => return,
            };
            if down {
                self.bits |= bit;
            } else {
                self.bits &= !bit;
            }
        }
        fn flush(&mut self, dev: &mut Device) -> Result<()> {
            if self.bits == self.last_sent {
                return Ok(());
            }
            dev.ble_hid_send(&input_report(self.id, &[self.bits]))?;
            self.last_sent = self.bits;
            Ok(())
        }
        fn release_json(&self) -> serde_json::Value {
            input_report(self.id, &[0u8; 1])
        }
    }

    fn parse_hotkey(spec: &str) -> Result<Vec<u16>> {
        let mut codes = Vec::new();
        for tok in spec.split('+') {
            let t = tok.trim().to_ascii_lowercase();
            if t.is_empty() {
                continue;
            }
            let code = key_name_to_linux(&t)
                .with_context(|| format!("unknown key in --release: '{t}'"))?;
            codes.push(code);
        }
        if codes.is_empty() {
            bail!("--release hotkey is empty");
        }
        Ok(codes)
    }

    fn key_name_to_linux(name: &str) -> Option<u16> {
        Some(match name {
            "ctrl" | "leftctrl" | "lctrl" => 29,
            "rightctrl" | "rctrl" => 97,
            "shift" | "leftshift" | "lshift" => 42,
            "rightshift" | "rshift" => 54,
            "alt" | "leftalt" | "lalt" => 56,
            "rightalt" | "ralt" | "altgr" => 100,
            "meta" | "super" | "win" | "leftmeta" => 125,
            "rightmeta" => 126,
            "esc" | "escape" => 1,
            "tab" => 15,
            "space" => 57,
            "enter" | "return" => 28,
            "backspace" => 14,
            "capslock" => 58,
            "scrolllock" => 70,
            "pause" => 119,
            "insert" => 110,
            "delete" | "del" => 111,
            "home" => 102,
            "end" => 107,
            "pageup" => 104,
            "pagedown" => 109,
            "up" => 103,
            "down" => 108,
            "left" => 105,
            "right" => 106,
            "f1" => 59,
            "f2" => 60,
            "f3" => 61,
            "f4" => 62,
            "f5" => 63,
            "f6" => 64,
            "f7" => 65,
            "f8" => 66,
            "f9" => 67,
            "f10" => 68,
            "f11" => 87,
            "f12" => 88,
            _ if name.len() == 1 => {
                let c = name.as_bytes()[0];
                match c {
                    b'a'..=b'z' => LINUX_LETTER[(c - b'a') as usize],
                    b'0' => 11,
                    b'1'..=b'9' => 1 + (c - b'0') as u16,
                    _ => return None,
                }
            }
            _ => return None,
        })
    }

    // Linux keycodes for a..z, in alphabetical order.
    const LINUX_LETTER: [u16; 26] = [
        30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17,
        45, 21, 44,
    ];

    // Map a Linux keycode to a modifier bit in the HID report, if it is one.
    fn linux_modifier_bit(code: u16) -> Option<u8> {
        Some(match code {
            29 => 0x01,  // LeftCtrl
            42 => 0x02,  // LeftShift
            56 => 0x04,  // LeftAlt
            125 => 0x08, // LeftMeta
            97 => 0x10,  // RightCtrl
            54 => 0x20,  // RightShift
            100 => 0x40, // RightAlt
            126 => 0x80, // RightMeta
            _ => return None,
        })
    }

    // Map a Linux keycode to a HID Keyboard/Keypad usage (page 0x07).
    fn linux_to_hid_usage(code: u16) -> Option<u8> {
        Some(match code {
            1 => 0x29,                         // Esc
            2..=10 => 0x1e + (code - 2) as u8, // 1..9
            11 => 0x27,                        // 0
            12 => 0x2d,                        // -
            13 => 0x2e,                        // =
            14 => 0x2a,                        // Backspace
            15 => 0x2b,                        // Tab
            16 => 0x14,
            17 => 0x1a,
            18 => 0x08,
            19 => 0x15,
            20 => 0x17,
            21 => 0x1c,
            22 => 0x18,
            23 => 0x0c,
            24 => 0x12,
            25 => 0x13, // q w e r t y u i o p
            26 => 0x2f, // [
            27 => 0x30, // ]
            28 => 0x28, // Enter
            30 => 0x04,
            31 => 0x16,
            32 => 0x07,
            33 => 0x09,
            34 => 0x0a,
            35 => 0x0b,
            36 => 0x0d,
            37 => 0x0e,
            38 => 0x0f, // a s d f g h j k l
            39 => 0x33, // ;
            40 => 0x34, // '
            41 => 0x35, // `
            43 => 0x31, // backslash
            44 => 0x1d,
            45 => 0x1b,
            46 => 0x06,
            47 => 0x19,
            48 => 0x05,
            49 => 0x11,
            50 => 0x10,                          // z x c v b n m
            51 => 0x36,                          // ,
            52 => 0x37,                          // .
            53 => 0x38,                          // /
            57 => 0x2c,                          // Space
            58 => 0x39,                          // CapsLock
            59..=68 => 0x3a + (code - 59) as u8, // F1..F10
            70 => 0x47,                          // ScrollLock
            87 => 0x44,                          // F11
            88 => 0x45,                          // F12
            99 => 0x46,                          // PrintScreen (SysRq)
            102 => 0x4a,                         // Home
            103 => 0x52,                         // Up
            104 => 0x4b,                         // PageUp
            105 => 0x50,                         // Left
            106 => 0x4f,                         // Right
            107 => 0x4d,                         // End
            108 => 0x51,                         // Down
            109 => 0x4e,                         // PageDown
            110 => 0x49,                         // Insert
            111 => 0x4c,                         // Delete
            119 => 0x48,                         // Pause
            _ => return None,
        })
    }
}
