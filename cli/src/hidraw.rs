//! ble hid clone: read a real USB HID device's report descriptor from
//! /dev/hidraw*, strip it to input-only (drop Output/Feature/PID reports),
//! advertise that exact descriptor over BLE, and forward the device's raw input
//! reports to the paired host. Non-exclusive: the host still sees the device
//! too. Linux only (hidraw; needs /dev access, usually root).

use anyhow::Result;
use infishark::Device;

pub struct CloneOpts {
    pub device: Option<String>,
    pub no_start: bool,
}

pub fn run(dev: Device, opts: CloneOpts) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run(dev, opts)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dev, opts);
        anyhow::bail!("`ble hid bridge --clone` supports Linux only for now (needs hidraw)")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::CloneOpts;
    use crate::signals::{RUNNING, install_sigint};
    use anyhow::{Context, Result, bail};
    use infishark::{Device, hex};
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::atomic::Ordering;

    // hidraw ioctls are _IOR('H', nr, size); this builds the request number.
    fn ior(nr: u8, size: usize) -> libc::c_ulong {
        (2 << 30)
            | ((size as libc::c_ulong) << 16)
            | ((b'H' as libc::c_ulong) << 8)
            | nr as libc::c_ulong
    }

    const HID_MAX_DESC: usize = 4096;

    // HIDIOCGRDESCSIZE / HIDIOCGRDESC: fetch the raw report descriptor bytes.
    fn read_desc(fd: RawFd) -> Option<Vec<u8>> {
        let mut size: libc::c_int = 0;
        if unsafe { libc::ioctl(fd, ior(0x01, 4), &mut size as *mut libc::c_int) } < 0 {
            return None;
        }
        let size = size as usize;
        if size == 0 || size > HID_MAX_DESC {
            return None;
        }
        // struct hidraw_report_descriptor { u32 size; u8 value[HID_MAX_DESC]; }
        let mut buf = vec![0u8; 4 + HID_MAX_DESC];
        buf[0..4].copy_from_slice(&(size as u32).to_ne_bytes());
        if unsafe { libc::ioctl(fd, ior(0x02, 4 + HID_MAX_DESC), buf.as_mut_ptr()) } < 0 {
            return None;
        }
        Some(buf[4..4 + size].to_vec())
    }

    // HIDIOCGRAWINFO: struct hidraw_devinfo { u32 bustype; s16 vendor; s16 product;
    // }
    fn raw_info(fd: RawFd) -> (u16, u16) {
        let mut info = [0u8; 8];
        if unsafe { libc::ioctl(fd, ior(0x03, 8), info.as_mut_ptr()) } < 0 {
            return (0, 0);
        }
        (
            u16::from_ne_bytes([info[4], info[5]]),
            u16::from_ne_bytes([info[6], info[7]]),
        )
    }

    fn raw_name(fd: RawFd) -> String {
        let mut buf = [0u8; 256];
        let r = unsafe { libc::ioctl(fd, ior(0x04, buf.len()), buf.as_mut_ptr()) };
        if r <= 0 {
            return String::new();
        }
        let n = (r as usize).min(buf.len());
        String::from_utf8_lossy(&buf[..n])
            .trim_end_matches('\0')
            .trim()
            .to_string()
    }

    #[derive(Clone)]
    struct Item {
        prefix: u8,
        data: Vec<u8>,
    }

    // Walk the HID item stream into (prefix, data) items. Short items only; long
    // items (0xFE) are skipped whole (vendor-defined, never input).
    fn parse_items(desc: &[u8]) -> Vec<Item> {
        let mut items = Vec::new();
        let mut i = 0;
        while i < desc.len() {
            let prefix = desc[i];
            i += 1;
            if prefix == 0xFE {
                let dsize = desc.get(i).copied().unwrap_or(0) as usize;
                i += 2 + dsize;
                continue;
            }
            let len = match prefix & 0x03 {
                0 => 0,
                1 => 1,
                2 => 2,
                _ => 4,
            };
            if i + len > desc.len() {
                break;
            }
            items.push(Item {
                prefix,
                data: desc[i..i + len].to_vec(),
            });
            i += len;
        }
        items
    }

    fn serialize(items: &[Item]) -> Vec<u8> {
        let mut out = Vec::new();
        for it in items {
            out.push(it.prefix);
            out.extend_from_slice(&it.data);
        }
        out
    }

    fn le_u16(d: &[u8]) -> u16 {
        match d.len() {
            0 => 0,
            1 => d[0] as u16,
            _ => u16::from_le_bytes([d[0], d[1]]),
        }
    }

    // Strip a descriptor to input-only: drop Output (0x90) and Feature (0xB0) main
    // items, keep the input items and all structure/globals. If the source is
    // unnumbered, inject Report ID 1 so HOGP can route the single input report by
    // id. This function returns (descriptor, input report ids, numbered)
    fn input_only(desc: &[u8]) -> (Vec<u8>, BTreeSet<u8>, bool) {
        let mut out: Vec<Item> = Vec::new();
        let mut cur_id: u8 = 0;
        let mut numbered = false;
        let mut ids: BTreeSet<u8> = BTreeSet::new();
        for it in parse_items(desc) {
            match it.prefix & 0xFC {
                0x84 => {
                    cur_id = it.data.first().copied().unwrap_or(0);
                    numbered = true;
                    out.push(it);
                }
                0x90 | 0xB0 => {} // drop Output / Feature
                0x80 => {
                    ids.insert(cur_id);
                    out.push(it);
                }
                _ => out.push(it),
            }
        }
        if !numbered {
            // Inject Report ID 1 after the first collection (or at the front if there is
            // none).
            let pos = out
                .iter()
                .position(|it| it.prefix & 0xFC == 0xA0)
                .map(|p| p + 1)
                .unwrap_or(0);
            out.insert(
                pos,
                Item {
                    prefix: 0x85,
                    data: vec![1],
                },
            );
            ids.clear();
            ids.insert(1);
        }
        (serialize(&out), ids, numbered)
    }

    // GAP appearance from the first top-level Usage Page + Usage (before the first
    // collection).
    fn appearance_of(desc: &[u8]) -> u16 {
        let mut page: Option<u16> = None;
        let mut usage: Option<u16> = None;
        for it in parse_items(desc) {
            match it.prefix & 0xFC {
                0x04 if page.is_none() => page = Some(le_u16(&it.data)),
                0x08 if usage.is_none() => usage = Some(le_u16(&it.data)),
                0xA0 => break,
                _ => {}
            }
        }
        match (page.unwrap_or(0), usage.unwrap_or(0)) {
            (0x01, 0x06) => crate::hid::APPEARANCE_KEYBOARD,
            (0x01, 0x02) => crate::hid::APPEARANCE_MOUSE,
            (0x01, 0x04) => crate::hid::APPEARANCE_JOYSTICK,
            (0x01, 0x05) => crate::hid::APPEARANCE_GAMEPAD,
            (0x0D, _) => crate::hid::APPEARANCE_DIGITIZER,
            _ => crate::hid::APPEARANCE_GENERIC,
        }
    }

    #[derive(Clone)]
    struct RawDev {
        path: String,
        name: String,
        vid: u16,
        pid: u16,
    }

    fn enumerate() -> Result<Vec<RawDev>> {
        let mut devs: Vec<RawDev> = Vec::new();
        for entry in fs::read_dir("/dev").context("reading /dev")?.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("hidraw") {
                continue;
            }
            let path = format!("/dev/{name}");
            let Ok(file) = fs::OpenOptions::new().read(true).open(&path) else {
                continue;
            };
            let fd = file.as_raw_fd();
            let (vid, pid) = raw_info(fd);
            devs.push(RawDev {
                path,
                name: raw_name(fd),
                vid,
                pid,
            });
        }
        devs.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(devs)
    }

    pub fn run(mut dev: Device, opts: CloneOpts) -> Result<()> {
        let target = match opts.device {
            Some(p) => p,
            None => {
                let devs = enumerate()?;
                if devs.is_empty() {
                    bail!("no /dev/hidraw* devices found (need root?)");
                }
                let pick = crate::ui::pick_from_list(&devs, "Pick a HID device to clone: ", |d| {
                    let name = if d.name.is_empty() {
                        "(unknown)"
                    } else {
                        &d.name
                    };
                    format!("{}  {}  ({:04x}:{:04x})", d.path, name, d.vid, d.pid)
                })?;
                pick.path.clone()
            }
        };

        let file = fs::OpenOptions::new()
            .read(true)
            .open(&target)
            .with_context(|| format!("opening {target} (need root?)"))?;
        let fd = file.as_raw_fd();
        let desc = read_desc(fd)
            .with_context(|| format!("reading HID report descriptor from {target}"))?;
        let (vid, pid) = raw_info(fd);
        let name = raw_name(fd);

        let (map, ids, numbered) = input_only(&desc);
        if ids.is_empty() {
            bail!("{target} declares no input reports to clone");
        }
        if ids.len() > 8 {
            bail!(
                "{target} declares {} input report ids; the device supports at most 8",
                ids.len()
            );
        }
        if map.len() > 512 {
            bail!(
                "cloned input-only descriptor is {} bytes (>512 ATT limit); device too complex",
                map.len()
            );
        }

        let reports: Vec<serde_json::Value> = ids
            .iter()
            .map(|id| serde_json::json!({ "id": id, "type": "input" }))
            .collect();
        let dev_name = if name.is_empty() {
            "BLEShark Clone".to_string()
        } else {
            name.clone()
        };
        let spec = serde_json::json!({
            "report_map": hex::encode(&map),
            "reports": reports,
            "appearance": appearance_of(&desc),
            "name": dev_name,
            "pnp": { "source": 0x02, "vid": vid, "pid": pid, "ver": 0 },
        });

        if !opts.no_start {
            let ident = dev.ble_hid_start(&spec)?;
            let mac = ident.get("mac").and_then(|m| m.as_str()).unwrap_or("?");
            eprintln!(
                "Cloned {dev_name:?} ({vid:04x}:{pid:04x}, {} input report(s), {}B map). Advertising as {mac}.",
                ids.len(),
                map.len()
            );
        }
        eprintln!(
            "Forwarding {target} input reports. Non-exclusive: your host still sees this device. Ctrl-C to stop."
        );
        install_sigint();
        forward(&file, &mut dev, numbered)
    }

    fn forward(file: &fs::File, dev: &mut Device, numbered: bool) -> Result<()> {
        let fd = file.as_raw_fd();
        let mut buf = [0u8; HID_MAX_DESC];
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let mut warned_oversize = false;
        while RUNNING.load(Ordering::SeqCst) {
            let r = unsafe { libc::poll(&mut pfd, 1, 200) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            if r == 0 {
                continue;
            }
            if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                eprintln!("Input device disconnected.");
                break;
            }
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                continue;
            }
            let n = n as usize;
            // Numbered reports carry the id in byte 0; unnumbered we forward as the
            // injected id 1.
            let (id, data): (u8, &[u8]) = if numbered {
                (buf[0], &buf[1..n])
            } else {
                (1, &buf[..n])
            };
            // Reports over 64 bytes are skipped rather than letting one oversized report
            // tear down the whole clone.
            if data.len() > 64 {
                if !warned_oversize {
                    eprintln!(
                        "warning: some input reports exceed the 64-byte limit and are skipped"
                    );
                    warned_oversize = true;
                }
                continue;
            }
            dev.ble_hid_send(&crate::hid::input_report(id, data))?;
        }
        eprintln!("Stopped. Run `infishark ble stop` to stop advertising on the device.");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // A standard boot keyboard: modifier + reserved + 6 keys of input, with an LED
        // output report. Unnumbered.
        const BOOT_KEYBOARD: &[u8] = &[
            0x05, 0x01, 0x09, 0x06, 0xA1,
            0x01, // Usage Page Generic, Usage Keyboard, Collection App
            0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08,
            0x81, 0x02, // 8 modifier bits (input)
            0x95, 0x01, 0x75, 0x08, 0x81, 0x03, // reserved byte (input const)
            0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91,
            0x02, // 5 LED bits (OUTPUT)
            0x95, 0x01, 0x75, 0x03, 0x91, 0x03, // LED padding (OUTPUT)
            0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
            0x81, 0x00, // 6 key bytes (input)
            0xC0, // End Collection
        ];

        #[test]
        fn strips_output_forces_report_id_and_keeps_input() {
            let (map, ids, numbered) = input_only(BOOT_KEYBOARD);
            assert!(!numbered);
            assert_eq!(ids, BTreeSet::from([1]));
            // No Output/Feature main items survive.
            assert!(
                parse_items(&map)
                    .iter()
                    .all(|it| it.prefix & 0xFC != 0x90 && it.prefix & 0xFC != 0xB0)
            );
            // Report ID 1 injected right after Collection(Application).
            assert!(map.windows(4).any(|w| w == [0xA1, 0x01, 0x85, 0x01]));
            // Still has input items and stays well under the 512-byte ATT ceiling.
            assert!(parse_items(&map).iter().any(|it| it.prefix & 0xFC == 0x80));
            assert!(map.len() <= 512);
        }

        #[test]
        fn appearance_reads_top_level_usage() {
            assert_eq!(appearance_of(BOOT_KEYBOARD), 0x03C1);
        }
    }
}
