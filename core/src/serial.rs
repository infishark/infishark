//! Opening the device's USB-CDC serial port and wrapping it in a Transport.

use std::time::Duration;

use crate::error::{Context, Result};
use serialport::{SerialPort, SerialPortType};

use crate::transport::Transport;

const ESPRESSIF_VID: u16 = 0x303A;
const BAUD: u32 = 921_600;

pub fn open_device(port: Option<&str>, timeout_ms: u64) -> Result<Transport<Box<dyn SerialPort>>> {
    let path = match port {
        Some(p) => p.to_string(),
        None => auto_select()?,
    };
    let stream = serialport::new(&path, BAUD)
        .timeout(Duration::from_millis(timeout_ms))
        .open()
        .with_context(|| format!("opening serial port {path}"))?;
    Ok(Transport::new(stream))
}

/// returns device-info JSON if a Nano answers else None
pub fn probe_device_info(path: &str, timeout_ms: u64) -> Option<serde_json::Value> {
    let stream = serialport::new(path, BAUD)
        .timeout(Duration::from_millis(timeout_ms))
        .open()
        .ok()?;
    let mut transport = Transport::new(stream);
    let resp = transport
        .transact(crate::protocol::CMD_DEVICE_INFO, b"")
        .ok()?;
    if !resp.is_ok() || resp.body.is_empty() {
        return None;
    }
    serde_json::from_slice(&resp.body).ok()
}

// BLEShark Nano is not registered under the espressif/usb-pids GitHub repo
// because it is based on an ESP32-C3 which does not have OTG. This means it
// cannot use a custom PID, so we must use the Espressif VID to shortlist
// candidates and then confirm each is a Nano by probing its identity. A bare
// JTAG/serial debug unit or ESP shares the VID but never answers the
// device-info probe.
fn auto_select() -> Result<String> {
    let ports = serialport::available_ports().context("listing serial ports")?;
    let mut espressif: Vec<String> = ports
        .into_iter()
        .filter_map(|p| match p.port_type {
            SerialPortType::UsbPort(usb) if usb.vid == ESPRESSIF_VID => Some(p.port_name),
            _ => None,
        })
        .collect();
    espressif.sort();
    let espressif = prefer_cu_over_tty(espressif);
    // one device can still answer on more than one node
    let mut devices: Vec<(String, String)> = Vec::new();
    for path in &espressif {
        let Some(info) = probe_device_info(path, 800) else {
            continue;
        };
        let Some(serial) = info.get("serial").and_then(|v| v.as_str()) else {
            continue;
        };
        if devices.iter().any(|(_, s)| s == serial) {
            continue;
        }
        devices.push((path.clone(), serial.to_string()));
    }
    match devices.len() {
        1 => Ok(devices.remove(0).0),
        0 if espressif.is_empty() => bail!("no BLEShark Nano found; pass --port"),
        0 => bail!(
            "no BLEShark Nano found; Espressif port(s) present but not responding: {}. pass --port",
            espressif.join(", ")
        ),
        _ => bail!(
            "multiple BLEShark Nano devices found ({}); pass --port to choose",
            devices
                .iter()
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// BSD & macOS expose each USB serial endpoint as both a callout (`cu`) and a
/// dial-in (`tty`). Opening either talks to the same device; keeping both makes
/// one Nano look like two. `cu` is the best choice as no cf<->lr processing, it
/// waits for a real hardware connection, etc
pub fn prefer_cu_over_tty(paths: Vec<String>) -> Vec<String> {
    let callout_names: std::collections::BTreeSet<String> = paths
        .iter()
        .filter_map(|p| p.strip_prefix("/dev/cu.").map(str::to_string))
        .collect();

    paths
        .into_iter()
        .filter(|p| {
            p.strip_prefix("/dev/tty.")
                .map(|name| !callout_names.contains(name))
                .unwrap_or(true)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::prefer_cu_over_tty;

    #[test]
    fn macos_cu_port_wins_over_matching_tty_port() {
        let ports = vec![
            "/dev/cu.usbmodem13377".to_string(),
            "/dev/tty.usbmodem13377".to_string(),
        ];
        assert_eq!(prefer_cu_over_tty(ports), vec!["/dev/cu.usbmodem13377"]);
    }

    #[test]
    fn keeps_tty_port_when_no_matching_cu_port_exists() {
        let ports = vec!["/dev/ttyUSB0".to_string()];
        assert_eq!(prefer_cu_over_tty(ports), vec!["/dev/ttyUSB0"]);
    }

    #[test]
    fn keeps_unrelated_ports() {
        let ports = vec![
            "/dev/cu.usbmodem13377".to_string(),
            "/dev/tty.usbmodem99999".to_string(),
        ];
        assert_eq!(
            prefer_cu_over_tty(ports),
            vec!["/dev/cu.usbmodem13377", "/dev/tty.usbmodem99999"]
        );
    }
}
