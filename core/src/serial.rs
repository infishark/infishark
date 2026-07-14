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

// BLEShark Nano is not registered under the espressif/usb-pids GitHub repo because it is
// based on an ESP32-C3 which does not have OTG. This means it cannot use a custom PID, so
// we must use the Espressif VID to shortlist candidates and then confirm each is a Nano
// by probing its identity. A bare JTAG/serial debug unit or ESP shares the VID but never
// answers the device-info probe.
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
    let mut nanos: Vec<String> = espressif
        .iter()
        .filter(|p| probe_device_info(p, 800).is_some())
        .cloned()
        .collect();
    match nanos.len() {
        1 => Ok(nanos.remove(0)),
        0 if espressif.is_empty() => bail!("no BLEShark Nano found; pass --port"),
        0 => bail!(
            "no BLEShark Nano found; Espressif port(s) present but not responding: {}. pass --port",
            espressif.join(", ")
        ),
        _ => bail!(
            "multiple BLEShark Nano devices found ({}); pass --port to choose",
            nanos.join(", ")
        ),
    }
}
