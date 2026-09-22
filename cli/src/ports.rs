use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;
use serialport::{SerialPortInfo, SerialPortType};

use infishark::serial::ESPRESSIF_VID;

#[derive(Debug, Serialize)]
pub struct PortEntry {
    pub name: String,
    pub kind: String,
    pub vid: Option<u16>,
    pub pid: Option<u16>,
    pub serial_number: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceIdent>,
}

#[derive(Debug, Serialize)]
pub struct DeviceIdent {
    pub serial: String,
    pub version: String,
    pub mode: String,
}

pub fn run(all: bool, json: bool) -> Result<()> {
    let ports = list(all)?;

    if json {
        return crate::print_items("ports", &ports, true);
    }

    if ports.is_empty() {
        crate::log::info("no serial ports found");
        return Ok(());
    }

    let mut nano = 0;
    for port in &ports {
        let tag = if port.device.is_some() {
            let t = format!("nano{nano}");
            nano += 1;
            t
        } else {
            String::new()
        };
        print_port(&tag, port);
    }

    Ok(())
}

pub(crate) fn list(all: bool) -> Result<Vec<PortEntry>> {
    let mut ports: Vec<PortEntry> = serialport::available_ports()?
        .into_iter()
        .map(PortEntry::from)
        .filter(|port| all || !is_builtin_system_port(&port.name))
        .collect();

    let keep: std::collections::HashSet<String> =
        infishark::serial::prefer_cu_over_tty(ports.iter().map(|p| p.name.clone()).collect())
            .into_iter()
            .collect();
    ports.retain(|p| keep.contains(&p.name));

    // Confirm Espressif-VID ports by asking for identity; a real Nano answers.
    for port in &mut ports {
        if port.vid == Some(ESPRESSIF_VID) {
            port.device = probe(&port.name);
        }
    }

    ports = dedupe_confirmed_nanos(ports);

    ports.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ports)
}

/// Keep a single row per confirmed Nano identity (`device.serial`).
fn dedupe_confirmed_nanos(ports: Vec<PortEntry>) -> Vec<PortEntry> {
    let mut best: HashMap<String, PortEntry> = HashMap::new();
    let mut other = Vec::new();
    for p in ports {
        let Some(serial) = p.device.as_ref().map(|d| d.serial.clone()) else {
            other.push(p);
            continue;
        };
        match best.get(&serial) {
            None => {
                best.insert(serial, p);
            }
            Some(prev) if port_rank(&p.name) < port_rank(&prev.name) => {
                best.insert(serial, p);
            }
            Some(_) => {}
        }
    }
    other.extend(best.into_values());
    other
}

/// Lower is better
fn port_rank(name: &str) -> u8 {
    if name.starts_with("/dev/cu.") {
        0
    } else if name.starts_with("/dev/tty.") {
        2
    } else {
        1
    }
}

fn probe(name: &str) -> Option<DeviceIdent> {
    let info = infishark::serial::probe_device_info(name, 800)?;
    let field = |k: &str| info.get(k).and_then(|v| v.as_str()).map(String::from);
    Some(DeviceIdent {
        serial: field("serial")?,
        version: field("version").unwrap_or_else(|| "?".into()),
        mode: field("mode").unwrap_or_else(|| "?".into()),
    })
}

fn is_builtin_system_port(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("/dev/ttyS") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

fn print_port(tag: &str, port: &PortEntry) {
    let tag = format!("{tag:<6}");
    if let Some(d) = &port.device {
        println!(
            "{tag}  {}  BLEShark Nano  {}  {} ({})",
            port.name, d.serial, d.version, d.mode
        );
        return;
    }
    // Espressif VID but no DEVICE_INFO.
    let note = if port.vid == Some(ESPRESSIF_VID) {
        "  (Espressif device, not a BLEShark Nano)"
    } else {
        ""
    };
    match (&port.manufacturer, &port.product, &port.serial_number) {
        (Some(manufacturer), Some(product), Some(serial)) => {
            println!(
                "{tag}  {}  {}  {} {}  {}{}",
                port.name, port.kind, manufacturer, product, serial, note
            );
        }
        (Some(manufacturer), Some(product), None) => {
            println!(
                "{tag}  {}  {}  {} {}{}",
                port.name, port.kind, manufacturer, product, note
            );
        }
        _ => {
            println!("{tag}  {}  {}{}", port.name, port.kind, note);
        }
    }
}

impl From<SerialPortInfo> for PortEntry {
    fn from(info: SerialPortInfo) -> Self {
        let mut entry = PortEntry {
            name: info.port_name,
            kind: String::from("unknown"),
            vid: None,
            pid: None,
            serial_number: None,
            manufacturer: None,
            product: None,
            device: None,
        };

        match info.port_type {
            SerialPortType::UsbPort(usb) => {
                entry.kind = String::from("usb");
                entry.vid = Some(usb.vid);
                entry.pid = Some(usb.pid);
                entry.serial_number = usb.serial_number;
                entry.manufacturer = usb.manufacturer;
                entry.product = usb.product;
            }
            SerialPortType::BluetoothPort => {
                entry.kind = String::from("bluetooth");
            }
            SerialPortType::PciPort => {
                entry.kind = String::from("pci");
            }
            SerialPortType::Unknown => {}
        }

        entry
    }
}
