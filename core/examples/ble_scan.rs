//! Minimal BLE scan. Run with: `cargo run --example ble_scan`
//!
//! Opens the first BLEShark Nano found on USB and prints every BLE device it
//! sees, strongest signal first.

use infishark::{BleScanOpts, Device};

fn main() -> infishark::Result<()> {
    let mut dev = Device::open(None, 12_000)?;
    let mut devices = dev.ble_scan(&BleScanOpts::default())?;
    devices.sort_by_key(|d| std::cmp::Reverse(d.rssi));
    for d in devices {
        let name = d.name.as_deref().unwrap_or("<unknown>");
        println!("{}  {:>4} dBm  {name}", d.address, d.rssi);
    }
    Ok(())
}
