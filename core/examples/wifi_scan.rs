//! Minimal Wi-Fi scan. Run with: `cargo run --example wifi_scan`
//!
//! Opens the first BLEShark Nano found on USB and prints nearby access points,
//! strongest signal first.

use infishark::{Device, WifiScanOpts};

fn main() -> infishark::Result<()> {
    let mut dev = Device::open(None, 12_000)?;
    let mut nets = dev.wifi_scan(&WifiScanOpts::default())?;
    nets.sort_by_key(|n| std::cmp::Reverse(n.rssi));
    for n in nets {
        println!("{:>4} dBm  ch{:<3} {}  {}", n.rssi, n.channel, n.bssid, n.ssid);
    }
    Ok(())
}
