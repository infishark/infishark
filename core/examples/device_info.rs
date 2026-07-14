//! Minimal identity probe. Run with: `cargo run --example device_info`
//!
//! Opens the first BLEShark Nano found on USB and prints its identity JSON.

use infishark::Device;

fn main() -> infishark::Result<()> {
    let mut dev = Device::open(None, 12_000)?;
    println!("{:#}", dev.device_info()?);
    Ok(())
}
