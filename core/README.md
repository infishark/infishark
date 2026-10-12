# InfiShark device SDK

Framed transport and a typed [`Device`] client. BLE scans default to active.

```no_run
let mut dev = infishark::Device::open(None, 15_000)?;
for device in dev.ble_scan(&infishark::BleScanOpts::default())? {
    let name = device.name.as_deref().unwrap_or("<unknown>");
    println!("{}  {} dBm  {name}", device.address, device.rssi);
}
# Ok::<(), infishark::Error>(())
```
