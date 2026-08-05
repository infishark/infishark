# infishark

The Rust SDK and command-line tool for the BLEShark Nano.

This turns the Nano into a raw RF peripheral your computer drives over serial.

`core/` is the SDK (`infishark`) -- a typed `Device` client over a framed serial transport. `cli/` is the `infishark` CLI built on it.

## Install

**CLI** (the `infishark` tool) installs with one command. Prefer the published release binaries (no Rust required):

**Linux/MacOS (bash)**
```sh
curl -fsSL https://cdn.infishark.com/install.sh | sh
```

**Windows (PowerShell)**
```powershell
irm https://cdn.infishark.com/install.ps1 | iex
```

Binary lands in `~/.local/bin` (or `%USERPROFILE%\.infishark\bin` on Windows).

## Quickstart (SDK)

```rust
use infishark::{BleScanOpts, Device};

fn main() -> infishark::Result<()> {
    let mut dev = Device::open(None, 12_000)?; // None auto-detects the port
    for d in dev.ble_scan(&BleScanOpts::default())? {
        println!("{}  {} dBm", d.address, d.rssi);
    }
    Ok(())
}
```

Add it to your project:

```sh
cargo add infishark --git https://github.com/infishark/infishark
```

Runnable examples live in `core/examples/`.

## CLI

```sh
infishark # open up the shell
help
ports
device info
wifi scan
ble scan
```

[Full docs](https://docs.infishark.com/docs/sdk)

## License

GPL-3.0-only. You may use, modify, and redistribute this freely, but any work built on it must also be open-source under the GPL. The BLEShark Nano firmware itself is a separate, closed-source product. For commercial (closed-source) licensing, contact `support@infishark.com`.

This SDK is in the early stages, so bugs are to be expected. If you hit one, please open an issue or pull request.
