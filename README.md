# infishark

The Rust SDK and command-line tool for the BLEShark Nano.

This turns the Nano into a raw RF peripheral your computer drives over serial. The device is the radio; the host is the compute; this SDK is the membrane between them.

`core/` is the SDK (`infishark`), a typed `Device` client over a framed serial transport. `cli/` is the `infishark` binary built on it.

## Install

**CLI** (the `infishark` tool) installs with one command; no Rust needed once release binaries are published:

```sh
# Linux / macOS
curl -fsSL https://cdn.infishark.com/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://cdn.infishark.com/install.ps1 | iex
```

The installer grabs a prebuilt binary for your platform, or builds from source with your Rust toolchain if none is published yet (Linux source builds need `libudev` + `pkg-config`, which the script installs for you). The binary lands in `~/.local/bin` (`%USERPROFILE%\.infishark\bin` on Windows).

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

Runnable examples live in `core/examples/`: `cargo run --example ble_scan` (also `wifi_scan`, `device_info`). For a fuller worked example, see the `airhorn` project, an automated Find My tag locator built entirely on this SDK.

## CLI

```sh
infishark # open up the shell
ports # list detected devices
device info
wifi scan
ble scan
```

Every command also takes `--json` for machine-readable output.

## License

GPL-3.0-only. You may use, modify, and redistribute this freely, but any work built on it must also be open-source under the GPL. The BLEShark Nano firmware itself is a separate, closed-source product. For commercial (closed-source) licensing, contact support@infishark.com.

This SDK is in the early stages, so bugs are to be expected. If you hit one, please open an issue or pull request.
