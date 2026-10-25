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

Capture and reuse IR signals in the same shell session:

```text
ir rx                         # Ctrl-C stops and retains the captures
ir show                       # list captures, numbered from 1
ir save remote.ir             # save all captures
ir save selected.ir 1,3        # save selected captures in the given order
ir tx --capture 1             # retransmit a retained code or raw waveform
ir tx --capture 1 --repeats 2  # repeat a decoded code
```

Saving works without a connected Nano and retains the original `Capture_N`
button names. Duplicate selections are saved once. Existing destination files
are replaced, as with `ir rx --out`. The cache lasts for the current shell
session; use the saved `.ir` file in later sessions.

Monitor presets accept compatible address, signal, PHY, length, byte-match, and
dedup refinements:

```text
wifi monitor --channel 6 --filter beacons --bssid AA:BB:CC:DD:EE:FF --min-rssi=-70 --out beacons.pcap
```

Frame types, subtypes, and EtherType remain fixed by the preset. Encryption
options must agree with any encryption rule built into it.

Portal logs show one request/response summary per request in host-content mode,
or one request line with on-device content. Use `wifi portal --dir pages --verbose` (or `-v`) for full
headers, arguments, and event details. Host-content summaries include HTTP
status, response-body bytes, and request ID.

[Full docs](https://docs.infishark.com/docs/sdk)

## License

GPL-3.0-only. You may use, modify, and redistribute this freely, but any work built on it must also be open-source under the GPL. The BLEShark Nano firmware itself is a separate, closed-source product. For commercial (closed-source) licensing, contact `support@infishark.com`.

This SDK is in the early stages, so bugs are to be expected. If you hit one, please open an issue or pull request.
