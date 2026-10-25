//! Hold DNS questions on a Wi-Fi MITM session and allow each one.
//!
//! `cargo run -p infishark --example wifi_mitm -- --ssid Lab --upstream-ssid
//! Cafe`

use std::time::Duration;

use infishark::wifi_mitm::{WifiMitmAction, WifiMitmOpts, WifiUpstream};
use infishark::{Device, protocol};

fn main() -> infishark::Result<()> {
    let mut dev = Device::open(None, 3_600_000)?;
    let result = session(&mut dev);
    let _ = dev.wifi_mitm_stop();
    result
}

fn session(dev: &mut Device) -> infishark::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut ssid = None;
    let mut upstream = None;
    let mut pass = String::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ssid" => ssid = args.next(),
            "--upstream-ssid" => upstream = args.next(),
            "--upstream-pass" => pass = args.next().unwrap_or_default(),
            other => return Err(infishark::Error::msg(format!("unknown arg {other}"))),
        }
    }
    let ssid = ssid.ok_or_else(|| infishark::Error::msg("pass --ssid"))?;
    let upstream = upstream.ok_or_else(|| infishark::Error::msg("pass --upstream-ssid"))?;
    let mut opts = WifiMitmOpts::new(
        ssid,
        WifiUpstream::Explicit {
            ssid: upstream,
            pass,
        },
    );
    opts.intercept_dns = true;
    opts.intercept_timeout_ms = 500;
    opts.dns_log = true;
    dev.set_read_timeout(Duration::from_millis(300))?;
    let ident = dev.wifi_mitm_start(&opts, |ev| println!("{ev}"))?;
    println!("{ident}");
    loop {
        match dev.next_event() {
            Ok((protocol::EVT_WIFI_MITM, payload)) => {
                let Ok(v) = serde_json::from_slice::<serde_json::Value>(&payload) else {
                    continue;
                };
                println!("{v}");
                if v.get("held").and_then(|h| h.as_bool()) == Some(true) {
                    if let Some(id) = v.get("id").and_then(|n| n.as_u64()) {
                        dev.wifi_mitm_action(id as u16, WifiMitmAction::Allow)?;
                    }
                }
            }
            Ok(_) | Err(infishark::Error::Timeout) => {}
            Err(e) => return Err(e),
        }
    }
}
