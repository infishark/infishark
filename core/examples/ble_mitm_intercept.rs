//! BLE MITM with host intercept. Auto-allows every PDU; swap the callback
//! to drop or replace HID reports.
//!
//!   cargo run -p infishark --example ble_mitm_intercept -- AA:BB:CC:DD:EE:FF

use infishark::{Device, MitmAction};

fn main() -> infishark::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .expect("usage: ble_mitm_intercept <ble-address>");
    let mut spec = serde_json::Map::new();
    spec.insert("address".into(), addr.into());
    spec.insert("intercept".into(), true.into());
    spec.insert("intercept_timeout_ms".into(), 40.into());

    let mut dev = Device::open(None, 120_000)?;
    let ident = dev.ble_mitm_start(&serde_json::Value::Object(spec), |ev| {
        eprintln!("setup {}", ev);
    })?;
    eprintln!("cloned {ident}");
    dev.set_read_timeout(std::time::Duration::from_millis(300))?;
    loop {
        match dev.next_event() {
            Ok((infishark::protocol::EVT_BLE_MITM, payload)) => {
                let v: serde_json::Value =
                    serde_json::from_slice(&payload).unwrap_or_else(|_| serde_json::json!({}));
                eprintln!("{v}");
                if let Some(id) = v.get("id").and_then(|x| x.as_u64()) {
                    // Example: drop a specific HID key-down instead of Allow.
                    // if v.get("hex").and_then(|h| h.as_str()) == Some("00090000000000") {
                    //     dev.ble_mitm_action(id as u8, MitmAction::Drop)?;
                    //     continue;
                    // }
                    dev.ble_mitm_action(id as u8, MitmAction::Allow)?;
                }
            }
            Ok(_) => {}
            Err(infishark::Error::Timeout) => continue,
            Err(e) => return Err(e),
        }
    }
}
