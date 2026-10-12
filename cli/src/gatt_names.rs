//! Format GATT enum with offline Bluetooth SIG Assigned Numbers.
//! Unknown (including vendor-specific) UUIDs stay unnamed.

use infishark::GattService;

// Only SIG 16-bit UUIDs (including their 128-bit Bluetooth-base form) can be
// assigned these names. In particular, never label a vendor's 128-bit UUID by
// matching just its first four hex digits.
pub(crate) fn sig_uuid16(uuid: &str) -> Option<u16> {
    let full = infishark::hex::bluetooth_uuid(uuid).ok()?;
    let compact: String = full.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if compact.len() != 32 || !compact.starts_with("0000") {
        return None;
    }
    if !compact.ends_with("00001000800000805f9b34fb") {
        return None;
    }
    u16::from_str_radix(&compact[4..8], 16).ok()
}

pub fn service(uuid: &str) -> Option<&'static str> {
    crate::gatt_assigned::service(sig_uuid16(uuid)?)
}

pub fn characteristic(uuid: &str) -> Option<&'static str> {
    crate::gatt_assigned::characteristic(sig_uuid16(uuid)?)
}

/// Preserve the existing GATT enum JSON, adding `name` only for known UUIDs.
pub fn named_services(services: &[GattService]) -> serde_json::Result<serde_json::Value> {
    let mut items = serde_json::to_value(services)?;
    if let Some(array) = items.as_array_mut() {
        for (item, s) in array.iter_mut().zip(services) {
            if let Some(name) = service(&s.uuid) {
                item["name"] = name.into();
            }
            if let Some(chars) = item["characteristics"].as_array_mut() {
                for (entry, c) in chars.iter_mut().zip(&s.characteristics) {
                    if let Some(name) = characteristic(&c.uuid) {
                        entry["name"] = name.into();
                    }
                }
            }
        }
    }
    Ok(serde_json::json!({ "count": services.len(), "services": items }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use infishark::GattChar;

    #[test]
    fn looks_up_only_sig_uuids_of_the_correct_kind() {
        assert_eq!(service("180F"), Some("Battery"));
        assert_eq!(service("0x1812"), Some("Human Interface Device"));
        assert_eq!(characteristic("00002A19"), Some("Battery Level"));
        assert_eq!(characteristic("0x2b3a"), Some("Server Supported Features"));
        assert_eq!(service("1802"), Some("Immediate Alert"));
        assert_eq!(service("1860"), Some("Tire Pressure Monitoring System"));
        assert_eq!(characteristic("2c00"), Some("GMAP Role"));
        assert_eq!(characteristic("2c42"), Some("Cookware Device ID"));
        assert_eq!(
            characteristic("00002a37-0000-1000-8000-00805F9B34FB"),
            Some("Heart Rate Measurement")
        );
        assert_eq!(service("2a19"), None);
        assert_eq!(characteristic("180f"), None);
        assert_eq!(service("12345678-0000-1000-8000-00805f9b34fb"), None);
        assert_eq!(characteristic("00002a19-0000-1000-8000-00805f9b34fc"), None);
        assert_eq!(service("abcd"), None);
        assert_eq!(service("\u{1f499}\u{1f499}"), None);
    }

    #[test]
    fn json_keeps_existing_fields_and_leaves_unknown_uuids_unmodified() {
        let services = [
            GattService {
                uuid: "0000180f-0000-1000-8000-00805f9b34fb".into(),
                handle: 1,
                end_handle: 4,
                characteristics: vec![
                    GattChar {
                        uuid: "2a19".into(),
                        handle: 3,
                        properties: vec!["read".into()],
                    },
                    GattChar {
                        uuid: "f00d".into(),
                        handle: 4,
                        properties: vec![],
                    },
                ],
            },
            GattService {
                uuid: "deadbeef-1234-5678-9abc-000000000000".into(),
                handle: 5,
                end_handle: 6,
                characteristics: vec![],
            },
        ];
        let value = named_services(&services).unwrap();
        assert_eq!(value["count"], 2);
        assert_eq!(value["services"][0]["name"], "Battery");
        assert_eq!(value["services"][0]["uuid"], services[0].uuid);
        assert_eq!(value["services"][0]["handle"], 1);
        assert_eq!(
            value["services"][0]["characteristics"][0]["name"],
            "Battery Level"
        );
        assert_eq!(
            value["services"][0]["characteristics"][0]["properties"][0],
            "read"
        );
        assert!(
            value["services"][0]["characteristics"][1]
                .get("name")
                .is_none()
        );
        assert_eq!(value["services"][1]["uuid"], services[1].uuid);
        assert!(value["services"][1].get("name").is_none());
    }
}
