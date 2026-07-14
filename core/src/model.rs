//! Typed data model for the device's recon output, plus the scan-option
//! structs that encode a scan request.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::company;
use crate::json::{insert_flag, insert_opt};
use crate::oui;

/// One Wi-Fi access point from a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub bssid: String,
    #[serde(default)]
    pub ssid: String,
    #[serde(default)]
    pub rssi: i64,
    #[serde(default)]
    pub channel: i64,
    #[serde(default)]
    pub encryption: String,
    /// Host-resolved OUI vendor; omitted until enriched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Every other field present in the scan record (ciphers, PHY, country, ...).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Network {
    pub fn enrich(&mut self, oui: Option<&oui::Db>) {
        if let Some(db) = oui {
            if let Some(v) = db.lookup(&self.bssid) {
                self.vendor = Some(v.to_string());
            }
        }
    }
}

/// One entry in the device's saved-network store. Passwords never leave the
/// device, so this carries only the slot index and SSID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedNetwork {
    pub index: u8,
    pub ssid: String,
}

/// What network the Wi-Fi adapter should join.
#[derive(Debug, Clone)]
pub enum AdapterTarget {
    /// A saved-network slot on the device (credentials stay on-device).
    Saved(u8),
    /// Explicit credentials, sent for this session only and not persisted.
    Explicit { ssid: String, pass: String },
}

impl std::fmt::Display for AdapterTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterTarget::Saved(index) => write!(f, "saved network {index}"),
            AdapterTarget::Explicit { ssid, .. } => write!(f, "network {ssid:?}"),
        }
    }
}

/// Optional per-association settings for [`AdapterTarget`].
#[derive(Debug, Clone, Default)]
pub struct AdapterConfig {
    pub randomize_mac: bool,
    pub hostname: Option<String>,
}

/// Captive-portal SoftAP / content options for [`crate::Device::wifi_portal_start`].
/// Omitted fields keep device session defaults (settings SSID, open AP, ch 1, …).
#[derive(Debug, Clone, Default)]
pub struct PortalOpts {
    /// Stream HTML bodies from the host (`EVT_PORTAL_REQUEST` / `CMD_PORTAL_RESP`).
    pub host_content: bool,
    pub ssid: Option<String>,
    /// WPA2-PSK passphrase; `None` or empty = open network.
    pub pass: Option<String>,
    pub channel: Option<u8>,
    pub hidden: bool,
    pub max_clients: Option<u8>,
    pub mac: Option<String>,
    pub random_mac: bool,
    pub ip: Option<String>,
    pub netmask: Option<String>,
    pub beacon_ms: Option<u16>,
    pub detailed_capture: Option<bool>,
    pub host_timeout_ms: Option<u32>,
}

impl PortalOpts {
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("host_content".into(), self.host_content.into());
        if let Some(s) = &self.ssid {
            m.insert("ssid".into(), s.clone().into());
        }
        if let Some(p) = &self.pass {
            m.insert("pass".into(), p.clone().into());
        }
        if let Some(c) = self.channel {
            m.insert("channel".into(), c.into());
        }
        if self.hidden {
            m.insert("hidden".into(), true.into());
        }
        if let Some(n) = self.max_clients {
            m.insert("max_clients".into(), n.into());
        }
        if let Some(mac) = &self.mac {
            m.insert("mac".into(), mac.clone().into());
        }
        if self.random_mac {
            m.insert("random_mac".into(), true.into());
        }
        if let Some(ip) = &self.ip {
            m.insert("ip".into(), ip.clone().into());
        }
        if let Some(nm) = &self.netmask {
            m.insert("netmask".into(), nm.clone().into());
        }
        if let Some(b) = self.beacon_ms {
            m.insert("beacon_ms".into(), b.into());
        }
        if let Some(d) = self.detailed_capture {
            m.insert("detailed_capture".into(), d.into());
        }
        if let Some(t) = self.host_timeout_ms {
            m.insert("host_timeout_ms".into(), t.into());
        }
        serde_json::Value::Object(m)
    }
}

/// One BLE device aggregated from a scan (latest sighting wins).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleDevice {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub rssi: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr_type: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company_id: Option<u16>,
    /// Host-resolved OUI vendor (public addresses only); omitted until
    /// enriched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Host-resolved Bluetooth SIG manufacturer name; omitted until enriched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl BleDevice {
    /// Whether this address class carries a real OUI (public /
    /// public-identity).
    fn has_public_oui(&self) -> bool {
        matches!(self.addr_type, Some(0) | Some(2))
    }

    /// Fill `vendor` (public addresses only) and override `company` from the
    /// SIG database.
    pub fn enrich(&mut self, oui: Option<&oui::Db>, companies: Option<&company::Db>) {
        if self.has_public_oui() {
            if let Some(db) = oui {
                if let Some(v) = db.lookup(&self.address) {
                    self.vendor = Some(v.to_string());
                }
            }
        }
        if let Some(db) = companies {
            if let Some(id) = self.company_id {
                if let Some(name) = db.lookup(id) {
                    self.company = Some(name.to_string());
                }
            }
        }
    }
}

/// Wi-Fi scan request. `None`/`false` fields use the device default (passive,
/// driver dwell, all channels, hidden APs included, no SSID/BSSID filter).
#[derive(Debug, Clone, Default)]
pub struct WifiScanOpts {
    pub active: bool,
    pub dwell_ms: Option<u32>,
    pub channel: Option<u8>,
    pub hide_hidden: bool,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
}

impl WifiScanOpts {
    /// Wire arg object for the scan request (only non-default overrides are emitted).
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        insert_flag(&mut m, "active", self.active, true.into());
        insert_opt(&mut m, "dwell_ms", self.dwell_ms);
        insert_opt(&mut m, "channel", self.channel);
        insert_flag(&mut m, "show_hidden", self.hide_hidden, false.into());
        insert_opt(&mut m, "ssid", self.ssid.clone());
        insert_opt(&mut m, "bssid", self.bssid.clone());
        serde_json::Value::Object(m)
    }
}

/// BLE scan request. `None`/`false` fields use the device default (10s active
/// scan, controller interval/window, dedup off, SCAN_ALL PHY).
#[derive(Debug, Clone, Default)]
pub struct BleScanOpts {
    pub duration_ms: Option<u32>,
    pub passive: bool,
    pub interval: Option<u16>,
    pub window: Option<u16>,
    pub dedup: bool,
    /// BLE PHY mask: 1 = 1M, 2 = Coded, 3 = both.
    pub scan_phy: Option<u8>,
}

impl BleScanOpts {
    /// Wire arg object for the scan request (only non-default overrides are emitted).
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        insert_opt(&mut m, "duration_ms", self.duration_ms);
        insert_flag(&mut m, "active", self.passive, false.into());
        insert_opt(&mut m, "interval", self.interval);
        insert_opt(&mut m, "window", self.window);
        insert_flag(&mut m, "dedup", self.dedup, true.into());
        insert_opt(&mut m, "scan_phy", self.scan_phy);
        serde_json::Value::Object(m)
    }
}

/// One characteristic in a discovered GATT tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GattChar {
    pub uuid: String,
    pub handle: u16,
    #[serde(default)]
    pub properties: Vec<String>,
}

/// One service (with its characteristics) in a discovered GATT tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GattService {
    pub uuid: String,
    pub handle: u16,
    pub end_handle: u16,
    #[serde(default)]
    pub characteristics: Vec<GattChar>,
}

/// One GATT notification or indication pushed by a subscribed characteristic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GattNotification {
    #[serde(rename = "char")]
    pub characteristic: String,
    pub handle: u16,
    pub is_notify: bool,
    pub hex: String,
}

impl GattNotification {
    /// Decode the value bytes.
    pub fn value(&self) -> crate::Result<Vec<u8>> {
        crate::hex::decode(&self.hex)
    }
}

/// Options for a GATT-central connection.
#[derive(Debug, Clone, Default)]
pub struct GattConnectOpts {
    pub addr_type: u8, // 0=public, 1=random
    pub timeout_ms: Option<u32>,
    pub min_interval: Option<u16>,
    pub max_interval: Option<u16>,
    pub latency: Option<u16>,
    pub supervision_timeout: Option<u16>,
    pub secure: bool,
    pub bond: bool,
    pub mitm: bool,
    pub sc: bool,
    pub io_cap: Option<u8>,
    pub passkey: Option<u32>,
}

impl GattConnectOpts {
    /// Wire arg object for the connect request.
    pub fn to_json(&self, address: &str) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("address".into(), address.into());
        insert_flag(&mut m, "addr_type", self.addr_type != 0, self.addr_type.into());
        insert_opt(&mut m, "timeout_ms", self.timeout_ms);
        insert_opt(&mut m, "min_interval", self.min_interval);
        insert_opt(&mut m, "max_interval", self.max_interval);
        insert_opt(&mut m, "latency", self.latency);
        insert_opt(&mut m, "supervision_timeout", self.supervision_timeout);
        insert_flag(&mut m, "secure", self.secure, true.into());
        insert_flag(&mut m, "bond", self.bond, true.into());
        insert_flag(&mut m, "mitm", self.mitm, true.into());
        insert_flag(&mut m, "sc", self.sc, true.into());
        insert_opt(&mut m, "io_cap", self.io_cap);
        insert_opt(&mut m, "passkey", self.passkey);
        serde_json::Value::Object(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn oui_db(prefix_hex: u32, name: &str) -> oui::Db {
        oui::Db::from_map(HashMap::from([(prefix_hex, name.to_string())]))
    }

    #[test]
    fn network_enrich_sets_known_vendor_and_leaves_unknown() {
        let db = oui_db(0x001B63, "Apple, Inc.");
        let mut known: Network = serde_json::from_str(r#"{"bssid":"00:1B:63:11:22:33"}"#).unwrap();
        let mut unknown: Network =
            serde_json::from_str(r#"{"bssid":"FF:FF:FF:00:00:00"}"#).unwrap();
        known.enrich(Some(&db));
        unknown.enrich(Some(&db));
        assert_eq!(known.vendor.as_deref(), Some("Apple, Inc."));
        assert!(unknown.vendor.is_none());
        // Unenriched vendor is omitted on the wire.
        assert!(!serde_json::to_string(&unknown).unwrap().contains("vendor"));
    }

    #[test]
    fn network_preserves_unknown_fields_in_extra() {
        let n: Network =
            serde_json::from_str(r#"{"bssid":"x","ssid":"a","pairwise_cipher":"ccmp"}"#).unwrap();
        assert_eq!(n.extra.get("pairwise_cipher").unwrap(), "ccmp");
        // Round-trips back out.
        assert!(
            serde_json::to_string(&n)
                .unwrap()
                .contains("pairwise_cipher")
        );
    }

    #[test]
    fn ble_enrich_resolves_public_address_only() {
        let db = oui_db(0x001B63, "Apple, Inc.");
        let mut public: BleDevice =
            serde_json::from_str(r#"{"address":"00:1B:63:11:22:33","addr_type":0}"#).unwrap();
        let mut random: BleDevice =
            serde_json::from_str(r#"{"address":"00:1B:63:AA:BB:CC","addr_type":1}"#).unwrap();
        public.enrich(Some(&db), None);
        random.enrich(Some(&db), None);
        assert_eq!(public.vendor.as_deref(), Some("Apple, Inc."));
        assert!(random.vendor.is_none());
    }

    #[test]
    fn ble_company_override_keeps_value_on_miss() {
        let db = company::Db::from_map(HashMap::from([(0x004Cu16, "Apple, Inc.".to_string())]));
        let mut known: BleDevice =
            serde_json::from_str(r#"{"address":"x","company_id":76}"#).unwrap();
        let mut unknown: BleDevice =
            serde_json::from_str(r#"{"address":"y","company_id":65535,"company":"Stale"}"#)
                .unwrap();
        known.enrich(None, Some(&db));
        unknown.enrich(None, Some(&db));
        assert_eq!(known.company.as_deref(), Some("Apple, Inc."));
        assert_eq!(unknown.company.as_deref(), Some("Stale"));
    }

    #[test]
    fn enrich_without_db_is_noop() {
        let mut n: Network = serde_json::from_str(r#"{"bssid":"00:1B:63:11:22:33"}"#).unwrap();
        n.enrich(None);
        assert!(n.vendor.is_none());
    }

    #[test]
    fn gatt_connect_opts_require_address_emit_overrides() {
        let opts = GattConnectOpts {
            addr_type: 1,
            passkey: Some(123456),
            ..Default::default()
        };
        let j = opts.to_json("AA:BB:CC:DD:EE:FF");
        assert_eq!(j["address"], "AA:BB:CC:DD:EE:FF");
        assert_eq!(j["addr_type"], 1);
        assert_eq!(j["passkey"], 123456);
        assert!(j.get("bond").is_none()); // default -> omitted
    }

    #[test]
    fn ble_opts_emit_only_overrides() {
        let opts = BleScanOpts {
            passive: true,
            scan_phy: Some(2),
            ..Default::default()
        };
        let j = opts.to_json();
        assert_eq!(j["active"], false);
        assert_eq!(j["scan_phy"], 2);
        assert!(j.get("interval").is_none());
    }
}
