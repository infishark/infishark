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
    pub rssi: i8,
    #[serde(default)]
    pub channel: u8,
    #[serde(default)]
    pub encryption: String,
    /// Host-resolved OUI vendor; omitted until enriched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Every other field present in the scan record (ciphers, PHY, country,
    /// ...).
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

    pub fn extra_str(&self, key: &str) -> &str {
        self.extra.get(key).and_then(|v| v.as_str()).unwrap_or("")
    }

    pub fn extra_bool(&self, key: &str) -> bool {
        match self.extra.get(key) {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::Number(n)) => n.as_u64() == Some(1),
            Some(serde_json::Value::String(s)) => {
                matches!(s.to_ascii_lowercase().as_str(), "true" | "yes" | "1")
            }
            _ => false,
        }
    }

    pub fn extra_num(&self, key: &str) -> String {
        match self.extra.get(key) {
            Some(serde_json::Value::Number(x)) => x.to_string(),
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => String::new(),
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

/// Captive-portal SoftAP / content options for
/// [`crate::Device::wifi_portal_start`]. Omitted fields keep device session
/// defaults (settings SSID, open AP, ch 1, etc).
#[derive(Debug, Clone, Default)]
pub struct PortalOpts {
    /// Stream HTML bodies from the host (`EVT_PORTAL_REQUEST` /
    /// `CMD_PORTAL_RESP`).
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

/// One BLE device aggregated from a scan
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
    /// Saved on the Nano (paired); may not be advertising.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub paired: bool,
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

    /// Fold a newer sighting into this entry (same address).
    pub fn merge_from(&mut self, newer: &BleDevice) {
        if let Some(n) = newer.name.as_ref().filter(|s| !s.is_empty()) {
            self.name = Some(n.clone());
        }
        self.rssi = newer.rssi;
        if self.addr_type.is_none() {
            self.addr_type = newer.addr_type;
        }
        if newer.company_id.is_some() {
            self.company_id = newer.company_id;
        }
        if newer.vendor.as_ref().is_some_and(|s| !s.is_empty()) {
            self.vendor = newer.vendor.clone();
        }
        if newer.company.as_ref().is_some_and(|s| !s.is_empty()) {
            self.company = newer.company.clone();
        }
        if newer.paired {
            self.paired = true;
        }
        for (k, v) in &newer.extra {
            merge_extra_field(&mut self.extra, k, v);
        }
    }
}

/// Merge one JSON extra field: sticky true for connectable/scannable; skip
/// null/empty overwrites that would wipe earlier enrichment.
fn merge_extra_field(
    extra: &mut BTreeMap<String, serde_json::Value>,
    key: &str,
    value: &serde_json::Value,
) {
    if value.is_null() {
        return;
    }
    if value.as_str() == Some("") {
        return;
    }
    if value.as_array().is_some_and(|a| a.is_empty()) {
        if !extra.contains_key(key) {
            extra.insert(key.to_string(), value.clone());
        }
        return;
    }
    match key {
        "connectable" | "scannable" => {
            if value.as_bool() == Some(true) {
                extra.insert(key.to_string(), value.clone());
            } else if !extra.contains_key(key) {
                extra.insert(key.to_string(), value.clone());
            }
        }
        _ => {
            extra.insert(key.to_string(), value.clone());
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
    /// Wire arg object for the scan request (only non-default overrides are
    /// emitted).
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        insert_flag(&mut m, "active", self.active, true.into());
        insert_opt(&mut m, "dwell_ms", self.dwell_ms);
        insert_opt(&mut m, "channel", self.channel.filter(|&c| c != 0));
        insert_flag(&mut m, "show_hidden", self.hide_hidden, false.into());
        insert_opt(&mut m, "ssid", self.ssid.clone());
        insert_opt(&mut m, "bssid", self.bssid.clone());
        serde_json::Value::Object(m)
    }
}

/// BLE scan request. Default is an active scan (scan responses / names).
/// Set [`BleScanOpts::passive`] for listen-only in dense RF. Other `None`
/// fields use device defaults (10s, controller interval/window, dedup off, 1M).
#[derive(Debug, Clone, Default)]
pub struct BleScanOpts {
    pub duration_ms: Option<u32>,
    /// When true, listen only (no SCAN_REQ). Default false = active scan.
    pub passive: bool,
    pub interval: Option<u16>,
    pub window: Option<u16>,
    pub dedup: bool,
    /// 1 = 1M, 2 = Coded, 3 = both.
    pub scan_phy: Option<u8>,
}

impl BleScanOpts {
    /// Wire arg object for the scan request (only non-default overrides are
    /// emitted).
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        insert_opt(&mut m, "duration_ms", self.duration_ms);
        // Always emit active: device defaults to passive if the key is absent.
        m.insert("active".into(), (!self.passive).into());
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
        insert_flag(
            &mut m,
            "addr_type",
            self.addr_type != 0,
            self.addr_type.into(),
        );
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

/// Host decision for one intercepted ATT PDU (`ble mitm --intercept`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MitmAction {
    Allow,
    Drop,
    Replace(Vec<u8>),
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
    fn wifi_opts_omit_channel_zero() {
        let j = WifiScanOpts {
            channel: Some(0),
            ..Default::default()
        }
        .to_json();
        assert!(j.get("channel").is_none());
    }

    #[test]
    fn ble_opts_emit_active_true_by_default() {
        let j = BleScanOpts::default().to_json();
        assert_eq!(j["active"], true);
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

    #[test]
    fn ble_device_merge_keeps_name_when_later_sighting_is_nameless() {
        let mut d = BleDevice {
            address: "aa:bb:cc:dd:ee:ff".into(),
            name: Some("Device123".into()),
            rssi: -50,
            addr_type: Some(1),
            company_id: Some(0x004c),
            vendor: None,
            company: None,
            paired: false,
            extra: BTreeMap::from([("connectable".into(), serde_json::json!(true))]),
        };
        let later = BleDevice {
            address: "aa:bb:cc:dd:ee:ff".into(),
            name: None,
            rssi: -62,
            addr_type: Some(1),
            company_id: None,
            vendor: None,
            company: None,
            paired: false,
            extra: BTreeMap::from([
                ("connectable".into(), serde_json::json!(false)),
                ("rssi_ema".into(), serde_json::json!(-60)),
            ]),
        };
        d.merge_from(&later);
        assert_eq!(d.name.as_deref(), Some("Device123"));
        assert_eq!(d.rssi, -62);
        assert_eq!(d.company_id, Some(0x004c));
        assert_eq!(d.extra.get("connectable"), Some(&serde_json::json!(true)));
        assert_eq!(d.extra.get("rssi_ema"), Some(&serde_json::json!(-60)));
    }

    #[test]
    fn ble_device_merge_takes_newer_nonempty_name() {
        let mut d = BleDevice {
            address: "aa:bb:cc:dd:ee:ff".into(),
            name: None,
            rssi: -70,
            addr_type: None,
            company_id: None,
            vendor: None,
            company: None,
            paired: false,
            extra: BTreeMap::new(),
        };
        let later = BleDevice {
            address: "aa:bb:cc:dd:ee:ff".into(),
            name: Some("Device123".into()),
            rssi: -41,
            addr_type: Some(0),
            company_id: None,
            vendor: None,
            company: None,
            paired: false,
            extra: BTreeMap::new(),
        };
        d.merge_from(&later);
        assert_eq!(d.name.as_deref(), Some("Device123"));
        assert_eq!(d.addr_type, Some(0));
        assert_eq!(d.rssi, -41);
    }
}
