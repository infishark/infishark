//! Device-side capture filter: only wanted frames cross the serial link.

use crate::hex;
use crate::ieee80211::{FrameType, Mac, mgmt_subtype};
use crate::json::insert_opt;
use serde_json::json;

/// One custom predicate: `frame[offset + i] & mask[i] == bytes[i]` for all i.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteMatch {
    pub offset: u16,
    pub bytes: Vec<u8>,
    pub mask: Vec<u8>,
}

impl ByteMatch {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "off": self.offset,
            "val": hex::encode_lower(&self.bytes),
            "mask": hex::encode_lower(&self.mask),
        })
    }
}

/// What the device forwards. A field at its zero/`None` value is not filtered
/// on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorFilter {
    pub types: u8,
    pub mgmt_subtypes: u16,
    pub ctrl_subtypes: u16,
    pub data_subtypes: u16,
    pub subtype_block: bool,
    pub ethertype: Option<u16>,
    pub addr: Option<Mac>,
    pub min_rssi: Option<i8>,
    pub max_rssi: Option<i8>,
    pub phy: Option<u8>,
    pub min_len: Option<u16>,
    pub max_len: Option<u16>,
    pub protected: Option<bool>,
    pub dedup: bool,
    pub matches: Vec<ByteMatch>,
}

impl MonitorFilter {
    pub fn all() -> Self {
        Self {
            types: FrameType::Mgmt.bit() | FrameType::Ctrl.bit() | FrameType::Data.bit(),
            mgmt_subtypes: 0,
            ctrl_subtypes: 0,
            data_subtypes: 0,
            subtype_block: false,
            ethertype: None,
            addr: None,
            min_rssi: None,
            max_rssi: None,
            phy: None,
            min_len: None,
            max_len: None,
            protected: None,
            dedup: false,
            matches: Vec::new(),
        }
    }

    pub fn eapol() -> Self {
        Self {
            types: FrameType::Data.bit(),
            ethertype: Some(0x888e),
            ..Self::all()
        }
    }

    pub fn deauth() -> Self {
        Self::mgmt_allow((1 << mgmt_subtype::DEAUTH) | (1 << mgmt_subtype::DISASSOC))
    }

    pub fn probe_req() -> Self {
        Self::mgmt_allow(1 << mgmt_subtype::PROBE_REQ)
    }

    pub fn beacons() -> Self {
        Self::mgmt_allow(1 << mgmt_subtype::BEACON)
    }

    pub fn no_beacons() -> Self {
        Self {
            types: FrameType::Mgmt.bit() | FrameType::Data.bit(),
            mgmt_subtypes: 1 << mgmt_subtype::BEACON,
            subtype_block: true,
            ..Self::all()
        }
    }

    fn mgmt_allow(mask: u16) -> Self {
        Self {
            types: FrameType::Mgmt.bit(),
            mgmt_subtypes: mask,
            ..Self::all()
        }
    }

    fn protected_tristate(&self) -> u8 {
        match self.protected {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("types".into(), self.types.into());
        m.insert("mgmt_subtypes".into(), self.mgmt_subtypes.into());
        m.insert("ctrl_subtypes".into(), self.ctrl_subtypes.into());
        m.insert("data_subtypes".into(), self.data_subtypes.into());
        m.insert("subtype_block".into(), self.subtype_block.into());
        m.insert("protected".into(), self.protected_tristate().into());
        m.insert("dedup".into(), self.dedup.into());
        insert_opt(&mut m, "ethertype", self.ethertype);
        insert_opt(&mut m, "addr", self.addr.map(|a| hex::encode_lower(&a)));
        insert_opt(&mut m, "min_rssi", self.min_rssi);
        insert_opt(&mut m, "max_rssi", self.max_rssi);
        insert_opt(&mut m, "phy", self.phy);
        insert_opt(&mut m, "min_len", self.min_len);
        insert_opt(&mut m, "max_len", self.max_len);
        if !self.matches.is_empty() {
            let arr: Vec<serde_json::Value> = self.matches.iter().map(ByteMatch::to_json).collect();
            m.insert("matches".into(), arr.into());
        }
        serde_json::Value::Object(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_forwards_every_type_unfiltered() {
        let f = MonitorFilter::all();
        assert_eq!(
            f.types,
            FrameType::Mgmt.bit() | FrameType::Ctrl.bit() | FrameType::Data.bit()
        );
        assert_eq!(f.protected, None);
        assert!(f.matches.is_empty());
    }

    #[test]
    fn eapol_is_data_with_ethertype_gate() {
        let f = MonitorFilter::eapol();
        assert_eq!(f.types, FrameType::Data.bit());
        assert_eq!(f.ethertype, Some(0x888e));
        assert_eq!(f.mgmt_subtypes, 0);
    }

    #[test]
    fn deauth_allows_deauth_and_disassoc() {
        let f = MonitorFilter::deauth();
        assert_eq!(f.types, FrameType::Mgmt.bit());
        assert!(!f.subtype_block);
        assert_eq!(
            f.mgmt_subtypes,
            (1 << mgmt_subtype::DEAUTH) | (1 << mgmt_subtype::DISASSOC)
        );
    }

    #[test]
    fn probe_req_and_beacons_target_one_subtype() {
        assert_eq!(
            MonitorFilter::probe_req().mgmt_subtypes,
            1 << mgmt_subtype::PROBE_REQ
        );
        assert_eq!(
            MonitorFilter::beacons().mgmt_subtypes,
            1 << mgmt_subtype::BEACON
        );
    }

    #[test]
    fn no_beacons_blocks_the_beacon_subtype() {
        let f = MonitorFilter::no_beacons();
        assert_eq!(f.types, FrameType::Mgmt.bit() | FrameType::Data.bit());
        assert!(f.subtype_block);
        assert_eq!(f.mgmt_subtypes, 1 << mgmt_subtype::BEACON);
    }

    #[test]
    fn to_json_emits_core_fields_and_omits_unset_options() {
        let v = MonitorFilter::deauth().to_json();
        assert_eq!(v["types"], 1);
        assert_eq!(v["mgmt_subtypes"], (1 << 12) | (1 << 10));
        assert_eq!(v["ctrl_subtypes"], 0);
        assert_eq!(v["subtype_block"], false);
        assert_eq!(v["protected"], 0);
        assert_eq!(v["dedup"], false);
        assert!(v.get("ethertype").is_none());
        assert!(v.get("addr").is_none());
        assert!(v.get("max_rssi").is_none());
        assert!(v.get("phy").is_none());
        assert!(v.get("min_len").is_none());
        assert!(v.get("max_len").is_none());
        assert!(v.get("matches").is_none());
    }

    #[test]
    fn to_json_emits_max_rssi_phy_len_and_dedup() {
        let mut f = MonitorFilter::all();
        f.max_rssi = Some(-40);
        f.phy = Some(1);
        f.min_len = Some(60);
        f.max_len = Some(1500);
        f.dedup = true;
        let v = f.to_json();
        assert_eq!(v["max_rssi"], -40);
        assert_eq!(v["phy"], 1);
        assert_eq!(v["min_len"], 60);
        assert_eq!(v["max_len"], 1500);
        assert_eq!(v["dedup"], true);
    }

    #[test]
    fn to_json_emits_ethertype_and_protected_tristate() {
        let mut f = MonitorFilter::all();
        f.ethertype = Some(0x888e);
        f.protected = Some(true);
        let v = f.to_json();
        assert_eq!(v["ethertype"], 0x888e);
        assert_eq!(v["protected"], 2);

        f.protected = Some(false);
        assert_eq!(f.to_json()["protected"], 1);
    }

    #[test]
    fn to_json_emits_addr_as_bare_lowercase_hex() {
        let mut f = MonitorFilter::all();
        f.addr = Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(f.to_json()["addr"], "aabbccddeeff");
    }

    #[test]
    fn to_json_emits_signed_min_rssi() {
        let mut f = MonitorFilter::all();
        f.min_rssi = Some(-70);
        assert_eq!(f.to_json()["min_rssi"], -70);
    }

    #[test]
    fn to_json_emits_matches_with_hex_val_and_mask() {
        let mut f = MonitorFilter::all();
        f.matches.push(ByteMatch {
            offset: 0,
            bytes: vec![0x80],
            mask: vec![0xfc],
        });
        let v = f.to_json();
        assert_eq!(v["matches"][0]["off"], 0);
        assert_eq!(v["matches"][0]["val"], "80");
        assert_eq!(v["matches"][0]["mask"], "fc");
    }
}
