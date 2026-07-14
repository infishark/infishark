use anyhow::Result;
use infishark::hex;
use infishark::ieee80211;
use infishark::monitor::{ByteMatch, MonitorFilter};

pub struct MonitorArgs<'a> {
    pub filter: Option<&'a str>,
    pub types: &'a [String],
    pub subtype: &'a [String],
    pub ctrl_subtype: &'a [String],
    pub data_subtype: &'a [String],
    pub block: bool,
    pub ethertype: Option<&'a str>,
    pub bssid: Option<&'a str>,
    pub min_rssi: Option<i8>,
    pub max_rssi: Option<i8>,
    pub phy: Option<&'a str>,
    pub min_len: Option<u16>,
    pub max_len: Option<u16>,
    pub dedup: bool,
    pub encrypted: bool,
    pub unencrypted: bool,
    pub matches: &'a [String],
    pub vendor: Option<&'a str>,
    pub src: Option<&'a str>,
    pub dst: Option<&'a str>,
}

impl MonitorArgs<'_> {
    fn any_raw(&self) -> bool {
        !self.types.is_empty()
            || !self.subtype.is_empty()
            || !self.ctrl_subtype.is_empty()
            || !self.data_subtype.is_empty()
            || self.block
            || self.ethertype.is_some()
            || self.bssid.is_some()
            || self.min_rssi.is_some()
            || self.max_rssi.is_some()
            || self.phy.is_some()
            || self.min_len.is_some()
            || self.max_len.is_some()
            || self.dedup
            || self.encrypted
            || self.unencrypted
            || !self.matches.is_empty()
            || self.vendor.is_some()
            || self.src.is_some()
            || self.dst.is_some()
    }
}

pub fn build_monitor_filter(a: &MonitorArgs) -> Result<MonitorFilter> {
    if let Some(p) = a.filter {
        if a.any_raw() {
            anyhow::bail!("--filter is a preset; drop it to use the raw filter flags");
        }
        return preset(p);
    }
    let mut f = MonitorFilter::all();
    if !a.types.is_empty() {
        f.types = types_mask(a.types)?;
    }
    if !a.subtype.is_empty() {
        f.mgmt_subtypes = subtype_mask(a.subtype, mgmt_subtype_num)?;
    }
    if !a.ctrl_subtype.is_empty() {
        f.ctrl_subtypes = subtype_mask(a.ctrl_subtype, ctrl_subtype_num)?;
    }
    if !a.data_subtype.is_empty() {
        f.data_subtypes = subtype_mask(a.data_subtype, data_subtype_num)?;
    }
    f.subtype_block = a.block;
    if let Some(e) = a.ethertype {
        f.ethertype = Some(ethertype_num(e)?);
    }
    if let Some(b) = a.bssid {
        f.addr = Some(ieee80211::parse_mac(b)?);
    }
    f.min_rssi = a.min_rssi;
    f.max_rssi = a.max_rssi;
    if let Some(p) = a.phy {
        f.phy = Some(phy_num(p)?);
    }
    f.min_len = a.min_len;
    f.max_len = a.max_len;
    f.dedup = a.dedup;
    f.protected = if a.encrypted {
        Some(true)
    } else if a.unencrypted {
        Some(false)
    } else {
        None
    };
    for m in a.matches {
        f.matches.push(parse_match(m)?);
    }
    if let Some(oui) = a.vendor {
        f.matches.push(vendor_match(oui)?);
    }
    if let Some(mac) = a.src {
        f.matches.push(mac_match(10, mac)?);
    }
    if let Some(mac) = a.dst {
        f.matches.push(mac_match(4, mac)?);
    }
    if f.matches.len() > 8 {
        anyhow::bail!("at most 8 filter predicates ({} given)", f.matches.len());
    }
    Ok(f)
}

fn phy_num(s: &str) -> Result<u8> {
    Ok(match s {
        "legacy" => 0,
        "ht" => 1,
        "vht" => 2,
        "he" => 3,
        _ => s.parse().map_err(|_| anyhow::anyhow!("bad --phy '{s}'"))?,
    })
}

/// A 3-byte OUI (`0017f2` or `00:17:f2`) matched against addr2.
fn vendor_match(s: &str) -> Result<ByteMatch> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 3 {
        anyhow::bail!("--vendor '{s}' needs a 3-byte OUI");
    }
    Ok(ByteMatch {
        offset: 10,
        bytes,
        mask: vec![0xff; 3],
    })
}

fn mac_match(offset: u16, mac: &str) -> Result<ByteMatch> {
    Ok(ByteMatch {
        offset,
        bytes: ieee80211::parse_mac(mac)?.to_vec(),
        mask: vec![0xff; 6],
    })
}

fn preset(p: &str) -> Result<MonitorFilter> {
    Ok(match p {
        "all" => MonitorFilter::all(),
        "eapol" => MonitorFilter::eapol(),
        "deauth" => MonitorFilter::deauth(),
        "probe-req" => MonitorFilter::probe_req(),
        "beacons" => MonitorFilter::beacons(),
        "no-beacons" => MonitorFilter::no_beacons(),
        other => anyhow::bail!("unknown --filter preset '{other}'"),
    })
}

fn types_mask(types: &[String]) -> Result<u8> {
    let mut m = 0u8;
    for t in types {
        m |= match t.as_str() {
            "mgmt" => ieee80211::FrameType::Mgmt.bit(),
            "data" => ieee80211::FrameType::Data.bit(),
            "ctrl" => ieee80211::FrameType::Ctrl.bit(),
            o => anyhow::bail!("unknown --type '{o}'"),
        };
    }
    Ok(m)
}

fn subtype_mask(names: &[String], resolve: impl Fn(&str) -> Result<u8>) -> Result<u16> {
    let mut m = 0u16;
    for s in names {
        m |= 1u16 << resolve(s)?;
    }
    Ok(m)
}

fn mgmt_subtype_num(s: &str) -> Result<u8> {
    use ieee80211::mgmt_subtype as st;
    Ok(match s {
        "assoc-req" => st::ASSOC_REQ,
        "assoc-resp" => st::ASSOC_RESP,
        "reassoc-req" => st::REASSOC_REQ,
        "reassoc-resp" => st::REASSOC_RESP,
        "probe-req" => st::PROBE_REQ,
        "probe-resp" => st::PROBE_RESP,
        "beacon" => st::BEACON,
        "atim" => st::ATIM,
        "disassoc" => st::DISASSOC,
        "auth" => st::AUTH,
        "deauth" => st::DEAUTH,
        "action" => st::ACTION,
        _ => subtype_num(s)?,
    })
}

fn ctrl_subtype_num(s: &str) -> Result<u8> {
    use ieee80211::ctrl_subtype as ct;
    Ok(match s {
        "bar" => ct::BAR,
        "ba" => ct::BA,
        "ps-poll" => ct::PS_POLL,
        "rts" => ct::RTS,
        "cts" => ct::CTS,
        "ack" => ct::ACK,
        "cf-end" => ct::CF_END,
        _ => subtype_num(s)?,
    })
}

fn data_subtype_num(s: &str) -> Result<u8> {
    use ieee80211::data_subtype as dt;
    Ok(match s {
        "data" => dt::DATA,
        "null" => dt::NULL,
        "qos-data" => dt::QOS_DATA,
        "qos-null" => dt::QOS_NULL,
        _ => subtype_num(s)?,
    })
}

fn subtype_num(s: &str) -> Result<u8> {
    let n: u8 = s
        .parse()
        .map_err(|_| anyhow::anyhow!("unknown subtype '{s}'"))?;
    if n > 15 {
        anyhow::bail!("subtype {n} out of range (0-15)");
    }
    Ok(n)
}

fn ethertype_num(s: &str) -> Result<u16> {
    Ok(match s {
        "eapol" => 0x888e,
        "arp" => 0x0806,
        "ipv4" => 0x0800,
        "ipv6" => 0x86dd,
        _ => {
            let h = s.strip_prefix("0x").unwrap_or(s);
            u16::from_str_radix(h, 16).map_err(|_| anyhow::anyhow!("bad --ethertype '{s}'"))?
        }
    })
}

/// Parse `<offset>:<hexbytes>[/<hexmask>]`; the mask defaults to all-0xff.
pub fn parse_match(s: &str) -> Result<ByteMatch> {
    let (off, rest) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("bad --match '{s}': expected OFFSET:HEX[/HEX]"))?;
    let offset: u16 = off
        .parse()
        .map_err(|_| anyhow::anyhow!("bad --match offset '{off}'"))?;
    let (bytes_hex, mask_hex) = match rest.split_once('/') {
        Some((b, m)) => (b, Some(m)),
        None => (rest, None),
    };
    let bytes = hex::decode(bytes_hex)?;
    if bytes.is_empty() || bytes.len() > 16 {
        anyhow::bail!("--match '{s}' needs 1..=16 bytes");
    }
    let mask = match mask_hex {
        Some(m) => {
            let mask = hex::decode(m)?;
            if mask.len() != bytes.len() {
                anyhow::bail!("--match '{s}' mask and bytes differ in length");
            }
            mask
        }
        None => vec![0xff; bytes.len()],
    };
    Ok(ByteMatch {
        offset,
        bytes,
        mask,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args<'a>() -> MonitorArgs<'a> {
        MonitorArgs {
            filter: None,
            types: &[],
            subtype: &[],
            ctrl_subtype: &[],
            data_subtype: &[],
            block: false,
            ethertype: None,
            bssid: None,
            min_rssi: None,
            max_rssi: None,
            phy: None,
            min_len: None,
            max_len: None,
            dedup: false,
            encrypted: false,
            unencrypted: false,
            matches: &[],
            vendor: None,
            src: None,
            dst: None,
        }
    }

    #[test]
    fn preset_expands() {
        let mut a = args();
        a.filter = Some("deauth");
        let f = build_monitor_filter(&a).unwrap();
        assert_eq!(f.mgmt_subtypes, (1 << 12) | (1 << 10));
    }

    #[test]
    fn preset_rejects_extra_raw_flags() {
        let mut a = args();
        a.filter = Some("all");
        a.block = true;
        assert!(build_monitor_filter(&a).is_err());
    }

    #[test]
    fn raw_type_and_subtype_compose() {
        let types = vec!["mgmt".to_string()];
        let subtype = vec!["probe-req".to_string()];
        let mut a = args();
        a.types = &types;
        a.subtype = &subtype;
        let f = build_monitor_filter(&a).unwrap();
        assert_eq!(f.types, ieee80211::FrameType::Mgmt.bit());
        assert_eq!(f.mgmt_subtypes, 1 << 4);
    }

    #[test]
    fn ctrl_and_data_and_atim_subtype_names_resolve() {
        assert_eq!(ctrl_subtype_num("cf-end").unwrap(), 14);
        assert_eq!(ctrl_subtype_num("ba").unwrap(), 9);
        assert_eq!(data_subtype_num("qos-data").unwrap(), 8);
        assert_eq!(mgmt_subtype_num("atim").unwrap(), 9);
    }

    #[test]
    fn unknown_subtype_falls_back_to_number_in_range() {
        assert_eq!(mgmt_subtype_num("7").unwrap(), 7);
        assert!(mgmt_subtype_num("16").is_err());
        assert!(ctrl_subtype_num("nope").is_err());
    }

    #[test]
    fn ethertype_names_and_hex_resolve() {
        assert_eq!(ethertype_num("eapol").unwrap(), 0x888e);
        assert_eq!(ethertype_num("arp").unwrap(), 0x0806);
        assert_eq!(ethertype_num("ipv4").unwrap(), 0x0800);
        assert_eq!(ethertype_num("ipv6").unwrap(), 0x86dd);
        assert_eq!(ethertype_num("0x0806").unwrap(), 0x0806);
        assert_eq!(ethertype_num("888e").unwrap(), 0x888e);
        assert!(ethertype_num("zzz").is_err());
    }

    #[test]
    fn match_uses_default_all_ones_mask() {
        let m = parse_match("0:80").unwrap();
        assert_eq!(m.offset, 0);
        assert_eq!(m.bytes, vec![0x80]);
        assert_eq!(m.mask, vec![0xff]);
    }

    #[test]
    fn match_takes_an_explicit_mask() {
        let m = parse_match("4:aabb/f0f0").unwrap();
        assert_eq!(m.offset, 4);
        assert_eq!(m.bytes, vec![0xaa, 0xbb]);
        assert_eq!(m.mask, vec![0xf0, 0xf0]);
    }

    #[test]
    fn match_rejects_over_16_bytes() {
        let s = format!("0:{}", "aa".repeat(17));
        assert!(parse_match(&s).is_err());
    }

    #[test]
    fn match_rejects_mask_length_mismatch() {
        assert!(parse_match("0:aabb/ff").is_err());
    }

    #[test]
    fn raw_composes_addr_rssi_protected_and_matches() {
        let matches = vec!["0:80/fc".to_string()];
        let mut a = args();
        a.bssid = Some("aa:bb:cc:dd:ee:ff");
        a.min_rssi = Some(-70);
        a.encrypted = true;
        a.matches = &matches;
        let f = build_monitor_filter(&a).unwrap();
        assert_eq!(f.addr, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(f.min_rssi, Some(-70));
        assert_eq!(f.protected, Some(true));
        assert_eq!(f.matches.len(), 1);
    }

    #[test]
    fn too_many_matches_rejected() {
        let matches: Vec<String> = (0..9).map(|i| format!("{i}:aa")).collect();
        let mut a = args();
        a.matches = &matches;
        assert!(build_monitor_filter(&a).is_err());
    }

    #[test]
    fn eight_predicates_including_aliases_pass() {
        let matches: Vec<String> = (0..6).map(|i| format!("{i}:aa")).collect();
        let mut a = args();
        a.matches = &matches;
        a.src = Some("aa:bb:cc:dd:ee:ff");
        a.dst = Some("11:22:33:44:55:66");
        let f = build_monitor_filter(&a).unwrap();
        assert_eq!(f.matches.len(), 8);
        let mut a9 = args();
        a9.matches = &matches;
        a9.src = Some("aa:bb:cc:dd:ee:ff");
        a9.dst = Some("11:22:33:44:55:66");
        a9.vendor = Some("0017f2");
        assert!(build_monitor_filter(&a9).is_err());
    }

    #[test]
    fn phy_names_and_numbers_resolve() {
        assert_eq!(phy_num("legacy").unwrap(), 0);
        assert_eq!(phy_num("ht").unwrap(), 1);
        assert_eq!(phy_num("vht").unwrap(), 2);
        assert_eq!(phy_num("he").unwrap(), 3);
        assert_eq!(phy_num("1").unwrap(), 1);
        assert!(phy_num("nope").is_err());
    }

    #[test]
    fn vendor_src_dst_build_the_right_predicates() {
        let mut a = args();
        a.vendor = Some("00:17:f2");
        a.src = Some("aa:bb:cc:dd:ee:ff");
        a.dst = Some("11:22:33:44:55:66");
        let f = build_monitor_filter(&a).unwrap();
        assert_eq!(f.matches.len(), 3);
        assert_eq!(f.matches[0].offset, 10);
        assert_eq!(f.matches[0].bytes, vec![0x00, 0x17, 0xf2]);
        assert_eq!(f.matches[1].offset, 10);
        assert_eq!(f.matches[1].bytes, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(f.matches[2].offset, 4);
        assert_eq!(f.matches[2].bytes, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn max_rssi_len_and_dedup_compose() {
        let mut a = args();
        a.max_rssi = Some(-40);
        a.min_len = Some(60);
        a.max_len = Some(1500);
        a.dedup = true;
        let f = build_monitor_filter(&a).unwrap();
        assert_eq!(f.max_rssi, Some(-40));
        assert_eq!(f.min_len, Some(60));
        assert_eq!(f.max_len, Some(1500));
        assert!(f.dedup);
    }
}
