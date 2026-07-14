//! 802.11 MAC frame builders (raw TX; the radio appends FCS) and a parser.
//!
//! Management frames and injectable control frames: CTS, RTS, BAR, PS-Poll.
//! ACK needs SIFS timing the host cannot hit, so it stays on raw hex.

use crate::error::{Context, Result};

/// A 48-bit MAC address, wire order.
pub type Mac = [u8; 6];

/// The broadcast address.
pub const BROADCAST: Mac = [0xff; 6];

/// Parse "AA:BB:CC:DD:EE:FF" (or '-' separated) into a [`Mac`].
pub fn parse_mac(s: &str) -> Result<Mac> {
    let mut mac = [0u8; 6];
    let mut n = 0;
    for part in s.split([':', '-']) {
        if n == 6 {
            bail!("MAC '{s}' has too many octets");
        }
        mac[n] = u8::from_str_radix(part, 16).with_context(|| format!("bad MAC octet '{part}'"))?;
        n += 1;
    }
    if n != 6 {
        bail!("MAC '{s}' needs 6 octets");
    }
    Ok(mac)
}

/// Management-frame subtype bitmask values (type is always 00 for these). Use
/// with `1 << [mgmt_subtype::type]`
pub mod mgmt_subtype {
    pub const ASSOC_REQ: u8 = 0;
    pub const ASSOC_RESP: u8 = 1;
    pub const REASSOC_REQ: u8 = 2;
    pub const REASSOC_RESP: u8 = 3;
    pub const PROBE_REQ: u8 = 4;
    pub const PROBE_RESP: u8 = 5;
    pub const BEACON: u8 = 8;
    pub const ATIM: u8 = 9;
    pub const DISASSOC: u8 = 10;
    pub const AUTH: u8 = 11;
    pub const DEAUTH: u8 = 12;
    pub const ACTION: u8 = 13;
}

/// Control-frame subtype values (type is always 01 for these).
pub mod ctrl_subtype {
    pub const BAR: u8 = 8;
    pub const BA: u8 = 9;
    pub const PS_POLL: u8 = 10;
    pub const RTS: u8 = 11;
    pub const CTS: u8 = 12;
    pub const ACK: u8 = 13;
    pub const CF_END: u8 = 14;
}

/// Data-frame subtype values (type is always 10 for these).
pub mod data_subtype {
    pub const DATA: u8 = 0;
    pub const NULL: u8 = 4;
    pub const QOS_DATA: u8 = 8;
    pub const QOS_NULL: u8 = 12;
}

/// Common EtherType values (carried after an LLC/SNAP header on data frames).
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const IPV6: u16 = 0x86dd;
    pub const EAPOL: u16 = 0x888e;
}

/// The 802.11 frame type (the FC type field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Mgmt = 0,
    Ctrl = 1,
    Data = 2,
    Ext = 3,
}

impl FrameType {
    fn from_fc(v: u8) -> Self {
        match v & 0x3 {
            0 => Self::Mgmt,
            1 => Self::Ctrl,
            2 => Self::Data,
            _ => Self::Ext,
        }
    }

    /// This type's bit in a monitor type-mask (`1 << the FC type field`).
    pub fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A parsed 802.11 frame (3-address); `body` starts after the MAC header.
pub struct Frame {
    pub ftype: FrameType,
    pub subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub protected: bool,
    pub addr1: Mac,
    pub addr2: Mac,
    pub addr3: Mac,
    pub body: Vec<u8>,
}

impl Frame {
    /// The BSSID under the To/From-DS address convention.
    pub fn bssid(&self) -> Mac {
        match (self.to_ds, self.from_ds) {
            (false, false) => self.addr3,
            (false, true) => self.addr2,
            (true, false) => self.addr1,
            (true, true) => self.addr3, // 4-addr WDS has no single BSSID
        }
    }

    /// The non-AP station of an infrastructure frame.
    pub fn station(&self) -> Mac {
        if self.from_ds { self.addr1 } else { self.addr2 }
    }

    /// Source address.
    pub fn src(&self) -> Mac {
        if self.from_ds { self.addr3 } else { self.addr2 }
    }

    /// Destination address.
    pub fn dst(&self) -> Mac {
        if self.to_ds { self.addr3 } else { self.addr1 }
    }
}

/// Parse the 802.11 MAC header; None if too short. `body` skips the QoS Control
/// and HT Control fields; 4-address WDS frames are not resolved.
/// Note that the device filters for bandwidth; this parser validates for
/// correctness.
pub fn parse_frame(f: &[u8]) -> Option<Frame> {
    if f.len() < 24 {
        return None;
    }
    let subtype = (f[0] >> 4) & 0xf;
    let ftype = FrameType::from_fc(f[0] >> 2);
    let qos = ftype == FrameType::Data && subtype & 0x8 != 0;
    let order = f[1] & 0x80 != 0;
    let hdr = 24 + if qos { 2 } else { 0 } + if qos && order { 4 } else { 0 };
    Some(Frame {
        ftype,
        subtype,
        to_ds: f[1] & 0x01 != 0,
        from_ds: f[1] & 0x02 != 0,
        protected: f[1] & 0x40 != 0,
        addr1: f[4..10].try_into().ok()?,
        addr2: f[10..16].try_into().ok()?,
        addr3: f[16..22].try_into().ok()?,
        body: f.get(hdr..).unwrap_or(&[]).to_vec(),
    })
}

#[cfg(test)]
mod frame_tests {
    use super::*;

    #[test]
    fn parses_beacon_type_subtype_bssid_and_body() {
        let mut f = vec![0x80, 0x00, 0, 0]; // mgmt, subtype 8 (beacon)
        f.extend_from_slice(&[0xff; 6]); // addr1
        f.extend_from_slice(&[0xAA; 6]); // addr2
        f.extend_from_slice(&[0xAA; 6]); // addr3 = bssid
        f.extend_from_slice(&[0, 0]); // seq
        f.extend_from_slice(b"body");
        let fr = parse_frame(&f).unwrap();
        assert_eq!(fr.ftype, FrameType::Mgmt);
        assert_eq!(fr.subtype, mgmt_subtype::BEACON);
        assert_eq!(fr.bssid(), [0xAA; 6]);
        assert_eq!(fr.body, b"body");
    }

    #[test]
    fn qos_data_body_skips_qos_control_and_ht_control() {
        let mut f = vec![0x88, 0x80, 0, 0]; // qos-data, Order bit -> +HTC
        f.extend_from_slice(&[0x11; 6]);
        f.extend_from_slice(&[0x22; 6]);
        f.extend_from_slice(&[0x33; 6]);
        f.extend_from_slice(&[0, 0]); // seq
        f.extend_from_slice(&[0, 0]); // qos control
        f.extend_from_slice(&[0, 0, 0, 0]); // ht control
        f.extend_from_slice(b"payload");
        assert_eq!(parse_frame(&f).unwrap().body, b"payload");
    }

    #[test]
    fn address_roles_follow_the_ds_bits() {
        let mut f = vec![0x08, 0x02, 0, 0]; // data, FromDS (AP -> station)
        f.extend_from_slice(&[0x11; 6]); // addr1 = station
        f.extend_from_slice(&[0xAA; 6]); // addr2 = bssid
        f.extend_from_slice(&[0x33; 6]); // addr3 = src
        f.extend_from_slice(&[0, 0]);
        let fr = parse_frame(&f).unwrap();
        assert_eq!(fr.bssid(), [0xAA; 6]);
        assert_eq!(fr.station(), [0x11; 6]);
        assert_eq!(fr.src(), [0x33; 6]);
        assert_eq!(fr.dst(), [0x11; 6]);
    }

    #[test]
    fn rejects_a_short_frame() {
        assert!(parse_frame(&[0x08, 0, 0]).is_none());
    }
}

/// An RSN cipher suite selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cipher {
    /// Pairwise selector meaning "use the group cipher".
    UseGroup,
    Wep40,
    Tkip,
    Ccmp128,
    Wep104,
    /// BIP-CMAC-128, group management-frame protection (PMF).
    BipCmac128,
    /// Group addressed traffic not allowed.
    GroupNotAllowed,
    Gcmp128,
    Gcmp256,
    Ccmp256,
    /// BIP-GMAC-128, group management-frame protection.
    BipGmac128,
    /// BIP-GMAC-256, group management-frame protection.
    BipGmac256,
    /// BIP-CMAC-256, group management-frame protection.
    BipCmac256,
}

impl Cipher {
    /// The suite-type byte (the fourth octet of the suite selector).
    pub fn suite_type(self) -> u8 {
        match self {
            Cipher::UseGroup => 0,
            Cipher::Wep40 => 1,
            Cipher::Tkip => 2,
            Cipher::Ccmp128 => 4,
            Cipher::Wep104 => 5,
            Cipher::BipCmac128 => 6,
            Cipher::GroupNotAllowed => 7,
            Cipher::Gcmp128 => 8,
            Cipher::Gcmp256 => 9,
            Cipher::Ccmp256 => 10,
            Cipher::BipGmac128 => 11,
            Cipher::BipGmac256 => 12,
            Cipher::BipCmac256 => 13,
        }
    }

    /// The cipher for a suite-type byte, or None if reserved/unknown.
    pub fn from_suite_type(t: u8) -> Option<Cipher> {
        Some(match t {
            0 => Cipher::UseGroup,
            1 => Cipher::Wep40,
            2 => Cipher::Tkip,
            4 => Cipher::Ccmp128,
            5 => Cipher::Wep104,
            6 => Cipher::BipCmac128,
            7 => Cipher::GroupNotAllowed,
            8 => Cipher::Gcmp128,
            9 => Cipher::Gcmp256,
            10 => Cipher::Ccmp256,
            11 => Cipher::BipGmac128,
            12 => Cipher::BipGmac256,
            13 => Cipher::BipCmac256,
            _ => return None,
        })
    }

    /// The cipher for a device scan-record string.
    pub fn from_device_str(s: &str) -> Option<Cipher> {
        Some(match s {
            "tkip" => Cipher::Tkip,
            "ccmp" | "tkip_ccmp" => Cipher::Ccmp128,
            "gcmp" => Cipher::Gcmp128,
            "gcmp256" => Cipher::Gcmp256,
            "wep40" => Cipher::Wep40,
            "wep104" => Cipher::Wep104,
            "aes_cmac128" => Cipher::BipCmac128,
            _ => return None,
        })
    }
}

/// An RSN AKM (authentication and key management) suite selector: the
/// suite-type byte under OUI 00-0F-AC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Akm {
    /// IEEE 802.1X / EAP (WPA-Enterprise).
    Dot1x,
    /// Pre-shared key (WPA-Personal).
    Psk,
    FtDot1x,
    FtPsk,
    Dot1xSha256,
    PskSha256,
    Tdls,
    /// Simultaneous Authentication of Equals (WPA3).
    Sae,
    FtSae,
    ApPeerKey,
    Dot1xSuiteBSha256,
    Dot1xSuiteBSha384,
    FtDot1xSha384,
    FilsSha256,
    FilsSha384,
    FtFilsSha256,
    FtFilsSha384,
    /// Opportunistic Wireless Encryption (enhanced open).
    Owe,
    FtPskSha384,
    PskSha384,
    Pasn,
}

impl Akm {
    /// The suite-type byte (the fourth octet of the suite selector).
    pub fn suite_type(self) -> u8 {
        match self {
            Akm::Dot1x => 1,
            Akm::Psk => 2,
            Akm::FtDot1x => 3,
            Akm::FtPsk => 4,
            Akm::Dot1xSha256 => 5,
            Akm::PskSha256 => 6,
            Akm::Tdls => 7,
            Akm::Sae => 8,
            Akm::FtSae => 9,
            Akm::ApPeerKey => 10,
            Akm::Dot1xSuiteBSha256 => 11,
            Akm::Dot1xSuiteBSha384 => 12,
            Akm::FtDot1xSha384 => 13,
            Akm::FilsSha256 => 14,
            Akm::FilsSha384 => 15,
            Akm::FtFilsSha256 => 16,
            Akm::FtFilsSha384 => 17,
            Akm::Owe => 18,
            Akm::FtPskSha384 => 19,
            Akm::PskSha384 => 20,
            Akm::Pasn => 21,
        }
    }

    /// The AKM for a suite-type byte, or None if reserved/unknown.
    pub fn from_suite_type(t: u8) -> Option<Akm> {
        Some(match t {
            1 => Akm::Dot1x,
            2 => Akm::Psk,
            3 => Akm::FtDot1x,
            4 => Akm::FtPsk,
            5 => Akm::Dot1xSha256,
            6 => Akm::PskSha256,
            7 => Akm::Tdls,
            8 => Akm::Sae,
            9 => Akm::FtSae,
            10 => Akm::ApPeerKey,
            11 => Akm::Dot1xSuiteBSha256,
            12 => Akm::Dot1xSuiteBSha384,
            13 => Akm::FtDot1xSha384,
            14 => Akm::FilsSha256,
            15 => Akm::FilsSha384,
            16 => Akm::FtFilsSha256,
            17 => Akm::FtFilsSha384,
            18 => Akm::Owe,
            19 => Akm::FtPskSha384,
            20 => Akm::PskSha384,
            21 => Akm::Pasn,
            _ => return None,
        })
    }
}

/// A tagged information element: an id byte, a length byte, then the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ie {
    pub id: u8,
    pub data: Vec<u8>,
}

impl Ie {
    /// SSID element. An empty string is the wildcard SSID.
    pub fn ssid(ssid: &str) -> Ie {
        Ie {
            id: 0,
            data: ssid.as_bytes().to_vec(),
        }
    }

    /// Supported Rates; empty = default b/g set, else 500 kbps-unit rate bytes.
    pub fn supported_rates(rates: &[u8]) -> Ie {
        let data = if rates.is_empty() {
            vec![0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c]
        } else {
            rates.to_vec()
        };
        Ie { id: 1, data }
    }

    /// DS Parameter Set element, carrying the current channel.
    pub fn ds_param(channel: u8) -> Ie {
        Ie {
            id: 3,
            data: vec![channel],
        }
    }

    /// A WPA2 robust security network element with the given group + pairwise
    /// ciphers and pre-shared key (PSK) authentication and key management.
    pub fn rsn_psk(group: Cipher, pairwise: Cipher) -> Ie {
        const OUI: [u8; 3] = [0x00, 0x0f, 0xac];
        let mut data = vec![0x01, 0x00]; // version 1
        data.extend_from_slice(&OUI); // group cipher suite
        data.push(group.suite_type());
        data.extend_from_slice(&[0x01, 0x00]); // 1 pairwise cipher
        data.extend_from_slice(&OUI);
        data.push(pairwise.suite_type());
        data.extend_from_slice(&[0x01, 0x00]); // 1 AKM
        data.extend_from_slice(&OUI);
        data.push(0x02); // PSK
        data.extend_from_slice(&[0x00, 0x00]); // RSN capabilities
        Ie { id: 48, data }
    }

    /// A standard WPA2 RSN element: CCMP group + pairwise cipher, PSK AKM.
    pub fn rsn_ccmp_psk() -> Ie {
        Ie::rsn_psk(Cipher::Ccmp128, Cipher::Ccmp128)
    }

    /// Element with a caller-supplied id and body.
    pub fn raw(id: u8, data: Vec<u8>) -> Ie {
        Ie { id, data }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.id);
        out.push(self.data.len() as u8);
        out.extend_from_slice(&self.data);
    }
}

fn encode_ies(ies: &[Ie], out: &mut Vec<u8>) {
    for ie in ies {
        ie.encode(out);
    }
}

fn seq_ctrl_le(v: u16) -> [u8; 2] {
    ((v & 0x0fff) << 4).to_le_bytes()
}

/// The subtype-specific part of a management frame: fixed fields then any IEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Deauth {
        reason: u16,
    },
    Disassoc {
        reason: u16,
    },
    Auth {
        algo: u16,
        seq: u16,
        status: u16,
        ies: Vec<Ie>,
    },
    Beacon {
        interval: u16,
        capability: u16,
        ies: Vec<Ie>,
    },
    ProbeResp {
        interval: u16,
        capability: u16,
        ies: Vec<Ie>,
    },
    ProbeReq {
        ies: Vec<Ie>,
    },
    AssocReq {
        capability: u16,
        listen_interval: u16,
        ies: Vec<Ie>,
    },
    AssocResp {
        capability: u16,
        status: u16,
        aid: u16,
        ies: Vec<Ie>,
    },
    ReassocReq {
        capability: u16,
        listen_interval: u16,
        current_ap: Mac,
        ies: Vec<Ie>,
    },
    ReassocResp {
        capability: u16,
        status: u16,
        aid: u16,
        ies: Vec<Ie>,
    },
    Action {
        category: u8,
        data: Vec<u8>,
    },
}

impl Body {
    fn subtype(&self) -> u8 {
        match self {
            Body::AssocReq { .. } => mgmt_subtype::ASSOC_REQ,
            Body::AssocResp { .. } => mgmt_subtype::ASSOC_RESP,
            Body::ReassocReq { .. } => mgmt_subtype::REASSOC_REQ,
            Body::ReassocResp { .. } => mgmt_subtype::REASSOC_RESP,
            Body::ProbeReq { .. } => mgmt_subtype::PROBE_REQ,
            Body::ProbeResp { .. } => mgmt_subtype::PROBE_RESP,
            Body::Beacon { .. } => mgmt_subtype::BEACON,
            Body::Disassoc { .. } => mgmt_subtype::DISASSOC,
            Body::Auth { .. } => mgmt_subtype::AUTH,
            Body::Deauth { .. } => mgmt_subtype::DEAUTH,
            Body::Action { .. } => mgmt_subtype::ACTION,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Body::Deauth { reason } | Body::Disassoc { reason } => {
                out.extend_from_slice(&reason.to_le_bytes());
            }
            Body::Auth {
                algo,
                seq,
                status,
                ies,
            } => {
                out.extend_from_slice(&algo.to_le_bytes());
                out.extend_from_slice(&seq.to_le_bytes());
                out.extend_from_slice(&status.to_le_bytes());
                encode_ies(ies, out);
            }
            Body::Beacon {
                interval,
                capability,
                ies,
            }
            | Body::ProbeResp {
                interval,
                capability,
                ies,
            } => {
                out.extend_from_slice(&0u64.to_le_bytes()); // timestamp (ignored on injection)
                out.extend_from_slice(&interval.to_le_bytes());
                out.extend_from_slice(&capability.to_le_bytes());
                encode_ies(ies, out);
            }
            Body::ProbeReq { ies } => encode_ies(ies, out),
            Body::AssocReq {
                capability,
                listen_interval,
                ies,
            } => {
                out.extend_from_slice(&capability.to_le_bytes());
                out.extend_from_slice(&listen_interval.to_le_bytes());
                encode_ies(ies, out);
            }
            Body::AssocResp {
                capability,
                status,
                aid,
                ies,
            }
            | Body::ReassocResp {
                capability,
                status,
                aid,
                ies,
            } => {
                out.extend_from_slice(&capability.to_le_bytes());
                out.extend_from_slice(&status.to_le_bytes());
                out.extend_from_slice(&aid.to_le_bytes());
                encode_ies(ies, out);
            }
            Body::ReassocReq {
                capability,
                listen_interval,
                current_ap,
                ies,
            } => {
                out.extend_from_slice(&capability.to_le_bytes());
                out.extend_from_slice(&listen_interval.to_le_bytes());
                out.extend_from_slice(current_ap);
                encode_ies(ies, out);
            }
            Body::Action { category, data } => {
                out.push(*category);
                out.extend_from_slice(data);
            }
        }
    }
}

/// A management frame: the 24-byte MAC header plus a typed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mgmt {
    /// Address 1: receiver / destination.
    pub addr1: Mac,
    /// Address 2: transmitter / source.
    pub addr2: Mac,
    /// Address 3: BSSID.
    pub addr3: Mac,
    pub duration: u16,
    /// Sequence number (0-4095); occupies the top 12 bits of Sequence Control.
    pub seq: u16,
    pub body: Body,
}

impl Mgmt {
    /// Serialize to wire bytes, without the trailing FCS.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut f = Vec::with_capacity(64);
        f.push(self.body.subtype() << 4); // FC byte 0: version 0, type 00 (mgmt), subtype
        f.push(0x00); // FC byte 1: flags
        f.extend_from_slice(&self.duration.to_le_bytes());
        f.extend_from_slice(&self.addr1);
        f.extend_from_slice(&self.addr2);
        f.extend_from_slice(&self.addr3);
        f.extend_from_slice(&seq_ctrl_le(self.seq));
        self.body.encode(&mut f);
        f
    }
}

fn mgmt(addr1: Mac, addr2: Mac, addr3: Mac, body: Body) -> Mgmt {
    Mgmt {
        addr1,
        addr2,
        addr3,
        duration: 0,
        seq: 0,
        body,
    }
}

/// Deauth from `ap` aimed at `station`; [`BROADCAST`] hits all clients.
pub fn deauth(ap: Mac, station: Mac, reason: u16) -> Mgmt {
    mgmt(station, ap, ap, Body::Deauth { reason })
}

/// Disassociation from `ap` aimed at `station`.
pub fn disassoc(ap: Mac, station: Mac, reason: u16) -> Mgmt {
    mgmt(station, ap, ap, Body::Disassoc { reason })
}

/// Beacon advertising `ssid` on `channel`, sourced from `bssid`.
pub fn beacon(bssid: Mac, ssid: &str, channel: u8) -> Mgmt {
    mgmt(
        BROADCAST,
        bssid,
        bssid,
        Body::Beacon {
            interval: 100,
            capability: 0x0021, // ESS + short preamble
            ies: vec![
                Ie::ssid(ssid),
                Ie::supported_rates(&[]),
                Ie::ds_param(channel),
            ],
        },
    )
}

/// Probe request for `ssid` (empty = wildcard), sourced from `source`.
pub fn probe_req(source: Mac, ssid: &str) -> Mgmt {
    mgmt(
        BROADCAST,
        source,
        BROADCAST,
        Body::ProbeReq {
            ies: vec![Ie::ssid(ssid), Ie::supported_rates(&[])],
        },
    )
}

/// Open-system Auth (algo 0, seq 1) from `sta` to `ap`; step 1 of association.
pub fn auth_open(ap: Mac, sta: Mac) -> Mgmt {
    mgmt(
        ap,
        sta,
        ap,
        Body::Auth {
            algo: 0,
            seq: 1,
            status: 0,
            ies: vec![],
        },
    )
}

/// Association request from `sta` to `ap` for `ssid`; `ies_extra` follows the
/// SSID + rates elements.
pub fn assoc_req(ap: Mac, sta: Mac, ssid: &str, ies_extra: Vec<Ie>) -> Mgmt {
    let mut ies = vec![Ie::ssid(ssid), Ie::supported_rates(&[])];
    ies.extend(ies_extra);
    mgmt(
        ap,
        sta,
        ap,
        Body::AssocReq {
            capability: 0x0031, // ESS + short preamble + privacy
            listen_interval: 1,
            ies,
        },
    )
}

const FC_TYPE_CTRL: u8 = 0b01 << 2;
const BAR_COMPRESSED: u16 = 1 << 2;

/// A control frame; only the injectable subtypes are modeled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ctrl {
    /// Clear To Send. "CTS-to-self" (`ra` = own MAC) sets every listener's NAV.
    Cts { ra: Mac, duration: u16 },
    /// Request To Send; `duration` sets the NAV. NAV-DoS pair to [`Ctrl::Cts`].
    Rts { ra: Mac, ta: Mac, duration: u16 },
    /// PS-Poll: poll `bssid` for frames buffered for `ta` (assoc id `aid`).
    PsPoll { bssid: Mac, ta: Mac, aid: u16 },
    /// Block Ack Request; `ssn` past the peer's window desyncs its block-ack.
    Bar {
        ra: Mac,
        ta: Mac,
        tid: u8,
        ssn: u16,
        duration: u16,
    },
}

impl Ctrl {
    fn subtype(&self) -> u8 {
        match self {
            Ctrl::Bar { .. } => ctrl_subtype::BAR,
            Ctrl::PsPoll { .. } => ctrl_subtype::PS_POLL,
            Ctrl::Rts { .. } => ctrl_subtype::RTS,
            Ctrl::Cts { .. } => ctrl_subtype::CTS,
        }
    }

    /// Serialize to wire bytes, without the trailing FCS.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut f = Vec::with_capacity(24);
        f.push((self.subtype() << 4) | FC_TYPE_CTRL); // FC byte 0: version 0, type 01 (ctrl), subtype
        f.push(0x00); // FC byte 1: flags
        match self {
            Ctrl::Cts { ra, duration } => {
                f.extend_from_slice(&duration.to_le_bytes());
                f.extend_from_slice(ra);
            }
            Ctrl::Rts { ra, ta, duration } => {
                f.extend_from_slice(&duration.to_le_bytes());
                f.extend_from_slice(ra);
                f.extend_from_slice(ta);
            }
            Ctrl::PsPoll { bssid, ta, aid } => {
                f.extend_from_slice(&(aid | 0xc000).to_le_bytes()); // AID in the Duration/ID field, top two bits set
                f.extend_from_slice(bssid);
                f.extend_from_slice(ta);
            }
            Ctrl::Bar {
                ra,
                ta,
                tid,
                ssn,
                duration,
            } => {
                f.extend_from_slice(&duration.to_le_bytes());
                f.extend_from_slice(ra);
                f.extend_from_slice(ta);
                f.extend_from_slice(&((u16::from(*tid) << 12) | BAR_COMPRESSED).to_le_bytes());
                f.extend_from_slice(&seq_ctrl_le(*ssn));
            }
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: Mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const STA: Mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    #[test]
    fn deauth_wire_layout() {
        let f = deauth(AP, STA, 7).to_bytes();
        assert_eq!(f.len(), 26); // 24 header + 2 reason
        assert_eq!(&f[0..2], &[0xc0, 0x00]); // deauth frame control
        assert_eq!(&f[4..10], &STA); // addr1 = receiver
        assert_eq!(&f[10..16], &AP); // addr2 = source
        assert_eq!(&f[16..22], &AP); // addr3 = bssid
        assert_eq!(&f[24..26], &7u16.to_le_bytes()); // reason
    }

    #[test]
    fn sequence_number_sits_in_top_12_bits() {
        let mut m = deauth(AP, STA, 1);
        m.seq = 1;
        let f = m.to_bytes();
        assert_eq!(&f[22..24], &[0x10, 0x00]);
    }

    #[test]
    fn beacon_carries_ssid_and_channel() {
        let f = beacon(AP, "test", 6).to_bytes();
        assert_eq!(f[0] >> 4, mgmt_subtype::BEACON);
        // header 24 + timestamp 8 + interval 2 + capability 2 = 36 (then IEs)
        assert_eq!(&f[36..38], &[0, 4]); // SSID element id 0, len 4
        assert_eq!(&f[38..42], b"test");
        // SSID(2+4) then Supported Rates(2+8) then DS param(2+1)
        let ds = 36 + 6 + 10;
        assert_eq!(&f[ds..ds + 3], &[3, 1, 6]); // DS param id 3, len 1, channel 6
    }

    #[test]
    fn ie_encodes_id_len_data() {
        let mut out = Vec::new();
        Ie::ssid("ab").encode(&mut out);
        assert_eq!(out, vec![0, 2, b'a', b'b']);
    }

    #[test]
    fn wildcard_ssid_is_zero_length() {
        assert_eq!(Ie::ssid("").data.len(), 0);
    }

    #[test]
    fn default_rates_are_nonempty() {
        assert_eq!(Ie::supported_rates(&[]).data.len(), 8);
        assert_eq!(Ie::supported_rates(&[0x82]).data, vec![0x82]);
    }

    #[test]
    fn parse_mac_accepts_colons_and_dashes() {
        assert_eq!(parse_mac("00:11:22:33:44:55").unwrap(), AP);
        assert_eq!(parse_mac("aa-bb-cc-dd-ee-ff").unwrap(), STA);
        assert!(parse_mac("00:11:22:33:44").is_err());
        assert!(parse_mac("zz:11:22:33:44:55").is_err());
    }

    fn ie_present(ies: &[u8], id: u8) -> bool {
        let mut i = 0;
        while i + 2 <= ies.len() {
            if ies[i] == id {
                return true;
            }
            i += 2 + ies[i + 1] as usize;
        }
        false
    }

    #[test]
    fn auth_open_is_subtype_11_algo0_seq1() {
        let f = auth_open(AP, STA).to_bytes();
        assert_eq!(f[0] >> 4, mgmt_subtype::AUTH);
        assert_eq!(&f[4..10], &AP); // addr1 = receiver (AP)
        assert_eq!(&f[10..16], &STA); // addr2 = fake client
        assert_eq!(&f[24..30], &[0, 0, 1, 0, 0, 0]); // algo 0, seq 1, status 0
    }

    #[test]
    fn assoc_req_carries_ssid_and_rsn_ie() {
        let f = assoc_req(AP, STA, "net", vec![Ie::rsn_ccmp_psk()]).to_bytes();
        assert_eq!(f[0] >> 4, mgmt_subtype::ASSOC_REQ);
        let ies = &f[28..]; // header 24 + capability 2 + listen_interval 2
        assert_eq!(ies[0], 0); // first element is the SSID
        assert!(ie_present(ies, 48)); // RSN element present
        assert_eq!(Ie::rsn_ccmp_psk().data.len(), 20);
    }

    #[test]
    fn rsn_psk_encodes_group_and_pairwise_ciphers() {
        let ie = Ie::rsn_psk(Cipher::Tkip, Cipher::Ccmp128); // mixed net
        assert_eq!(ie.id, 48);
        assert_eq!(&ie.data[2..6], &[0x00, 0x0f, 0xac, 0x02]); // group = TKIP
        assert_eq!(&ie.data[8..12], &[0x00, 0x0f, 0xac, 0x04]); // pairwise = CCMP
        assert_eq!(&ie.data[14..18], &[0x00, 0x0f, 0xac, 0x02]); // AKM = PSK
        assert_eq!(
            Ie::rsn_ccmp_psk(),
            Ie::rsn_psk(Cipher::Ccmp128, Cipher::Ccmp128)
        );
    }

    #[test]
    fn cipher_suite_type_round_trips() {
        for c in [
            Cipher::Tkip,
            Cipher::Ccmp128,
            Cipher::Gcmp256,
            Cipher::BipCmac256,
        ] {
            assert_eq!(Cipher::from_suite_type(c.suite_type()), Some(c));
        }
        assert_eq!(Cipher::from_suite_type(3), None); // reserved
    }

    #[test]
    fn cipher_from_device_str_maps_scan_names() {
        assert_eq!(Cipher::from_device_str("ccmp"), Some(Cipher::Ccmp128));
        assert_eq!(Cipher::from_device_str("tkip"), Some(Cipher::Tkip));
        assert_eq!(Cipher::from_device_str("tkip_ccmp"), Some(Cipher::Ccmp128)); // strongest
        assert_eq!(Cipher::from_device_str("gcmp256"), Some(Cipher::Gcmp256));
        assert_eq!(Cipher::from_device_str("none"), None);
        assert_eq!(Cipher::from_device_str("sms4"), None); // WAPI, unsupported
    }

    #[test]
    fn akm_suite_type_round_trips() {
        for a in [Akm::Psk, Akm::Sae, Akm::Dot1x, Akm::Owe, Akm::Pasn] {
            assert_eq!(Akm::from_suite_type(a.suite_type()), Some(a));
        }
        assert_eq!(Akm::from_suite_type(0), None); // reserved
        assert_eq!(Akm::from_suite_type(200), None);
    }

    #[test]
    fn cts_to_self_wire_layout() {
        let f = Ctrl::Cts {
            ra: STA,
            duration: 3000,
        }
        .to_bytes();
        assert_eq!(f.len(), 10);
        assert_eq!(&f[0..2], &[0xc4, 0x00]);
        assert_eq!(&f[2..4], &3000u16.to_le_bytes());
        assert_eq!(&f[4..10], &STA);
    }

    #[test]
    fn rts_has_receiver_and_transmitter() {
        let f = Ctrl::Rts {
            ra: STA,
            ta: AP,
            duration: 100,
        }
        .to_bytes();
        assert_eq!(f.len(), 16);
        assert_eq!(&f[0..2], &[0xb4, 0x00]);
        assert_eq!(&f[4..10], &STA);
        assert_eq!(&f[10..16], &AP);
    }

    #[test]
    fn ps_poll_sets_aid_high_bits() {
        let f = Ctrl::PsPoll {
            bssid: AP,
            ta: STA,
            aid: 5,
        }
        .to_bytes();
        assert_eq!(f.len(), 16);
        assert_eq!(&f[0..2], &[0xa4, 0x00]);
        assert_eq!(&f[2..4], &(5u16 | 0xc000).to_le_bytes());
        assert_eq!(&f[4..10], &AP);
        assert_eq!(&f[10..16], &STA);
    }

    #[test]
    fn bar_places_ssn_in_ssc() {
        let f = Ctrl::Bar {
            ra: STA,
            ta: AP,
            tid: 0,
            ssn: 100,
            duration: 0,
        }
        .to_bytes();
        assert_eq!(f.len(), 20);
        assert_eq!(&f[0..2], &[0x84, 0x00]);
        assert_eq!(&f[4..10], &STA);
        assert_eq!(&f[10..16], &AP);
        assert_eq!(&f[16..18], &[0x04, 0x00]);
        assert_eq!(&f[18..20], &(100u16 << 4).to_le_bytes());
    }
}
