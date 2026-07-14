//! Parse EAPOL, assemble the WPA 4-way / PMKID, emit pcap + hashcat 22000.

use crate::ieee80211::{FrameType, Mac, beacon, ethertype, parse_frame};
use crate::pcap::{LINKTYPE_IEEE802_11_RADIOTAP, write_global_header, write_radiotap_record};

/// EAPOL-Key key_info bits (big-endian on the wire).
pub const KI_PAIRWISE: u16 = 1 << 3;
pub const KI_INSTALL: u16 = 1 << 6;
pub const KI_ACK: u16 = 1 << 7;
pub const KI_MIC: u16 = 1 << 8;
pub const KI_SECURE: u16 = 1 << 9;

/// The fields the handshake assembly needs. This is a parsed EAPOL-Key frame.
pub struct EapolView {
    pub bssid: Mac,
    pub station: Mac,
    pub key_info: u16,
    pub nonce: [u8; 32],
    pub mic: [u8; 16],
    pub key_data: Vec<u8>,
    pub eapol: Vec<u8>,
}

// LLC/SNAP header preceding the EtherType on a data frame.
const LLC_SNAP: [u8; 6] = [0xAA, 0xAA, 0x03, 0, 0, 0];

/// Parse a captured 802.11 frame as an EAPOL-Key, or None if it isn't one.
pub fn parse_eapol(f: &[u8]) -> Option<EapolView> {
    let frame = parse_frame(f)?;
    if frame.ftype != FrameType::Data {
        return None;
    }
    // The data body is LLC/SNAP, its EtherType, then the EAPOL-Key PDU.
    let b = &frame.body;
    let is_eapol = b.len() >= 8
        && b.starts_with(&LLC_SNAP)
        && u16::from_be_bytes([b[6], b[7]]) == ethertype::EAPOL;
    if !is_eapol {
        return None;
    }
    let e = &b[8..];
    if e.len() < 99 || e[1] != 3 {
        return None; // not an EAPOL-Key PDU (type 3)
    }
    let kd_len = u16::from_be_bytes([e[97], e[98]]) as usize;
    Some(EapolView {
        bssid: frame.bssid(),
        station: frame.station(),
        key_info: u16::from_be_bytes([e[5], e[6]]),
        nonce: e[17..49].try_into().ok()?,
        mic: e[81..97].try_into().ok()?,
        key_data: e.get(99..99 + kd_len).unwrap_or(&[]).to_vec(),
        eapol: e.to_vec(),
    })
}

/// The 4-way message number (1-4) from the key_info bits, if it is one.
pub fn message_number(ki: u16) -> Option<u8> {
    if ki & KI_PAIRWISE == 0 {
        return None;
    }
    let (ack, mic, install, secure) = (
        ki & KI_ACK != 0,
        ki & KI_MIC != 0,
        ki & KI_INSTALL != 0,
        ki & KI_SECURE != 0,
    );
    match (ack, mic, install, secure) {
        (true, false, _, _) => Some(1),
        (false, true, false, false) => Some(2),
        (true, true, true, _) => Some(3),
        (false, true, false, true) => Some(4),
        _ => None,
    }
}

/// The PMKID from an M1's key-data KDEs (OUI 00:0F:AC, type 4), if present.
pub fn pmkid_from_key_data(kd: &[u8]) -> Option<[u8; 16]> {
    let mut i = 0;
    while i + 2 <= kd.len() {
        let len = kd[i + 1] as usize;
        let body = kd.get(i + 2..i + 2 + len)?;
        if kd[i] == 0xDD && len >= 20 && body[0..3] == [0x00, 0x0F, 0xAC] && body[3] == 0x04 {
            return body[4..20].try_into().ok();
        }
        i += 2 + len;
    }
    None
}

/// One captured EAPOL message with its PHY metadata and full 802.11 bytes.
pub struct CapturedMsg {
    pub rssi: i8,
    pub channel: u8,
    pub frame: Vec<u8>,
    pub view: EapolView,
}

/// Single-target capture session: M1-M4 and/or a PMKID for one AP.
pub struct Handshake {
    pub ssid: String,
    pub bssid: Mac,
    pub channel: u8,
    pub ap_rssi: i8,
    pub station: Option<Mac>,
    pub pmkid: Option<[u8; 16]>,
    pub msgs: [Option<CapturedMsg>; 4],
}

impl Handshake {
    pub fn new(bssid: Mac, ssid: &str, channel: u8) -> Self {
        Self {
            ssid: ssid.to_string(),
            bssid,
            channel,
            ap_rssi: 0,
            station: None,
            pmkid: None,
            msgs: [None, None, None, None],
        }
    }

    /// Fold in a captured frame; true if it advanced the session.
    pub fn add_frame(&mut self, rssi: i8, channel: u8, frame: &[u8]) -> bool {
        let Some(view) = parse_eapol(frame) else {
            return false;
        };
        if view.bssid != self.bssid {
            return false;
        }
        let Some(msg) = message_number(view.key_info) else {
            return false;
        };
        if msg == 1 {
            // A fresh M1 (re)locks the client and restarts the 4-way.
            self.station = Some(view.station);
            if let Some(p) = pmkid_from_key_data(&view.key_data) {
                self.pmkid = Some(p);
            }
            self.msgs[1] = None;
            self.msgs[2] = None;
            self.msgs[3] = None;
        } else if self.station.is_none() && msg == 3 {
            self.station = Some(view.station); // late join: M3 bootstraps the lock
        } else if self.station != Some(view.station) {
            return false; // other clients' M2-M4 don't count
        }
        if msg == 1 || msg == 3 {
            self.ap_rssi = rssi; // M1/M3 are AP-sourced
        }
        self.msgs[(msg - 1) as usize] = Some(CapturedMsg {
            rssi,
            channel,
            frame: frame.to_vec(),
            view,
        });
        true
    }

    /// A PMKID, or an ANonce (M1/M3) plus a usable SNonce+MIC (M2/M4).
    pub fn crackable(&self) -> bool {
        self.pmkid.is_some() || (self.anonce_msg().is_some() && self.supplicant_msg().is_some())
    }

    // The AP->STA message carrying the ANonce: prefer M1, else M3; flag marks M3.
    fn anonce_msg(&self) -> Option<(&CapturedMsg, bool)> {
        self.msgs[0]
            .as_ref()
            .map(|m| (m, false))
            .or_else(|| self.msgs[2].as_ref().map(|m| (m, true)))
    }

    // The client message with SNonce+MIC+EAPOL: prefer M2, else a non-zero-nonce M4
    // (M4 is often sent zeroed in the wild); flag marks M4.
    fn supplicant_msg(&self) -> Option<(&CapturedMsg, bool)> {
        if let Some(m2) = self.msgs[1].as_ref() {
            return Some((m2, false));
        }
        self.msgs[3]
            .as_ref()
            .filter(|m4| m4.view.nonce != [0u8; 32])
            .map(|m| (m, true))
    }

    /// Radiotap pcap: a synth beacon (for the ESSID) then captured frames.
    pub fn to_pcap<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        write_global_header(w, LINKTYPE_IEEE802_11_RADIOTAP)?;
        let bcn = beacon(self.bssid, &self.ssid, self.channel).to_bytes();
        write_radiotap_record(w, self.ap_rssi, self.channel, &bcn)?;
        for m in self.msgs.iter().flatten() {
            write_radiotap_record(w, m.rssi, m.channel, &m.frame)?;
        }
        Ok(())
    }

    /// hashcat mode 22000 lines: a PMKID line and/or a 4-way line, if
    /// crackable.
    ///
    /// In a 22000, there are nine *-delimited fields.
    /// [SIGNATURE][TYPE][PMKID/MIC][MACAP][MACSTA][ESSID][ANONCE][EAPOL]
    /// [MESSAGEPAIR]
    ///
    /// SIGNATURE   literal "WPA"
    /// TYPE        01 = PMKID, 02 = EAPOL (selects validation + which fields
    /// are populated)
    /// PMKID/MIC   16 bytes hex; PMKID when TYPE=01, EAPOL
    /// MIC when TYPE=02
    /// MACAP       6 bytes hex, AP BSSID
    /// MACSTA      6 bytes hex, client MAC
    /// ESSID       SSID hex-encoded, <=32 bytes
    /// ANONCE      32 bytes hex, AP nonce; TYPE=02 only (empty for 01)
    /// EAPOL       supplicant (M2/M4) EAPOL frame hex, MIC field zeroed;
    /// TYPE=02 only (empty for 01) MESSAGEPAIR 1 byte hex; TYPE=02 only.
    /// 00=M1+M2 02=M3+M2 01=M1+M4 05=M3+M4
    ///
    /// TYPE=01: WPA01<pmkid><ap><sta><essid>**
    /// TYPE=02: WPA02<mic><ap><sta><essid><anonce><eapol><mp>
    pub fn to_hc22000(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let ap = hc_hex(&self.bssid);
        let essid = hc_hex(self.ssid.as_bytes());
        if let (Some(pmkid), Some(sta)) = (self.pmkid, self.station) {
            lines.push(format!(
                "WPA*01*{}*{ap}*{}*{essid}***",
                hc_hex(&pmkid),
                hc_hex(&sta)
            ));
        }
        if let (Some((am, from_m3)), Some((sm, from_m4))) =
            (self.anonce_msg(), self.supplicant_msg())
        {
            // messagepair (ANonce src, EAPOL src): M12E2=00, M32E2=02, M14E4=01, M34E4=05.
            let mp = match (from_m3, from_m4) {
                (false, false) => "00",
                (true, false) => "02",
                (false, true) => "01",
                (true, true) => "05",
            };
            lines.push(format!(
                "WPA*02*{}*{ap}*{}*{essid}*{}*{}*{mp}",
                hc_hex(&sm.view.mic),
                hc_hex(&sm.view.station),
                hc_hex(&am.view.nonce),
                hc_hex(&eapol_mic_zeroed(&sm.view.eapol)),
            ));
        }
        lines
    }
}

// Lowercase hex, the convention hashcat 22000 fields use.
fn hc_hex(b: &[u8]) -> String {
    crate::hex::encode_lower(b)
}

// The EAPOL PDU with its 16-byte MIC field zeroed, as mode 22000 requires.
fn eapol_mic_zeroed(eapol: &[u8]) -> Vec<u8> {
    let mut e = eapol.to_vec();
    if e.len() >= 97 {
        e[81..97].fill(0);
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a data frame carrying an EAPOL-Key PDU, for the parser tests.
    fn eapol_frame(from_ds: bool, qos: bool, ki: u16, nonce: u8, mic: u8, kd: &[u8]) -> Vec<u8> {
        let (ap, sta) = ([0xAAu8; 6], [0xBBu8; 6]);
        let mut e = vec![2, 3, 0, 0, 2]; // ver, type 3, len, descriptor
        e.extend_from_slice(&ki.to_be_bytes());
        e.extend_from_slice(&[0, 16]); // key_length
        e.extend_from_slice(&[0; 8]); // replay counter
        e.extend_from_slice(&[nonce; 32]);
        e.extend_from_slice(&[0; 16]); // key_iv
        e.extend_from_slice(&[0; 16]); // key_rsc + key_id
        e.extend_from_slice(&[mic; 16]);
        e.extend_from_slice(&(kd.len() as u16).to_be_bytes());
        e.extend_from_slice(kd);
        let fc1 = if from_ds { 0x02 } else { 0x01 };
        let mut f = vec![if qos { 0x88 } else { 0x08 }, fc1, 0, 0];
        let (a1, a2) = if from_ds { (sta, ap) } else { (ap, sta) };
        f.extend_from_slice(&a1);
        f.extend_from_slice(&a2);
        f.extend_from_slice(&ap); // addr3
        f.extend_from_slice(&[0, 0]); // seq control
        if qos {
            f.extend_from_slice(&[0, 0]);
        }
        f.extend_from_slice(&[0xAA, 0xAA, 0x03, 0, 0, 0, 0x88, 0x8e]);
        f.extend_from_slice(&e);
        f
    }

    #[test]
    fn parses_m1_addrs_nonce_and_keyinfo() {
        let f = eapol_frame(true, false, KI_PAIRWISE | KI_ACK, 0x11, 0, &[]);
        let v = parse_eapol(&f).unwrap();
        assert_eq!(v.bssid, [0xAA; 6]);
        assert_eq!(v.station, [0xBB; 6]);
        assert_eq!(v.nonce, [0x11; 32]);
        assert_eq!(message_number(v.key_info), Some(1));
    }

    #[test]
    fn parses_qos_offset_and_to_ds_direction() {
        let f = eapol_frame(false, true, KI_PAIRWISE | KI_MIC, 0x22, 0x33, &[]);
        let v = parse_eapol(&f).unwrap();
        assert_eq!(v.station, [0xBB; 6]);
        assert_eq!(v.mic, [0x33; 16]);
        assert_eq!(message_number(v.key_info), Some(2));
    }

    #[test]
    fn rejects_non_eapol_frames() {
        assert!(parse_eapol(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
        assert!(parse_eapol(&[]).is_none());
    }

    #[test]
    fn classifies_the_four_messages() {
        assert_eq!(message_number(KI_PAIRWISE | KI_ACK), Some(1));
        assert_eq!(message_number(KI_PAIRWISE | KI_MIC), Some(2));
        assert_eq!(
            message_number(KI_PAIRWISE | KI_ACK | KI_MIC | KI_INSTALL),
            Some(3)
        );
        assert_eq!(message_number(KI_PAIRWISE | KI_MIC | KI_SECURE), Some(4));
        assert_eq!(message_number(0), None);
    }

    #[test]
    fn finds_pmkid_kde() {
        let mut kd = vec![0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04];
        kd.extend_from_slice(&[0xAB; 16]);
        assert_eq!(pmkid_from_key_data(&kd), Some([0xAB; 16]));
        assert_eq!(pmkid_from_key_data(&[0xDD, 0x02, 0, 0]), None);
    }

    #[test]
    fn crackable_needs_m2_plus_m1_or_m3_or_a_pmkid() {
        let mut hs = Handshake::new([0; 6], "net", 6);
        assert!(!hs.crackable());
        hs.pmkid = Some([0; 16]);
        assert!(hs.crackable());
    }

    #[test]
    fn a_new_m1_locks_the_station_and_gates_later_msgs() {
        let mut hs = Handshake::new([0xAA; 6], "net", 6);
        let m1 = eapol_frame(true, false, KI_PAIRWISE | KI_ACK, 0x11, 0, &[]);
        assert!(hs.add_frame(-40, 6, &m1));
        assert_eq!(hs.station, Some([0xBB; 6]));

        // M2 from a different station is ignored.
        let mut wrong = eapol_frame(false, false, KI_PAIRWISE | KI_MIC, 0x22, 0x33, &[]);
        wrong[10..16].copy_from_slice(&[0xCC; 6]);
        assert!(!hs.add_frame(-50, 6, &wrong));
        assert!(hs.msgs[1].is_none());

        // M2 from the locked station completes a crackable 4-way.
        let m2 = eapol_frame(false, false, KI_PAIRWISE | KI_MIC, 0x22, 0x33, &[]);
        assert!(hs.add_frame(-50, 6, &m2));
        assert!(hs.crackable());

        // A fresh M1 restarts the exchange, clearing M2.
        assert!(hs.add_frame(-40, 6, &m1));
        assert!(hs.msgs[1].is_none());
    }

    #[test]
    fn to_pcap_writes_radiotap_beacon_plus_captured_msgs() {
        let mut hs = Handshake::new([0xAA; 6], "net", 6);
        hs.add_frame(
            -40,
            6,
            &eapol_frame(true, false, KI_PAIRWISE | KI_ACK, 0x11, 0, &[]),
        );
        let mut buf = Vec::new();
        hs.to_pcap(&mut buf).unwrap();
        assert_eq!(u32::from_le_bytes(buf[20..24].try_into().unwrap()), 127);
        let (mut i, mut records) = (24, 0);
        while i + 16 <= buf.len() {
            let incl = u32::from_le_bytes(buf[i + 8..i + 12].try_into().unwrap()) as usize;
            i += 16 + incl;
            records += 1;
        }
        assert_eq!(i, buf.len());
        assert_eq!(records, 2); // synth beacon + M1
    }

    #[test]
    fn to_hc22000_emits_pmkid_and_fourway_lines() {
        let mut hs = Handshake::new([0xAA; 6], "ab", 6);
        let mut kd = vec![0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04];
        kd.extend_from_slice(&[0xCD; 16]);
        hs.add_frame(
            -40,
            6,
            &eapol_frame(true, false, KI_PAIRWISE | KI_ACK, 0x11, 0, &kd),
        );
        hs.add_frame(
            -50,
            6,
            &eapol_frame(false, false, KI_PAIRWISE | KI_MIC, 0x22, 0x33, &[]),
        );

        let (ap, sta, essid) = ("aaaaaaaaaaaa", "bbbbbbbbbbbb", "6162");
        let lines = hs.to_hc22000();
        assert!(lines.contains(&format!("WPA*01*{}*{ap}*{sta}*{essid}***", "cd".repeat(16))));

        let four = lines.iter().find(|l| l.starts_with("WPA*02")).unwrap();
        let parts: Vec<&str> = four.split('*').collect();
        assert_eq!(parts[2], "33".repeat(16)); // MIC from M2
        assert_eq!(parts[3], ap);
        assert_eq!(parts[4], sta);
        assert_eq!(parts[5], essid);
        assert_eq!(parts[6], "11".repeat(32)); // ANonce from M1
        assert_eq!(&parts[7][162..194], "0".repeat(32)); // MIC field zeroed
        assert_eq!(*parts.last().unwrap(), "00"); // M1+M2 pair
    }

    // M4 (Pairwise + MIC + Secure), from the station, with an arbitrary nonce.
    fn m4(nonce: u8) -> Vec<u8> {
        eapol_frame(
            false,
            false,
            KI_PAIRWISE | KI_MIC | KI_SECURE,
            nonce,
            0x55,
            &[],
        )
    }

    #[test]
    fn m1_plus_nonzero_m4_cracks_as_messagepair_01() {
        let mut hs = Handshake::new([0xAA; 6], "ab", 6);
        hs.add_frame(
            -40,
            6,
            &eapol_frame(true, false, KI_PAIRWISE | KI_ACK, 0x11, 0, &[]),
        );
        assert!(hs.add_frame(-50, 6, &m4(0x44)));
        assert!(hs.crackable());
        let four = hs
            .to_hc22000()
            .into_iter()
            .find(|l| l.starts_with("WPA*02"))
            .unwrap();
        let parts: Vec<&str> = four.split('*').collect();
        assert_eq!(parts[2], "55".repeat(16)); // MIC from M4
        assert_eq!(parts[6], "11".repeat(32)); // ANonce from M1
        assert_eq!(*parts.last().unwrap(), "01"); // M1+M4
    }

    #[test]
    fn a_zero_nonce_m4_is_ingested_but_not_crackable() {
        let mut hs = Handshake::new([0xAA; 6], "ab", 6);
        hs.add_frame(
            -40,
            6,
            &eapol_frame(true, false, KI_PAIRWISE | KI_ACK, 0x11, 0, &[]),
        );
        assert!(hs.add_frame(-50, 6, &m4(0x00)));
        assert!(!hs.crackable());
        assert!(!hs.to_hc22000().iter().any(|l| l.starts_with("WPA*02")));
    }

    #[test]
    fn late_join_m3_plus_m4_cracks_as_messagepair_05() {
        let mut hs = Handshake::new([0xAA; 6], "ab", 6);
        // No M1 seen; M3 bootstraps the client lock and carries the ANonce.
        let m3 = eapol_frame(
            true,
            false,
            KI_PAIRWISE | KI_ACK | KI_MIC | KI_INSTALL,
            0x11,
            0x22,
            &[],
        );
        assert!(hs.add_frame(-40, 6, &m3));
        assert_eq!(hs.station, Some([0xBB; 6]));
        assert!(hs.add_frame(-50, 6, &m4(0x44)));
        assert!(hs.crackable());
        let four = hs
            .to_hc22000()
            .into_iter()
            .find(|l| l.starts_with("WPA*02"))
            .unwrap();
        let parts: Vec<&str> = four.split('*').collect();
        assert_eq!(parts[6], "11".repeat(32)); // ANonce from M3
        assert_eq!(*parts.last().unwrap(), "05"); // M3+M4
    }
}
