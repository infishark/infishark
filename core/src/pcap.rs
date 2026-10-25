//! libpcap writer/reader. The device streams raw frames; the host stamps them
//! with its own wall-clock and wraps them in pcap for Wireshark/tshark. A
//! reader recovers ATT PDUs from HCI captures so recorded traffic can be
//! replayed.

use std::io::{Read, Result, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// pcap link type for bare 802.11 MAC frames
pub const LINKTYPE_IEEE802_11: u32 = 105;
pub const LINKTYPE_RAW: u32 = 101;

/// pcap link type for 802.11 frames prefixed with a radiotap header
pub const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;

/// Write the 24-byte pcap global header. Call once before any records.
pub fn write_global_header<W: Write>(w: &mut W, linktype: u32) -> Result<()> {
    // 0xa1b2c3d4: standard microsecond-resolution pcap magic, little-endian on the
    // wire.
    w.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic
    w.write_all(&2u16.to_le_bytes())?; // version major
    w.write_all(&4u16.to_le_bytes())?; // version minor
    w.write_all(&0i32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&65535u32.to_le_bytes())?; // snaplen
    w.write_all(&linktype.to_le_bytes())?; // network
    Ok(())
}

/// Write one packet record, timestamped with the host clock at call time.
pub fn write_record<W: Write>(w: &mut W, frame: &[u8]) -> Result<()> {
    write_record_truncated(w, frame, frame.len() as u32)
}

/// Write a captured prefix while retaining the original IP packet length.
pub fn write_record_truncated<W: Write>(w: &mut W, frame: &[u8], orig_len: u32) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let len = frame.len() as u32;
    w.write_all(&(now.as_secs() as u32).to_le_bytes())?; // ts_sec
    w.write_all(&now.subsec_micros().to_le_bytes())?; // ts_usec
    w.write_all(&len.to_le_bytes())?; // incl_len
    w.write_all(&orig_len.to_le_bytes())?; // orig_len
    w.write_all(frame)?;
    Ok(())
}

/// A 15-byte radiotap header carrying Flags, Channel, and dBm antenna signal,
/// derived from the device's compact PHY prefix.
fn radiotap_header(rssi: i8, channel: u8) -> [u8; 15] {
    let freq: u16 = if channel == 14 {
        2484
    } else {
        2407 + (channel as u16) * 5
    };
    let mut h = [0u8; 15];
    h[2..4].copy_from_slice(&15u16.to_le_bytes()); // header length
    h[4..8].copy_from_slice(&0x0000_002Au32.to_le_bytes()); // present: Flags | Channel | dBm signal
    h[8] = 0x00; // Flags: FCS not present (device strips it)
    h[10..12].copy_from_slice(&freq.to_le_bytes()); // channel frequency (MHz)
    h[12..14].copy_from_slice(&0x0080u16.to_le_bytes()); // channel flags: 2 GHz
    h[14] = rssi as u8; // dBm antenna signal
    h
}

/// Write a pcap record whose frame is prefixed with a radiotap header built
/// from `rssi`/`channel`.
pub fn write_radiotap_record<W: Write>(
    w: &mut W,
    rssi: i8,
    channel: u8,
    frame: &[u8],
) -> Result<()> {
    let mut buf = Vec::with_capacity(15 + frame.len());
    buf.extend_from_slice(&radiotap_header(rssi, channel));
    buf.extend_from_slice(frame);
    write_record(w, &buf)
}

/// Bluetooth HCI UART + 4-byte direction prefix. Wireshark dissects ATT
/// inside ACL / L2CAP CID 4.
pub const LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR: u32 = 201;

/// Wrap an ATT PDU as HCI H4 ACL (conn handle 1) with a direction prefix.
/// `host_to_controller` true = we sent it (p2c notify); false = we received it
/// (c2p write/subscribe).
pub fn hci_att_frame(host_to_controller: bool, att_pdu: &[u8]) -> Vec<u8> {
    let l2cap_len = att_pdu.len() as u16;
    let acl_data_len = 4u16 + l2cap_len;
    let mut v = Vec::with_capacity(4 + 1 + 4 + acl_data_len as usize);
    let dir: u32 = if host_to_controller { 0 } else { 1 };
    v.extend_from_slice(&dir.to_be_bytes());
    v.push(0x02); // HCI ACL
    let handle_pb: u16 = 0x0001 | (2 << 12); // handle 1, PB=complete
    v.extend_from_slice(&handle_pb.to_le_bytes());
    v.extend_from_slice(&acl_data_len.to_le_bytes());
    v.extend_from_slice(&l2cap_len.to_le_bytes());
    v.extend_from_slice(&0x0004u16.to_le_bytes()); // L2CAP CID ATT
    v.extend_from_slice(att_pdu);
    v
}

fn att_handle_value(opcode: u8, handle: u16, value: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(3 + value.len());
    p.push(opcode);
    p.extend_from_slice(&handle.to_le_bytes());
    p.extend_from_slice(value);
    p
}

/// Reconstruct an HCI frame from a device `EVT_BLE_MITM` JSON object.
/// Status/connect events have no ATT PDU and return `None`.
pub fn mitm_event_to_hci(v: &serde_json::Value) -> Option<Vec<u8>> {
    let dir = v.get("dir").and_then(|x| x.as_str())?;
    let op = v.get("op").and_then(|x| x.as_str())?;
    let handle = v.get("handle").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
    let value = v
        .get("hex")
        .and_then(|x| x.as_str())
        .and_then(|h| crate::hex::decode(h).ok())
        .unwrap_or_default();
    let att = match op {
        "notify" if handle != 0 => att_handle_value(0x1B, handle, &value),
        "indicate" if handle != 0 => att_handle_value(0x1D, handle, &value),
        "write" if handle != 0 => att_handle_value(0x52, handle, &value),
        // Subscribe is skipped. The CCCD is not the value handle plus one.
        "subscribe" | "unsubscribe" => return None,
        _ => return None,
    };
    let host_to_controller = dir == "p2c";
    Some(hci_att_frame(host_to_controller, &att))
}

/// One ATT PDU read back from an HCI H4-with-pseudoheader pcap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttRecord {
    /// Record timestamp, microseconds since the capture epoch.
    pub ts_us: u64,
    /// Direction prefix: true = host -> controller (our p2c notifications).
    pub host_to_controller: bool,
    /// ATT PDU bytes (opcode + handle + value).
    pub pdu: Vec<u8>,
}

/// Read ATT PDUs from a `LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR` capture written
/// by [`hci_att_frame`]. Frames that are not complete ACL packets on the ATT
/// L2CAP CID (4) are skipped. Both pcap byte orders are accepted.
pub fn read_hci_att_pcap<R: Read>(mut r: R) -> Result<Vec<AttRecord>> {
    fn le(b: &[u8]) -> u32 {
        u32::from_le_bytes(b.try_into().expect("4 bytes"))
    }
    let mut hdr = [0u8; 24];
    r.read_exact(&mut hdr)?;
    let little = match le(&hdr[0..4]) {
        0xa1b2c3d4 => true,
        0xd4c3b2a1 => false,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a microsecond-resolution pcap file",
            ));
        }
    };
    let u32_at = |b: &[u8]| {
        if little {
            le(b)
        } else {
            u32::from_be_bytes(b.try_into().expect("4 bytes"))
        }
    };
    let linktype = u32_at(&hdr[20..24]);
    if linktype != LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported pcap link type {linktype}"),
        ));
    }
    let mut out = Vec::new();
    let mut rec = [0u8; 16];
    let mut frame = Vec::new();
    loop {
        match r.read_exact(&mut rec) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let ts_us = (u32_at(&rec[0..4]) as u64) * 1_000_000 + u32_at(&rec[4..8]) as u64;
        let incl = u32_at(&rec[8..12]) as usize;
        if incl > 1 << 20 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "implausible pcap record length",
            ));
        }
        frame.clear();
        frame.resize(incl, 0);
        if let Err(e) = r.read_exact(&mut frame) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break; // truncated tail
            }
            return Err(e);
        }
        if let Some((p2c, pdu)) = parse_hci_att_frame(&frame) {
            out.push(AttRecord {
                ts_us,
                host_to_controller: p2c,
                pdu,
            });
        }
    }
    Ok(out)
}

/// Split one HCI H4-with-pseudoheader frame into (peripheral_to_central, ATT
/// PDU). Returns `None` for non-ACL frames, L2CAP fragments, and non-ATT CIDs.
fn parse_hci_att_frame(frame: &[u8]) -> Option<(bool, Vec<u8>)> {
    if frame.len() < 13 || frame[4] != 0x02 {
        return None; // not HCI ACL
    }
    let handle_pb = u16::from_le_bytes(frame[5..7].try_into().ok()?);
    if (handle_pb >> 12) & 0b11 != 0b10 {
        return None; // not a complete-packet start; our writer never fragments
    }
    let l2_len = u16::from_le_bytes(frame[9..11].try_into().ok()?) as usize;
    let cid = u16::from_le_bytes(frame[11..13].try_into().ok()?);
    if cid != 4 || frame.len() < 13 + l2_len {
        return None; // not ATT, or truncated
    }
    Some((
        u32::from_be_bytes(frame[0..4].try_into().ok()?) == 0,
        frame[13..13 + l2_len].to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_record_keeps_original_ip_length() {
        let mut data = Vec::new();
        write_record_truncated(&mut data, &[0x45, 0, 0, 60], 60).unwrap();
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(data[12..16].try_into().unwrap()), 60);
    }

    #[test]
    fn mitm_notify_is_att_handle_value_notification() {
        let v = serde_json::json!({
            "dir": "p2c",
            "op": "notify",
            "handle": 42,
            "hex": "00090000000000"
        });
        let frame = mitm_event_to_hci(&v).unwrap();
        assert_eq!(&frame[0..4], &[0, 0, 0, 0]); // host → controller
        assert_eq!(frame[4], 0x02); // ACL
        let att_off = 4 + 1 + 4 + 4; // phdr + H4 + ACL hdr + L2CAP hdr
        assert_eq!(frame[att_off], 0x1B);
        assert_eq!(&frame[att_off + 1..att_off + 3], &[42, 0]);
        assert_eq!(&frame[att_off + 3..], &[0x00, 0x09, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn mitm_subscribe_is_not_invented() {
        let v = serde_json::json!({
            "dir": "c2p",
            "op": "subscribe",
            "handle": 16
        });
        assert!(mitm_event_to_hci(&v).is_none());
    }

    #[test]
    fn mitm_status_has_no_pdu() {
        let v = serde_json::json!({"op":"status","step":"ready"});
        assert!(mitm_event_to_hci(&v).is_none());
    }

    #[test]
    fn read_back_written_att_pcaps() {
        let mut buf = Vec::new();
        write_global_header(&mut buf, LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR).unwrap();
        let notify = hci_att_frame(true, &att_handle_value(0x1B, 42, &[0, 9, 0, 0, 0, 0, 0]));
        let write = hci_att_frame(false, &att_handle_value(0x52, 17, &[1, 0]));
        for f in [&notify, &write] {
            // Hand-rolled record so the test stays timestamp-deterministic.
            buf.extend_from_slice(&7u32.to_le_bytes());
            buf.extend_from_slice(&500_000u32.to_le_bytes());
            buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
            buf.extend_from_slice(f);
        }
        buf.extend_from_slice(&[0]); // truncated trailing record: ignored

        let recs = read_hci_att_pcap(&buf[..]).unwrap();
        assert_eq!(recs.len(), 2);
        assert!(recs[0].host_to_controller);
        assert_eq!(recs[0].ts_us, 7 * 1_000_000 + 500_000);
        assert_eq!(recs[0].pdu[0], 0x1B);
        assert_eq!(recs[0].pdu[1..3], [42, 0]);
        assert!(!recs[1].host_to_controller);
        assert_eq!(recs[1].pdu[0], 0x52);
    }
}
