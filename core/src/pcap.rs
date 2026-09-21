//! libpcap writer. The device streams raw frames; the host stamps them with its
//! own wall-clock and wraps them in pcap for Wireshark/tshark.

use std::io::{Result, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// pcap link type for bare 802.11 MAC frames
pub const LINKTYPE_IEEE802_11: u32 = 105;

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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let len = frame.len() as u32;
    w.write_all(&(now.as_secs() as u32).to_le_bytes())?; // ts_sec
    w.write_all(&now.subsec_micros().to_le_bytes())?; // ts_usec
    w.write_all(&len.to_le_bytes())?; // incl_len
    w.write_all(&len.to_le_bytes())?; // orig_len
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
        "subscribe" if handle != 0 => {
            // CCCD is the next attribute after the value handle.
            att_handle_value(0x12, handle.saturating_add(1), &[0x01, 0x00])
        }
        "unsubscribe" if handle != 0 => {
            att_handle_value(0x12, handle.saturating_add(1), &[0x00, 0x00])
        }
        _ => return None,
    };
    let host_to_controller = dir == "p2c";
    Some(hci_att_frame(host_to_controller, &att))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn mitm_subscribe_is_cccd_write() {
        let v = serde_json::json!({
            "dir": "c2p",
            "op": "subscribe",
            "handle": 16
        });
        let frame = mitm_event_to_hci(&v).unwrap();
        assert_eq!(&frame[0..4], &[0, 0, 0, 1]); // controller → host
        let att_off = 4 + 1 + 4 + 4;
        assert_eq!(frame[att_off], 0x12);
        assert_eq!(&frame[att_off + 1..att_off + 3], &[17, 0]); // handle+1
        assert_eq!(&frame[att_off + 3..], &[0x01, 0x00]);
    }

    #[test]
    fn mitm_status_has_no_pdu() {
        let v = serde_json::json!({"op":"status","step":"ready"});
        assert!(mitm_event_to_hci(&v).is_none());
    }
}
