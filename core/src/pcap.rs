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
