//! Control-frame encoding for the host -> device direction.
//!
//! Decoding (device -> host) lives in `demux`, which has to resync on a shared,
//! lossy stream. This module only builds well-formed frames.

#![allow(dead_code)]

use crate::crc::crc16_ccitt;
use crate::protocol::{MAGIC, PKT_COMMAND, VERSION};

/// A decoded control frame (the unit `demux` yields and the unit we encode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub typ: u8,
    pub seq: u16,
    pub payload: Vec<u8>,
}

/// Encode an arbitrary frame: magic, version, type, seq_le, len_le, payload,
/// crc_le. The CRC16-CCITT (init 0xFFFF) covers everything after the magic.
pub fn encode(typ: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut covered = Vec::with_capacity(6 + payload.len());
    covered.push(VERSION);
    covered.push(typ);
    covered.extend_from_slice(&seq.to_le_bytes());
    covered.extend_from_slice(&len.to_le_bytes());
    covered.extend_from_slice(payload);
    let crc = crc16_ccitt(&covered, 0xFFFF);

    let mut out = Vec::with_capacity(MAGIC.len() + covered.len() + 2);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&covered);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// Encode a `PKT_COMMAND`: a little-endian `u16` opcode followed by raw JSON argument bytes (empty for argument-less commands).
pub fn encode_command(seq: u16, opcode: u16, json: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + json.len());
    payload.extend_from_slice(&opcode.to_le_bytes());
    payload.extend_from_slice(json);
    encode(PKT_COMMAND, seq, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CMD_DEVICE_INFO;

    #[test]
    fn encode_command_lays_out_device_info_with_no_args() {
        let f = encode_command(1, CMD_DEVICE_INFO, b"");
        assert_eq!(&f[0..3], &[0xB5, 0x5A, 0xC1], "magic");
        assert_eq!(f[3], 0x01, "version");
        assert_eq!(f[4], PKT_COMMAND, "type");
        assert_eq!(&f[5..7], &[0x01, 0x00], "seq le");
        assert_eq!(&f[7..9], &[0x02, 0x00], "len le = opcode(2)+json(0)");
        assert_eq!(&f[9..11], &[0x01, 0x00], "opcode le in payload");
        // CRC covers version..payload (offsets 3..11) and is little-endian.
        let crc = crc16_ccitt(&f[3..11], 0xFFFF);
        assert_eq!(&f[11..13], &crc.to_le_bytes(), "crc le");
        assert_eq!(f.len(), 13);
    }

    #[test]
    fn encode_command_appends_json_args() {
        let f = encode_command(0x0102, 0x0401, b"{\"a\":1}");
        assert_eq!(&f[5..7], &[0x02, 0x01], "seq le");
        assert_eq!(&f[7..9], &[0x09, 0x00], "len le = 2 + 7 json bytes");
        assert_eq!(&f[9..11], &[0x01, 0x04], "opcode le");
        assert_eq!(&f[11..18], b"{\"a\":1}", "json tail");
    }
}
