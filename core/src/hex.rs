//! Hex string <-> bytes.

use std::fmt::Write;

use crate::error::{Context, Result};

/// Encode bytes as uppercase hex with no separators.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// Encode bytes as lowercase hex with no separators.
pub fn encode_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a hex string to bytes. Tolerates whitespace and `:`/`-` separators.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();
    if !cleaned.is_ascii() {
        bail!("hex string contains non-hex characters");
    }
    if cleaned.len() % 2 != 0 {
        bail!("hex string has an odd number of digits");
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| crate::Error::msg(format!("invalid hex byte '{}'", &cleaned[i..i + 2])))
        })
        .collect()
}

/// Parse a bare or `0x`-prefixed hex integer as `u16`.
pub fn parse_u16(s: &str) -> Result<u16> {
    let s = s.trim().trim_matches(['"', '\'']).trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u16::from_str_radix(hex, 16).with_context(|| format!("bad hex u16 '{s}'"))
}

/// Parse a bare or `0x`-prefixed hex integer as `u64` (IR code data, etc.).
pub fn parse_u64(s: &str) -> Result<u64> {
    let s = s.trim().trim_matches(['"', '\'']).trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(hex, 16).with_context(|| format!("bad hex u64 '{s}'"))
}

/// Parse 1-4 little-endian space-separated hex bytes into a `u32` (`.ir` address/command).
pub fn parse_le_u32_bytes(s: &str) -> Result<u32> {
    let mut bytes = [0u8; 4];
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.is_empty() || parts.len() > 4 {
        bail!("expected 1-4 hex bytes, got {s:?}");
    }
    for (i, p) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(p, 16).with_context(|| format!("bad hex byte {p}"))?;
    }
    Ok(u32::from_le_bytes(bytes))
}

/// Format a `u32` as four little-endian uppercase hex bytes (`AA BB CC DD`).
pub fn encode_le_u32_bytes(v: u32) -> String {
    let b = v.to_le_bytes();
    format!("{:02X} {:02X} {:02X} {:02X}", b[0], b[1], b[2], b[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        assert_eq!(encode(&[0xAF, 0x01, 0x00]), "AF0100");
        assert_eq!(encode_lower(&[0xAF, 0x01, 0x00]), "af0100");
        assert_eq!(decode("AF0100").unwrap(), vec![0xAF, 0x01, 0x00]);
    }

    #[test]
    fn decode_tolerates_separators_and_case() {
        assert_eq!(decode("af:01-00 ff").unwrap(), vec![0xAF, 0x01, 0x00, 0xFF]);
    }

    #[test]
    fn decode_rejects_odd_and_garbage() {
        assert!(decode("ABC").is_err());
        assert!(decode("ZZ").is_err());
    }

    #[test]
    fn decode_rejects_non_ascii_without_panicking() {
        assert!(decode("€€").is_err());
    }

    #[test]
    fn parse_u16_variants() {
        assert_eq!(parse_u16("0x00E0").unwrap(), 0xE0);
        assert_eq!(parse_u16("00e0").unwrap(), 0xE0);
        assert_eq!(parse_u16("\"0x004C\"").unwrap(), 0x4C);
    }

    #[test]
    fn parse_u64_variants() {
        assert_eq!(parse_u64("20DF10EF").unwrap(), 0x20DF_10EF);
        assert_eq!(parse_u64("0x20df10ef").unwrap(), 0x20DF_10EF);
    }

    #[test]
    fn le_u32_bytes() {
        assert_eq!(parse_le_u32_bytes("EE 87 00 00").unwrap(), 0x0000_87EE);
        assert_eq!(parse_le_u32_bytes("01 00 00 00").unwrap(), 1);
        assert_eq!(encode_le_u32_bytes(0x0000_87EE), "EE 87 00 00");
    }
}
