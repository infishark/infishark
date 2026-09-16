//! Recommended firmware version for this SDK release.

use std::cmp::Ordering;

use crate::error::{Error, Result};
use crate::hex;

pub const RECOMMENDED: &str = "1.1.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches(['v', 'V']);
        let num = s.split(['-', '+']).next().unwrap_or(s);
        let mut it = num.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next().unwrap_or("0").parse().ok()?;
        let patch = it.next().unwrap_or("0").parse().ok()?;
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

pub fn is_outdated(device: &str) -> bool {
    let Some(have) = Version::parse(device) else {
        return true;
    };
    let Some(need) = Version::parse(RECOMMENDED) else {
        return false;
    };
    have < need
}

pub fn outdated_message(device: &str) -> Option<String> {
    if !is_outdated(device) {
        return None;
    }
    Some(format!(
        "device firmware {device} is older than recommended {RECOMMENDED}"
    ))
}

#[derive(Debug, Clone)]
pub struct DeviceFw {
    pub serial: String,
    pub version: String,
    pub mode: String,
    pub efuse: [u8; 6],
    pub signature: Option<[u8; 32]>,
}

impl DeviceFw {
    pub fn from_info(v: &serde_json::Value) -> Result<Self> {
        let serial = v
            .get("serial")
            .and_then(|x| x.as_str())
            .ok_or_else(|| Error::msg("device_info missing serial"))?
            .to_string();
        let version = v
            .get("version")
            .and_then(|x| x.as_str())
            .unwrap_or("0.0")
            .to_string();
        let mode = v
            .get("mode")
            .and_then(|x| x.as_str())
            .unwrap_or("main")
            .to_string();
        let efuse = hex::decode_n(
            v.get("efuse")
                .and_then(|x| x.as_str())
                .ok_or_else(|| Error::msg("device_info missing efuse"))?,
        )?;
        let signature = v
            .get("signature")
            .and_then(|x| x.as_str())
            .and_then(|s| hex::decode_n(s).ok());
        Ok(Self {
            serial,
            version,
            mode,
            efuse,
            signature,
        })
    }

    pub fn warning(&self) -> Option<String> {
        outdated_message(&self.version)
    }
}

/// True when both strings parse as the same dotted version (`1.1.1` == `v1.1.1`).
pub fn same(a: &str, b: &str) -> bool {
    match (Version::parse(a), Version::parse(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a.trim().eq_ignore_ascii_case(b.trim()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_order() {
        assert!(Version::parse("0.0").unwrap() < Version::parse("1.1.1").unwrap());
        assert!(Version::parse("v1.1.0").unwrap() < Version::parse("1.1.1").unwrap());
        assert_eq!(
            Version::parse("1.1.1").unwrap(),
            Version::parse("v1.1.1").unwrap()
        );
        assert!(!is_outdated("1.1.1"));
        assert!(!is_outdated("2.0.0"));
        assert!(is_outdated("0.0"));
        assert!(is_outdated("1.1.0"));
        assert!(outdated_message("0.0").unwrap().contains(RECOMMENDED));
        assert!(outdated_message("1.1.1").is_none());
        assert!(same("1.1.1", "v1.1.1"));
        assert!(same("1.1", "v1.1.0"));
        assert!(!same("1.1.0", "1.1.1"));
    }

    #[test]
    fn parses_optional_signature() {
        let v: serde_json::Value = serde_json::json!({
            "serial": "BLS-N-TEST",
            "version": "0.0",
            "mode": "main",
            "efuse": "E0:2E:9E:81:8C:58",
            "signature": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        });
        let id = DeviceFw::from_info(&v).unwrap();
        assert_eq!(id.signature.unwrap()[0], 0x00);
        assert_eq!(id.signature.unwrap()[1], 0x11);
        let v2: serde_json::Value = serde_json::json!({
            "serial": "BLS-N-TEST",
            "version": "0.0",
            "mode": "main",
            "efuse": "E0:2E:9E:81:8C:58",
        });
        assert!(DeviceFw::from_info(&v2).unwrap().signature.is_none());
    }
}
