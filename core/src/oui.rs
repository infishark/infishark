//! Host-side OUI (vendor) resolution for Wi-Fi/BLE addresses.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{Error, Result};

pub const DEFAULT_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";

const DB_FILENAME: &str = "oui.tsv";

pub fn db_path(explicit: Option<&str>) -> Result<PathBuf> {
    crate::paths::resolve_db(explicit, DB_FILENAME)
}

/// Extract 24-bit OUI key from MAC/BSSID string
pub fn oui_key(addr: &str) -> Option<u32> {
    let mut nibbles = addr.chars().filter_map(|c| c.to_digit(16));
    let mut key = 0u32;
    for _ in 0..6 {
        key = (key << 4) | nibbles.next()?;
    }
    Some(key)
}

/// Split one CSV record, honouring "..." quoting and "" escapes.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

/// (prefix bits, prefix length). 24 = MA-L, 28 = MA-M, 36 = MA-S.
fn prefix_key(assignment: &str, kind: &str) -> Option<(u64, u8)> {
    let hex: String = assignment
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    let nbits = match (kind, hex.len()) {
        ("MA-L", 6) => 24,
        ("MA-M", 7) => 28,
        ("MA-S", 9) => 36,
        _ => return None,
    };
    let bits = u64::from_str_radix(&hex, 16).ok()?;
    Some((bits, nbits))
}

fn parse_registry(csv: &str) -> Vec<((u64, u8), String)> {
    let mut out = Vec::new();
    for line in csv.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let cols = parse_csv_line(line);
        if cols.len() < 3 {
            continue;
        }
        let Some(key) = prefix_key(cols[1].trim(), cols[0].trim()) else {
            continue;
        };
        let name = cols[2].trim().replace(['\t', '\r', '\n'], " ");
        if name.is_empty() {
            continue;
        }
        out.push((key, name));
    }
    out
}

fn hex_digits(addr: &str) -> Option<String> {
    let parts: Vec<&str> = addr.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 && parts.len() != 8 {
        return None;
    }
    let mut out = String::new();
    for part in parts {
        if part.len() != 1 && part.len() != 2 {
            return None;
        }
        if !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if part.len() == 1 {
            out.push('0');
        }
        out.push_str(&part.to_ascii_uppercase());
    }
    Some(out)
}

fn parse_stored_key(h: &str) -> Option<(u64, u8)> {
    let nbits = match h.trim().len() {
        6 => 24,
        7 => 28,
        9 => 36,
        _ => return None,
    };
    let bits = u64::from_str_radix(h.trim(), 16).ok()?;
    Some((bits, nbits))
}

/// Fetch the registry, parse it, and write a sorted oui.tsv to path.
pub fn update(url: &str, path: &std::path::Path) -> Result<usize> {
    let body = crate::registry::fetch(url)?;
    let entries = parse_registry(&body);
    if entries.is_empty() {
        return Err(Error::msg(
            "no OUI entries parsed from the registry, maybe the format changed?",
        ));
    }
    crate::registry::sort_dedup_write(entries, path, |(bits, nbits), name| {
        let width = nbits as usize / 4;
        format!("{bits:0width$X}\t{name}\n")
    })
}

pub struct Db(crate::registry::Db<(u64, u8)>);

impl Db {
    /// Build a database from an in-memory map (24-bit OUI key -> vendor).
    pub fn from_map(map: HashMap<u32, String>) -> Db {
        let map = map
            .into_iter()
            .map(|(k, v)| ((u64::from(k), 24u8), v))
            .collect();
        Db(crate::registry::Db::from_map(map))
    }

    pub fn load(path: &std::path::Path) -> Result<Db> {
        let hint = format!(
            "reading OUI database {} (run `infishark manage oui update` to install it)",
            path.display()
        );
        Ok(Db(crate::registry::Db::load(
            path,
            &hint,
            parse_stored_key,
        )?))
    }

    /// Number of vendor entries loaded.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn lookup_hex(&self, hex: &str) -> Option<&str> {
        for (chars, nbits) in [(9usize, 36u8), (7, 28), (6, 24)] {
            if hex.len() < chars {
                continue;
            }
            let Ok(bits) = u64::from_str_radix(&hex[..chars], 16) else {
                continue;
            };
            if let Some(name) = self.0.get(&(bits, nbits)) {
                return Some(name);
            }
        }
        None
    }

    /// Resolve a MAC to its vendor. Longer IEEE blocks (MA-S, MA-M) win over
    /// MA-L.
    pub fn lookup(&self, addr: &str) -> Option<&str> {
        self.lookup_hex(&hex_digits(addr)?)
    }

    /// Vendor for an AP BSSID. A virtual BSSID often sets the local bit on a
    /// real OUI.
    pub fn lookup_ap(&self, addr: &str) -> Option<&str> {
        let hex = hex_digits(addr)?;
        if let Some(name) = self.lookup_hex(&hex) {
            return Some(name);
        }
        let first = u8::from_str_radix(&hex[..2], 16).ok()?;
        if first & 0x01 != 0 || first & 0x02 == 0 {
            return None;
        }
        let cleared = format!("{:02X}{}", first & !0x02, &hex[2..]);
        self.lookup_hex(&cleared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oui_key_handles_separators() {
        let expected = 0x00_22_72;
        assert_eq!(oui_key("00:22:72:11:22:33"), Some(expected));
        assert_eq!(oui_key("00-22-72-11-22-33"), Some(expected));
        assert_eq!(oui_key("002272112233"), Some(expected));
    }

    #[test]
    fn oui_key_rejects_short_input() {
        assert_eq!(oui_key("00:22"), None);
        assert_eq!(oui_key(""), None);
    }

    #[test]
    fn parses_quoted_organization_with_comma() {
        let csv = "Registry,Assignment,Organization Name,Organization Address\n\
                   MA-L,0022AE,\"Some Vendor, Inc.\",Somewhere\n\
                   MA-L,001B63,Apple,Cupertino\n\
                   MA-M,AABBCC,Too Short,Nowhere\n\
                   MA-M,AABBCC1,Slice,Nowhere\n\
                   CID,ABCDEF,Not A Mac Block,Nowhere\n";
        let entries = parse_registry(csv);
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            ((0x0022AE, 24), "Some Vendor, Inc.".to_string())
        );
        assert_eq!(entries[1], ((0x001B63, 24), "Apple".to_string()));
        assert_eq!(entries[2], ((0xAABBCC1, 28), "Slice".to_string()));
    }

    #[test]
    fn db_lookup_round_trips() {
        let db = Db::from_map(HashMap::from([(0x001B63u32, "Apple".to_string())]));
        assert_eq!(db.lookup("00:1B:63:AA:BB:CC"), Some("Apple"));
        assert_eq!(db.lookup("FF:FF:FF:00:00:00"), None);
    }

    #[test]
    fn longer_prefix_beats_oui24() {
        let csv = "Registry,Assignment,Organization Name,Organization Address\n\
                   MA-L,AABBCC,Block,X\n\
                   MA-M,AABBCC1,Slice,X\n\
                   MA-S,AABBCC1DE,Chip,X\n";
        let db = Db(crate::registry::Db::from_map(
            parse_registry(csv).into_iter().collect(),
        ));
        assert_eq!(db.lookup("AA:BB:CC:1D:E0:00"), Some("Chip"));
        assert_eq!(db.lookup("AA:BB:CC:10:00:00"), Some("Slice"));
        assert_eq!(db.lookup("AA:BB:CC:00:00:00"), Some("Block"));
    }

    #[test]
    fn lookup_ap_clears_the_local_bit() {
        let db = Db::from_map(HashMap::from([(0x001122u32, "Example".to_string())]));
        assert_eq!(db.lookup("02:11:22:00:00:01"), None);
        assert_eq!(db.lookup_ap("02:11:22:00:00:01"), Some("Example"));
        assert_eq!(db.lookup_ap("00:11:22:00:00:01"), Some("Example"));
    }
}
