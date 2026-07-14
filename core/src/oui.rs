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

fn parse_registry(csv: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for line in csv.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let cols = parse_csv_line(line);
        if cols.len() < 3 || cols[0].trim() != "MA-L" {
            continue;
        }
        let Some(key) = oui_key(cols[1].trim()) else {
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

/// Fetch the registry, parse it, and write a sorted oui.tsv to path.
pub fn update(url: &str, path: &std::path::Path) -> Result<usize> {
    let body = crate::registry::fetch(url)?;
    let entries = parse_registry(&body);
    if entries.is_empty() {
        return Err(Error::msg(
            "no MA-L entries parsed from the registry, maybe the format changed?",
        ));
    }
    crate::registry::sort_dedup_write(entries, path, |key, name| format!("{key:06X}\t{name}\n"))
}

pub struct Db(crate::registry::Db<u32>);

impl Db {
    /// Build a database from an in-memory map (24-bit OUI key -> vendor).
    pub fn from_map(map: HashMap<u32, String>) -> Db {
        Db(crate::registry::Db::from_map(map))
    }

    pub fn load(path: &std::path::Path) -> Result<Db> {
        let hint = format!(
            "reading OUI database {} (run infishark oui update to install it)",
            path.display()
        );
        Ok(Db(crate::registry::Db::load(path, &hint, |h| {
            u32::from_str_radix(h, 16).ok()
        })?))
    }

    /// Number of vendor entries loaded.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Resolve a MAC/BSSID string to its vendor, if known.
    pub fn lookup(&self, addr: &str) -> Option<&str> {
        self.0.get(&oui_key(addr)?)
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
                   MA-M,AABBCC,Should Be Skipped,Nowhere\n";
        let entries = parse_registry(csv);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (0x0022AE, "Some Vendor, Inc.".to_string()));
        assert_eq!(entries[1], (0x001B63, "Apple".to_string()));
    }

    #[test]
    fn db_lookup_round_trips() {
        let db = Db::from_map(HashMap::from([(0x001B63u32, "Apple".to_string())]));
        assert_eq!(db.lookup("00:1B:63:AA:BB:CC"), Some("Apple"));
        assert_eq!(db.lookup("FF:FF:FF:00:00:00"), None);
    }
}
