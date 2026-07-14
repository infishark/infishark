//! Bluetooth SIG company-identifier resolution (the 16-bit IDs in BLE manufacturer data). Mirrors the oui module but for the SIG registry.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{Error, Result};

pub const DEFAULT_URL: &str = "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml";

const DB_FILENAME: &str = "ble_companies.tsv";

pub fn db_path(explicit: Option<&str>) -> Result<PathBuf> {
    crate::paths::resolve_db(explicit, DB_FILENAME)
}

fn unquote(s: &str) -> Cow<'_, str> {
    let t = s.trim();
    let inner = if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        &t[1..t.len() - 1]
    } else {
        t
    }
    .trim();
    if inner.contains(['\t', '\r', '\n']) {
        Cow::Owned(inner.replace(['\t', '\r', '\n'], " ").trim().to_string())
    } else {
        Cow::Borrowed(inner)
    }
}

fn parse_registry(yaml: &str) -> Vec<(u16, String)> {
    let mut out = Vec::new();
    let mut pending: Option<u16> = None;
    for raw in yaml.lines() {
        let line = raw.trim().trim_start_matches('-').trim();
        if let Some(rest) = line.strip_prefix("value:") {
            pending = crate::hex::parse_u16(rest).ok();
        } else if let Some(rest) = line.strip_prefix("name:") {
            if let Some(id) = pending.take() {
                let name = unquote(rest);
                if !name.is_empty() {
                    out.push((id, name.into_owned()));
                }
            }
        }
    }
    out
}

pub fn update(url: &str, path: &std::path::Path) -> Result<usize> {
    let body = crate::registry::fetch(url)?;
    let entries = parse_registry(&body);
    if entries.is_empty() {
        return Err(Error::msg(
            "no company identifiers parsed from the registry, maybe the format changed?",
        ));
    }
    crate::registry::sort_dedup_write(entries, path, |id, name| format!("{id:04X}\t{name}\n"))
}

pub struct Db(crate::registry::Db<u16>);

impl Db {
    /// Build a database from an in-memory map (SIG company ID -> name).
    pub fn from_map(map: HashMap<u16, String>) -> Db {
        Db(crate::registry::Db::from_map(map))
    }

    pub fn load(path: &std::path::Path) -> Result<Db> {
        let hint = format!(
            "reading BLE company database {} (run infishark company update to install it)",
            path.display()
        );
        Ok(Db(crate::registry::Db::load(path, &hint, |h| {
            u16::from_str_radix(h, 16).ok()
        })?))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn lookup(&self, id: u16) -> Option<&str> {
        self.0.get(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_value_name_pairs() {
        let yaml = "company_identifiers:\n  \
                    - value: 0x004C\n    name: Apple, Inc.\n  \
                    - value: 0x0006\n    name: \"Microsoft\"\n  \
                    - value: 0x0DA7\n    name: 'InfiShark'\n";
        let e = parse_registry(yaml);
        assert_eq!(e.len(), 3);
        assert_eq!(e[0], (0x004C, "Apple, Inc.".to_string()));
        assert_eq!(e[1], (0x0006, "Microsoft".to_string()));
        assert_eq!(e[2], (0x0DA7, "InfiShark".to_string()));
    }

    #[test]
    fn db_lookup_round_trips() {
        let db = Db::from_map(HashMap::from([(0x004Cu16, "Apple, Inc.".to_string())]));
        assert_eq!(db.lookup(0x004C), Some("Apple, Inc."));
        assert_eq!(db.lookup(0xFFFF), None);
    }
}
