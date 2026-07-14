//! Shared plumbing for the downloadable reference databases (oui, company):
//! fetching the registry, persisting a sorted TSV, and loading it back.

use std::collections::HashMap;
use std::hash::Hash;
use std::path::Path;
use std::time::Duration;

use crate::error::{Context, Result};

/// Sort entries by key, drop duplicate keys, serialize each with `row`, and
/// write the TSV. The return value is the entry count.
pub fn sort_dedup_write<K: Ord + Copy>(
    mut entries: Vec<(K, String)>,
    path: &Path,
    row: impl Fn(K, &str) -> String,
) -> Result<usize> {
    entries.sort_unstable_by_key(|(k, _)| *k);
    entries.dedup_by_key(|(k, _)| *k);
    let mut text = String::with_capacity(entries.len() * 32);
    for (k, name) in &entries {
        text.push_str(&row(*k, name));
    }
    write_tsv(path, &text)?;
    Ok(entries.len())
}

// IEEE's CDN returns HTTP 418 to non-browser User-Agents, so we present one.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

/// Download a registry file as text.
pub fn fetch(url: &str) -> Result<String> {
    eprintln!("Fetching {url} ...");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build();
    agent
        .get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .with_context(|| format!("downloading {url}"))?
        .into_string()
        .context("reading registry response body")
}

/// Write the TSV body to `path`, creating the parent directory.
fn write_tsv(path: &Path, body: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))
}

/// Load a `key<TAB>name` TSV into a map, parsing each key with `parse_key`.
/// Lines that don't split or whose key doesn't parse are skipped.
pub fn load_tsv<K, F>(path: &Path, missing_hint: &str, parse_key: F) -> Result<HashMap<K, String>>
where
    K: Eq + Hash,
    F: Fn(&str) -> Option<K>,
{
    let text = std::fs::read_to_string(path).with_context(|| missing_hint.to_string())?;
    let mut map = HashMap::new();
    for line in text.lines() {
        if let Some((key, name)) = line.split_once('\t') {
            if let Some(k) = parse_key(key.trim()) {
                map.insert(k, name.to_string());
            }
        }
    }
    Ok(map)
}

/// A loaded reference database: keys resolved to display names.
pub struct Db<K> {
    map: HashMap<K, String>,
}

impl<K: Eq + Hash> Db<K> {
    /// Build from an in-memory map.
    pub fn from_map(map: HashMap<K, String>) -> Self {
        Db { map }
    }

    /// Load a `key<TAB>name` TSV, parsing each key with `parse_key`.
    pub fn load(
        path: &Path,
        missing_hint: &str,
        parse_key: impl Fn(&str) -> Option<K>,
    ) -> Result<Self> {
        Ok(Db {
            map: load_tsv(path, missing_hint, parse_key)?,
        })
    }

    /// Number of entries loaded.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when no entries are loaded.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Resolve a key to its name, if present.
    pub fn get(&self, key: &K) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }
}
