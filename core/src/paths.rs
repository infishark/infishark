//! Single source of truth for where InfiShark host data (lookup DBs, caches) lives on disk.

use std::path::PathBuf;

use crate::error::{Error, Result};

pub fn infishark_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("INFISHARK_DATA_DIR") {
        return Ok(PathBuf::from(p));
    }
    let base = dirs::data_dir()
        .ok_or_else(|| Error::msg("could not determine a data directory for this platform"))?;
    Ok(base.join("infishark"))
}

pub fn resolve_db(explicit: Option<&str>, filename: &str) -> Result<PathBuf> {
    match explicit {
        Some(p) => Ok(PathBuf::from(p)),
        None => Ok(infishark_dir()?.join(filename)),
    }
}
