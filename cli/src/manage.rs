//! `manage` command group: the local OUI (vendor) and Bluetooth SIG company
//! reference databases used to enrich scan output.

use anyhow::Result;
use clap::Subcommand;

use infishark::{company, oui};

use crate::DbOpts;

#[derive(Debug, Subcommand)]
pub enum ManageCmd {
    /// Manage the local OUI (vendor) database.
    Oui {
        #[command(subcommand)]
        action: OuiCmd,
    },
    /// Manage the local Bluetooth SIG company-identifier database.
    Company {
        #[command(subcommand)]
        action: CompanyCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum OuiCmd {
    /// Download the IEEE registry and install the local vendor database.
    Update {
        /// Source URL (defaults to the IEEE MA-L registry).
        #[arg(long)]
        url: Option<String>,
    },
    /// Print the resolved database path and install status.
    Path,
    /// Resolve one or more MAC/BSSID addresses to vendors (offline).
    Lookup {
        /// Addresses to resolve, e.g. 78:8D:AF:7E:51:90.
        #[arg(required = true)]
        addrs: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum CompanyCmd {
    /// Download the Bluetooth SIG registry and install the local database.
    Update {
        /// Source URL (defaults to the SIG company_identifiers.yaml).
        #[arg(long)]
        url: Option<String>,
    },
    /// Print the resolved database path and install status.
    Path,
    /// Resolve one or more company IDs (e.g. 0x004C or 76) to names.
    Lookup {
        #[arg(required = true)]
        ids: Vec<String>,
    },
}

pub fn run(json: bool, db: &DbOpts, action: &ManageCmd) -> Result<()> {
    match action {
        ManageCmd::Oui { action } => oui_cmd(json, db.oui_db.as_deref(), action),
        ManageCmd::Company { action } => company_cmd(json, db.company_db.as_deref(), action),
    }
}

fn oui_cmd(json: bool, db_path: Option<&str>, action: &OuiCmd) -> Result<()> {
    let path = oui::db_path(db_path)?;
    match action {
        OuiCmd::Path => {
            let entries = oui::Db::load(&path).map(|db| db.len()).unwrap_or(0);
            let status = db_status(&path, entries);
            if json {
                crate::print_value(&status, true)
            } else {
                crate::ui::value_detail(&status);
                Ok(())
            }
        }
        OuiCmd::Update { url } => {
            let url = url.as_deref().unwrap_or(oui::DEFAULT_URL);
            let count = oui::update(url, &path)?;
            crate::print_action(
                serde_json::json!({ "ok": true, "count": count, "path": path.display().to_string() }),
                format!("Installed {count} vendor entries -> {}", path.display()),
                json,
            )
        }
        OuiCmd::Lookup { addrs } => {
            let db = oui::Db::load(&path)?;
            let results: Vec<serde_json::Value> = addrs
                .iter()
                .map(|addr| serde_json::json!({ "query": addr, "vendor": db.lookup(addr) }))
                .collect();
            if json {
                crate::print_items("results", &results, true)
            } else {
                print_lookup(&results);
                Ok(())
            }
        }
    }
}

fn company_cmd(json: bool, db_path: Option<&str>, action: &CompanyCmd) -> Result<()> {
    let path = company::db_path(db_path)?;
    match action {
        CompanyCmd::Path => {
            let entries = company::Db::load(&path).map(|db| db.len()).unwrap_or(0);
            let status = db_status(&path, entries);
            if json {
                crate::print_value(&status, true)
            } else {
                crate::ui::value_detail(&status);
                Ok(())
            }
        }
        CompanyCmd::Update { url } => {
            let url = url.as_deref().unwrap_or(company::DEFAULT_URL);
            let count = company::update(url, &path)?;
            crate::print_action(
                serde_json::json!({ "ok": true, "count": count, "path": path.display().to_string() }),
                format!("Installed {count} company entries -> {}", path.display()),
                json,
            )
        }
        CompanyCmd::Lookup { ids } => {
            let db = company::Db::load(&path)?;
            let results: Vec<serde_json::Value> = ids
                .iter()
                .map(|id| match parse_company_id(id) {
                    Some(n) => serde_json::json!({ "query": id, "id": n, "company": db.lookup(n) }),
                    None => serde_json::json!({ "query": id, "error": "invalid id" }),
                })
                .collect();
            if json {
                crate::print_items("results", &results, true)
            } else {
                print_lookup(&results);
                Ok(())
            }
        }
    }
}

/// Print `query -> name` (or the error / "(unknown)") for each lookup result.
fn print_lookup(results: &[serde_json::Value]) {
    for r in results {
        let q = r.get("query").and_then(|v| v.as_str()).unwrap_or("?");
        match r
            .get("vendor")
            .or_else(|| r.get("company"))
            .and_then(|v| v.as_str())
        {
            Some(name) => println!("{q}  {name}"),
            None => {
                let note = r.get("error").and_then(|v| v.as_str()).unwrap_or("(unknown)");
                println!("{q}  {note}");
            }
        }
    }
}

fn db_status(path: &std::path::Path, entries: usize) -> serde_json::Value {
    serde_json::json!({
        "path": path.display().to_string(),
        "installed": entries > 0,
        "entries": entries,
    })
}

/// Parse a company ID given as decimal ("76") or hex ("0x004C").
fn parse_company_id(s: &str) -> Option<u16> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}
