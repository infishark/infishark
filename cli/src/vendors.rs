//! Cached OUI and Bluetooth company databases. Scan tables fill names
//! themselves.

use std::sync::{Arc, Mutex, OnceLock};

use infishark::{BleDevice, Network, company, oui};

struct Load<T> {
    key: Option<String>,
    db: Option<Arc<T>>,
    ready: bool,
    warned: bool,
}

impl<T> Load<T> {
    fn new() -> Self {
        Self {
            key: None,
            db: None,
            ready: false,
            warned: false,
        }
    }
}

struct State {
    oui: Load<oui::Db>,
    company: Load<company::Db>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(State {
            oui: Load::new(),
            company: Load::new(),
        })
    })
}

/// Remember an `--oui-db` override. `None` is the default data directory.
pub fn set_oui(explicit: Option<&str>) {
    let mut st = state().lock().unwrap();
    let key = explicit.map(str::to_string);
    if st.oui.key != key {
        st.oui = Load {
            key,
            db: None,
            ready: false,
            warned: false,
        };
    }
}

/// Remember a `--company-db` override. `None` is the default data directory.
pub fn set_company(explicit: Option<&str>) {
    let mut st = state().lock().unwrap();
    let key = explicit.map(str::to_string);
    if st.company.key != key {
        st.company = Load {
            key,
            db: None,
            ready: false,
            warned: false,
        };
    }
}

fn open_oui(explicit: Option<&str>) -> Option<Arc<oui::Db>> {
    let path = oui::db_path(explicit).ok()?;
    let db = oui::Db::load(&path).ok()?;
    if db.is_empty() {
        None
    } else {
        Some(Arc::new(db))
    }
}

fn open_company(explicit: Option<&str>) -> Option<Arc<company::Db>> {
    let path = company::db_path(explicit).ok()?;
    let db = company::Db::load(&path).ok()?;
    if db.is_empty() {
        None
    } else {
        Some(Arc::new(db))
    }
}

/// Loaded OUI database, if one is installed.
pub fn oui() -> Option<Arc<oui::Db>> {
    let mut st = state().lock().unwrap();
    if !st.oui.ready {
        let explicit = st.oui.key.clone();
        let db = open_oui(explicit.as_deref());
        if db.is_none() && !st.oui.warned {
            crate::log::warn(
                "OUI database not installed; run `infishark manage oui update` for vendor names",
            );
            st.oui.warned = true;
        }
        st.oui.db = db;
        st.oui.ready = true;
    }
    st.oui.db.clone()
}

/// Loaded Bluetooth company database, if one is installed.
pub fn company() -> Option<Arc<company::Db>> {
    let mut st = state().lock().unwrap();
    if !st.company.ready {
        let explicit = st.company.key.clone();
        let db = open_company(explicit.as_deref());
        if db.is_none() && !st.company.warned {
            crate::log::warn(
                "BLE company database not installed; run `infishark manage company update` for manufacturer names",
            );
            st.company.warned = true;
        }
        st.company.db = db;
        st.company.ready = true;
    }
    st.company.db.clone()
}

pub fn fill_wifi(nets: &mut [Network]) {
    let Some(db) = oui() else {
        return;
    };
    for n in nets {
        if n.vendor.as_ref().is_none_or(|s| s.is_empty()) {
            n.enrich(Some(&db));
        }
    }
}

pub fn fill_ble(devices: &mut [BleDevice]) {
    let oui = oui();
    let company = company();
    if oui.is_none() && company.is_none() {
        return;
    }
    for d in devices {
        let need_vendor = d.vendor.as_ref().is_none_or(|s| s.is_empty());
        let need_company = d.company.as_ref().is_none_or(|s| s.is_empty());
        if need_vendor || need_company {
            d.enrich(oui.as_deref(), company.as_deref());
        }
    }
}
