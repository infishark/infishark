//! Small helpers for building the sparse JSON arg objects the device expects
//! (only non-default fields are emitted).

use serde_json::{Map, Value};

/// Insert `key: value` only when `value` is `Some`.
pub fn insert_opt<T: Into<Value>>(m: &mut Map<String, Value>, key: &str, value: Option<T>) {
    if let Some(v) = value {
        m.insert(key.to_string(), v.into());
    }
}

/// Insert `key: value` only when `cond` holds (for emitting a non-default flag).
pub fn insert_flag(m: &mut Map<String, Value>, key: &str, cond: bool, value: Value) {
    if cond {
        m.insert(key.to_string(), value);
    }
}
