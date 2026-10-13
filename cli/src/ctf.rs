//! Flash a CTF box, provision a RAM-only flag, reload it after a power-cycle,
//! submit.

use serde::{Deserialize, Serialize};

pub const DEFAULT_URL: &str = "https://ctf.infishark.com";

pub struct ApiOpts {
    pub url: Option<String>,
    pub token: Option<String>,
    pub user: Option<String>,
}

// Derived Serde structs also accept positional arrays; this wire format does
// not.
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct JsonObject<T>(pub(crate) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for JsonObject<T> {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserialize_object(deserializer).map(Self)
    }
}

pub(crate) fn deserialize_object<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
        type Value = T;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            map: M,
        ) -> std::result::Result<T, M::Error> {
            // Delegate field checks without buffering into Value (which loses duplicates).
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

pub(crate) fn pick(flag: Option<String>, keys: &[&str]) -> Option<String> {
    if let Some(s) = flag {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    for k in keys {
        if let Ok(s) = std::env::var(k) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}
