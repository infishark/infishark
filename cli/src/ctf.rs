//! Flash a CTF box, provision a RAM-only flag, reload it after a power-cycle,
//! submit.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, bail};
use infishark::hex;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const DEFAULT_URL: &str = "https://ctf.infishark.com";

pub struct ApiOpts {
    pub url: Option<String>,
    pub token: Option<String>,
    pub user: Option<String>,
}

const CTF_PROTO: u32 = 2;
const REFLASH_REQUIRED: &str = "CTF firmware identity missing, unknown, or invalid; reflash required with a protocol-2 challenge image";
const MAX_FLAG_BYTES: usize = 95;

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

fn lower_hex(s: &str, min_bytes: usize, max_bytes: usize) -> bool {
    s.len() >= min_bytes * 2
        && s.len() <= max_bytes * 2
        && s.len() % 2 == 0
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_public_key(key: &[u8; 32]) -> Result<()> {
    // A fixed scalar only checks X25519 admissibility; it authenticates nothing.
    let probe = StaticSecret::from([0x42; 32]);
    if !probe
        .diffie_hellman(&PublicKey::from(*key))
        .was_contributory()
    {
        bail!("invalid CTF public key");
    }
    Ok(())
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

fn check_slug(s: &str) -> Result<()> {
    if !(1..=64).contains(&s.len())
        || !s
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        // Do not echo untrusted serial/API values (including terminal control bytes).
        bail!("invalid challenge slug; expected [a-z0-9][a-z0-9_-]{{0,63}}");
    }
    Ok(())
}

fn check_flag_shape(s: &str) -> Result<()> {
    let t = s.trim();
    if t.starts_with("flag{") && t.ends_with('}') && t.len() > 6 {
        return Ok(());
    }
    let hexish: String = t
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    if hexish.len() >= 8 && hexish.len() % 2 == 0 && hexish.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("that looks like a hex dump. decode it to ASCII and submit flag{{...}}");
    }
    bail!("submit a flag{{...}} string");
}

pub fn gen_flag() -> String {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    format!("flag{{ish-{}}}", hex::encode_lower(&b))
}

pub struct Load {
    pub host_pub: [u8; 32],
    pub nonce: [u8; 12],
    pub ct: Vec<u8>,
}

fn load_aad(slug: &str) -> Result<Vec<u8>> {
    check_slug(slug)?;
    Ok(format!("infishark-ctf:2:{slug}").into_bytes())
}

pub fn seal(device_pub: &[u8; 32], slug: &str, flag: &[u8]) -> Result<Load> {
    let aad = load_aad(slug)?;
    if !(1..=MAX_FLAG_BYTES).contains(&flag.len()) {
        bail!("CTF flag must contain 1..95 bytes");
    }
    let sk = StaticSecret::random_from_rng(OsRng);
    let host_pub = PublicKey::from(&sk).to_bytes();
    let their = PublicKey::from(*device_pub);
    let shared = sk.diffie_hellman(&their);
    if !shared.was_contributory() {
        bail!("invalid CTF public key");
    }
    let key = shared.to_bytes();
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new((&key).into());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: flag,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("aes-gcm encrypt failed"))?;
    Ok(Load {
        host_pub,
        nonce,
        ct,
    })
}

#[cfg(test)]
fn unseal(device_sk: &StaticSecret, slug: &str, load: &Load) -> Result<Vec<u8>> {
    let aad = load_aad(slug)?;
    let their = PublicKey::from(load.host_pub);
    let key = device_sk.diffie_hellman(&their).to_bytes();
    let cipher = Aes256Gcm::new((&key).into());
    cipher
        .decrypt(
            Nonce::from_slice(&load.nonce),
            Payload {
                msg: &load.ct,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("aes-gcm decrypt failed"))
}

fn flags_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn load_json(load: &Load) -> serde_json::Value {
    serde_json::json!({
        "pub": hex::encode_lower(&load.host_pub),
        "n": hex::encode_lower(&load.nonce),
        "ct": hex::encode_lower(&load.ct),
    })
}

#[derive(Debug, PartialEq)]
struct BoxHello {
    key: [u8; 32],
    slug: String,
}

fn box_hello(hello: &serde_json::Value, requested: Option<&str>) -> Result<BoxHello> {
    let object = hello.as_object().context(REFLASH_REQUIRED)?;
    if object.get("proto").and_then(|v| v.as_u64()) != Some(u64::from(CTF_PROTO)) {
        bail!("unsupported CTF protocol; reflash required with a protocol-2 challenge image");
    }
    let slug = object
        .get("challenge")
        .and_then(|v| v.as_str())
        .context(REFLASH_REQUIRED)?;
    if slug == "unknown" || check_slug(slug).is_err() {
        bail!("{REFLASH_REQUIRED}");
    }
    for field in ["reset", "ready"] {
        if object.get(field).is_some_and(|v| !v.is_boolean()) {
            bail!("invalid CTF HELLO capability; reflash required");
        }
    }
    let public = object
        .get("pub")
        .and_then(|v| v.as_str())
        .context(REFLASH_REQUIRED)?;
    if public.len() != 64 || !public.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid CTF HELLO public key; reflash required");
    }
    let key: [u8; 32] = hex::decode_n(public).context(REFLASH_REQUIRED)?;
    check_public_key(&key).context(REFLASH_REQUIRED)?;
    if let Some(requested) = requested {
        check_slug(requested)?;
        if requested != slug {
            bail!(
                "CTF challenge mismatch: requested {requested}, connected firmware {slug}; reflash the selected challenge (no flag issued or loaded)"
            );
        }
    }
    Ok(BoxHello {
        key,
        slug: slug.to_string(),
    })
}

fn check_load_identity(before: &BoxHello, after: &BoxHello) -> Result<()> {
    if after.key != before.key {
        bail!("CTF boot key changed before LOAD");
    }
    if after.slug != before.slug {
        bail!("CTF challenge identity changed before LOAD");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_flag_shape() {
        let f = gen_flag();
        assert!(f.starts_with("flag{ish-"), "{f}");
        assert!(f.ends_with('}'), "{f}");
        assert_eq!(f.len(), 26, "{f}");
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let device_sk = StaticSecret::random_from_rng(OsRng);
        let device_pk = PublicKey::from(&device_sk).to_bytes();
        let flag = b"flag{ish-deadbeefcafebabe}";
        let load = seal(&device_pk, "gate", flag).unwrap();
        assert_eq!(load.host_pub.len(), 32);
        assert_eq!(load.nonce.len(), 12);
        assert_eq!(load.ct.len(), flag.len() + 16);
        let got = unseal(&device_sk, "gate", &load).unwrap();
        assert_eq!(got, flag);
    }

    #[test]
    fn load_json_lowercase_hex() {
        let device_sk = StaticSecret::random_from_rng(OsRng);
        let device_pk = PublicKey::from(&device_sk).to_bytes();
        let load = seal(&device_pk, "gate", b"flag{x}").unwrap();
        let v = load_json(&load);
        let p = v["pub"].as_str().unwrap();
        let n = v["n"].as_str().unwrap();
        let c = v["ct"].as_str().unwrap();
        assert_eq!(p.len(), 64);
        assert_eq!(n.len(), 24);
        assert!(
            p.chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
        assert!(
            n.chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
        assert!(
            c.chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
    }

    #[test]
    fn flags_eq_rejects_mismatch() {
        assert!(flags_eq("flag{a}", "flag{a}"));
        assert!(!flags_eq("flag{a}", "flag{b}"));
        assert!(!flags_eq("flag{a}", "flag{aa}"));
    }

    #[test]
    fn ctf_opcodes() {
        assert_eq!(infishark::protocol::CMD_CTF_HELLO, 0x0600);
        assert_eq!(infishark::protocol::CMD_CTF_LOAD, 0x0601);
        assert_eq!(infishark::protocol::CMD_CTF_RESET, 0x0602);
    }

    #[test]
    fn flag_shape_accepts_flag_rejects_hex() {
        check_flag_shape("flag{ish-deadbeefcafebabe}").unwrap();
        check_flag_shape("  flag{x}  ").unwrap();
        let hex = "666c61677b6973682d646561646265656663616665626162657d";
        let err = check_flag_shape(hex).unwrap_err().to_string();
        assert!(err.contains("hex dump"), "{err}");
        let err = check_flag_shape("not a flag").unwrap_err().to_string();
        assert!(err.contains("flag{"), "{err}");
    }

    #[test]
    fn check_slug_rejects_junk() {
        check_slug("flag_gatt").unwrap();
        check_slug("gate").unwrap();
        assert!(check_slug("../x").is_err());
        assert!(check_slug("").is_err());
        assert!(check_slug("a/b").is_err());
    }

    fn issue_fixture(device_pub: &[u8; 32], load: &Load) -> serde_json::Value {
        serde_json::json!({
            "proto": CTF_PROTO,
            "challenge": "gate",
            "device_pub": hex::encode_lower(device_pub),
            "reused": false,
            "load": load_json(load),
        })
    }

    #[test]
    fn hello_key_requires_protocol_and_exact_contributory_public_key() {
        let key = [9; 32];
        let hello =
            serde_json::json!({"proto": 2, "pub": hex::encode_lower(&key), "challenge": "gate"});
        assert_eq!(box_hello(&hello, Some("gate")).unwrap().key, key);
        let mut uppercase = hello.clone();
        uppercase["pub"] = serde_json::json!(hex::encode(&key));
        assert_eq!(box_hello(&uppercase, None).unwrap().key, key);
        for (field, value) in [
            ("proto", serde_json::json!(1)),
            ("proto", serde_json::json!(true)),
            ("proto", serde_json::json!("2")),
            ("pub", serde_json::json!("aa")),
            ("pub", serde_json::json!("g".repeat(64))),
            ("pub", serde_json::json!("00".repeat(32))),
            (
                "pub",
                serde_json::json!(format!("{} ", hex::encode_lower(&key))),
            ),
        ] {
            let mut invalid = hello.clone();
            invalid[field] = value;
            assert!(box_hello(&invalid, None).is_err());
        }
    }
}
