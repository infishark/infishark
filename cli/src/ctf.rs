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
use url::Url;
use x25519_dalek::{PublicKey, StaticSecret};

pub const DEFAULT_URL: &str = "https://ctf.infishark.com";

pub struct ApiOpts {
    pub url: Option<String>,
    pub token: Option<String>,
    pub user: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct Firmware {
    pub version: u32,
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

impl std::fmt::Debug for Firmware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Firmware")
            .field("version", &self.version)
            .field("url", &"[redacted]")
            .field("sha256", &self.sha256)
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirmwareGrant {
    challenge: String,
    #[serde(deserialize_with = "deserialize_grant_firmware")]
    firmware: Firmware,
    // Unlike an ordinary Option field, this requires an explicit integer or null.
    #[serde(deserialize_with = "deserialize_grant_expiry")]
    expires_at: Option<i64>,
}

impl std::fmt::Debug for FirmwareGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirmwareGrant")
            .field("challenge", &self.challenge)
            .field("version", &self.firmware.version)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

fn deserialize_grant_expiry<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<i64>, D::Error> {
    Option::<i64>::deserialize(deserializer)
}

fn deserialize_grant_firmware<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Firmware, D::Error> {
    // Keep the public catalog's existing schema/decoder; grants are stricter.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Metadata {
        version: u32,
        url: String,
        sha256: String,
        size_bytes: u64,
    }
    let metadata: Metadata = deserialize_object(deserializer)?;
    Ok(Firmware {
        version: metadata.version,
        url: metadata.url,
        sha256: metadata.sha256,
        size_bytes: metadata.size_bytes,
    })
}

impl FirmwareGrant {
    fn validate(&self, slug: &str) -> Result<Url> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .ok_or_else(|| anyhow::anyhow!("cannot validate CTF firmware grant expiry"))?;
        self.validate_at(slug, now)
    }

    fn validate_at(&self, slug: &str, now: i64) -> Result<Url> {
        if self.challenge != slug {
            bail!("CTF firmware grant challenge mismatch");
        }
        let url = validate_firmware(&self.firmware)?;
        match self.expires_at {
            Some(expiry) => {
                if expiry <= now {
                    bail!("CTF firmware grant expired; request a new grant");
                }
                if expiry > now.saturating_add(MAX_GRANT_LIFETIME_SECS) {
                    bail!("CTF firmware grant expiry exceeds ten minutes");
                }
                validate_signed_firmware_url(
                    &self.firmware.url,
                    &url,
                    slug,
                    self.firmware.version,
                    expiry,
                    now,
                )?;
            }
            None if signed_firmware_url(&url) => {
                bail!("signed CTF firmware grant requires an expiry");
            }
            None => {}
        }
        Ok(url)
    }

    fn into_report(mut self) -> Firmware {
        if self.expires_at.is_some() {
            // Do not expose even the private endpoint/path in JSON or Debug output.
            self.firmware.url = "[redacted]".into();
        }
        self.firmware
    }
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

const MAX_FIRMWARE_SIZE: u64 = 0x1e0000;
const MAX_FIRMWARE_GRANT_BYTES: u64 = 16 * 1024;
const MAX_FIRMWARE_URL_BYTES: usize = 8 * 1024;
const R2_ACCOUNT_SUFFIX: &str = ".r2.cloudflarestorage.com";
const MAX_GRANT_LIFETIME_SECS: i64 = 10 * 60;
const MAX_SIGNED_URL_LIFETIME_SECS: i64 = 300;
const SIGNED_CLOCK_SKEW_SECS: i64 = 60;

fn signed_firmware_url(url: &Url) -> bool {
    url.host_str()
        .is_some_and(|host| host.ends_with(R2_ACCOUNT_SUFFIX))
        || url
            .query_pairs()
            .any(|(name, _)| name.to_ascii_lowercase().starts_with("x-amz-"))
}

fn validate_signed_firmware_url(
    raw: &str,
    url: &Url,
    slug: &str,
    version: u32,
    expiry: i64,
    now: i64,
) -> Result<()> {
    let host = url.host_str().unwrap_or_default();
    let account = host.strip_suffix(R2_ACCOUNT_SUFFIX).unwrap_or_default();
    let authority = raw
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next());
    // Require canonical URLs without normalization, ports, credentials or
    // fragments.
    if !lower_hex(account, 16, 16)
        || authority != Some(host)
        || raw != url.as_str()
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("signed firmware URL must use the canonical HTTPS S3 R2 account-host");
    }
    let (bucket, key) = url
        .path()
        .strip_prefix('/')
        .and_then(|path| path.split_once('/'))
        .unwrap_or(("", ""));
    if !(3..=63).contains(&bucket.len())
        || !bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        || !bucket
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !bucket
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || bucket.contains("..")
        || bucket.contains(".-")
        || bucket.contains("-.")
        || bucket.parse::<std::net::Ipv4Addr>().is_ok()
        || key != format!("ctf/{slug}/{version}.bin")
    {
        bail!("signed firmware object path does not match the challenge and version");
    }
    validate_sigv4_query(url, expiry, now)
}

fn validate_sigv4_query(url: &Url, expiry: i64, now: i64) -> Result<()> {
    const NAMES: [&str; 6] = [
        "X-Amz-Algorithm",
        "X-Amz-Credential",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-SignedHeaders",
        "X-Amz-Signature",
    ];
    let invalid = || anyhow::anyhow!("invalid or expired signed firmware authorization");
    let query = url.query().ok_or_else(invalid)?;
    // Require six unique presigning fields with literal names and encoded
    // credential slashes.
    if !query.split('&').all(|part| {
        part.split_once('=')
            .is_some_and(|(name, _)| NAMES.contains(&name))
    }) {
        return Err(invalid());
    }
    let mut fields: [Option<String>; 6] = std::array::from_fn(|_| None);
    for (name, value) in url.query_pairs() {
        let index = NAMES
            .iter()
            .position(|expected| *expected == name)
            .ok_or_else(invalid)?;
        if fields[index].replace(value.into_owned()).is_some() {
            return Err(invalid());
        }
    }
    let [
        Some(algorithm),
        Some(credential),
        Some(date),
        Some(lifetime),
        Some(headers),
        Some(signature),
    ] = fields
    else {
        return Err(invalid());
    };
    let signed_at = sigv4_timestamp(&date).ok_or_else(invalid)?;
    let seconds = lifetime.parse::<i64>().map_err(|_| invalid())?;
    let scope: Vec<_> = credential.split('/').collect();
    let [access_key, scope_date, region, service, terminator] = scope.as_slice() else {
        return Err(invalid());
    };
    if algorithm != "AWS4-HMAC-SHA256"
        || headers != "host"
        || !lower_hex(&signature, 32, 32)
        || access_key.is_empty()
        || access_key.len() > 128
        || !access_key.bytes().all(|b| b.is_ascii_alphanumeric())
        || *scope_date != &date[..8]
        || *region != "auto"
        || *service != "s3"
        || *terminator != "aws4_request"
        || !(1..=MAX_SIGNED_URL_LIFETIME_SECS).contains(&seconds)
        || lifetime != seconds.to_string()
        || signed_at > now.saturating_add(SIGNED_CLOCK_SKEW_SECS)
        || signed_at + seconds <= now
        || expiry > signed_at + seconds
    {
        return Err(invalid());
    }
    // Check scope and syntax; R2 verifies signatures and the backend enforces
    // entitlement.
    Ok(())
}

fn sigv4_timestamp(date: &str) -> Option<i64> {
    // AWS's exact UTC YYYYMMDDTHHMMSSZ format, without a new crate dependency.
    if date.len() != 16
        || !date.is_ascii()
        || &date[8..9] != "T"
        || &date[15..] != "Z"
        || !date[..8]
            .bytes()
            .chain(date[9..15].bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let year = date[..4].parse::<i64>().ok()?;
    let month = date[4..6].parse::<usize>().ok()?;
    let day = date[6..8].parse::<i64>().ok()?;
    let hour = date[9..11].parse::<i64>().ok()?;
    let minute = date[11..13].parse::<i64>().ok()?;
    let second = date[13..15].parse::<i64>().ok()?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        28 + i64::from(leap),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year < 1970
        || !(1..=12).contains(&month)
        || !(1..=month_days[month - 1]).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let leap_days = |last_year: i64| last_year / 4 - last_year / 100 + last_year / 400;
    let days = 365 * (year - 1970) + leap_days(year - 1) - leap_days(1969)
        + month_days[..month - 1].iter().sum::<i64>()
        + day
        - 1;
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

fn firmware_url(raw: &str) -> Result<Url> {
    if raw.len() > MAX_FIRMWARE_URL_BYTES {
        bail!("firmware URL is too large");
    }
    let url = Url::parse(raw).map_err(|_| anyhow::anyhow!("invalid firmware URL"))?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if url.host().is_none()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!(
            "firmware URL must use HTTPS without embedded credentials (HTTP is allowed only on loopback)"
        );
    }
    Ok(url)
}

fn validate_firmware(firmware: &Firmware) -> Result<Url> {
    if firmware.version == 0 {
        bail!("firmware version must be positive");
    }
    if firmware.size_bytes == 0 || firmware.size_bytes > MAX_FIRMWARE_SIZE {
        bail!(
            "invalid firmware size {}; app partition limit is {MAX_FIRMWARE_SIZE} bytes",
            firmware.size_bytes
        );
    }
    if firmware.sha256.len() != 64
        || !firmware
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("invalid firmware SHA-256; expected 64 lowercase hexadecimal characters");
    }
    firmware_url(&firmware.url)
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
#[path = "ctf_download_tests.rs"]
mod download_tests;

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
