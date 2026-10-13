//! Flash a CTF box, provision a RAM-only flag, reload it after a power-cycle,
//! submit.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

use crate::ctf_http::{USER_AGENT as UA, send, send_json};
use crate::flash;
use crate::{log, signals};

pub const DEFAULT_URL: &str = "https://ctf.infishark.com";

pub struct ApiOpts {
    pub url: Option<String>,
    pub token: Option<String>,
    pub user: Option<String>,
}

pub struct Start {
    pub target: String,
    pub bin: Option<PathBuf>,
    pub local: bool,
    pub yes: bool,
    pub json: bool,
    pub port: Option<String>,
    pub timeout_ms: u64,
    pub api: ApiOpts,
}

pub struct Submit {
    pub challenge: String,
    pub flag: String,
    pub json: bool,
    pub api: ApiOpts,
}

pub struct LoadOpts {
    pub slug: Option<String>,
    pub json: bool,
    pub port: Option<String>,
    pub timeout_ms: u64,
    pub api: ApiOpts,
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

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Challenge {
    pub slug: String,
    pub title: String,
    pub difficulty: String,
    #[serde(default)]
    pub firmware: Option<Firmware>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct HintBody {
    pub challenge: String,
    pub level: u32,
    pub total: u32,
    pub text: String,
}

const CTF_PROTO: u32 = 2;
const REFLASH_REQUIRED: &str = "CTF firmware identity missing, unknown, or invalid; reflash required with a protocol-2 challenge image";
const MAX_FLAG_BYTES: usize = 95;
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct IssueLoad {
    #[serde(rename = "pub")]
    sender_pub: String,
    n: String,
    ct: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct IssueBody {
    proto: u32,
    challenge: String,
    device_pub: String,
    reused: bool,
    #[serde(deserialize_with = "deserialize_object")]
    load: IssueLoad,
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

impl IssueBody {
    fn validate(&self, slug: &str, device_pub: &[u8; 32]) -> Result<()> {
        if self.proto != CTF_PROTO
            || self.challenge != slug
            || self.device_pub != hex::encode_lower(device_pub)
        {
            bail!("CTF issue response protocol, challenge or recipient mismatch");
        }
        let load = &self.load;
        if !lower_hex(&load.sender_pub, 32, 32)
            || !lower_hex(&load.n, 12, 12)
            || !lower_hex(&load.ct, 17, MAX_FLAG_BYTES + 16)
        {
            bail!("invalid CTF issue envelope");
        }
        let sender: [u8; 32] = hex::decode_n(&load.sender_pub)?;
        check_public_key(&sender)?;
        Ok(())
    }
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

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SubmitBody {
    pub ok: bool,
    pub already: bool,
}

struct Api {
    url: String,
    token: Option<String>,
    user: String,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("url", &self.url)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl Api {
    fn resolve(opts: &ApiOpts) -> Result<Self> {
        let url = pick(opts.url.clone(), &["INFISHARK_CTF_URL", "CTF_URL"])
            .unwrap_or_else(|| DEFAULT_URL.to_string());
        let url = crate::ctf_account::normalize_endpoint(&url)?;
        let token = pick(opts.token.clone(), &["INFISHARK_CTF_TOKEN", "CTF_TOKEN"]);
        let user = pick(
            opts.user.clone(),
            &["INFISHARK_CTF_USER", "CTF_USER", "USER", "USERNAME"],
        )
        .unwrap_or_else(|| "player".into());
        if user.is_empty() {
            bail!("missing player id (--user or INFISHARK_CTF_USER)");
        }
        Ok(Self { url, token, user })
    }

    fn authorized(opts: &ApiOpts) -> Result<Self> {
        let mut api = Self::resolve(opts)?;
        api.token = Some(crate::ctf_account::credential(&api.url, api.token)?);
        api.require_token()?;
        Ok(api)
    }

    #[cfg(test)]
    fn at(url: &str, token: &str, user: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            token: Some(token.into()),
            user: user.into(),
        }
    }

    fn agent() -> ureq::Agent {
        crate::ctf_http::agent()
    }

    fn authed(&self, req: ureq::Request) -> ureq::Request {
        let req = req.set("User-Agent", UA);
        // Account bearer tokens are the identity; only explicit legacy tokens use
        // x-user.
        let req = if self.token.as_deref().is_some_and(|t| t.starts_with("ctf_")) {
            req
        } else {
            req.set("x-user", &self.user)
        };
        match &self.token {
            Some(t) if !t.is_empty() => req.set("Authorization", &format!("Bearer {t}")),
            _ => req,
        }
    }

    fn require_token(&self) -> Result<()> {
        match &self.token {
            Some(t) if !t.is_empty() => Ok(()),
            _ => bail!("set INFISHARK_CTF_TOKEN (or --token)"),
        }
    }

    fn challenges(&self) -> Result<Vec<Challenge>> {
        let url = format!("{}/v1/challenges", self.url);
        let (st, body) = send(Self::agent().get(&url).set("User-Agent", UA))?;
        if st != 200 {
            bail!("{}", api_error(st, &body));
        }
        serde_json::from_str(&body).map_err(|_| anyhow::anyhow!("invalid CTF catalog response"))
    }

    fn firmware_grant(&self, slug: &str) -> Result<FirmwareGrant> {
        self.require_token()?;
        check_slug(slug)?;
        let url = format!("{}/v1/challenges/{slug}/firmware", self.url);
        // Bound grant responses and discard provider bodies and URL-bearing transport
        // errors.
        let response = match self
            .authed(Self::agent().post(&url))
            .set("Content-Type", "application/json")
            .send_string("{}")
        {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(_) => {
                bail!("CTF firmware grant request failed; check your connection and try again")
            }
        };
        match response.status() {
            200 => {}
            401 => bail!(
                "CTF firmware grant requires valid credentials; log in again or check --token"
            ),
            403 => bail!("CTF firmware grant requires an active membership"),
            404 => bail!("CTF firmware grant not found; check the challenge or pass a local .bin"),
            503 => bail!("CTF billing or firmware artifact unavailable; try again later"),
            status => bail!("CTF firmware grant HTTP {status}; try again later"),
        }
        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_FIRMWARE_GRANT_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| anyhow::anyhow!("could not read CTF firmware grant"))?;
        if body.len() as u64 > MAX_FIRMWARE_GRANT_BYTES {
            bail!("CTF firmware grant response is too large");
        }
        let JsonObject(grant) = serde_json::from_slice::<JsonObject<FirmwareGrant>>(&body)
            .map_err(|_| anyhow::anyhow!("invalid CTF firmware grant response"))?;
        grant.validate(slug)?;
        Ok(grant)
    }

    fn hint(&self, slug: &str, level: u32) -> Result<HintBody> {
        check_slug(slug)?;
        if level == 0 {
            bail!("hint levels start at 1");
        }
        let url = format!("{}/v1/challenges/{slug}/hints/{level}", self.url);
        let (st, body) = send(Self::agent().get(&url).set("User-Agent", UA))?;
        if st == 404 {
            bail!("CTF server HTTP 404: hint unavailable; try an earlier level");
        }
        if st != 200 {
            bail!("{}", api_error(st, &body));
        }
        let hint: HintBody = serde_json::from_str(&body)
            .map_err(|_| anyhow::anyhow!("invalid CTF hint response"))?;
        if hint.challenge != slug
            || hint.level != level
            || hint.total < level
            || hint.text.is_empty()
        {
            bail!("invalid hint response for {slug} level {level}");
        }
        Ok(hint)
    }

    fn issue(&self, slug: &str, device_pub: &[u8; 32]) -> Result<IssueBody> {
        self.require_token()?;
        check_slug(slug)?;
        check_public_key(device_pub)?;
        let url = format!("{}/v1/challenges/{slug}/issue", self.url);
        let (st, body) = send_json(
            self.authed(Self::agent().post(&url)),
            serde_json::json!({
                "proto": CTF_PROTO,
                "device_pub": hex::encode_lower(device_pub),
            }),
        )?;
        if st != 200 {
            // Enforce entitlement for local images without echoing untrusted issue bodies.
            match st {
                401 => bail!("CTF issue requires valid credentials; log in again or check --token"),
                403 => bail!("CTF issue requires an active membership"),
                409 => bail!("CTF issue HTTP 409: already solved; not re-issuing"),
                503 => bail!("CTF billing or firmware artifact unavailable; try again later"),
                _ => bail!("CTF issue HTTP {st}"),
            }
        }
        let JsonObject(issued) =
            serde_json::from_str::<JsonObject<IssueBody>>(&body).map_err(|_| {
                anyhow::anyhow!(
                    "invalid ciphertext-only CTF issue response; update the API and CLI together"
                )
            })?;
        issued.validate(slug, device_pub)?;
        Ok(issued)
    }

    fn submit(&self, challenge: &str, flag: &str) -> Result<SubmitBody> {
        self.require_token()?;
        check_slug(challenge)?;
        let url = format!("{}/v1/submit", self.url);
        let (st, body) = send_json(
            self.authed(Self::agent().post(&url)),
            serde_json::json!({ "challenge": challenge, "flag": flag }),
        )?;
        if st == 200 {
            return serde_json::from_str(&body)
                .map_err(|_| anyhow::anyhow!("invalid CTF submit response"));
        }
        bail!("{}", api_error(st, &body));
    }
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

fn api_error(status: u16, _body: &str) -> String {
    match status {
        401 => "CTF server HTTP 401: invalid credentials; log in again or check --token".into(),
        403 => "CTF server HTTP 403: access denied; check your membership".into(),
        429 => "CTF server HTTP 429: rate limited; try again later".into(),
        503 => "CTF server HTTP 503: service unavailable; try again later".into(),
        _ => format!("CTF server HTTP {status}"),
    }
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

#[derive(Debug)]
struct DownloadedFirmware {
    dir: PathBuf,
    bin: PathBuf,
}

impl Drop for DownloadedFirmware {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl DownloadedFirmware {
    fn new() -> Result<Self> {
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let dir =
            std::env::temp_dir().join(format!("infishark-ctf-{}", hex::encode_lower(&random)));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&dir)
            .context("create private firmware download directory")?;
        Ok(Self {
            bin: dir.join("firmware.bin"),
            dir,
        })
    }
}

fn firmware_redirect(url: &Url, location: &str) -> Result<Url> {
    if signed_firmware_url(url) {
        bail!("signed firmware redirects are not allowed");
    }
    let next = url
        .join(location)
        .map_err(|_| anyhow::anyhow!("invalid firmware redirect"))?;
    let next = firmware_url(next.as_str())?;
    if url.scheme() == "https" && next.scheme() != "https" {
        bail!("firmware redirect cannot downgrade HTTPS");
    }
    if signed_firmware_url(&next) {
        bail!("public firmware cannot redirect to signed firmware; request a grant");
    }
    Ok(next)
}

fn download_firmware(firmware: &Firmware) -> Result<DownloadedFirmware> {
    let url = validate_firmware(firmware)?;
    let signed = signed_firmware_url(&url);
    if signed {
        bail!("signed firmware download requires a validated CTF firmware grant");
    }
    download_firmware_from(firmware, url, true)
}

fn download_firmware_from(
    firmware: &Firmware,
    mut url: Url,
    allow_redirects: bool,
) -> Result<DownloadedFirmware> {
    // This separate, unauthenticated agent must never inherit API credentials.
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(90))
        .build();
    let mut redirects = 0;
    let response = loop {
        let response = match agent.get(url.as_str()).set("User-Agent", UA).call() {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            // ureq's transport errors embed the full URL, including its signature.
            Err(_) => {
                bail!("CTF firmware download failed; check your connection or request a new grant")
            }
        };
        match response.status() {
            200 => break response,
            301 | 302 | 303 | 307 | 308 => {
                if !allow_redirects {
                    bail!("signed firmware redirects are not allowed");
                }
                if redirects == 5 {
                    bail!("too many firmware redirects");
                }
                let location = response
                    .header("Location")
                    .context("firmware redirect missing Location")?;
                url = firmware_redirect(&url, location)?;
                redirects += 1;
            }
            status => bail!("firmware download HTTP {status}; expected 200"),
        }
    };
    store_firmware(firmware, response.into_reader(), DownloadedFirmware::new()?)
}

fn store_firmware(
    firmware: &Firmware,
    reader: impl Read,
    download: DownloadedFirmware,
) -> Result<DownloadedFirmware> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&download.bin)
        .context("create firmware download file")?;
    let mut reader = reader.take(firmware.size_bytes + 1);
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0u8; 16 * 1024];
    loop {
        // Stream errors can also carry transport details; discard their sources.
        let n = reader
            .read(&mut buf)
            .map_err(|_| anyhow::anyhow!("could not read CTF firmware"))?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > firmware.size_bytes {
            bail!(
                "firmware size mismatch: expected {} bytes, received more",
                firmware.size_bytes
            );
        }
        hash.update(&buf[..n]);
        file.write_all(&buf[..n]).context("write CTF firmware")?;
    }
    if count != firmware.size_bytes {
        bail!(
            "firmware size mismatch: expected {} bytes, got {count}",
            firmware.size_bytes
        );
    }
    let actual = hex::encode_lower(&hash.finalize());
    if actual != firmware.sha256 {
        bail!(
            "firmware SHA-256 mismatch: expected {}, got {actual}",
            firmware.sha256
        );
    }
    file.flush().context("flush CTF firmware")?;
    drop(file);
    Ok(download)
}

#[derive(Debug, PartialEq)]
struct StartSpec {
    slug: Option<String>,
    bin: Option<PathBuf>,
}

fn looks_like_bin(s: &str) -> bool {
    Path::new(s).is_file() || s.ends_with(".bin") || s.ends_with(".BIN")
}

fn resolve_start(target: &str, bin: Option<&Path>, local: bool) -> Result<StartSpec> {
    if looks_like_bin(target) {
        if let Some(extra) = bin {
            bail!("unexpected extra path {}", extra.display());
        }
        if local {
            return Ok(StartSpec {
                slug: None,
                bin: Some(PathBuf::from(target)),
            });
        }
        bail!(
            "pass a challenge slug: infishark ctf start <slug> [bin]\n       or --local to skip the server"
        );
    }
    check_slug(target)?;
    if local && bin.is_none() {
        bail!("--local requires a .bin: infishark ctf start {target} <bin> --local");
    }
    Ok(StartSpec {
        slug: Some(target.to_string()),
        bin: bin.map(Path::to_path_buf),
    })
}

#[derive(Debug)]
struct PreparedStart {
    bin: PathBuf,
    _download: Option<DownloadedFirmware>,
    firmware: Option<Firmware>,
    api: Option<Api>,
}

fn prepare_start(spec: &StartSpec, local: bool, opts: &ApiOpts) -> Result<PreparedStart> {
    let api = if local {
        None
    } else {
        Some(Api::authorized(opts)?)
    };
    if let Some(api) = &api {
        api.require_token()?;
    }
    let mut firmware = None;
    let mut download = None;
    let bin = match &spec.bin {
        Some(path) => path.clone(),
        None => {
            let api = api
                .as_ref()
                .context("firmware grant requires the CTF server")?;
            let slug = spec.slug.as_deref().context("missing challenge slug")?;
            let grant = api.firmware_grant(slug)?;
            // Recheck expiry immediately before the artifact request.
            let url = grant.validate(slug)?;
            log::info(format!(
                "downloading {slug} v{} ({} bytes)...",
                grant.firmware.version, grant.firmware.size_bytes
            ));
            let image = if grant.expires_at.is_some() {
                download_firmware_from(&grant.firmware, url, false)?
            } else {
                download_firmware(&grant.firmware)?
            };
            let path = image.bin.clone();
            download = Some(image);
            firmware = Some(grant.into_report());
            log::ok("firmware size and SHA-256 verified");
            path
        }
    };
    flash::require_bin(&bin)?;
    // Issuance must wait for the active post-flash boot key, not the old image.
    Ok(PreparedStart {
        bin,
        _download: download,
        firmware,
        api,
    })
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
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn serve_once(status: u16, body: &str) -> String {
        serve_response(status, body).0
    }

    fn serve_response(status: u16, body: &str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        let worker = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 8192];
            let header_end = loop {
                let n = s.read(&mut buf).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while request.len() < header_end + length {
                let n = s.read(&mut buf).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
            }
            let reason = match status {
                200 => "OK",
                401 => "Unauthorized",
                404 => "Not Found",
                409 => "Conflict",
                _ => "X",
            };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
            String::from_utf8(request).unwrap()
        });
        (format!("http://{addr}"), worker)
    }

    #[test]
    fn malformed_success_responses_do_not_echo_provider_values() {
        let secret = "flag{private-provider-value}";
        for (kind, body) in [
            (
                "catalog",
                format!(
                    r#"[{{"slug":"gate","title":"Gate","difficulty":"easy","firmware":{{"version":"{secret}","url":"https://example.com/image","sha256":"","size_bytes":1}}}}]"#
                ),
            ),
            (
                "hint",
                format!(r#"{{"challenge":"gate","level":"{secret}","total":1,"text":"hint"}}"#),
            ),
            ("submit", format!(r#"{{"ok":"{secret}","already":false}}"#)),
        ] {
            let (url, worker) = serve_response(200, &body);
            let api = Api::at(&url, "synthetic-token", "player");
            let error = match kind {
                "catalog" => api.challenges().unwrap_err(),
                "hint" => api.hint("gate", 1).unwrap_err(),
                "submit" => api.submit("gate", "flag{synthetic}").unwrap_err(),
                _ => unreachable!(),
            };
            worker.join().unwrap();
            assert_eq!(format!("{error:#}"), format!("invalid CTF {kind} response"));
            assert!(!format!("{error:#}").contains(secret));
        }
    }

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
    fn resolve_start_slug_and_local_bin() {
        let spec = resolve_start("flag_gatt", Some(Path::new("firmware.bin")), false).unwrap();
        assert_eq!(
            spec,
            StartSpec {
                slug: Some("flag_gatt".into()),
                bin: Some(PathBuf::from("firmware.bin")),
            }
        );
        let spec = resolve_start("firmware.bin", None, true).unwrap();
        assert_eq!(
            spec,
            StartSpec {
                slug: None,
                bin: Some(PathBuf::from("firmware.bin")),
            }
        );
        assert_eq!(
            resolve_start("gate", None, false).unwrap(),
            StartSpec {
                slug: Some("gate".into()),
                bin: None,
            }
        );
        assert!(resolve_start("firmware.bin", None, false).is_err());
        assert!(resolve_start("flag_gatt", None, true).is_err());
        assert!(resolve_start("firmware.bin", Some(Path::new("a.bin")), true).is_err());
        assert!(resolve_start("nope!", Some(Path::new("a.bin")), false).is_err());
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

    #[test]
    fn issue_response_rejects_legacy_extras_mismatches_and_malformed_envelopes() {
        let key = [9; 32];
        let load = seal(&key, "gate", b"flag{test}").unwrap();
        let valid = issue_fixture(&key, &load);
        let decode = |value: &serde_json::Value| -> Result<IssueBody> {
            let JsonObject(body) = serde_json::from_value::<JsonObject<IssueBody>>(value.clone())?;
            body.validate("gate", &key)?;
            Ok(body)
        };
        decode(&valid).unwrap();
        assert!(
            decode(&serde_json::json!([
                1,
                "gate",
                hex::encode_lower(&key),
                false,
                valid["load"]
            ]))
            .is_err()
        );
        assert!(decode(&serde_json::json!({"flag": "flag{legacy}", "reused": false})).is_err());
        for (field, value) in [
            ("proto", serde_json::json!(1)),
            ("proto", serde_json::json!(true)),
            ("challenge", serde_json::json!("flag_gatt")),
            ("device_pub", serde_json::json!("00".repeat(32))),
            ("reused", serde_json::json!(1)),
            ("flag", serde_json::json!("flag{legacy}")),
            ("load", serde_json::json!(null)),
            (
                "load",
                serde_json::json!([
                    valid["load"]["pub"],
                    valid["load"]["n"],
                    valid["load"]["ct"]
                ]),
            ),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(decode(&invalid).is_err());
        }
        for (field, value) in [
            ("pub", serde_json::json!("aa")),
            ("pub", serde_json::json!("00".repeat(32))),
            (
                "pub",
                serde_json::json!(
                    load_json(&load)["pub"]
                        .as_str()
                        .unwrap()
                        .to_ascii_uppercase()
                ),
            ),
            ("n", serde_json::json!("00".repeat(11))),
            ("n", serde_json::json!("00".repeat(13))),
            ("ct", serde_json::json!("00".repeat(16))),
            ("ct", serde_json::json!("00".repeat(MAX_FLAG_BYTES + 17))),
            ("ct", serde_json::json!("a".repeat(35))),
            ("ct", serde_json::json!("g".repeat(40))),
            ("flag", serde_json::json!("flag{legacy}")),
        ] {
            let mut invalid = valid.clone();
            invalid["load"][field] = value;
            assert!(decode(&invalid).is_err());
        }
        for bytes in [17, MAX_FLAG_BYTES + 16] {
            let mut boundary = valid.clone();
            boundary["load"]["ct"] = serde_json::json!("00".repeat(bytes));
            decode(&boundary).unwrap(); // Authentication is the box's job, not the relay's.
        }
        let duplicate = valid.to_string().replacen("{", "{\"proto\":1,", 1);
        assert!(serde_json::from_str::<JsonObject<IssueBody>>(&duplicate).is_err());
        let nested_duplicate = valid.to_string().replace(
            &valid["load"].to_string(),
            &valid["load"]
                .to_string()
                .replacen("{", "{\"n\":\"000000000000000000000000\",", 1),
        );
        assert!(serde_json::from_str::<JsonObject<IssueBody>>(&nested_duplicate).is_err());
    }

    #[test]
    fn issue_errors_never_echo_plaintext_or_envelope_values() {
        let key = [9; 32];
        let load = seal(&key, "gate", b"flag{must-not-escape}").unwrap();
        let valid = issue_fixture(&key, &load);
        let mut extra = valid.clone();
        extra["reused"] = serde_json::json!("flag{must-not-escape}");
        let positional =
            serde_json::json!([1, "gate", hex::encode_lower(&key), false, valid["load"]]);
        let mut nested_positional = valid.clone();
        nested_positional["load"] = serde_json::json!([
            valid["load"]["pub"],
            valid["load"]["n"],
            valid["load"]["ct"]
        ]);
        for (status, body) in [
            (
                200,
                r#"{"flag":"flag{must-not-escape}","reused":false}"#.into(),
            ),
            (200, extra.to_string()),
            (200, positional.to_string()),
            (200, nested_positional.to_string()),
            (400, r#"{"flag":"flag{must-not-escape}"}"#.into()),
            (502, issue_fixture(&key, &load).to_string()),
        ] {
            let url = serve_once(status, &body);
            let error = format!(
                "{:#}",
                Api::at(&url, "tok", "alice")
                    .issue("gate", &key)
                    .unwrap_err()
            );
            for value in [
                "must-not-escape",
                &hex::encode_lower(&load.ct),
                &hex::encode_lower(&key),
            ] {
                assert!(!error.contains(value), "{error}");
            }
        }
    }

    #[test]
    fn low_order_keys_fail_before_issue_or_local_encryption() {
        let api = Api::at("http://127.0.0.1:1", "tok", "alice");
        let mut one = [0; 32];
        one[0] = 1;
        for key in [[0; 32], one] {
            assert!(
                api.issue("gate", &key)
                    .unwrap_err()
                    .to_string()
                    .contains("invalid CTF public key")
            );
            assert!(seal(&key, "gate", b"flag{local}").is_err());
        }
    }

    #[test]
    fn api_challenges_and_issue_and_submit() {
        let url = serve_once(
            200,
            r#"[{"slug":"gate","title":"Write then notify","difficulty":"medium"}]"#,
        );
        let api = Api::at(&url, "tok", "alice");
        let list = api.challenges().unwrap();
        assert_eq!(list[0].slug, "gate");

        let device_sk = StaticSecret::random_from_rng(OsRng);
        let device_pub = PublicKey::from(&device_sk).to_bytes();
        let flag = b"flag{ish-deadbeefcafebabe}";
        let load = seal(&device_pub, "gate", flag).unwrap();
        let envelope = issue_fixture(&device_pub, &load);
        let (url, worker) = serve_response(200, &envelope.to_string());
        let api = Api::at(&url, "tok", "alice");
        let issued = api.issue("gate", &device_pub).unwrap();
        assert!(!issued.reused);
        assert_eq!(
            serde_json::to_value(&issued.load).unwrap(),
            load_json(&load)
        );
        assert_eq!(unseal(&device_sk, "gate", &load).unwrap(), flag);
        let request = worker.join().unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        let headers = headers.to_ascii_lowercase();
        assert!(headers.starts_with("post /v1/challenges/gate/issue "));
        assert!(headers.contains("authorization: bearer tok"));
        assert!(headers.contains("x-user: alice"));
        assert!(headers.contains("content-type: application/json"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({
                "proto": 2,
                "device_pub": hex::encode_lower(&device_pub),
            })
        );
        assert!(!serde_json::to_string(&issued).unwrap().contains("flag"));

        let url = serve_once(409, "already solved; not re-issuing");
        let api = Api::at(&url, "tok", "alice");
        let err = api.issue("gate", &device_pub).unwrap_err().to_string();
        assert!(err.contains("already solved"), "{err}");

        let url = serve_once(200, r#"{"ok":false,"already":false}"#);
        let api = Api::at(&url, "tok", "alice");
        let body = api.submit("gate", "flag{ish-deadbeefcafebabe}").unwrap();
        assert!(!body.ok);

        let url = serve_once(401, "bad token private-provider-body\u{1b}[2J");
        let api = Api::at(&url, "nope", "alice");
        let err = api.submit("gate", "flag{x}").unwrap_err().to_string();
        assert!(
            err.contains("HTTP 401") && err.contains("invalid credentials"),
            "{err}"
        );
        assert!(!err.contains("private-provider-body") && !err.contains('\u{1b}'));
    }

    #[test]
    fn api_requires_token() {
        let api = Api {
            url: "http://127.0.0.1:1".into(),
            token: None,
            user: "alice".into(),
        };
        let err = api.issue("gate", &[9; 32]).unwrap_err().to_string();
        assert!(err.contains("INFISHARK_CTF_TOKEN"), "{err}");
    }
}
