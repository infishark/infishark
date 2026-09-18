//! Signed OTA fetch from firmware.infishark.com (UA "BLEShark Nano").

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use infishark::hex;
use infishark::paths;
use sha2::{Digest, Sha256};

pub const API_BASE: &str = "https://firmware.infishark.com/api";
const UA: &str = "BLEShark Nano";

type HmacSha256 = Hmac<Sha256>;

const SIG_SEED: &[u8] = b"d0d1b164131df4509658c68f3c2b414f";
const CHECKSUM_KEY: &[u8] = b"Ch3cksumBL3Sh4rk";

fn hmac_sha256(msg: &[u8], key: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

pub fn signature_from_efuse(efuse: &[u8; 6]) -> [u8; 32] {
    let efuse_hex = hex::encode_lower(efuse);
    let hmac_key = hmac_sha256(efuse_hex.as_bytes(), SIG_SEED);
    let hmac_key_hex = hex::encode_lower(&hmac_key);
    hmac_sha256(efuse_hex.as_bytes(), hmac_key_hex.as_bytes())
}

pub fn device_signature(id: &infishark::DeviceFw) -> [u8; 32] {
    id.signature
        .unwrap_or_else(|| signature_from_efuse(&id.efuse))
}

fn checksum_sig(kind: &str, tag: &str) -> String {
    let mut msg = Vec::with_capacity(kind.len() + 1 + tag.len());
    msg.extend_from_slice(kind.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(tag.as_bytes());
    hex::encode_lower(&hmac_sha256(&msg, CHECKSUM_KEY))
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .build()
}

fn get(url: &str) -> Result<ureq::Response> {
    agent()
        .get(url)
        .set("User-Agent", UA)
        .call()
        .with_context(|| format!("GET {url}"))
}

fn get_text(url: &str) -> Result<String> {
    let body = get(url)?.into_string().context("reading response")?;
    Ok(body.trim().to_string())
}

pub fn with_v(tag: &str) -> String {
    let t = tag.trim().trim_start_matches(['v', 'V']);
    format!("v{t}")
}

pub fn latest_tag(kind: &str) -> Result<String> {
    let url = format!("{API_BASE}/version?type={kind}");
    let tag = get_text(&url)?;
    if tag.is_empty() {
        bail!("empty firmware tag from {url}");
    }
    Ok(with_v(&tag))
}

#[derive(Debug, Clone)]
pub struct Release {
    pub tag: String,
    pub released: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChannelVersions {
    pub latest: Option<String>,
    pub versions: Vec<Release>,
}

pub fn list_versions(kind: &str) -> Result<ChannelVersions> {
    let url = format!("{API_BASE}/versions?type={kind}");
    let v: serde_json::Value = serde_json::from_str(&get_text(&url)?).context("versions JSON")?;
    Ok(parse_channel(&v))
}

pub fn list_catalog() -> Result<BTreeMap<String, ChannelVersions>> {
    let url = format!("{API_BASE}/versions");
    parse_catalog_body(&get_text(&url)?)
}

fn parse_channel(v: &serde_json::Value) -> ChannelVersions {
    let latest = v
        .get("latest")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(with_v);
    let versions = v
        .get("versions")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|row| {
                    let tag = with_v(row.get("tag")?.as_str()?);
                    let released = row
                        .get("released")
                        .and_then(|x| x.as_str())
                        .map(str::to_string);
                    Some(Release { tag, released })
                })
                .collect()
        })
        .unwrap_or_default();
    ChannelVersions { latest, versions }
}

fn parse_catalog_body(body: &str) -> Result<BTreeMap<String, ChannelVersions>> {
    let v: serde_json::Value = serde_json::from_str(body).context("versions JSON")?;
    let mut out = BTreeMap::new();
    if let Some(ch) = v.get("channels").and_then(|x| x.as_object()) {
        for (k, val) in ch {
            out.insert(k.clone(), parse_channel(val));
        }
    } else if v.get("versions").is_some() {
        let kind = v
            .get("type")
            .and_then(|x| x.as_str())
            .unwrap_or("main")
            .to_string();
        out.insert(kind, parse_channel(&v));
    } else {
        bail!("versions API did not return a catalog");
    }
    Ok(out)
}

pub fn known_tag(kind: &str, tag: &str) -> Result<bool> {
    match list_versions(kind) {
        Ok(ch) => Ok(ch.versions.iter().any(|r| infishark::fw::same(&r.tag, tag))),
        // Setup changelogs are not published on /api/changelog.
        Err(_) if kind == "setup" => Ok(true),
        Err(_) => changelog_exists(tag),
    }
}

fn changelog_exists(tag: &str) -> Result<bool> {
    let url = format!("{API_BASE}/changelog?version={tag}");
    match agent().get(&url).set("User-Agent", UA).call() {
        Ok(_) => Ok(true),
        Err(ureq::Error::Status(404, _)) => Ok(false),
        Err(e) => Err(e).context(format!("GET {url}")),
    }
}

pub fn expected_checksum(serial: &str, kind: &str, tag: &str) -> Result<String> {
    let sig = checksum_sig(kind, tag);
    let url = format!("{API_BASE}/checksum?serial={serial}&type={kind}&tag={tag}&sig={sig}");
    let hash = get_text(&url)?;
    if hash.len() != 64 {
        bail!("checksum response was not a SHA-256 hex digest");
    }
    Ok(hash.to_ascii_lowercase())
}

pub struct SignedImage {
    pub url: String,
    pub sha256: Option<String>,
}

pub fn signed_image(
    serial: &str,
    signature_hex: &str,
    kind: &str,
    tag: &str,
) -> Result<SignedImage> {
    let url =
        format!("{API_BASE}/ota?serial={serial}&type={kind}&signature={signature_hex}&fw={tag}");
    parse_signed_body(&get_text(&url)?)
}

fn parse_signed_body(body: &str) -> Result<SignedImage> {
    let v: serde_json::Value = serde_json::from_str(body).context("OTA JSON")?;
    let url = v
        .get("url")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("OTA API did not return a url"))?;
    if !url.starts_with("https://") {
        bail!("refusing non-HTTPS firmware URL");
    }
    let sha256 = v
        .get("sha256")
        .or_else(|| v.get("hash"))
        .and_then(|x| x.as_str())
        .filter(|s| s.len() == 64)
        .map(|s| s.to_ascii_lowercase());
    Ok(SignedImage {
        url: url.to_string(),
        sha256,
    })
}

pub fn download(url: &str, dest: &Path) -> Result<u64> {
    copy_to(url, dest, None)
}

pub fn download_verified(url: &str, expected_sha256: &str, dest: &Path) -> Result<u64> {
    copy_to(url, dest, Some(expected_sha256))
}

fn copy_to(url: &str, dest: &Path, expected_sha256: Option<&str>) -> Result<u64> {
    let resp = get(url)?;
    let mut reader = resp.into_reader();
    let mut hasher = expected_sha256.map(|_| Sha256::new());
    let mut file =
        std::fs::File::create(dest).with_context(|| format!("create {}", dest.display()))?;
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).context("reading firmware")?;
        if n == 0 {
            break;
        }
        if let Some(h) = hasher.as_mut() {
            h.update(&buf[..n]);
        }
        file.write_all(&buf[..n])
            .with_context(|| format!("write {}", dest.display()))?;
        total += n as u64;
    }
    if let (Some(h), Some(expect)) = (hasher, expected_sha256) {
        let got = hex::encode_lower(&h.finalize());
        if got != expect.to_ascii_lowercase() {
            let _ = std::fs::remove_file(dest);
            bail!("firmware SHA-256 mismatch (got {got})");
        }
    }
    Ok(total)
}

pub fn cache_file(name: &str) -> Result<PathBuf> {
    let dir = paths::infishark_dir()?.join("firmware");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let name = name.replace(['/', '\\'], "-");
    Ok(dir.join(name))
}

pub fn cache_path(kind: &str, tag: &str) -> Result<PathBuf> {
    let tag = tag.replace(['/', '\\'], "-");
    cache_file(&format!("nano-{kind}-{tag}.bin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_from_efuse_is_stable() {
        let a = signature_from_efuse(&[0xe0, 0x2e, 0x9e, 0x81, 0x8c, 0x58]);
        let b = signature_from_efuse(&[0xe0, 0x2e, 0x9e, 0x81, 0x8c, 0x58]);
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
        assert_eq!(checksum_sig("main", "1.1.1").len(), 64);
    }

    #[test]
    fn prefers_device_supplied_signature() {
        let mut id = infishark::DeviceFw {
            serial: "x".into(),
            version: "0.0".into(),
            mode: "main".into(),
            efuse: [0xe0, 0x2e, 0x9e, 0x81, 0x8c, 0x58],
            signature: Some([7u8; 32]),
        };
        assert_eq!(device_signature(&id), [7u8; 32]);
        id.signature = None;
        assert_eq!(device_signature(&id), signature_from_efuse(&id.efuse));
    }

    #[test]
    fn signed_ota_json_unescapes_url_and_reads_hash() {
        let img = parse_signed_body(
            r#"{"url":"https:\/\/cdn.example\/fw.bin","hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .unwrap();
        assert_eq!(img.url, "https://cdn.example/fw.bin");
        assert_eq!(img.sha256.as_deref().unwrap().len(), 64);
    }

    #[test]
    fn signed_ota_json_rejects_http() {
        assert!(parse_signed_body(r#"{"url":"http://evil/fw.bin"}"#).is_err());
    }

    #[test]
    fn with_v_keeps_prefix() {
        assert_eq!(with_v("1.0.1"), "v1.0.1");
        assert_eq!(with_v("v1.0.1"), "v1.0.1");
        assert_eq!(with_v("V1.1.0"), "v1.1.0");
    }

    #[test]
    fn parses_versions_catalog() {
        let cat = parse_catalog_body(
            r#"{
                "channels": {
                    "main": {
                        "latest": "v1.1.0",
                        "versions": [
                            {"tag": "v1.1.0", "released": "2026-07-14T20:32:13.000Z"},
                            {"tag": "1.0.1", "released": "2026-05-04T15:05:40.000Z"}
                        ]
                    }
                }
            }"#,
        )
        .unwrap();
        let main = cat.get("main").unwrap();
        assert_eq!(main.latest.as_deref(), Some("v1.1.0"));
        assert_eq!(main.versions[0].tag, "v1.1.0");
        assert_eq!(main.versions[1].tag, "v1.0.1");
        assert_eq!(
            main.versions[0].released.as_deref().unwrap().get(..10),
            Some("2026-07-14")
        );
    }
}
