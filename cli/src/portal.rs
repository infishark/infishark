//! Captive portal: SoftAP knobs + optional host-streamed HTML directory.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use infishark::protocol;
use infishark::{Device, PortalOpts};

pub fn run(mut dev: Device, dir: Option<PathBuf>, opts: PortalOpts) -> Result<()> {
    let root = if let Some(dir) = dir {
        let root = dir
            .canonicalize()
            .with_context(|| format!("portal dir {}", dir.display()))?;
        if !root.is_dir() {
            bail!("{} is not a directory", root.display());
        }
        Some(root)
    } else {
        None
    };

    crate::signals::install_sigint();
    crate::signals::RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);

    let eff = dev.wifi_portal_start(&opts)?;
    print_effective(&eff, root.as_ref());

    loop {
        if !crate::signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        match dev.next_event() {
            Ok((id, payload)) if id == protocol::EVT_PORTAL_REQUEST => {
                if let Some(root) = &root {
                    if let Err(e) = handle_request(&mut dev, root, &payload) {
                        eprintln!("  portal request: {e:#}");
                    }
                } else {
                    // On-device HTML; still log the rich request snapshot.
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&payload) {
                        eprintln!("  event: {v}");
                    }
                }
            }
            Ok(_) => {}
            Err(infishark::Error::Timeout) => continue,
            Err(e) => {
                if !crate::signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                let _ = dev.stop_current_task();
                return Err(e.into());
            }
        }
    }

    let _ = dev.stop_current_task();
    eprintln!("portal stopped");
    Ok(())
}

fn print_effective(eff: &serde_json::Value, root: Option<&PathBuf>) {
    let ssid = eff.get("ssid").and_then(|x| x.as_str()).unwrap_or("?");
    let mac = eff.get("mac").and_then(|x| x.as_str()).unwrap_or("?");
    let ch = eff.get("channel").and_then(|x| x.as_u64()).unwrap_or(0);
    let ip = eff.get("ip").and_then(|x| x.as_str()).unwrap_or("?");
    let open = eff.get("open").and_then(|x| x.as_bool()).unwrap_or(true);
    let mode = if root.is_some() {
        "host content"
    } else {
        "on-device HTML"
    };
    eprintln!(
        "captive portal up ({mode}) - SSID={ssid:?} ch={ch} mac={mac} ip={ip} {} - Ctrl-C to stop",
        if open { "open" } else { "WPA2" }
    );
    if let Some(r) = root {
        eprintln!("  streaming pages from {}", r.display());
    }
}

fn handle_request(dev: &mut Device, root: &Path, payload: &[u8]) -> Result<()> {
    let v: serde_json::Value = serde_json::from_slice(payload)?;
    let req_id = v
        .get("id")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| anyhow::anyhow!("missing id"))? as u16;
    let method = v.get("method").and_then(|x| x.as_str()).unwrap_or("GET");
    let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("/");
    let request_line = v.get("request_line").and_then(|x| x.as_str());

    if let Some(rl) = request_line {
        eprintln!("  {rl}  (id={req_id})");
    } else {
        eprintln!("  {method} {path}  (id={req_id})");
    }
    if let Some(c) = v.get("client") {
        let ip = c.get("ip").and_then(|x| x.as_str()).unwrap_or("?");
        let port = c.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
        eprintln!("    client: {ip}:{port}");
    }
    if let Some(s) = v.get("sta") {
        let mac = s.get("mac").and_then(|x| x.as_str()).unwrap_or("?");
        let rssi = s.get("rssi").and_then(|x| x.as_i64()).unwrap_or(0);
        eprintln!("    sta: {mac}  rssi={rssi} dBm");
    }
    if let Some(ua) = v.get("ua").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        eprintln!("    ua: {ua}");
    }
    if let Some(h) = v.get("headers").and_then(|x| x.as_object()) {
        if !h.is_empty() {
            eprintln!("    headers ({}):", h.len());
            for (k, val) in h {
                let s = val.as_str().unwrap_or("");
                if s.is_empty() {
                    continue;
                }
                eprintln!("      {k}: {s}");
            }
        }
    }
    if let Some(a) = v.get("args").and_then(|x| x.as_object()) {
        if !a.is_empty() {
            eprintln!("    args: {}", serde_json::Value::Object(a.clone()));
        }
    }
    eprintln!("    event: {v}");

    match method {
        "GET" => match resolve_file(root, path) {
            Some((file, ctype)) => {
                let body = fs::read(&file).with_context(|| format!("read {}", file.display()))?;
                dev.portal_resp_body(req_id, 200, ctype, &body)?;
                eprintln!("    -> {} ({} bytes)", file.display(), body.len());
            }
            None => {
                dev.portal_resp_body(req_id, 404, "text/plain", b"not found")?;
                eprintln!("    -> 404");
            }
        },
        "HEAD" => match resolve_file(root, path) {
            Some((file, ctype)) => {
                let len = fs::metadata(&file).map(|m| m.len()).unwrap_or(0) as u32;
                dev.portal_resp_chunk(req_id, 0, len, 200, ctype, &[])?;
                eprintln!("    -> {} (HEAD, {len} bytes)", file.display());
            }
            None => {
                dev.portal_resp_body(req_id, 404, "text/plain", &[])?;
                eprintln!("    -> 404");
            }
        },
        _ => {
            dev.portal_resp_body(req_id, 405, "text/plain", b"method not allowed")?;
            eprintln!("    -> 405 (static dir serves GET/HEAD only)");
        }
    }
    Ok(())
}

fn resolve_file(root: &Path, req_path: &str) -> Option<(PathBuf, &'static str)> {
    let path_only = req_path.split('?').next().unwrap_or("/");
    let rel = if path_only.is_empty() || path_only == "/" {
        "index.html"
    } else {
        path_only.trim_start_matches('/')
    };
    if rel.is_empty() {
        return None;
    }
    let mut joined = root.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(s) => joined.push(s),
            Component::CurDir => {}
            _ => return None,
        }
    }
    let canon = joined.canonicalize().ok()?;
    if !canon.starts_with(root) || !canon.is_file() {
        return None;
    }
    let ctype = content_type(&canon);
    Some((canon, ctype))
}

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_html() {
        assert!(content_type(Path::new("x.html")).starts_with("text/html"));
        assert_eq!(content_type(Path::new("a.css")), "text/css");
    }

    #[test]
    fn resolve_rejects_parent_components() {
        let root = PathBuf::from("/tmp");
        assert!(resolve_file(&root, "/../etc/passwd").is_none());
    }
}
