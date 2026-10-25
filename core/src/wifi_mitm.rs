//! Wi-Fi router session options and selective event capture.

use std::io::{self, Write};
use std::net::Ipv4Addr;

use serde_json::{Value, json};

use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub enum WifiUpstream {
    None { channel: u8 },
    Saved(u8),
    Explicit { ssid: String, pass: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiDnsMode {
    Forward,
    Captive,
    Static,
}

impl WifiDnsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Captive => "captive",
            Self::Static => "static",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiHttpMode {
    Off,
    Portal,
}

impl WifiHttpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Portal => "portal",
        }
    }
}

#[derive(Clone, Debug)]
pub struct WifiMitmOpts {
    pub ssid: String,
    pub pass: String,
    pub hidden: bool,
    pub max_clients: u8,
    pub clone_ssid: bool,
    pub upstream: WifiUpstream,
    pub dns: WifiDnsMode,
    pub dns_server: Option<Ipv4Addr>,
    pub dns_log: bool,
    pub intercept_dns: bool,
    pub intercept_timeout_ms: u32,
    pub capture_flows: bool,
    pub diagnostics: bool,
    pub http: WifiHttpMode,
    pub host_timeout_ms: u32,
    pub block: Vec<[u8; 6]>,
    /// Deauth the upstream BSSID so its clients rejoin this AP.
    pub steer: bool,
    /// AP passphrase is the saved upstream password and must not be sent.
    pub pass_from_upstream: bool,
}

impl WifiMitmOpts {
    pub fn new(ssid: impl Into<String>, upstream: WifiUpstream) -> Self {
        let dns = if matches!(upstream, WifiUpstream::None { .. }) {
            WifiDnsMode::Captive
        } else {
            WifiDnsMode::Forward
        };
        Self {
            ssid: ssid.into(),
            pass: String::new(),
            hidden: false,
            max_clients: 4,
            clone_ssid: false,
            upstream,
            dns,
            dns_server: None,
            dns_log: false,
            intercept_dns: false,
            intercept_timeout_ms: 50,
            capture_flows: false,
            diagnostics: false,
            http: WifiHttpMode::Off,
            host_timeout_ms: 15_000,
            block: Vec::new(),
            steer: false,
            pass_from_upstream: false,
        }
    }

    pub fn to_json(&self) -> Result<Value> {
        fn password_valid(pass: &str) -> bool {
            pass.is_empty() || (8..=63).contains(&pass.len())
        }
        if self.ssid.len() > 32
            || (self.ssid.is_empty() != self.clone_ssid)
            || !password_valid(&self.pass)
            || !(1..=10).contains(&self.max_clients)
            || self.block.len() > 10
        {
            return Err(Error::msg("invalid Wi-Fi MITM AP settings"));
        }
        let upstream = match &self.upstream {
            WifiUpstream::None { channel } => {
                if !(1..=13).contains(channel) || self.dns != WifiDnsMode::Captive {
                    return Err(Error::msg("island requires channel 1..13 and captive DNS"));
                }
                json!({"type":"none","channel":channel})
            }
            WifiUpstream::Saved(index) => json!({"type":"saved","index":index}),
            WifiUpstream::Explicit { ssid, pass } => {
                if ssid.is_empty() || ssid.len() > 32 || !password_valid(pass) {
                    return Err(Error::msg("invalid Wi-Fi MITM upstream settings"));
                }
                json!({"type":"explicit","ssid":ssid,"pass":pass})
            }
        };
        if self.dns == WifiDnsMode::Static && self.dns_server.is_none() {
            return Err(Error::msg("static DNS requires a DNS server"));
        }
        if self.dns != WifiDnsMode::Static && self.dns_server.is_some() {
            return Err(Error::msg("DNS server is only valid with static DNS"));
        }
        if self.intercept_dns && self.dns != WifiDnsMode::Forward {
            return Err(Error::msg("DNS intercept requires forward DNS"));
        }
        if (self.steer || self.pass_from_upstream)
            && matches!(self.upstream, WifiUpstream::None { .. })
        {
            return Err(Error::msg("steer needs an upstream"));
        }
        let mut out = json!({
            "op":"start", "ssid":self.ssid, "pass":self.pass,
            "hidden":self.hidden, "max_clients":self.max_clients,
            "clone_ssid":self.clone_ssid, "upstream":upstream,
            "dns":self.dns.as_str(), "dns_log":self.dns_log,
            "intercept_dns":self.intercept_dns,
            "intercept_timeout_ms":self.intercept_timeout_ms,
            "capture_flows":self.capture_flows,
            "http":self.http.as_str(), "host_timeout_ms":self.host_timeout_ms,
            "steer":self.steer, "pass_from_upstream":self.pass_from_upstream,
        });
        if let Some(ip) = self.dns_server {
            out["dns_server"] = ip.to_string().into();
        }
        if self.diagnostics {
            out["diagnostics"] = true.into();
        }
        if out.to_string().len() + 1 > crate::protocol::MAX_PAYLOAD {
            return Err(Error::msg("Wi-Fi MITM start exceeds the serial frame"));
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum WifiMitmAction {
    Allow,
    Drop,
    ReplaceA(Ipv4Addr),
}

pub fn append_ndjson<W: Write>(w: &mut W, event: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *w, event)?;
    w.write_all(b"\n")
}

pub fn append_pcap<W: Write>(w: &mut W, event: &Value) -> io::Result<bool> {
    if event.get("type").and_then(Value::as_str) != Some("flow") {
        return Ok(false);
    }
    let Some(hex) = event.get("hex").and_then(Value::as_str) else {
        return Ok(false);
    };
    let frame = match crate::hex::decode(hex) {
        Ok(frame) => frame,
        Err(_) => return Ok(false),
    };
    let Some(orig) = event.get("len").and_then(Value::as_u64) else {
        return Ok(false);
    };
    if orig > u32::MAX as u64 || (orig as usize) < frame.len() || frame.len() > 65535 {
        return Ok(false);
    }
    crate::pcap::write_record_truncated(w, &frame, orig as u32)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{WifiMitmOpts, WifiUpstream};

    #[test]
    fn flow_capture_requires_opt_in() {
        let mut opts = WifiMitmOpts::new("test-ap", WifiUpstream::Saved(0));
        assert_eq!(opts.to_json().unwrap()["capture_flows"], false);
        opts.capture_flows = true;
        assert_eq!(opts.to_json().unwrap()["capture_flows"], true);
    }

    #[test]
    fn diagnostics_requires_opt_in() {
        let mut opts = WifiMitmOpts::new("test-ap", WifiUpstream::Saved(0));
        assert!(opts.to_json().unwrap().get("diagnostics").is_none());
        opts.diagnostics = true;
        assert_eq!(opts.to_json().unwrap()["diagnostics"], true);
    }
}
