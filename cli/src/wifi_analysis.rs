//! Host-only Wi-Fi scan enrichment

use infishark::{Network, ieee80211};

/// Coarse security posture derived from auth mode + pairwise cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    Open,
    Weak,
    Ok,
    Modern,
    Enterprise,
    Unknown,
}

impl Posture {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Weak => "weak",
            Self::Ok => "ok",
            Self::Modern => "modern",
            Self::Enterprise => "enterprise",
            Self::Unknown => "?",
        }
    }
}

/// Map encryption + cipher fields into a single posture token.
pub fn posture(n: &Network) -> Posture {
    let enc = n.encryption.to_ascii_uppercase();
    let pair = n.extra_str("pairwise_cipher").to_ascii_lowercase();
    if enc.contains("ENTERPRISE") {
        return Posture::Enterprise;
    }
    if enc == "OPEN" || enc.is_empty() {
        return Posture::Open;
    }
    if enc == "WEP" || pair.contains("wep") || pair == "tkip" || pair == "tkip_ccmp" {
        return Posture::Weak;
    }
    if enc.contains("WPA3") || pair.starts_with("gcmp") {
        return Posture::Modern;
    }
    if enc.contains("WPA") {
        return Posture::Ok;
    }
    Posture::Unknown
}

/// Compact risk badges for a single AP (empty when none).
pub fn risk_flags(n: &Network) -> Vec<&'static str> {
    let mut f = Vec::new();
    let enc = n.encryption.to_ascii_uppercase();
    let pair = n.extra_str("pairwise_cipher").to_ascii_lowercase();
    if n.ssid.is_empty() {
        f.push("HIDDEN");
    }
    if enc == "OPEN" {
        f.push("OPEN");
    }
    if enc == "WEP" || pair.contains("wep") {
        f.push("WEP");
    }
    if pair == "tkip" || pair == "tkip_ccmp" {
        f.push("TKIP");
    }
    if n.extra_bool("wps") {
        f.push("WPS");
    }
    if enc.contains("ENTERPRISE") {
        f.push("ENT");
    }
    if enc.contains("WPA3") {
        f.push("WPA3");
    }
    f
}

fn mac6(addr: &str) -> Option<[u8; 6]> {
    let mut n = addr.chars().filter_map(|c| c.to_digit(16));
    let mut out = [0u8; 6];
    for b in &mut out {
        *b = ((n.next()? << 4) | n.next()?) as u8;
    }
    Some(out)
}

/// A hidden AP that likely shares a radio with a named AP (same OUI, close
/// RSSI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenCorrelation {
    pub hidden_bssid: String,
    pub named_ssid: String,
    pub named_bssid: String,
    pub rssi_delta: u8,
    pub same_channel: bool,
}

/// Correlate empty-SSID rows with nearby named APs of the same OUI.
///
/// Thresholds: |dRSSI| <= rssi_window dB; same OUI, last-octet +/- 1, same channel.
pub fn hidden_correlations(nets: &[Network], rssi_window: u8) -> Vec<HiddenCorrelation> {
    let mut out = Vec::new();
    for h in nets.iter().filter(|n| n.ssid.is_empty()) {
        let Some(hm) = mac6(&h.bssid) else {
            continue;
        };
        if hm[0] & 0x02 != 0 {
            continue;
        }
        let mut best: Option<(u8, &Network)> = None;
        for n in nets.iter().filter(|n| !n.ssid.is_empty()) {
            let Some(nm) = mac6(&n.bssid) else {
                continue;
            };
            if nm[0] & 0x02 != 0 {
                continue;
            }
            if hm[..3] != nm[..3] {
                continue;
            }
            if hm[5].abs_diff(nm[5]) > 1 {
                continue;
            }
            let d = h.rssi.abs_diff(n.rssi);
            if d > rssi_window {
                continue;
            }
            if h.channel != n.channel {
                continue;
            }
            let better = match best {
                None => true,
                Some((bd, _)) => d < bd,
            };
            if better {
                best = Some((d, n));
            }
        }
        if let Some((d, n)) = best {
            out.push(HiddenCorrelation {
                hidden_bssid: h.bssid.clone(),
                named_ssid: n.ssid.clone(),
                named_bssid: n.bssid.clone(),
                rssi_delta: d,
                same_channel: true,
            });
        }
    }
    out
}

/// Aggregate counts for the post-table summary (CLI display only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanSummary {
    pub total: usize,
    pub open: usize,
    pub wep: usize,
    pub wpa2: usize,
    pub wpa3: usize,
    pub enterprise: usize,
    pub wps: usize,
    pub hidden: usize,
    /// (channel, ap count) for channels that have at least one AP, sorted by
    /// ch.
    pub by_channel: Vec<(u8, usize)>,
}

pub fn scan_summary(nets: &[Network]) -> ScanSummary {
    let mut s = ScanSummary {
        total: nets.len(),
        ..Default::default()
    };
    let mut ch = [0usize; 15];
    for n in nets {
        let enc = n.encryption.to_ascii_uppercase();
        if n.ssid.is_empty() {
            s.hidden += 1;
        }
        if n.extra_bool("wps") {
            s.wps += 1;
        }
        if enc == "OPEN" {
            s.open += 1;
        } else if enc == "WEP" {
            s.wep += 1;
        } else if enc.contains("ENTERPRISE") {
            s.enterprise += 1;
        } else if enc.contains("WPA3") {
            s.wpa3 += 1;
        } else if enc.contains("WPA") {
            s.wpa2 += 1;
        }
        if ieee80211::channel::check_ch(n.channel) {
            ch[n.channel as usize] += 1;
        }
    }
    s.by_channel = (1u8..=14)
        .filter(|&c| ch[c as usize] > 0)
        .map(|c| (c, ch[c as usize]))
        .collect();
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn net(
        ssid: &str,
        bssid: &str,
        rssi: i8,
        ch: u8,
        enc: &str,
        extra: &[(&str, serde_json::Value)],
    ) -> Network {
        let mut e = BTreeMap::new();
        for (k, v) in extra {
            e.insert((*k).into(), v.clone());
        }
        Network {
            bssid: bssid.into(),
            ssid: ssid.into(),
            rssi,
            channel: ch,
            encryption: enc.into(),
            vendor: None,
            extra: e,
        }
    }

    #[test]
    fn posture_maps_auth_and_cipher() {
        assert_eq!(
            posture(&net("", "aa:bb:cc:00:00:01", -50, 6, "Open", &[])),
            Posture::Open
        );
        assert_eq!(
            posture(&net(
                "x",
                "aa:bb:cc:00:00:01",
                -50,
                6,
                "WPA2_PSK",
                &[("pairwise_cipher", json!("tkip"))]
            )),
            Posture::Weak
        );
        assert_eq!(
            posture(&net(
                "x",
                "aa:bb:cc:00:00:01",
                -50,
                6,
                "WPA2_PSK",
                &[("pairwise_cipher", json!("ccmp"))]
            )),
            Posture::Ok
        );
        assert_eq!(
            posture(&net(
                "x",
                "aa:bb:cc:00:00:01",
                -50,
                6,
                "WPA3_PSK",
                &[("pairwise_cipher", json!("gcmp"))]
            )),
            Posture::Modern
        );
        assert_eq!(
            posture(&net(
                "x",
                "aa:bb:cc:00:00:01",
                -50,
                6,
                "WPA2_ENTERPRISE",
                &[]
            )),
            Posture::Enterprise
        );
    }

    #[test]
    fn hidden_same_oui_close_rssi_correlates() {
        let nets = vec![
            net("Home", "00:11:22:AA:BB:01", -42, 6, "WPA2_PSK", &[]),
            net("", "00:11:22:AA:BB:02", -44, 6, "WPA2_PSK", &[]),
            net("Other", "AA:BB:CC:00:00:01", -40, 1, "Open", &[]),
        ];
        let c = hidden_correlations(&nets, 8);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].named_ssid, "Home");
        assert_eq!(c[0].hidden_bssid, "00:11:22:AA:BB:02");
        assert!(c[0].same_channel);
        assert_eq!(c[0].rssi_delta, 2);
    }

    #[test]
    fn summary_counts_auth_and_channels() {
        let nets = vec![
            net(
                "a",
                "00:11:22:00:00:01",
                -40,
                1,
                "Open",
                &[("wps", json!(true))],
            ),
            net("", "00:11:22:00:00:02", -50, 1, "WPA2_PSK", &[]),
            net("c", "00:11:22:00:00:03", -60, 6, "WPA3_PSK", &[]),
        ];
        let s = scan_summary(&nets);
        assert_eq!(s.total, 3);
        assert_eq!(s.open, 1);
        assert_eq!(s.hidden, 1);
        assert_eq!(s.wps, 1);
        assert_eq!(s.wpa3, 1);
        assert_eq!(s.by_channel, vec![(1, 2), (6, 1)]);
    }
}
