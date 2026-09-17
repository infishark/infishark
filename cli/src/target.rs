//! Shared AP target resolution: scan + pick/filter into targets that Wi-Fi
//! attack workflows (deauth, handshake, ap-spam, ...) consume.

use anyhow::{Context, Result};
use infishark::{Cipher, Device, Network, WifiScanOpts, ieee80211};

use crate::ui;

pub(crate) struct Target {
    pub(crate) bssid: [u8; 6],
    pub(crate) channel: u8,
    pub(crate) label: String,
    /// SSID (empty when unknown, e.g. a bare --bssid target).
    pub(crate) ssid: String,
    /// (group, pairwise) ciphers from the scan; None disables cipher-matched
    /// PMKID solicitation (the handshake tool falls back to CCMP).
    pub(crate) rsn: Option<(Cipher, Cipher)>,
}

pub(crate) enum TargetPick {
    All,
    Strongest,
}

pub(crate) fn resolve_targets_ex(
    dev: &mut Device,
    ssid: Option<&str>,
    bssid: Option<&str>,
    channel: Option<u8>,
    oui_db: Option<&str>,
    keep: impl Fn(&Network) -> bool,
    pick: TargetPick,
    allow_interactive: bool,
) -> Result<Vec<Target>> {
    if let Some(ch) = channel {
        if ch != 0 {
            ieee80211::channel::require(ch).map_err(|e| anyhow::anyhow!("{e}"))?;
        }
    }
    if let Some(bssid) = bssid {
        let channel = channel.context("--bssid needs --channel")?;
        return Ok(vec![Target {
            bssid: ieee80211::parse_mac(bssid)?,
            channel,
            label: bssid.to_string(),
            ssid: String::new(),
            rsn: None,
        }]);
    }
    let scan = WifiScanOpts {
        active: false,
        dwell_ms: None,
        channel: None,
        hide_hidden: false,
        ssid: ssid.map(str::to_string),
        bssid: None,
    };
    let sp = ui::Spinner::start("scanning networks");
    let nets = dev.wifi_scan(&scan);
    sp.stop();
    let mut nets = nets?;
    nets.retain(|n| keep(n));
    if let Some(ssid) = ssid {
        return Ok(ssid_hits(&nets, ssid, pick)
            .into_iter()
            .filter_map(net_to_target)
            .collect());
    }
    if !allow_interactive {
        anyhow::bail!("pass --ssid or --bssid (no interactive picker under --json / a pipe)");
    }
    ui::require_interactive("pass --ssid or --bssid to choose a target")?;
    crate::enrich_wifi(oui_db, &mut nets); // vendor column in the picker
    Ok(ui::pick_networks(&nets)?
        .iter()
        .filter_map(net_to_target)
        .collect())
}

fn ssid_hits<'a>(nets: &'a [Network], ssid: &str, pick: TargetPick) -> Vec<&'a Network> {
    let mut hits: Vec<&Network> = nets.iter().filter(|n| n.ssid == ssid).collect();
    if matches!(pick, TargetPick::Strongest) {
        if let Some(best) = hits.iter().copied().max_by_key(|n| n.rssi) {
            let bssid = best.bssid.clone();
            hits.retain(|n| n.bssid == bssid);
        }
    }
    hits
}

fn net_to_target(n: &Network) -> Option<Target> {
    let cipher = |key| {
        n.extra
            .get(key)
            .and_then(|v| v.as_str())
            .and_then(Cipher::from_device_str)
    };
    let rsn = match (cipher("group_cipher"), cipher("pairwise_cipher")) {
        (Some(g), Some(p)) => Some((g, p)),
        _ => None,
    };
    Some(Target {
        bssid: ieee80211::parse_mac(&n.bssid).ok()?,
        channel: ieee80211::channel::check_ch(n.channel).then_some(n.channel)?,
        ssid: n.ssid.clone(),
        rsn,
        label: if n.ssid.is_empty() {
            n.bssid.clone()
        } else {
            n.ssid.clone()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(ssid: &str, bssid: &str, rssi: i8, ch: u8) -> Network {
        Network {
            bssid: bssid.into(),
            ssid: ssid.into(),
            rssi,
            channel: ch,
            encryption: "WPA2_PSK".into(),
            vendor: None,
            extra: Default::default(),
        }
    }

    #[test]
    fn strongest_ssid_keeps_one_bssid() {
        let nets = vec![
            net("Office", "AA:AA:AA:AA:AA:01", -80, 6),
            net("Office", "AA:AA:AA:AA:AA:02", -50, 1),
            net("Other", "BB:BB:BB:BB:BB:BB", -20, 1),
        ];
        let hits = ssid_hits(&nets, "Office", TargetPick::Strongest);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].bssid, "AA:AA:AA:AA:AA:02");
        assert_eq!(ssid_hits(&nets, "Office", TargetPick::All).len(), 2);
    }
}
