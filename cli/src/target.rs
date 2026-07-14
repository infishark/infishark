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

/// Resolve targets: a bare `--bssid`/`--channel`, an `--ssid` filter, or an
/// interactive pick from a scan.
pub(crate) fn resolve_targets(
    dev: &mut Device,
    ssid: Option<&str>,
    bssid: Option<&str>,
    channel: Option<u8>,
    oui_db: Option<&str>,
    keep: impl Fn(&Network) -> bool,
) -> Result<Vec<Target>> {
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
        return Ok(nets
            .iter()
            .filter(|n| n.ssid == ssid)
            .filter_map(net_to_target)
            .collect());
    }
    crate::enrich_wifi(oui_db, &mut nets); // vendor column in the picker
    Ok(ui::pick_networks(&nets)?
        .iter()
        .filter_map(net_to_target)
        .collect())
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
        channel: u8::try_from(n.channel).ok()?,
        ssid: n.ssid.clone(),
        rsn,
        label: if n.ssid.is_empty() {
            n.bssid.clone()
        } else {
            n.ssid.clone()
        },
    })
}
