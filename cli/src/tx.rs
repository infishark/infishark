//! wifi tx: named 802.11 templates or --hex, optional AP scan/picker.

use anyhow::{Result, bail};
use clap::ValueEnum;
use ieee80211::{Ctrl, Mac};
use infishark::client::Device;
use infishark::{hex, ieee80211};

use crate::target::{Target, resolve_targets};

/// Named Mac Protocol Data Unit (MPDU) templates (clap lists them via
/// ValueEnum).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Template {
    Deauth,
    Disassoc,
    #[value(name = "auth-open")]
    AuthOpen,
    #[value(name = "assoc-req")]
    AssocReq,
    #[value(name = "probe-req")]
    ProbeReq,
    Beacon,
    Rts,
    Cts,
    Ack,
    #[value(name = "ps-poll")]
    PsPoll,
    Bar,
    #[value(name = "cf-end")]
    CfEnd,
    Null,
    #[value(name = "qos-null")]
    QosNull,
    Data,
    #[value(name = "qos-data")]
    QosData,
}

const DEFAULT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DEFAULT_SSID: &str = "InfiShark";
const DEFAULT_CHANNEL: u8 = 6;

enum ApMode {
    /// Frame needs a real AP
    Required,
    /// Originate a frame
    Synthesize,
    /// No AP address
    None,
}

impl Template {
    fn ap_mode(self) -> ApMode {
        match self {
            Self::ProbeReq | Self::Cts | Self::Ack => ApMode::None,
            Self::Beacon => ApMode::Synthesize,
            _ => ApMode::Required,
        }
    }

    fn needs_sta(self) -> bool {
        matches!(
            self,
            Self::AuthOpen
                | Self::AssocReq
                | Self::Null
                | Self::QosNull
                | Self::Data
                | Self::QosData
        )
    }

    fn name(self) -> String {
        self.to_possible_value()
            .map(|p| p.get_name().to_string())
            .unwrap_or_else(|| format!("{self:?}").to_ascii_lowercase())
    }
}

pub struct Opts {
    pub template: Option<Template>,
    pub hex: Option<String>,
    pub channel: u8,
    pub count: u16,
    pub interval_ms: u16,
    pub ap: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub sta: Option<String>,
    pub ra: Option<String>,
    pub ta: Option<String>,
    pub reason: u16,
    pub duration: u16,
    pub aid: u16,
    pub tid: u8,
    pub ssn: u16,
    pub payload: Option<String>,
}

fn mac(s: &str) -> Result<Mac> {
    Ok(ieee80211::parse_mac(s)?)
}

fn require_mac(flag: &str, v: Option<&str>) -> Result<Mac> {
    match v {
        Some(s) => mac(s),
        None => bail!("--{flag} is required for this template"),
    }
}

fn sta_or_broadcast(sta: Option<&str>) -> Result<Mac> {
    match sta {
        Some(s) => mac(s),
        None => Ok(ieee80211::BROADCAST),
    }
}

fn payload_bytes(o: &Opts) -> Result<Vec<u8>> {
    match &o.payload {
        Some(p) => Ok(hex::decode(p)?),
        None => Ok(Vec::new()),
    }
}

fn require_2ghz(ch: u8) -> Result<u8> {
    if ieee80211::channel::check_ch(ch) {
        Ok(ch)
    } else {
        bail!("channel {ch} out of range (1-14)");
    }
}

#[derive(Debug)]
struct Synth {
    ap: Mac,
    ssid: String,
    channel: u8,
}

// beacon request identity
fn synthesize(o: &Opts) -> Result<Synth> {
    match o.ap.as_deref().or(o.bssid.as_deref()) {
        Some(b) => {
            if o.channel == 0 {
                bail!("--bssid/--ap needs --channel");
            }
            Ok(Synth {
                ap: mac(b)?,
                ssid: o.ssid.clone().unwrap_or_default(),
                channel: require_2ghz(o.channel)?,
            })
        }
        None => Ok(Synth {
            ap: DEFAULT_MAC,
            ssid: o.ssid.clone().unwrap_or_else(|| DEFAULT_SSID.to_string()),
            channel: require_2ghz(if o.channel == 0 {
                DEFAULT_CHANNEL
            } else {
                o.channel
            })?,
        }),
    }
}

fn build_no_ap(t: Template, o: &Opts) -> Result<Vec<u8>> {
    Ok(match t {
        Template::ProbeReq => {
            let src = match &o.sta {
                Some(s) => mac(s)?,
                None => DEFAULT_MAC,
            };
            ieee80211::probe_req(src, o.ssid.as_deref().unwrap_or("")).to_bytes()
        }
        Template::Cts => Ctrl::Cts {
            ra: require_mac("ra", o.ra.as_deref().or(o.sta.as_deref()))?,
            duration: o.duration,
        }
        .to_bytes(),
        Template::Ack => Ctrl::Ack {
            ra: require_mac("ra", o.ra.as_deref().or(o.sta.as_deref()))?,
        }
        .to_bytes(),
        _ => bail!("internal: template expects an AP"),
    })
}

fn build_with_ap(t: Template, ap: Mac, o: &Opts, ssid_hint: &str, channel: u8) -> Result<Vec<u8>> {
    let ssid = o
        .ssid
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(ssid_hint);
    Ok(match t {
        Template::Deauth => {
            ieee80211::deauth(ap, sta_or_broadcast(o.sta.as_deref())?, o.reason).to_bytes()
        }
        Template::Disassoc => {
            ieee80211::disassoc(ap, sta_or_broadcast(o.sta.as_deref())?, o.reason).to_bytes()
        }
        Template::AuthOpen => {
            ieee80211::auth_open(ap, require_mac("sta", o.sta.as_deref())?).to_bytes()
        }
        Template::AssocReq => {
            ieee80211::assoc_req(ap, require_mac("sta", o.sta.as_deref())?, ssid, vec![]).to_bytes()
        }
        Template::Beacon => ieee80211::beacon(ap, ssid, channel).to_bytes(),
        Template::PsPoll => Ctrl::PsPoll {
            bssid: ap,
            ta: require_mac("sta", o.sta.as_deref().or(o.ta.as_deref()))?,
            aid: o.aid,
        }
        .to_bytes(),
        Template::CfEnd => Ctrl::CfEnd {
            ra: match o.ra.as_deref().or(o.sta.as_deref()) {
                Some(s) => mac(s)?,
                None => ieee80211::BROADCAST,
            },
            bssid: ap,
        }
        .to_bytes(),
        Template::Null => {
            ieee80211::null_to_ap(ap, require_mac("sta", o.sta.as_deref())?).to_bytes()
        }
        Template::QosNull => {
            ieee80211::qos_null_to_ap(ap, require_mac("sta", o.sta.as_deref())?, o.tid).to_bytes()
        }
        Template::Data => {
            ieee80211::data_to_ap(ap, require_mac("sta", o.sta.as_deref())?, payload_bytes(o)?)
                .to_bytes()
        }
        Template::QosData => ieee80211::qos_data_to_ap(
            ap,
            require_mac("sta", o.sta.as_deref())?,
            o.tid,
            payload_bytes(o)?,
        )
        .to_bytes(),
        Template::Rts => Ctrl::Rts {
            ra: require_mac("ra", o.ra.as_deref().or(o.sta.as_deref()))?,
            ta: match o.ta.as_deref() {
                Some(s) => mac(s)?,
                None => ap,
            },
            duration: o.duration,
        }
        .to_bytes(),
        Template::Bar => Ctrl::Bar {
            ra: require_mac("ra", o.ra.as_deref().or(o.sta.as_deref()))?,
            ta: match o.ta.as_deref() {
                Some(s) => mac(s)?,
                None => ap,
            },
            tid: o.tid,
            ssn: o.ssn,
            duration: o.duration,
        }
        .to_bytes(),
        Template::ProbeReq | Template::Cts | Template::Ack => {
            bail!("internal: template does not use AP context")
        }
    })
}

fn resolve_ap(dev: &mut Device, o: &Opts, oui_db: Option<&str>) -> Result<Vec<Target>> {
    let bssid = o.ap.as_deref().or(o.bssid.as_deref());
    let channel = (o.channel != 0).then_some(o.channel);
    if bssid.is_none() && o.ssid.is_none() {
        eprintln!("no --ap/--bssid; scanning for targets...");
    }
    let targets = resolve_targets(dev, o.ssid.as_deref(), bssid, channel, oui_db, |_| true)?;
    if targets.is_empty() {
        bail!("no matching networks");
    }
    Ok(targets)
}

fn tx_channel(user: u8, target: &Target) -> u8 {
    if user != 0 { user } else { target.channel }
}

struct BurstResult {
    sent: u32,
    fail: u32,
    /// True if ended by Ctrl-C / stop before the device finished.
    stopped: bool,
}

fn burst(
    dev: &mut Device,
    frame: &[u8],
    channel: u8,
    count: u16,
    interval_ms: u16,
    json: bool,
) -> Result<BurstResult> {
    let oneshot = count == 1 && interval_ms == 0;
    let (ok, fail) = dev.wifi_raw_tx_burst(frame, channel, count, interval_ms)?;
    if oneshot {
        return Ok(BurstResult {
            sent: ok,
            fail,
            stopped: false,
        });
    }

    crate::signals::install_sigint();
    crate::signals::RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut last = (0u32, 0u32);
    let mut finished = false;
    while crate::signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
        dev.set_read_timeout(std::time::Duration::from_millis(400))?;
        match dev.wait_wifi_tx() {
            Ok((sent, fail, total, done)) => {
                last = (sent, fail);
                if !json {
                    if total == 0 {
                        eprint!("\r tx sent={sent} fail={fail} (until stop)   ");
                    } else {
                        eprint!("\r tx sent={sent} fail={fail} / {total}   ");
                    }
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
                if done {
                    finished = true;
                    break;
                }
            }
            Err(_) => {
                if !crate::signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
        }
    }
    if !json {
        eprintln!();
    }
    let interrupted = !finished;
    if interrupted || count == 0 {
        let _ = dev.stop_current_task();
    } else {
        // Finite burst completed on-device; still drop TX radio context.
        let _ = dev.stop_current_task();
    }
    Ok(BurstResult {
        sent: last.0,
        fail: last.1,
        stopped: interrupted,
    })
}

fn planned_total(count: u16, targets: usize) -> u32 {
    if count == 0 {
        0
    } else {
        u32::from(count).saturating_mul(targets as u32)
    }
}

fn result_json(
    sent: u32,
    fail: u32,
    total: u32,
    stopped: bool,
    len: usize,
    targets: usize,
    template: Option<String>,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("tx_ok".into(), sent.into());
    m.insert("tx_fail".into(), fail.into());
    m.insert("total".into(), total.into());
    m.insert("stopped".into(), stopped.into());
    m.insert("len".into(), len.into());
    m.insert("targets".into(), targets.into());
    if let Some(t) = template {
        m.insert("template".into(), t.into());
    }
    serde_json::Value::Object(m)
}

/// Build and transmit. Returns a JSON object for print_action.
pub fn run(
    dev: &mut Device,
    o: &Opts,
    oui_db: Option<&str>,
    json: bool,
) -> Result<serde_json::Value> {
    if o.hex.is_some() && o.template.is_some() {
        bail!("use either a template or --hex, not both");
    }
    if o.channel != 0 {
        require_2ghz(o.channel)?;
    }

    if let Some(h) = &o.hex {
        let frame = hex::decode(h)?;
        let r = burst(dev, &frame, o.channel, o.count, o.interval_ms, json)?;
        return Ok(result_json(
            r.sent,
            r.fail,
            planned_total(o.count, 1),
            r.stopped,
            frame.len(),
            1,
            None,
        ));
    }

    let t = o
        .template
        .ok_or_else(|| anyhow::anyhow!("pass a template name or --hex"))?;

    if t.needs_sta() && o.sta.is_none() {
        bail!("--sta is required for this template");
    }

    let mut sent = 0u32;
    let mut fail = 0u32;
    let mut stopped = false;
    let mut last_len = 0usize;
    let mut targets_n = 1usize;

    match t.ap_mode() {
        ApMode::Required => {
            let targets = resolve_ap(dev, o, oui_db)?;
            targets_n = targets.len();
            for tgt in &targets {
                let ch = tx_channel(o.channel, tgt);
                let frame = build_with_ap(t, tgt.bssid, o, &tgt.ssid, ch)?;
                last_len = frame.len();
                let r = burst(dev, &frame, ch, o.count, o.interval_ms, json)?;
                sent += r.sent;
                fail += r.fail;
                if r.stopped {
                    stopped = true;
                    break;
                }
            }
        }
        ApMode::Synthesize => {
            let s = synthesize(o)?;
            let frame = build_with_ap(t, s.ap, o, &s.ssid, s.channel)?;
            last_len = frame.len();
            let r = burst(dev, &frame, s.channel, o.count, o.interval_ms, json)?;
            sent = r.sent;
            fail = r.fail;
            stopped = r.stopped;
        }
        ApMode::None => {
            let frame = build_no_ap(t, o)?;
            last_len = frame.len();
            let r = burst(dev, &frame, o.channel, o.count, o.interval_ms, json)?;
            sent = r.sent;
            fail = r.fail;
            stopped = r.stopped;
        }
    }

    Ok(result_json(
        sent,
        fail,
        planned_total(o.count, targets_n),
        stopped,
        last_len,
        targets_n,
        Some(t.name()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> Opts {
        Opts {
            template: Some(Template::Beacon),
            hex: None,
            channel: 0,
            count: 1,
            interval_ms: 0,
            ap: None,
            bssid: None,
            ssid: None,
            sta: None,
            ra: None,
            ta: None,
            reason: 7,
            duration: 0,
            aid: 1,
            tid: 0,
            ssn: 0,
            payload: None,
        }
    }

    #[test]
    fn synthesize_defaults_local_beacon() {
        let s = synthesize(&opts()).unwrap();
        assert_eq!(s.ap, DEFAULT_MAC);
        assert_eq!(s.ssid, DEFAULT_SSID);
        assert_eq!(s.channel, DEFAULT_CHANNEL);
    }

    #[test]
    fn synthesize_ssid_is_advertised_name_not_a_scan() {
        let mut o = opts();
        o.ssid = Some("Lab".into());
        let s = synthesize(&o).unwrap();
        assert_eq!(s.ap, DEFAULT_MAC);
        assert_eq!(s.ssid, "Lab");
        assert_eq!(s.channel, DEFAULT_CHANNEL);
    }

    #[test]
    fn synthesize_bssid_requires_channel() {
        let mut o = opts();
        o.bssid = Some("DE:AD:BE:EF:12:34".into());
        assert!(
            synthesize(&o)
                .unwrap_err()
                .to_string()
                .contains("--channel")
        );
    }

    #[test]
    fn synthesize_clone_keeps_empty_ssid() {
        let mut o = opts();
        o.bssid = Some("DE:AD:BE:EF:12:34".into());
        o.channel = 11;
        let s = synthesize(&o).unwrap();
        assert_eq!(s.ap, mac("DE:AD:BE:EF:12:34").unwrap());
        assert!(s.ssid.is_empty());
        assert_eq!(s.channel, 11);
    }

    #[test]
    fn beacon_ds_param_matches_tx_channel() {
        let mut o = opts();
        o.bssid = Some("DE:AD:BE:EF:12:34".into());
        o.ssid = Some("Hello World AP".into());
        o.channel = 11;
        let s = synthesize(&o).unwrap();
        let f = build_with_ap(Template::Beacon, s.ap, &o, &s.ssid, s.channel).unwrap();
        let ds = f.windows(3).position(|w| w == [3, 1, 11]);
        assert!(ds.is_some(), "DS param channel 11 not in {f:?}");
    }

    #[test]
    fn planned_total_is_count_times_targets() {
        assert_eq!(planned_total(1, 19), 19);
        assert_eq!(planned_total(5, 3), 15);
        assert_eq!(planned_total(0, 19), 0);
    }
}
