mod adapter;
mod bridge;
mod crack;
mod deauth;
mod flash;
mod fwota;
mod handshake;
mod hid;
mod hidraw;
mod manage;
mod monitor;
mod portal;
mod ports;
mod privs;
mod recon;
mod shell;
mod signals;
mod target;
mod tx;
mod ui;
mod wifi_analysis;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use infishark::client::Device;
use infishark::ir::IrCapture;
use infishark::ir_file::IrRemote;
use infishark::json::insert_opt;
use infishark::model::{
    AdapterConfig, AdapterTarget, BleScanOpts, GattConnectOpts, PortalOpts, WifiScanOpts,
};
use infishark::{company, hex, oui, pcap};

// Host-held last scans (the device streams results; it doesn't retain them).
static LAST_BLE: std::sync::Mutex<Vec<infishark::model::BleDevice>> =
    std::sync::Mutex::new(Vec::new());
static LAST_WIFI: std::sync::Mutex<Vec<infishark::model::Network>> =
    std::sync::Mutex::new(Vec::new());
static LAST_IR: std::sync::Mutex<Vec<infishark::ir::IrCapture>> = std::sync::Mutex::new(Vec::new());
// Files from the last `files ls`, largest first - lets `files pull 1` etc.
// resolve a row #.
static LAST_FILES: std::sync::Mutex<Vec<serde_json::Value>> = std::sync::Mutex::new(Vec::new());

#[derive(Debug, Parser)]
#[command(
    name = "infishark",
    version,
    about = "Command-line tools for interacting with InfiShark devices"
)]
struct Cli {
    #[arg(long, global = true)]
    port: Option<String>,

    #[arg(long, global = true)]
    json: bool,

    /// Show the compact wordmark banner instead of the large shark.
    #[arg(long, global = true)]
    no_banner: bool,

    #[arg(long, global = true, default_value_t = 2000)]
    timeout_ms: u64,

    #[command(subcommand)]
    command: Option<Command>,
}

impl Cli {
    fn open(&self, timeout: u64) -> Result<Device> {
        let mut dev = Device::open(self.port.as_deref(), timeout)?;
        warn_firmware(&mut dev);
        Ok(dev)
    }
}

fn warn_firmware(dev: &mut Device) {
    static ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if ONCE.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    if let Ok(id) = dev.firmware_identity() {
        if let Some(w) = id.warning() {
            eprintln!("warning: {w}");
            eprintln!(
                "         update with `infishark device update` or `infishark flash latest`."
            );
        }
    }
}

#[derive(Debug, Args)]
struct DbOpts {
    #[arg(long, global = true)]
    oui_db: Option<String>,

    #[arg(long, global = true)]
    company_db: Option<String>,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// List connected serial ports; Espressif/Nano devices are probed and
    /// identified.
    Ports {
        /// Include low-level system serial ports such as Linux /dev/ttyS*.
        #[arg(long)]
        all: bool,
    },
    /// Device info, status, and USB firmware update.
    Device {
        #[command(subcommand)]
        action: DeviceCmd,
    },
    /// Wi-Fi tools.
    Wifi {
        /// Local OUI (vendor) database override.
        #[arg(long, global = true)]
        oui_db: Option<String>,
        #[command(subcommand)]
        action: WifiCmd,
    },
    /// BLE tools.
    Ble {
        #[command(flatten)]
        db: DbOpts,
        #[command(subcommand)]
        action: BleCmd,
    },
    /// IR tools.
    Ir {
        #[command(subcommand)]
        action: IrCmd,
    },
    /// On-device file store.
    Files {
        #[command(subcommand)]
        action: FilesCmd,
    },
    /// Management tools - OUI & company databases
    Manage {
        #[command(flatten)]
        db: DbOpts,
        #[command(subcommand)]
        action: manage::ManageCmd,
    },
    /// Update the infishark CLI binary to the latest published release.
    Update,
    /// Flash Nano firmware over USB.
    Flash {
        #[command(subcommand)]
        action: Option<FlashCmd>,
    },
}

#[derive(Debug, Subcommand)]
enum DeviceCmd {
    /// Identity: serial, firmware, MAC, flash.
    Info,
    /// Live status: uptime, heap, battery, mesh.
    Status,
    /// Flash latest firmware (same as `flash latest`).
    Update {
        #[command(flatten)]
        ch: FlashChannel,
    },
}

#[derive(Debug, Args)]
struct FlashChannel {
    /// Use the beta channel.
    #[arg(long)]
    beta: bool,
    /// Skip the confirm prompt.
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Debug, Subcommand)]
enum FlashCmd {
    /// List firmware channels and latest tags.
    Versions,
    /// Install latest firmware.
    Latest {
        #[command(flatten)]
        ch: FlashChannel,
    },
    /// Install BLEShark Setup.
    Setup {
        /// Setup tag (default: latest).
        tag: Option<String>,
        /// Skip the confirm prompt.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Keep on-device files and settings (skip full flash erase).
        #[arg(long)]
        keep_storage: bool,
    },
    /// Install a specific tag.
    Install {
        tag: String,
        #[command(flatten)]
        ch: FlashChannel,
    },
}

#[derive(Debug, Subcommand)]
enum IrCmd {
    /// Blast the TV-B-Gone power-off sweep.
    Tvbgone,
    /// Transmit a code (`ir tx nec 20DF10EF`) or a `.ir` button (`ir tx
    /// remote.ir` / `ir tx remote.ir Power`).
    Tx {
        /// Protocol name, or path to a `.ir` file.
        target: String,
        /// Hex data (protocol mode), or button name/# (file mode).
        arg: Option<String>,
        /// Bit count (protocol mode; 0 = the protocol's default).
        #[arg(long, default_value_t = 0)]
        bits: u16,
        /// Repeat count (0 = the protocol's minimum).
        #[arg(long, default_value_t = 0)]
        repeats: u16,
    },
    /// Transmit raw carrier timings.
    Raw {
        /// Carrier frequency, kHz.
        #[arg(long, default_value_t = 38)]
        khz: u16,
        /// Mark/space durations in microseconds, comma-separated.
        #[arg(long, value_delimiter = ',')]
        timings: Vec<u16>,
    },
    /// Listen for IR and print captures (Ctrl-C to stop).
    Rx {
        /// Exit after the first capture.
        #[arg(long)]
        once: bool,
        /// Include raw timings in the live table (default: summary only).
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Write the session to a `.ir` file on stop.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Install a `.ir` file into an on-device remote slot (1-5).
    Push {
        /// Path to a `.ir` file.
        file: PathBuf,
        /// Remote slot to overwrite (1-5).
        #[arg(long, short)]
        slot: u8,
    },
    /// Show detail for a capture from the last `ir rx` session (1-based #).
    Show {
        /// Capture index from the last session table; omit to re-list.
        index: Option<usize>,
    },
}

#[derive(Debug, Subcommand)]
enum FilesCmd {
    /// List device files and storage usage, largest first.
    Ls,
    /// Copy a file off the device (to `--out`, else stdout).
    Pull {
        /// Device path, alias, or row # from the last `files ls`.
        file: String,
        /// Destination file; omit to write raw bytes to stdout.
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Upload a local file to a writable device path or alias.
    Push {
        /// Local source file.
        src: PathBuf,
        /// Device destination path or alias (e.g. `remote1`, `ducky`).
        #[arg(long, short)]
        dest: String,
    },
    /// Delete a file (only files the device marks deletable).
    Rm {
        /// Device path, alias, or row # from the last `files ls`.
        file: String,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum WifiCmd {
    /// Scan for Wi-Fi networks and print them (also retained for `wifi list`).
    Scan {
        /// Active scan (probe-request bursts) instead of passive listen-only.
        #[arg(long)]
        active: bool,
        /// Per-channel dwell time in ms (0 = driver default ~300).
        #[arg(long)]
        dwell: Option<u32>,
        /// Restrict to a single channel (1-14); 0/omitted = all.
        #[arg(long, value_parser = clap::value_parser!(u8).range(0..=14))]
        channel: Option<u8>,
        /// Exclude hidden-SSID APs (default includes them).
        #[arg(long)]
        no_hidden: bool,
        /// Only report this SSID.
        #[arg(long)]
        ssid: Option<String>,
        /// Only report this BSSID (AA:BB:CC:DD:EE:FF).
        #[arg(long)]
        bssid: Option<String>,
        /// Extra columns (ciphers, bandwidth, secondary, country, risk flags).
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Print the last Wi-Fi scan results.
    List {
        /// Extra columns (ciphers, bandwidth, secondary, country, risk flags).
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Show full detail for one AP from the last scan (#, SSID, or BSSID).
    Show {
        /// Scan table row #, SSID, or BSSID.
        target: String,
    },
    /// Deep recon: lock an AP's channel and summarize clients / probes /
    /// airtime.
    Recon {
        /// Scan table row #, SSID, or BSSID (omit to pick interactively).
        target: Option<String>,
        /// Target AP by SSID (strongest BSSID if several).
        #[arg(long)]
        ssid: Option<String>,
        /// Target AP by BSSID.
        #[arg(long, conflicts_with = "ssid")]
        bssid: Option<String>,
        /// Seconds to dwell (0 = until Ctrl-C). Default 15.
        #[arg(long, short = 't', default_value_t = 15)]
        seconds: u64,
    },
    /// Manage the networks saved on the device (used by Connect, the adapter,
    /// OTA updates, and more).
    Saved {
        #[command(subcommand)]
        action: SavedCmd,
    },
    /// Run the device as a USB Wi-Fi adapter (Linux-only for now, root): it
    /// joins a saved network and tunnels host traffic over SLIP.
    Adapter {
        /// Saved-network slot to join (omit to pick interactively; see `wifi
        /// saved list`).
        index: Option<u8>,
        /// Join these credentials directly instead of a saved slot (not
        /// persisted to the device).
        #[arg(long, conflicts_with = "index")]
        ssid: Option<String>,
        /// Password for --ssid (prompted if omitted; blank = open).
        #[arg(long, requires = "ssid")]
        pass: Option<String>,
        /// Associate with a per-association random MAC.
        #[arg(long)]
        randomize_mac: bool,
        /// DHCP hostname the target LAN sees.
        #[arg(long)]
        hostname: Option<String>,
        /// tun interface name.
        #[arg(long, default_value = "ishark0")]
        ifname: String,
        /// Tunnel MTU.
        #[arg(long, default_value_t = 1400)]
        mtu: u32,
        /// TCP MSS clamp on the tunnel (avoids PMTUD blackholes through the
        /// NAT).
        #[arg(long, default_value_t = 1360)]
        mss: u32,
        /// Route ALL host traffic through the tunnel (saves/restores the
        /// default route).
        #[arg(long)]
        route_all: bool,
        /// Start with the device's OLED status screen off (max throughput).
        /// Toggle live with 'd'.
        #[arg(long)]
        no_oled: bool,
    },
    /// Stream a live pcap of 802.11 frames (pipe to Wireshark, or --out a
    /// file).
    Monitor {
        /// Channel to capture on (1-14). Default is 1. Ignored when
        /// associating (--ssid / --index); the AP's channel is used.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=14))]
        channel: u8,
        /// Join this SSID before enabling promisc (stay associated).
        #[arg(long, conflicts_with = "index")]
        ssid: Option<String>,
        /// Password for --ssid (omit or empty = open).
        #[arg(long, requires = "ssid")]
        pass: Option<String>,
        /// Join a saved-network slot before promisc (see `wifi saved list`).
        #[arg(long, conflicts_with = "ssid")]
        index: Option<u8>,
        /// Named filter preset: all, eapol, deauth, probe-req, beacons,
        /// no-beacons.
        #[arg(long)]
        filter: Option<String>,
        /// Raw: frame types to forward (mgmt,data,ctrl).
        #[arg(long, value_delimiter = ',')]
        r#type: Vec<String>,
        /// Raw: mgmt subtypes (names or 0-15) to forward, or drop with --block.
        #[arg(long, value_delimiter = ',')]
        subtype: Vec<String>,
        /// Raw: ctrl subtypes (bar,ba,ps-poll,rts,cts,ack,cf-end or 0-15).
        #[arg(long, value_delimiter = ',')]
        ctrl_subtype: Vec<String>,
        /// Raw: data subtypes (data,null,qos-data,qos-null or 0-15).
        #[arg(long, value_delimiter = ',')]
        data_subtype: Vec<String>,
        /// Raw: invert the subtype masks (forward all but the listed subtypes).
        #[arg(long)]
        block: bool,
        /// Raw: data-frame EtherType gate (eapol,arp,ipv4,ipv6 or a hex value).
        #[arg(long)]
        ethertype: Option<String>,
        /// Raw: only frames carrying this MAC in addr1/addr2/addr3.
        #[arg(long, visible_alias = "addr")]
        bssid: Option<String>,
        /// Raw: drop frames weaker than this RSSI (dBm).
        #[arg(long, allow_hyphen_values = true)]
        min_rssi: Option<i8>,
        /// Raw: drop frames stronger than this RSSI (dBm).
        #[arg(long, allow_hyphen_values = true)]
        max_rssi: Option<i8>,
        /// Raw: match PHY (legacy,ht,vht,he or 0-3); the C3 radio only reports
        /// legacy/ht.
        #[arg(long)]
        phy: Option<String>,
        /// Raw: drop frames shorter than this many bytes.
        #[arg(long)]
        min_len: Option<u16>,
        /// Raw: drop frames longer than this many bytes.
        #[arg(long)]
        max_len: Option<u16>,
        /// Raw: drop retransmitted duplicates (same addr2+seq within ~500 ms).
        #[arg(long)]
        dedup: bool,
        /// Raw: only Protected (encrypted) frames.
        #[arg(long, conflicts_with = "unencrypted")]
        encrypted: bool,
        /// Raw: only cleartext frames.
        #[arg(long)]
        unencrypted: bool,
        /// Raw: custom byte predicate OFFSET:HEX[/HEXMASK] (repeatable, <=8).
        #[arg(long = "match", value_name = "OFF:HEX[/MASK]")]
        r#match: Vec<String>,
        /// Raw: sugar for a 3-byte OUI in addr2 (hex or colon form).
        #[arg(long)]
        vendor: Option<String>,
        /// Raw: sugar for a source MAC in addr2.
        #[arg(long)]
        src: Option<String>,
        /// Raw: sugar for a destination MAC in addr1.
        #[arg(long)]
        dst: Option<String>,
        /// Write the pcap to a file instead of stdout.
        #[arg(long)]
        out: Option<String>,
    },
    /// Inject an 802.11 frame (named template or --hex), optionally as a burst.
    Tx {
        /// Named template. Omit when using --hex.
        #[arg(value_enum, value_name = "TEMPLATE", required_unless_present = "hex")]
        template: Option<tx::Template>,
        /// Full MAC frame as hex, no FCS (the radio appends it).
        #[arg(long, conflicts_with = "template")]
        hex: Option<String>,
        /// Channel (1-14). 0 = device current, or AP channel after a scan pick.
        /// Beacon: 0 = channel 6 when synthesizing.
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=14))]
        channel: u8,
        /// TX attempts per target (0 = until Ctrl-C). Runs on-device.
        #[arg(long, default_value_t = 1)]
        count: u16,
        /// Gap between on-device TX attempts in ms (not 802.11 Duration/ID).
        #[arg(long, default_value_t = 0)]
        interval_ms: u16,
        /// AP MAC (alias of --bssid). If omitted for AP-required templates,
        /// scan + pick. Beacon: omitted = local BSSID (no scan).
        #[arg(long)]
        ap: Option<String>,
        /// AP BSSID (needs --channel when set without a scan).
        #[arg(long)]
        bssid: Option<String>,
        /// Scan filter for AP-required templates. Beacon/probe-req: the
        /// advertised or probed SSID (no scan).
        #[arg(long)]
        ssid: Option<String>,
        /// Station MAC (default: broadcast on deauth/disassoc).
        #[arg(long)]
        sta: Option<String>,
        /// Receiver address (control templates).
        #[arg(long)]
        ra: Option<String>,
        /// Transmitter address (rts/bar/ps-poll; default AP when applicable).
        #[arg(long)]
        ta: Option<String>,
        /// 802.11 reason code (deauth/disassoc).
        #[arg(long, default_value_t = 7)]
        reason: u16,
        /// Duration/ID (rts/cts/bar).
        #[arg(long, default_value_t = 0)]
        duration: u16,
        /// Association id (ps-poll).
        #[arg(long, default_value_t = 1)]
        aid: u16,
        /// TID (qos-null, qos-data, bar).
        #[arg(long, default_value_t = 0)]
        tid: u8,
        /// Starting sequence number (bar).
        #[arg(long, default_value_t = 0)]
        ssn: u16,
        /// MSDU payload hex (data / qos-data).
        #[arg(long)]
        payload: Option<String>,
    },
    /// Deauth an AP's clients until Ctrl-C; picker or --ssid/--bssid.
    Deauth {
        /// Target AP by name; hits every BSSID advertising it.
        #[arg(long)]
        ssid: Option<String>,
        /// Target a single AP by BSSID (needs --channel).
        #[arg(long, conflicts_with = "ssid")]
        bssid: Option<String>,
        /// Channel of --bssid.
        #[arg(long, requires = "bssid", value_parser = clap::value_parser!(u8).range(1..=14))]
        channel: Option<u8>,
        /// Deauth one station (default: broadcast to all clients).
        #[arg(long)]
        client: Option<String>,
        /// 802.11 reason code.
        #[arg(long, default_value_t = 7)]
        reason: u16,
        /// Delay between deauth rounds in ms.
        #[arg(long, default_value_t = 0)]
        interval_ms: u64,
    },
    /// Capture a WPA handshake (PMKID + 4-way); picker or --ssid/--bssid.
    Handshake {
        /// Target AP by name; strongest BSSID if several.
        #[arg(long)]
        ssid: Option<String>,
        /// Target a single AP by BSSID (needs --channel).
        #[arg(long, conflicts_with = "ssid")]
        bssid: Option<String>,
        /// Channel of --bssid.
        #[arg(long, requires = "bssid", value_parser = clap::value_parser!(u8).range(1..=14))]
        channel: Option<u8>,
        /// Deauth one station (default: broadcast until a client is seen).
        #[arg(long)]
        client: Option<String>,
        /// 802.11 deauth reason code.
        #[arg(long, default_value_t = 7)]
        reason: u16,
        /// Solicit the clientless PMKID only; never deauth.
        #[arg(long)]
        pmkid_only: bool,
        /// Skip PMKID solicitation; force the 4-way by deauth only.
        #[arg(long, conflicts_with = "pmkid_only")]
        no_pmkid: bool,
        /// Sniff only: never transmit (no solicitation, no deauth).
        #[arg(long, conflicts_with_all = ["pmkid_only", "no_pmkid", "client"])]
        passive: bool,
        /// Keep collecting after the first crackable capture.
        #[arg(long)]
        continuous: bool,
        /// Deauth frames per burst (cold start uses at least 5).
        #[arg(long, default_value_t = 5)]
        deauth_count: u32,
        /// Delay between deauth bursts in ms (also floors the post-burst
        /// quiet).
        #[arg(long, default_value_t = 2000)]
        deauth_interval: u64,
        /// PMKID solicitation attempts.
        #[arg(long, default_value_t = 5)]
        solicit_count: u32,
        /// Delay between PMKID solicitations in ms.
        #[arg(long, default_value_t = 1000)]
        solicit_interval: u64,
        /// Seconds to hold on each AP (0 = until Ctrl-C).
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        /// Extra seconds to hold after the last EAPOL frame before moving on.
        #[arg(long, default_value_t = 10)]
        grace: u64,
        /// Output base path; writes <out>.pcap (+ <out>.22000). Default
        /// hs_<target>.
        #[arg(long)]
        out: Option<String>,
        /// Write only the pcap; skip the .22000.
        #[arg(long)]
        pcap_only: bool,
        /// After capture, hand the .22000 to hashcat.
        #[arg(long)]
        crack: bool,
        /// Wordlist for --crack (default: bundled rockyou top-100k).
        #[arg(long, requires = "crack")]
        wordlist: Option<String>,
    },
    /// Run the captive portal (SoftAP + captive DNS). With --dir, stream
    /// HTML from the host; omit --dir to use the device's stored/sample page.
    Portal {
        /// Directory of pages (index.html at /). Host-streams bodies over USB.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// SoftAP SSID (default: device settings, usually "Portal").
        #[arg(long)]
        ssid: Option<String>,
        /// WPA2-PSK passphrase (omit or empty = open network).
        #[arg(long)]
        pass: Option<String>,
        /// SoftAP channel 1-13 (default 1).
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=13))]
        channel: Option<u8>,
        /// Hide the SSID in beacons.
        #[arg(long)]
        hidden: bool,
        /// Max concurrent SoftAP stations (1-10, default 4).
        #[arg(long)]
        max_clients: Option<u8>,
        /// Spoof SoftAP BSSID (AA:BB:CC:DD:EE:FF).
        #[arg(long, conflicts_with = "random_mac")]
        mac: Option<String>,
        /// Random locally-administered SoftAP MAC.
        #[arg(long)]
        random_mac: bool,
        /// SoftAP / captive gateway IP (default 192.0.2.1).
        #[arg(long)]
        ip: Option<String>,
        /// SoftAP netmask (default 255.255.255.0).
        #[arg(long)]
        netmask: Option<String>,
        /// Beacon interval in ms (50-3000, default 100).
        #[arg(long)]
        beacon_ms: Option<u16>,
        /// Augment credential JSON with UA / RF fingerprint fields.
        #[arg(long)]
        detailed_capture: bool,
        /// Host body wait timeout in ms (host-content mode).
        #[arg(long)]
        host_timeout_ms: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
enum SavedCmd {
    /// List the saved networks (SSIDs only; passwords never leave the device).
    List,
    /// Save a network: scan and pick interactively, or pass --ssid/--pass.
    Add {
        /// SSID to save. If omitted, scan and choose interactively.
        #[arg(long)]
        ssid: Option<String>,
        /// Password. If omitted, you are prompted (open network: leave blank).
        #[arg(long)]
        pass: Option<String>,
        /// Scan duration (ms) used when choosing interactively.
        #[arg(long, default_value_t = 4000)]
        scan_ms: u32,
    },
    /// Remove a saved network by its slot index (see `wifi saved list`).
    Rm {
        /// Slot index to remove.
        index: u8,
    },
}

/// Scan PHY mask (extended advertising). `Coded` == LE LR (long range).
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ScanPhy {
    #[value(name = "1m")]
    OneM,
    Coded,
    All,
}

impl ScanPhy {
    fn mask(self) -> u8 {
        match self {
            ScanPhy::OneM => 1,
            ScanPhy::Coded => 2,
            ScanPhy::All => 3,
        }
    }
}

#[derive(Debug, Subcommand)]
enum BleCmd {
    /// Scan for BLE devices and print them
    Scan {
        /// Scan duration in ms (0 = until the device is stopped).
        #[arg(long)]
        duration: Option<u32>,
        /// Which PHYs to scan: 1m (fast), coded (long range), or all (default).
        #[arg(long, value_enum)]
        phy: Option<ScanPhy>,
        /// Passive scan: listen only (no SCAN_REQ / scan-response names).
        /// Default is active so local names can appear.
        #[arg(long)]
        passive: bool,
        /// Scan interval in milliseconds (how often a listen window starts).
        #[arg(long)]
        interval: Option<u16>,
        /// Scan window in milliseconds (listen time per interval; <= interval).
        #[arg(long)]
        window: Option<u16>,
        /// Have the device suppress duplicate adverts (controller-side).
        #[arg(long)]
        dedup: bool,
    },
    /// Print the last BLE scan results.
    List,
    /// Show full detail for one device from the last scan (by list number).
    Show {
        /// Device number from `ble scan`/`ble list` (omit to re-list).
        index: Option<usize>,
    },
    /// GATT central: connect out to a peripheral and act on its attributes.
    Gatt {
        #[command(subcommand)]
        action: GattCmd,
    },
    /// Broadcast a custom advertising payload (peripheral).
    #[command(group(clap::ArgGroup::new("payload").required(true).multiple(true).args([
        "raw", "name", "mfg", "service_uuid", "ibeacon", "eddystone_url", "appearance",
    ])))]
    Adv {
        /// Complete raw AD payload as hex (exclusive with the structured
        /// fields).
        #[arg(long)]
        raw: Option<String>,
        /// Advertised device name.
        #[arg(long)]
        name: Option<String>,
        /// Manufacturer data as hex (e.g. 4c0010...).
        #[arg(long)]
        mfg: Option<String>,
        /// Advertise a service UUID.
        #[arg(long)]
        service_uuid: Option<String>,
        /// Make it connectable (default: non-connectable broadcast).
        #[arg(long)]
        connectable: bool,
        /// Advertising interval in ms.
        #[arg(long)]
        interval_ms: Option<u32>,
        /// TX power in dBm.
        #[arg(long)]
        tx: Option<i32>,
        /// iBeacon as UUID:major:minor (UUID = 32 hex chars).
        #[arg(long)]
        ibeacon: Option<String>,
        /// Eddystone URL, e.g. https://example.com.
        #[arg(long)]
        eddystone_url: Option<String>,
        /// PHY: 1m (default), 2m, or coded (long range; only BLE5 scanners see
        /// it)
        #[arg(long)]
        phy: Option<String>,
        /// Modify the advertiser MAC (AA:BB:CC:DD:EE:FF).
        #[arg(long)]
        mac: Option<String>,
        /// Use a random locally-administered MAC.
        #[arg(long)]
        random_mac: bool,
        /// Scan-response payload as hex (a second 31-byte channel).
        #[arg(long)]
        scan_resp: Option<String>,
        /// Auto-stop after N ms (0/omitted = until `ble stop`).
        #[arg(long)]
        duration_ms: Option<u32>,
        /// GAP appearance value.
        #[arg(long)]
        appearance: Option<u16>,
    },
    /// Run a connectable GATT server; central activity streams as NDJSON.
    Serve {
        /// SVCUUID/CHARUUID:props[=hexvalue] (props: r/w/n/i, e=encrypted);
        /// repeatable.
        #[arg(long = "char", required = true, value_name = "SVC/CHAR:props=hex")]
        chars: Vec<String>,
        /// Advertised device name.
        #[arg(long)]
        name: Option<String>,
        /// Spoof the advertiser MAC (AA:BB:CC:DD:EE:FF).
        #[arg(long)]
        mac: Option<String>,
        /// Use a random locally-administered MAC.
        #[arg(long)]
        random_mac: bool,
    },
    /// Stream stdin (one hex value per line) as notifications on a
    /// characteristic.
    Stream {
        /// Characteristic UUID (must exist in a running `ble serve`).
        #[arg(long = "char")]
        char: String,
        /// Delay between notifications in ms.
        #[arg(long, default_value_t = 0)]
        interval_ms: u64,
    },
    /// Update a served characteristic's value (+ optional notify).
    Set {
        /// Characteristic UUID.
        #[arg(long = "char")]
        char: String,
        /// New value as hex.
        #[arg(long)]
        value: String,
        /// Notify subscribers of the new value.
        #[arg(long)]
        notify: bool,
    },
    /// Emulate an HID device (keyboard/mouse/gamepad/consumer or a raw report
    /// map).
    Hid {
        #[command(subcommand)]
        action: HidCmd,
    },
    /// Dual-link GATT proxy: clone a peripheral, wait for a central, relay ATT.
    Mitm {
        /// Target address, e.g. AA:BB:CC:DD:EE:FF (omit to scan and pick).
        address: Option<String>,
        /// Address type: 0=public, 1=random.
        #[arg(long, default_value_t = 0)]
        addr_type: u8,
        /// Advertised name (default: the target's GAP name).
        #[arg(long)]
        name: Option<String>,
        /// Advertiser MAC (default: the target's address).
        #[arg(long)]
        mac: Option<String>,
        /// Keep the Nano's own MAC instead of spoofing the target.
        #[arg(long)]
        no_spoof: bool,
        /// Skip pairing (default is bond + LE Secure Connections + passkey).
        #[arg(long)]
        no_pair: bool,
        /// Pairing IO capability for the target link.
        #[arg(long)]
        io_cap: Option<u8>,
        /// Passkey to supply if the target requests one.
        #[arg(long)]
        passkey: Option<u32>,
        /// BLE connection-attempt timeout in ms.
        #[arg(long)]
        connect_timeout_ms: Option<u32>,
        /// Write ATT traffic to a Bluetooth HCI pcap (Wireshark). Omit FILE for
        /// `ble-mitm-<unix>.pcap` in the current directory.
        #[arg(long, value_name = "FILE", num_args = 0..=1, default_missing_value = "AUTO")]
        pcap: Option<String>,
    },
    /// Stop the peripheral (advertiser or GATT server).
    Stop,
    /// Keep the device's BLE stack initialized across commands (on), or release
    /// it (off). Avoids rapid re-init during a scan/connect/write workflow.
    Keepalive {
        #[arg(value_enum)]
        state: OnOff,
    },
    /// Force a clean reset of the device's BLE stack
    Reset,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum OnOff {
    On,
    Off,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum HidPreset {
    Keyboard,
    Mouse,
    Gamepad,
    Consumer,
    Combo,
}

impl HidPreset {
    fn classes(self) -> Vec<hid::HidClass> {
        use hid::HidClass::*;
        match self {
            HidPreset::Keyboard => vec![Keyboard],
            HidPreset::Mouse => vec![Mouse],
            HidPreset::Gamepad => vec![Gamepad],
            HidPreset::Consumer => vec![Consumer],
            HidPreset::Combo => vec![Keyboard, Mouse],
        }
    }
}

#[derive(Debug, Subcommand)]
enum HidCmd {
    /// Advertise as an HID device, built from a preset or a raw report map.
    #[command(group(clap::ArgGroup::new("hid_source").required(true).args(["preset", "report_map"])))]
    Start {
        /// Device preset.
        #[arg(long, value_enum)]
        preset: Option<HidPreset>,
        /// Raw HID report descriptor as hex (needs at least one --report).
        #[arg(long, requires = "report")]
        report_map: Option<String>,
        /// Declare a report as ID:TYPE[:LEN] (type: input|output|feature);
        /// repeatable.
        #[arg(long = "report", value_name = "ID:TYPE:LEN")]
        report: Vec<String>,
        /// Advertised device name.
        #[arg(long)]
        name: Option<String>,
        /// GAP appearance (defaults to the preset's).
        #[arg(long)]
        appearance: Option<u16>,
        /// PnP identity as VID:PID:VER (decimal, or 0x-prefixed hex).
        #[arg(long)]
        pnp: Option<String>,
        /// Require a passkey for MITM-protected pairing (else just-works
        /// bonding).
        #[arg(long)]
        passkey: Option<u32>,
        /// Spoof the MAC (AA:BB:CC:DD:EE:FF).
        #[arg(long)]
        mac: Option<String>,
        /// Use a random locally-administered MAC.
        #[arg(long)]
        random_mac: bool,
        /// Stream connect/subscribe/output events as NDJSON instead of
        /// returning.
        #[arg(long)]
        watch: bool,
    },
    /// Send an input report (notify) or set a feature report by ID.
    Send {
        /// Report ID (as declared at start).
        #[arg(long)]
        id: u8,
        /// Report bytes as hex.
        #[arg(long)]
        hex: String,
        /// Report type: input (notify) or feature (set value).
        #[arg(long, default_value = "input")]
        r#type: String,
    },
    /// Type text over a running keyboard preset.
    Type {
        /// Text to type (\n = Enter, \t = Tab).
        text: String,
        /// Delay between keystrokes in ms.
        #[arg(long, default_value_t = 8)]
        delay_ms: u64,
    },
    /// Grab host HID inputs (keyboard, mouse, touchpad, gamepad, tablet,
    /// system) and drive the paired device over BLE. Selected inputs merge into
    /// one composite HID device; --clone instead clones one raw hidraw device
    /// wholesale.
    Bridge {
        /// Release hotkey; all keys held together ends the bridge.
        #[arg(long, default_value = "ctrl+esc")]
        release: String,
        /// evdev device to grab: a number from the list, a name substring, or a
        /// /dev/input/eventN path (repeatable). Default: pick interactively.
        #[arg(long = "device")]
        devices: Vec<String>,
        /// Grab every detected input device (skip the interactive picker).
        #[arg(long)]
        all: bool,
        /// Attach to an already-running HID device instead of starting one.
        #[arg(long)]
        no_start: bool,
        /// Clone one raw /dev/hidraw device wholesale (input-only) instead of
        /// the interpreted grab. Pass --device /dev/hidrawN or pick
        /// interactively.
        #[arg(long)]
        clone: bool,
    },
}

#[derive(Debug, Subcommand)]
enum GattCmd {
    /// Connect to a peripheral by address (omit to scan and pick
    /// interactively).
    Connect {
        /// Target address, e.g. AA:BB:CC:DD:EE:FF.
        address: Option<String>,
        /// Address type: 0=public, 1=random. Prefer the type from `ble scan`
        /// (interactive pick uses it). Wrong type is a common cause of
        /// connect timeout / HCI 0x3E.
        #[arg(long, default_value_t = 0)]
        addr_type: u8,
        /// BLE connection-attempt timeout in ms (distinct from the global
        /// --timeout-ms).
        #[arg(long)]
        connect_timeout_ms: Option<u32>,
        /// Min connection interval (1.25 ms units).
        #[arg(long)]
        min_interval: Option<u16>,
        /// Max connection interval (1.25 ms units).
        #[arg(long)]
        max_interval: Option<u16>,
        /// Slave latency (skippable events).
        #[arg(long)]
        latency: Option<u16>,
        /// Supervision timeout (10 ms units).
        #[arg(long)]
        supervision_timeout: Option<u16>,
        /// Initiate pairing/encryption right after connecting.
        #[arg(long)]
        secure: bool,
        /// Persist keys (bond/trust across reconnects).
        #[arg(long)]
        bond: bool,
        /// Require MITM protection (passkey / numeric comparison).
        #[arg(long)]
        mitm: bool,
        /// Use LE Secure Connections.
        #[arg(long)]
        sc: bool,
        /// Pairing IO capability (3=Just Works, 2=Keyboard for passkey entry).
        #[arg(long)]
        io_cap: Option<u8>,
        /// Passkey to supply when the peer requests one.
        #[arg(long)]
        passkey: Option<u32>,
    },
    /// Discover and print the service/characteristic tree.
    Enum,
    /// Read a characteristic value by UUID.
    Read {
        /// Characteristic UUID.
        uuid: String,
    },
    /// Write a hex value to a characteristic by UUID.
    Write {
        /// Characteristic UUID.
        uuid: String,
        /// Value as hex, e.g. AF or 01020304.
        data: String,
        /// Write without a response.
        #[arg(long)]
        no_response: bool,
    },
    /// Subscribe to one or more characteristics and stream values (NDJSON)
    /// until interrupted.
    Subscribe {
        /// Characteristic UUID(s) to subscribe to.
        #[arg(required = true)]
        uuids: Vec<String>,
        /// Use indications (acked) instead of notifications.
        #[arg(long)]
        indicate: bool,
    },
    /// Stop notifications/indications on a characteristic.
    Unsubscribe {
        /// Characteristic UUID.
        uuid: String,
    },
    /// Disconnect the current GATT session.
    Disconnect,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Keep the failure path machine-parseable under --json; anyhow's
            // default would print plain text even there.
            if cli.json {
                println!("{}", serde_json::json!({ "error": format!("{e:#}") }));
            } else {
                eprintln!("Error: {e:#}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Some(command) => dispatch(cli, command),
        None => shell::run(cli),
    }
}

fn dispatch(cli: &Cli, command: &Command) -> Result<()> {
    match command {
        Command::Ports { all } => ports::run(*all, cli.json),
        Command::Device { action } => cmd_device(cli, action),
        Command::Wifi { oui_db, action } => cmd_wifi(cli, oui_db.as_deref(), action),
        Command::Ble { db, action } => cmd_ble(cli, db, action),
        Command::Ir { action } => cmd_ir(cli, action),
        Command::Files { action } => cmd_files(cli, action),
        Command::Manage { db, action } => manage::run(cli.json, db, action),
        Command::Update => cmd_update(),
        Command::Flash { action } => match action {
            None | Some(FlashCmd::Versions) => flash::catalog(cli.json, cli.port.as_deref()),
            Some(FlashCmd::Latest { ch }) => flash_install(cli, "latest", ch.beta, ch.yes),
            Some(FlashCmd::Setup {
                tag,
                yes,
                keep_storage,
            }) => flash::setup(flash::Setup {
                tag: tag.clone(),
                yes: *yes,
                json: cli.json,
                port: cli.port.clone(),
                keep_storage: *keep_storage,
            }),
            Some(FlashCmd::Install { tag, ch }) => flash_install(cli, tag.clone(), ch.beta, ch.yes),
        },
    }
}

fn cmd_update() -> Result<()> {
    let status = self_update::backends::github::Update::configure()
        .repo_owner("infishark")
        .repo_name("infishark")
        .bin_name("infishark")
        .current_version(env!("CARGO_PKG_VERSION"))
        .show_download_progress(true)
        .build()?
        .update()?;
    if status.updated() {
        println!("Updated to {}.", status.version());
    } else {
        println!("Already up to date ({}).", status.version());
    }
    Ok(())
}

fn flash_install(cli: &Cli, tag: impl Into<String>, beta: bool, yes: bool) -> Result<()> {
    flash::install(flash::Install {
        tag: tag.into(),
        kind: if beta { "beta" } else { "main" },
        yes,
        json: cli.json,
        port: cli.port.clone(),
        timeout_ms: cli.timeout_ms,
    })
}

fn cmd_device(cli: &Cli, action: &DeviceCmd) -> Result<()> {
    if let DeviceCmd::Update { ch } = action {
        return flash_install(cli, "latest", ch.beta, ch.yes);
    }
    let mut dev = cli.open(cli.timeout_ms)?;
    let v = match action {
        DeviceCmd::Info => {
            let mut info = dev.device_info()?;
            if let Some(obj) = info.as_object_mut() {
                obj.insert(
                    "recommended_firmware".into(),
                    infishark::RECOMMENDED_FIRMWARE.into(),
                );
            }
            info
        }
        DeviceCmd::Status => dev.system_status()?,
        DeviceCmd::Update { .. } => unreachable!(),
    };
    if cli.json {
        print_value(&v, true)
    } else {
        ui::value_detail(&v);
        Ok(())
    }
}

/// Stream the Wi-Fi monitor to `w`, sending the device a stop on exit (Ctrl-C
/// or a closed sink) so it doesn't keep pushing frames and appear frozen.
fn stream_wifi_monitor<W: Write>(dev: &mut Device, w: &mut W) -> Result<()> {
    signals::install_sigint();
    loop {
        if !signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        match dev.next_wifi_frame() {
            Ok(payload) => {
                if payload.len() >= 6
                    && (pcap::write_radiotap_record(w, payload[0] as i8, payload[1], &payload[6..])
                        .is_err()
                        || w.flush().is_err())
                {
                    break; // downstream (Wireshark / file) closed
                }
            }
            Err(_) => break, // serial error or interrupt
        }
    }
    let _ = dev.stop_current_task();
    Ok(())
}

fn print_ir_note(note: Option<String>, json: bool) {
    if let Some(n) = note {
        if json {
            eprintln!("{}", serde_json::json!({ "note": n }));
        } else {
            eprintln!("note: {n}");
        }
    }
}

fn cmd_files(cli: &Cli, action: &FilesCmd) -> Result<()> {
    let mut dev = cli.open(cli.timeout_ms)?;
    match action {
        FilesCmd::Ls => {
            let v = dev.file_list()?;
            let mut files: Vec<serde_json::Value> = v
                .get("files")
                .and_then(|f| f.as_array())
                .cloned()
                .unwrap_or_default();
            files.sort_by_key(|f| {
                std::cmp::Reverse(f.get("size").and_then(|x| x.as_u64()).unwrap_or(0))
            });
            *LAST_FILES.lock().unwrap() = files.clone();
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({ "spiffs": v.get("spiffs"), "files": files })
                );
                return Ok(());
            }
            let rows: Vec<ui::FileRow> = files
                .iter()
                .map(|f| ui::FileRow {
                    size: f.get("size").and_then(|x| x.as_u64()).unwrap_or(0),
                    path: f
                        .get("path")
                        .and_then(|x| x.as_str())
                        .unwrap_or("?")
                        .to_string(),
                    read: f.get("read").and_then(|x| x.as_bool()).unwrap_or(true),
                    write: f.get("write").and_then(|x| x.as_bool()).unwrap_or(false),
                    deletable: f
                        .get("deletable")
                        .and_then(|x| x.as_bool())
                        .unwrap_or(false),
                })
                .collect();
            ui::file_table(&rows);
            if let Some(s) = v.get("spiffs") {
                let used = s.get("used").and_then(|x| x.as_u64()).unwrap_or(0);
                let total = s.get("total").and_then(|x| x.as_u64()).unwrap_or(0);
                println!(
                    "Storage: {} / {} used",
                    ui::fmt_size(used),
                    ui::fmt_size(total)
                );
            }
            Ok(())
        }
        FilesCmd::Pull { file, out } => {
            let path = resolve_file_target(file)?;
            let bytes = dev.file_read(&path)?;
            match out {
                Some(dest) => {
                    std::fs::write(dest, &bytes)
                        .with_context(|| format!("write {}", dest.display()))?;
                    print_action(
                        serde_json::json!({ "path": path, "bytes": bytes.len() }),
                        format!("Pulled {} byte(s) to {}.", bytes.len(), dest.display()),
                        cli.json,
                    )
                }
                None => {
                    std::io::stdout().write_all(&bytes)?;
                    Ok(())
                }
            }
        }
        FilesCmd::Push { src, dest } => {
            let bytes = std::fs::read(src).with_context(|| format!("read {}", src.display()))?;
            let dest = canonical_cli_path(dest);
            // refuse a file that can't fit
            if let Some(free) = device_free_bytes(&dev.file_list()?, &dest) {
                if bytes.len() as u64 > free {
                    bail!(
                        "{} is {} bytes but only {free} free on device",
                        src.display(),
                        bytes.len()
                    );
                }
            }
            dev.file_write(&dest, &bytes)?;
            print_action(
                serde_json::json!({ "dest": dest, "bytes": bytes.len() }),
                format!("Pushed {} byte(s) to {dest}.", bytes.len()),
                cli.json,
            )
        }
        FilesCmd::Rm { file } => {
            let path = resolve_file_target(file)?;
            dev.file_delete(&path)?;
            print_action(
                serde_json::json!({ "deleted": path }),
                format!("Deleted {path}."),
                cli.json,
            )
        }
    }
}

// Resolve a `files` argument to a device path.
fn resolve_file_target(arg: &str) -> Result<String> {
    if let Ok(n) = arg.parse::<usize>() {
        let cache = LAST_FILES.lock().unwrap();
        if cache.is_empty() {
            bail!("no cached listing; run `files ls` first (or pass a path)");
        }
        return cache
            .get(n.wrapping_sub(1))
            .with_context(|| format!("file #{n} out of range (1..{})", cache.len()))?
            .get("path")
            .and_then(|p| p.as_str())
            .map(String::from)
            .context("cached entry has no path");
    }
    Ok(cached_path_for(arg).unwrap_or_else(|| canonical_cli_path(arg)))
}

fn canonical_cli_path(arg: &str) -> String {
    let p = arg.trim();
    if p.is_empty() || p.starts_with('/') {
        return p.to_string();
    }
    if matches!(
        p,
        "ducky" | "remote1" | "remote2" | "remote3" | "remote4" | "remote5"
    ) {
        return p.to_string();
    }
    format!("/{p}")
}

// Match a name against cached `files ls` paths (exact path or basename).
fn cached_path_for(arg: &str) -> Option<String> {
    let cache = LAST_FILES.lock().unwrap();
    for f in cache.iter() {
        if let Some(p) = f.get("path").and_then(|x| x.as_str()) {
            if p == arg || p.rsplit('/').next() == Some(arg) {
                return Some(p.to_string());
            }
        }
    }
    None
}

// Bytes a push to `dest` may use
fn device_free_bytes(list: &serde_json::Value, dest: &str) -> Option<u64> {
    let spiffs = list.get("spiffs")?;
    let total = spiffs.get("total")?.as_u64()?;
    let used = spiffs.get("used")?.as_u64()?;
    let mut free = total.saturating_sub(used);
    if let Some(files) = list.get("files").and_then(|f| f.as_array()) {
        for f in files {
            let p = f.get("path").and_then(|x| x.as_str()).unwrap_or("");
            if p == dest || p.rsplit('/').next() == Some(dest) {
                free += f.get("size").and_then(|x| x.as_u64()).unwrap_or(0);
                break;
            }
        }
    }
    Some(free)
}

fn cmd_ir(cli: &Cli, action: &IrCmd) -> Result<()> {
    // Cache-only: no device open (same idea as `wifi list` / `ble show`).
    if let IrCmd::Show { index } = action {
        return cmd_ir_show(cli, *index);
    }

    let mut dev = cli.open(cli.timeout_ms)?;
    match action {
        IrCmd::Tvbgone => {
            let note = dev.ir_tvbgone()?;
            print_ir_note(note, cli.json);
            print_action(
                serde_json::json!({ "ok": true }),
                "IR TV-B-Gone sent.",
                cli.json,
            )
        }
        IrCmd::Tx {
            target,
            arg,
            bits,
            repeats,
        } => cmd_ir_tx(cli, &mut dev, target, arg.as_deref(), *bits, *repeats),
        IrCmd::Raw { khz, timings } => {
            if timings.is_empty() {
                bail!("--timings is required");
            }
            let raw = infishark::ir::RawIr {
                khz: *khz,
                timings: timings.clone(),
            };
            let note = dev.ir_raw_tx(&raw)?;
            print_ir_note(note, cli.json);
            print_action(
                serde_json::json!({ "ok": true, "count": timings.len() }),
                format!("Sent {} raw timing(s).", timings.len()),
                cli.json,
            )
        }
        IrCmd::Rx { once, verbose, out } => {
            cmd_ir_rx(cli, &mut dev, *once, *verbose, out.as_deref())
        }
        IrCmd::Push { file, slot } => cmd_ir_push(cli, &mut dev, file, *slot),
        IrCmd::Show { .. } => unreachable!("handled above"),
    }
}

// Max commands a device remote can store; extras stay in the source .ir.
const IR_REMOTE_MAX: usize = 32;

fn cmd_ir_push(cli: &Cli, dev: &mut Device, file: &Path, slot: u8) -> Result<()> {
    if !(1..=5).contains(&slot) {
        bail!("slot must be 1-5");
    }
    let remote = IrRemote::load_strict(file)?;
    let (csv, skipped) = remote.to_device_csv();
    let mut lines: Vec<&str> = csv.lines().collect();
    if lines.is_empty() {
        bail!(
            "no parsed buttons to install ({} raw skipped)",
            skipped.len()
        );
    }
    let overflow = lines.len().saturating_sub(IR_REMOTE_MAX);
    lines.truncate(IR_REMOTE_MAX);
    let installed = lines.len();
    let mut out = lines.join("\n");
    out.push('\n');

    let dest = format!("remote{slot}");
    dev.file_write(&dest, out.as_bytes())?;

    let mut notes = Vec::new();
    if overflow > 0 {
        notes.push(format!("{overflow} over the {IR_REMOTE_MAX}-command limit"));
    }
    if !skipped.is_empty() {
        notes.push(format!("{} raw", skipped.len()));
    }
    let tail = if notes.is_empty() {
        String::new()
    } else {
        format!(" ({} skipped)", notes.join(", "))
    };
    print_action(
        serde_json::json!({
            "slot": slot,
            "dest": dest,
            "installed": installed,
            "skipped_overflow": overflow,
            "skipped_raw": skipped.len(),
        }),
        format!("Installed {installed} button(s) into {dest}{tail}."),
        cli.json,
    )
}

fn is_ir_path(s: &str) -> bool {
    if s.rsplit_once('.')
        .is_some_and(|(_, e)| e.eq_ignore_ascii_case("ir"))
    {
        return true;
    }
    // A bare protocol name (no separator) never counts as a file path.
    s.contains(std::path::MAIN_SEPARATOR) && Path::new(s).is_file()
}

fn cmd_ir_tx(
    cli: &Cli,
    dev: &mut Device,
    target: &str,
    arg: Option<&str>,
    bits: u16,
    repeats: u16,
) -> Result<()> {
    if is_ir_path(target) {
        return cmd_ir_tx_file(cli, dev, target, arg, repeats);
    }
    let data = arg.context("hex data required (usage: ir tx <protocol> <hex>)")?;
    let proto = infishark::ir::Protocol::from_name(target)
        .with_context(|| format!("unknown IR protocol '{target}'"))?;
    let value = infishark::hex::parse_u64(data)?;
    let code = infishark::ir::IrCode {
        protocol: proto,
        data: value,
        bits,
    };
    let note = dev.ir_tx_capture(&IrCapture::Code(code), repeats)?;
    print_ir_note(note, cli.json);
    print_action(
        serde_json::json!({ "protocol": proto.name(), "data": format!("{value:X}") }),
        format!("Sent {} 0x{value:X}.", proto.name()),
        cli.json,
    )
}

fn cmd_ir_tx_file(
    cli: &Cli,
    dev: &mut Device,
    path: &str,
    button: Option<&str>,
    repeats: u16,
) -> Result<()> {
    let remote = IrRemote::load(path)?;
    let btn = match button {
        Some(k) => remote.find_button(k)?,
        None => pick_ir_button(&remote)?,
    };
    let note = dev.ir_tx_capture(&btn.capture, repeats)?;
    print_ir_note(note, cli.json);
    match &btn.capture {
        IrCapture::Code(code) => print_action(
            serde_json::json!({
                "file": path,
                "button": btn.name,
                "protocol": code.protocol.name(),
                "data": format!("{:X}", code.data),
            }),
            format!(
                "Sent '{}' ({} 0x{:X}).",
                btn.name,
                code.protocol.name(),
                code.data
            ),
            cli.json,
        ),
        IrCapture::Raw(raw) => print_action(
            serde_json::json!({
                "file": path,
                "button": btn.name,
                "khz": raw.khz,
                "count": raw.timings.len(),
            }),
            format!(
                "Sent '{}' (raw {} kHz, {} samples).",
                btn.name,
                raw.khz,
                raw.timings.len()
            ),
            cli.json,
        ),
    }
}

fn pick_ir_button(remote: &IrRemote) -> Result<&infishark::ir_file::IrButton> {
    if remote.buttons.is_empty() {
        bail!("remote has no buttons");
    }
    if remote.buttons.len() == 1 {
        return Ok(&remote.buttons[0]);
    }
    eprintln!("Buttons:");
    for (i, b) in remote.buttons.iter().enumerate() {
        let kind = match &b.capture {
            IrCapture::Code(c) => c.protocol.name(),
            IrCapture::Raw(_) => "raw",
        };
        eprintln!("  {:>3}  {:<16}  ({kind})", i + 1, b.name);
    }
    let line = ui::prompt_line("button # or name")?;
    let key = line.trim();
    if key.is_empty() {
        bail!("no button selected");
    }
    Ok(remote.find_button(key)?)
}

fn cmd_ir_show(cli: &Cli, index: Option<usize>) -> Result<()> {
    let caps = LAST_IR.lock().unwrap().clone();
    if caps.is_empty() {
        if !cli.json {
            println!("no cached captures; run `ir rx` first");
        }
        return Ok(());
    }
    match index {
        None => {
            if cli.json {
                for (i, c) in caps.iter().enumerate() {
                    println!("{}", ir_capture_json(i + 1, c, true));
                }
            } else {
                ui::ir_header(false);
                for (i, c) in caps.iter().enumerate() {
                    ui::ir_row(i + 1, c, false);
                }
            }
        }
        Some(n) if n == 0 || n > caps.len() => {
            anyhow::bail!("capture #{n} out of range (1..{})", caps.len());
        }
        Some(n) => {
            let c = &caps[n - 1];
            if cli.json {
                println!("{}", ir_capture_json(n, c, true));
            } else {
                ui::ir_detail(c);
            }
        }
    }
    Ok(())
}

fn ir_capture_json(n: usize, cap: &IrCapture, with_timings: bool) -> serde_json::Value {
    match cap {
        IrCapture::Code(c) => serde_json::json!({
            "n": n,
            "kind": "code",
            "protocol": c.protocol.name(),
            "data": format!("{:X}", c.data),
            "bits": c.bits,
        }),
        IrCapture::Raw(r) => {
            let mut v = serde_json::json!({
                "n": n,
                "kind": "raw",
                "khz": r.khz,
                "count": r.timings.len(),
            });
            if with_timings {
                v["timings"] = r
                    .timings
                    .iter()
                    .map(|t| serde_json::Value::from(*t))
                    .collect::<Vec<_>>()
                    .into();
            }
            v
        }
    }
}

fn cmd_ir_rx(
    cli: &Cli,
    dev: &mut Device,
    once: bool,
    verbose: bool,
    out: Option<&Path>,
) -> Result<()> {
    use std::time::Duration;

    signals::install_sigint();
    signals::RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    let note = dev.ir_rx_start()?;
    print_ir_note(note, cli.json);
    // Short reads so Ctrl-C is noticed between captures.
    dev.set_read_timeout(Duration::from_millis(300))?;
    if !cli.json {
        eprintln!("Listening for IR... (Ctrl-C to stop)");
        ui::ir_header(verbose);
    }
    let mut caps: Vec<IrCapture> = Vec::new();
    let mut n_code = 0u32;
    let mut n_raw = 0u32;
    while signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
        match dev.next_ir_opt() {
            Ok(None) => continue,
            Ok(Some(cap)) => {
                caps.push(cap.clone());
                let n = caps.len();
                match &cap {
                    IrCapture::Code(_) => n_code += 1,
                    IrCapture::Raw(_) => n_raw += 1,
                }
                if cli.json {
                    println!("{}", ir_capture_json(n, &cap, true));
                } else {
                    ui::ir_row(n, &cap, verbose);
                }
                if once {
                    break;
                }
            }
            // Transport/serial failure: stop listening, keep what we have.
            Err(e) => {
                if !cli.json {
                    eprintln!("warning: IR stream ended ({e:#})");
                }
                break;
            }
        }
    }
    let _ = dev.stop_current_task();
    // Retain for `ir show` even if the stream ended early.
    *LAST_IR.lock().unwrap() = caps.clone();
    if let Some(path) = out {
        let remote = IrRemote::from_captures(&caps);
        std::fs::write(path, remote.to_ir_string())
            .with_context(|| format!("write {}", path.display()))?;
        if !cli.json {
            eprintln!(
                "Wrote {} button(s) to {}.",
                remote.buttons.len(),
                path.display()
            );
        }
    }
    if !cli.json && !once {
        eprintln!("Stopped.  {n_code} code, {n_raw} raw (use `ir show <n>` for detail).");
    }
    Ok(())
}

fn cmd_wifi(cli: &Cli, oui_db: Option<&str>, action: &WifiCmd) -> Result<()> {
    if let WifiCmd::List { verbose } = action {
        let mut nets = LAST_WIFI.lock().unwrap().clone();
        if nets.is_empty() {
            let mut dev = cli.open(cli.timeout_ms.max(15_000))?;
            let sp = ui::Spinner::start("scanning networks");
            let scanned = dev.wifi_scan(&WifiScanOpts::default());
            sp.stop();
            nets = scanned?;
            enrich_wifi(oui_db, &mut nets);
            *LAST_WIFI.lock().unwrap() = nets.clone();
        }
        return print_networks(&nets, cli.json, *verbose);
    }
    if let WifiCmd::Show { target } = action {
        let mut nets = LAST_WIFI.lock().unwrap().clone();
        if nets.is_empty() {
            let mut dev = cli.open(cli.timeout_ms.max(15_000))?;
            let sp = ui::Spinner::start("scanning networks");
            let scanned = dev.wifi_scan(&WifiScanOpts::default());
            sp.stop();
            nets = scanned?;
            enrich_wifi(oui_db, &mut nets);
            *LAST_WIFI.lock().unwrap() = nets.clone();
        }
        let n = recon::resolve_from_cache(&nets, Some(target), None, None)?;
        if cli.json {
            return print_value(&serde_json::to_value(&n)?, true);
        }
        ui::network_detail(&n);
        return Ok(());
    }
    // TUN needs root; fail before opening the device or picking a network.
    if matches!(action, WifiCmd::Adapter { .. }) {
        privs::require_root("wifi adapter")?;
    }
    // Monitor streams indefinitely; give the read loop a long ceiling so a quiet
    // channel doesn't error between frames (Ctrl-C ends it).
    let timeout = match action {
        WifiCmd::Monitor { .. } => cli.timeout_ms.max(3_600_000),
        // A full scan sweeps every channel; wait for the device's SCAN_DONE.
        WifiCmd::Scan { .. } => cli.timeout_ms.max(15_000),
        // Recon dwells on one channel; size the ceiling to the dwell + margin.
        WifiCmd::Recon { seconds, .. } => {
            if *seconds == 0 {
                cli.timeout_ms.max(3_600_000)
            } else {
                cli.timeout_ms.max(seconds * 1000 + 10_000)
            }
        }
        // Interactive add scans first; size the read wait to the scan duration.
        WifiCmd::Saved {
            action:
                SavedCmd::Add {
                    ssid: None,
                    scan_ms,
                    ..
                },
        } => (*scan_ms as u64 + 5_000).max(cli.timeout_ms),
        // The adapter's STA association is async and can take ~20s.
        WifiCmd::Adapter { .. } => cli.timeout_ms.max(30_000),
        // Deauth runs until Ctrl-C; keep the read ceiling high like Monitor.
        WifiCmd::Deauth { .. } => cli.timeout_ms.max(3_600_000),
        // Named tx may scan; multi/continuous burst needs a long read ceiling.
        WifiCmd::Tx { count, .. } if *count != 1 => cli.timeout_ms.max(3_600_000),
        WifiCmd::Tx {
            template: Some(_),
            hex: None,
            ..
        } => cli.timeout_ms.max(15_000),
        // Handshake blocks on next_wifi_frame until crackable/timeout/Ctrl-C.
        WifiCmd::Handshake { .. } => cli.timeout_ms.max(3_600_000),
        // Host-streamed portal waits on phone GETs between serial timeouts.
        WifiCmd::Portal { .. } => cli.timeout_ms.max(3_600_000),
        _ => cli.timeout_ms,
    };
    let mut dev = cli.open(timeout)?;
    match action {
        WifiCmd::Scan {
            active,
            dwell,
            channel,
            no_hidden,
            ssid,
            bssid,
            verbose,
        } => {
            let opts = WifiScanOpts {
                active: *active,
                dwell_ms: *dwell,
                channel: *channel,
                hide_hidden: *no_hidden,
                ssid: ssid.clone(),
                bssid: bssid.clone(),
            };
            let sp = ui::Spinner::start("scanning networks");
            let nets = dev.wifi_scan(&opts);
            sp.stop();
            let mut nets = nets?;
            enrich_wifi(oui_db, &mut nets);
            *LAST_WIFI.lock().unwrap() = nets.clone();
            print_networks(&nets, cli.json, *verbose)
        }
        WifiCmd::List { .. } | WifiCmd::Show { .. } => {
            unreachable!("served from cache before the device opens")
        }
        WifiCmd::Recon {
            target,
            ssid,
            bssid,
            seconds,
        } => {
            // Prefer last scan; otherwise scan. No target/ssid/bssid: interactive picker.
            let mut nets = LAST_WIFI.lock().unwrap().clone();
            let interactive = target.is_none() && ssid.is_none() && bssid.is_none();
            if nets.is_empty() {
                let opts = WifiScanOpts {
                    active: false,
                    dwell_ms: None,
                    channel: None,
                    hide_hidden: false,
                    ssid: ssid.clone(),
                    bssid: bssid.clone(),
                };
                let sp = ui::Spinner::start("scanning networks");
                let scanned = dev.wifi_scan(&opts);
                sp.stop();
                nets = scanned?;
                enrich_wifi(oui_db, &mut nets);
                *LAST_WIFI.lock().unwrap() = nets.clone();
            }
            let net = if interactive {
                if cli.json {
                    bail!("pass a target, --ssid, or --bssid (no interactive picker under --json)");
                }
                ui::pick_network(&nets)?
            } else {
                recon::resolve_from_cache(
                    &nets,
                    target.as_deref(),
                    ssid.as_deref(),
                    bssid.as_deref(),
                )?
            };
            let oui = load_oui(oui_db);
            recon::run(&mut dev, &net, *seconds, oui.as_ref(), cli.json)
        }
        WifiCmd::Saved { action } => cmd_wifi_saved(&mut dev, cli, oui_db, action),
        WifiCmd::Adapter {
            index,
            ssid,
            pass,
            randomize_mac,
            hostname,
            ifname,
            mtu,
            mss,
            route_all,
            no_oled,
        } => {
            warn_if_mesh_active(&mut dev);
            let target = match ssid {
                Some(ssid) => {
                    let pass = match pass {
                        Some(p) => p.clone(),
                        None => ui::prompt_password(ssid)?,
                    };
                    AdapterTarget::Explicit {
                        ssid: ssid.clone(),
                        pass,
                    }
                }
                None => {
                    let index = match index {
                        Some(i) => *i,
                        None => pick_saved_index(&mut dev)?,
                    };
                    AdapterTarget::Saved(index)
                }
            };
            adapter::run(
                dev,
                target,
                AdapterConfig {
                    randomize_mac: *randomize_mac,
                    hostname: hostname.clone(),
                },
                adapter::AdapterOpts {
                    ifname: ifname.clone(),
                    mtu: *mtu,
                    mss: *mss,
                    route_all: *route_all,
                    no_oled: *no_oled,
                },
            )
        }
        WifiCmd::Monitor {
            channel,
            ssid,
            pass,
            index,
            filter,
            r#type,
            subtype,
            ctrl_subtype,
            data_subtype,
            block,
            ethertype,
            bssid,
            min_rssi,
            max_rssi,
            phy,
            min_len,
            max_len,
            dedup,
            encrypted,
            unencrypted,
            r#match,
            vendor,
            src,
            dst,
            out,
        } => {
            let mf = monitor::build_monitor_filter(&monitor::MonitorArgs {
                filter: filter.as_deref(),
                types: r#type,
                subtype,
                ctrl_subtype,
                data_subtype,
                block: *block,
                ethertype: ethertype.as_deref(),
                bssid: bssid.as_deref(),
                min_rssi: *min_rssi,
                max_rssi: *max_rssi,
                phy: phy.as_deref(),
                min_len: *min_len,
                max_len: *max_len,
                dedup: *dedup,
                encrypted: *encrypted,
                unencrypted: *unencrypted,
                matches: r#match,
                vendor: vendor.as_deref(),
                src: src.as_deref(),
                dst: dst.as_deref(),
            })?;
            // Associate can take ~20s; stretch the open timeout for this path.
            if ssid.is_some() || index.is_some() {
                dev.set_read_timeout(std::time::Duration::from_millis(cli.timeout_ms.max(30_000)))?;
            }
            if let Some(i) = index {
                dev.wifi_monitor_start_saved(*channel, &mf, *i)?;
            } else if let Some(s) = ssid {
                let p = pass.as_deref().unwrap_or("");
                dev.wifi_monitor_start(*channel, &mf, Some((s.as_str(), p)))?;
            } else {
                dev.wifi_monitor_start(*channel, &mf, None)?;
            }
            let mut w: Box<dyn Write> = match out {
                Some(f) => Box::new(std::io::BufWriter::new(ui::create_secure(f)?)),
                None => Box::new(std::io::stdout().lock()),
            };
            pcap::write_global_header(&mut w, pcap::LINKTYPE_IEEE802_11_RADIOTAP)?;
            w.flush()?;
            stream_wifi_monitor(&mut dev, &mut w)
        }
        WifiCmd::Tx {
            template,
            hex,
            channel,
            count,
            interval_ms,
            ap,
            bssid,
            ssid,
            sta,
            ra,
            ta,
            reason,
            duration,
            aid,
            tid,
            ssn,
            payload,
        } => {
            let v = tx::run(
                &mut dev,
                &tx::Opts {
                    template: *template,
                    hex: hex.clone(),
                    channel: *channel,
                    count: *count,
                    interval_ms: *interval_ms,
                    ap: ap.clone(),
                    bssid: bssid.clone(),
                    ssid: ssid.clone(),
                    sta: sta.clone(),
                    ra: ra.clone(),
                    ta: ta.clone(),
                    reason: *reason,
                    duration: *duration,
                    aid: *aid,
                    tid: *tid,
                    ssn: *ssn,
                    payload: payload.clone(),
                },
                oui_db,
                cli.json,
            )?;
            let ok = v.get("tx_ok").and_then(|x| x.as_u64()).unwrap_or(0);
            let fail = v.get("tx_fail").and_then(|x| x.as_u64()).unwrap_or(0);
            let total = v.get("total").and_then(|x| x.as_u64());
            let stopped = v.get("stopped").and_then(|x| x.as_bool()).unwrap_or(false);
            let msg = if stopped {
                match total {
                    Some(0) | None => format!("Stopped: sent {ok}, fail {fail}."),
                    Some(t) => format!("Stopped: sent {ok}, fail {fail} (of {t})."),
                }
            } else {
                match total {
                    Some(0) | None => format!("Transmitted {ok} frame(s) (fail {fail})."),
                    Some(t) => format!("Transmitted {ok}/{t} frame(s) (fail {fail})."),
                }
            };
            print_action(v, msg, cli.json)
        }
        WifiCmd::Deauth {
            ssid,
            bssid,
            channel,
            client,
            reason,
            interval_ms,
        } => deauth::run(
            &mut dev,
            &deauth::DeauthOpts {
                ssid: ssid.clone(),
                bssid: bssid.clone(),
                channel: *channel,
                client: client.clone(),
                reason: *reason,
                interval_ms: *interval_ms,
                interactive: !cli.json,
            },
            oui_db,
        ),
        WifiCmd::Handshake {
            ssid,
            bssid,
            channel,
            client,
            reason,
            pmkid_only,
            no_pmkid,
            passive,
            continuous,
            deauth_count,
            deauth_interval,
            solicit_count,
            solicit_interval,
            timeout,
            grace,
            out,
            pcap_only,
            crack,
            wordlist,
        } => handshake::run(
            &mut dev,
            &handshake::HandshakeOpts {
                ssid: ssid.clone(),
                bssid: bssid.clone(),
                channel: *channel,
                client: client.clone(),
                reason: *reason,
                pmkid_only: *pmkid_only,
                no_pmkid: *no_pmkid,
                passive: *passive,
                continuous: *continuous,
                deauth_count: *deauth_count,
                deauth_interval_ms: *deauth_interval,
                solicit_count: *solicit_count,
                solicit_interval_ms: *solicit_interval,
                timeout_s: *timeout,
                grace_s: *grace,
                out: out.clone(),
                pcap_only: *pcap_only,
                crack: *crack,
                wordlist: wordlist.clone(),
                interactive: !cli.json,
            },
            oui_db,
        ),
        WifiCmd::Portal {
            dir,
            ssid,
            pass,
            channel,
            hidden,
            max_clients,
            mac,
            random_mac,
            ip,
            netmask,
            beacon_ms,
            detailed_capture,
            host_timeout_ms,
        } => {
            let opts = PortalOpts {
                host_content: dir.is_some(),
                ssid: ssid.clone(),
                pass: pass.clone(),
                channel: *channel,
                hidden: *hidden,
                max_clients: *max_clients,
                mac: mac.clone(),
                random_mac: *random_mac,
                ip: ip.clone(),
                netmask: netmask.clone(),
                beacon_ms: *beacon_ms,
                detailed_capture: detailed_capture.then_some(true),
                host_timeout_ms: *host_timeout_ms,
            };
            portal::run(dev, dir.clone(), opts)
        }
    }
}

fn cmd_wifi_saved(
    dev: &mut Device,
    cli: &Cli,
    oui_db: Option<&str>,
    action: &SavedCmd,
) -> Result<()> {
    match action {
        SavedCmd::List => {
            let nets = dev.wifi_saved_list()?;
            if cli.json {
                print_items("networks", &nets, true)
            } else {
                ui::saved_networks(&nets);
                Ok(())
            }
        }
        SavedCmd::Add {
            ssid,
            pass,
            scan_ms,
        } => cmd_wifi_add(dev, cli, oui_db, ssid.clone(), pass.clone(), *scan_ms),
        SavedCmd::Rm { index } => {
            let count = dev.wifi_saved_delete(*index)?;
            print_action(
                serde_json::json!({ "ok": true, "count": count }),
                format!("Removed slot {index}; {count} saved network(s) remain."),
                cli.json,
            )
        }
    }
}

fn cmd_wifi_add(
    dev: &mut Device,
    cli: &Cli,
    oui_db: Option<&str>,
    ssid: Option<String>,
    pass: Option<String>,
    scan_ms: u32,
) -> Result<()> {
    if cli.json && (ssid.is_none() || pass.is_none()) {
        bail!("wifi saved add under --json needs --ssid and --pass");
    }
    let ssid = match ssid {
        Some(s) => s,
        None => pick_ssid_interactively(dev, oui_db, scan_ms)?,
    };
    // Prompt is echoed (personal-machine tool); pass --pass to avoid it in scripts.
    let pass = match pass {
        Some(p) => p,
        None => ui::prompt_password(&ssid)?,
    };
    let count = dev.wifi_saved_add(&ssid, &pass)?;
    print_action(
        serde_json::json!({ "ok": true, "ssid": ssid, "count": count }),
        format!("Saved {ssid:?}; {count} network(s) now on the device."),
        cli.json,
    )
}

/// Scan, then pick via the shared Wi-Fi table (`ui::pick_network`)
fn pick_ssid_interactively(dev: &mut Device, oui_db: Option<&str>, scan_ms: u32) -> Result<String> {
    let opts = WifiScanOpts {
        active: true,
        hide_hidden: true,
        ..Default::default()
    };
    let spin_msg = format!("scanning networks (~{}s)", (scan_ms / 1000).max(1));
    let sp = ui::Spinner::start(&spin_msg);
    let nets = dev.wifi_scan(&opts);
    sp.stop();
    let mut nets = nets?;
    nets.retain(|n| !n.ssid.is_empty());
    if nets.is_empty() {
        anyhow::bail!("no networks found (use --ssid for a hidden network)");
    }
    enrich_wifi(oui_db, &mut nets);
    Ok(ui::pick_network(&nets)?.ssid)
}

fn pick_saved_index(dev: &mut Device) -> Result<u8> {
    let saved = dev.wifi_saved_list()?;
    if saved.is_empty() {
        anyhow::bail!("no saved networks on the device; add one with `infishark wifi saved add`");
    }
    let pick = ui::pick_from_list(&saved, "Pick a saved network number: ", |n| {
        format!("[slot {}] {}", n.index, n.ssid)
    })?;
    Ok(pick.index)
}

/// Scan briefly, then pick a BLE peer by number. Returns its address and the
/// address type to connect with (so a random-address peer resolves correctly).
fn pick_ble_target(dev: &mut Device, db: &DbOpts) -> Result<(String, u8)> {
    eprintln!("Scanning for BLE devices (~5s)...");
    let opts = BleScanOpts {
        duration_ms: Some(5000),
        ..Default::default()
    };
    let mut devices = dev.ble_scan(&opts)?;
    enrich_ble(db, &mut devices);
    let pick = ui::pick_ble_device(&devices)?;
    Ok((pick.address.clone(), pick.addr_type.unwrap_or(0)))
}

fn cmd_ble(cli: &Cli, db: &DbOpts, action: &BleCmd) -> Result<()> {
    match action {
        BleCmd::Scan {
            duration,
            phy,
            passive,
            interval,
            window,
            dedup,
        } => {
            let opts = BleScanOpts {
                duration_ms: *duration,
                passive: *passive,
                interval: *interval,
                window: *window,
                dedup: *dedup,
                scan_phy: phy.map(|p| p.mask()),
            };
            // A sighting streams per advert; size the read timeout to the scan duration
            // plus headroom (0 = run until stopped, so fall back to a long idle ceiling).
            let dur = duration.unwrap_or(10_000);
            let timeout = if dur == 0 {
                cli.timeout_ms.max(30_000)
            } else {
                (dur as u64 + 5_000).max(8_000)
            };
            let mut dev = cli.open(timeout)?;
            let sp = ui::Spinner::start("scanning BLE");
            let devices = dev.ble_scan(&opts);
            sp.stop();
            let mut devices = devices?;
            enrich_ble(db, &mut devices);
            *LAST_BLE.lock().unwrap() = devices.clone();
            print_devices(&devices, cli.json)
        }
        BleCmd::List => {
            let mut devices = LAST_BLE.lock().unwrap().clone();
            if devices.is_empty() {
                let opts = BleScanOpts {
                    duration_ms: Some(10_000),
                    ..Default::default()
                };
                let mut dev = cli.open(cli.timeout_ms.max(15_000))?;
                let sp = ui::Spinner::start("scanning BLE");
                let scanned = dev.ble_scan(&opts);
                sp.stop();
                devices = scanned?;
                enrich_ble(db, &mut devices);
                *LAST_BLE.lock().unwrap() = devices.clone();
            }
            print_devices(&devices, cli.json)
        }
        BleCmd::Show { index } => {
            let mut devices = LAST_BLE.lock().unwrap().clone();
            if devices.is_empty() {
                let opts = BleScanOpts {
                    duration_ms: Some(10_000),
                    ..Default::default()
                };
                let mut dev = cli.open(cli.timeout_ms.max(15_000))?;
                let sp = ui::Spinner::start("scanning BLE");
                let scanned = dev.ble_scan(&opts);
                sp.stop();
                devices = scanned?;
                enrich_ble(db, &mut devices);
                *LAST_BLE.lock().unwrap() = devices.clone();
            }
            devices.sort_by_key(|d| std::cmp::Reverse(d.rssi));
            match index {
                Some(i) => {
                    let d = devices
                        .get(*i)
                        .ok_or_else(|| anyhow::anyhow!("no device #{i}; run 'ble scan' first"))?;
                    if cli.json {
                        print_value(&serde_json::to_value(d)?, true)
                    } else {
                        ui::ble_detail(d);
                        Ok(())
                    }
                }
                None => print_devices(&devices, cli.json),
            }
        }
        BleCmd::Gatt { action } => cmd_gatt(cli, db, action),
        BleCmd::Adv {
            raw,
            name,
            mfg,
            service_uuid,
            connectable,
            interval_ms,
            tx,
            ibeacon,
            eddystone_url,
            phy,
            mac,
            random_mac,
            scan_resp,
            duration_ms,
            appearance,
        } => {
            let spec = build_adv_spec(AdvArgs {
                raw,
                name,
                mfg,
                service_uuid,
                connectable: *connectable,
                interval_ms,
                tx,
                ibeacon,
                eddystone_url,
                phy,
                mac,
                random_mac: *random_mac,
                scan_resp,
                duration_ms,
                appearance,
            })?;
            let mut dev = cli.open(cli.timeout_ms)?;
            dev.ble_adv(&spec)?;
            if matches!(phy.as_deref(), Some("coded") | Some("2m")) {
                eprintln!(
                    "note: extended-PHY advertising is invisible to normal scanners; only `ble scan --phy coded` (or 2m) sees it."
                );
            }
            print_action(
                serde_json::json!({ "ok": true }),
                "Advertising. Run `infishark ble stop` to stop.",
                cli.json,
            )
        }
        BleCmd::Serve {
            chars,
            name,
            mac,
            random_mac,
        } => {
            let spec = build_serve_spec(chars, name, mac, *random_mac)?;
            let mut dev = cli.open(cli.timeout_ms.max(3_600_000))?;
            dev.ble_serve(&spec)?;
            eprintln!(
                "Serving. Central activity streams below (NDJSON). Ctrl-C detaches; run `infishark ble stop` to stop the device."
            );
            stream_ndjson(|| dev.next_ble_event().map_err(Into::into))
        }
        BleCmd::Set {
            char,
            value,
            notify,
        } => {
            let spec = char_set_spec(char, value, *notify);
            let mut dev = cli.open(cli.timeout_ms)?;
            dev.ble_char_set(&spec)?;
            print_ok(cli.json)
        }
        BleCmd::Stream { char, interval_ms } => {
            let mut dev = cli.open(cli.timeout_ms)?;
            eprintln!("Streaming stdin -> notify {char}. One hex value per line; Ctrl-D to end.");
            let stdin = std::io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                if stdin.read_line(&mut line)? == 0 {
                    break;
                }
                let hex = line.trim();
                if hex.is_empty() {
                    continue;
                }
                dev.ble_char_set(&char_set_spec(char, hex, true))?;
                if *interval_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(*interval_ms));
                }
            }
            print_ok(cli.json)
        }
        BleCmd::Hid { action } => cmd_hid(cli, action),
        BleCmd::Mitm {
            address,
            addr_type,
            name,
            mac,
            no_spoof,
            no_pair,
            io_cap,
            passkey,
            connect_timeout_ms,
            pcap,
        } => cmd_mitm(
            cli,
            db,
            address,
            *addr_type,
            name,
            mac,
            *no_spoof,
            *no_pair,
            *io_cap,
            *passkey,
            *connect_timeout_ms,
            pcap.as_deref(),
        ),
        BleCmd::Stop => {
            let mut dev = cli.open(cli.timeout_ms)?;
            dev.stop_current_task()?;
            print_ok(cli.json)
        }
        BleCmd::Keepalive { state } => {
            let mut dev = cli.open(cli.timeout_ms)?;
            dev.ble_keepalive(matches!(state, OnOff::On))?;
            print_ok(cli.json)
        }
        BleCmd::Reset => {
            let mut dev = cli.open(cli.timeout_ms)?;
            dev.ble_reset()?;
            print_ok(cli.json)
        }
    }
}

fn cmd_hid(cli: &Cli, action: &HidCmd) -> Result<()> {
    match action {
        HidCmd::Start {
            preset,
            report_map,
            report,
            name,
            appearance,
            pnp,
            passkey,
            mac,
            random_mac,
            watch,
        } => {
            let spec = build_hid_spec(
                *preset,
                report_map,
                report,
                name,
                *appearance,
                pnp,
                *passkey,
                mac,
                *random_mac,
            )?;
            // Bringing up the peripheral can take longer than the default read timeout, so
            // widen it here.
            let timeout = if *watch {
                cli.timeout_ms.max(3_600_000)
            } else {
                cli.timeout_ms.max(8_000)
            };
            let mut dev = cli.open(timeout)?;
            let ident = dev.ble_hid_start(&spec)?;
            if *watch {
                eprintln!("{}", hid_summary(&ident));
                eprintln!("Events stream below (NDJSON). Ctrl-C detaches.");
                stream_ndjson(|| dev.next_ble_event().map_err(Into::into))
            } else {
                let summary = hid_summary(&ident);
                print_action(ident, summary, cli.json)
            }
        }
        HidCmd::Send { id, hex, r#type } => {
            let spec = serde_json::json!({ "id": id, "type": r#type, "hex": hex });
            let mut dev = cli.open(cli.timeout_ms)?;
            dev.ble_hid_send(&spec)?;
            print_ok(cli.json)
        }
        HidCmd::Type { text, delay_ms } => {
            let mut dev = cli.open(cli.timeout_ms)?;
            let text = text.replace("\\n", "\n").replace("\\t", "\t");
            for c in text.chars() {
                let (modifier, usage) = hid::ascii_to_hid(c)
                    .ok_or_else(|| anyhow::anyhow!("cannot type character {c:?}"))?;
                dev.ble_hid_send(&hid::hid_key_report(1, modifier, usage))?;
                std::thread::sleep(std::time::Duration::from_millis(*delay_ms));
                dev.ble_hid_send(&hid::hid_key_report(1, 0, 0))?;
                std::thread::sleep(std::time::Duration::from_millis(*delay_ms));
            }
            print_ok(cli.json)
        }
        HidCmd::Bridge {
            release,
            devices,
            all,
            no_start,
            clone,
        } => {
            // /dev/input grab needs root; fail before opening the Nano.
            if !*clone {
                privs::require_root("ble hid bridge")?;
            }
            let dev = cli.open(cli.timeout_ms.max(15_000))?;
            if *clone {
                return hidraw::run(
                    dev,
                    hidraw::CloneOpts {
                        device: devices.first().cloned(),
                        no_start: *no_start,
                    },
                );
            }
            // The composite HID device depends on which inputs are selected, so
            // the bridge builds and starts it after device selection.
            bridge::run(
                dev,
                bridge::BridgeOpts {
                    release: release.clone(),
                    devices: devices.clone(),
                    all: *all,
                    no_start: *no_start,
                },
            )
        }
    }
}

fn hid_summary(ident: &serde_json::Value) -> String {
    let g = |k: &str| ident.get(k).and_then(|v| v.as_str()).unwrap_or("?");
    let appearance = ident
        .get("appearance")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;
    format!(
        "Advertising HID {} {:?} @ {} ({} pairing). Run `infishark ble hid type`/`send`, or `ble stop`.",
        hid::appearance_label(appearance),
        g("name"),
        g("mac"),
        g("pairing"),
    )
}

type JsonMap = serde_json::Map<String, serde_json::Value>;

/// Insert the shared spoof-MAC fields used by every peripheral spec.
fn insert_mac(m: &mut JsonMap, mac: &Option<String>, random_mac: bool) {
    insert_opt(m, "mac", mac.as_deref());
    infishark::json::insert_flag(m, "random_mac", random_mac, true.into());
}

/// Assemble the HID device spec JSON from a preset or a raw report map.
#[allow(clippy::too_many_arguments)]
fn build_hid_spec(
    preset: Option<HidPreset>,
    report_map: &Option<String>,
    report: &[String],
    name: &Option<String>,
    appearance: Option<u16>,
    pnp: &Option<String>,
    passkey: Option<u32>,
    mac: &Option<String>,
    random_mac: bool,
) -> Result<serde_json::Value> {
    let mut s = JsonMap::new();
    let mut appear = appearance;
    let (raw_map, reports): (String, Vec<serde_json::Value>) = if let Some(p) = preset {
        let (map, reps, ap) = hid::composite(&p.classes());
        appear.get_or_insert(ap);
        (map, reps)
    } else {
        // clap's required ArgGroup guarantees one of preset/report_map is set.
        let map = report_map
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no report source"))?;
        let reps = report
            .iter()
            .map(parse_report_decl)
            .collect::<Result<Vec<_>>>()?;
        (map.clone(), reps)
    };
    s.insert(
        "report_map".into(),
        serde_json::json!(raw_map.replace([' ', '\n'], "")),
    );
    s.insert("reports".into(), serde_json::json!(reports));
    insert_opt(&mut s, "name", name.as_deref());
    insert_opt(&mut s, "appearance", appear);
    if let Some(p) = pnp {
        let f: Vec<&str> = p.split(':').collect();
        if f.len() != 3 {
            anyhow::bail!("--pnp must be VID:PID:VER");
        }
        s.insert(
            "pnp".into(),
            serde_json::json!({
                "vid": parse_u16(f[0])?, "pid": parse_u16(f[1])?, "ver": parse_u16(f[2])?
            }),
        );
    }
    insert_opt(&mut s, "passkey", passkey);
    insert_mac(&mut s, mac, random_mac);
    Ok(serde_json::Value::Object(s))
}

fn parse_report_decl(d: &String) -> Result<serde_json::Value> {
    let f: Vec<&str> = d.split(':').collect();
    if f.len() < 2 {
        anyhow::bail!("bad --report '{d}': expected ID:TYPE[:LEN]");
    }
    let id: u8 = f[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("bad report id '{}'", f[0]))?;
    if !matches!(f[1], "input" | "output" | "feature") {
        anyhow::bail!("bad report type '{}': input|output|feature", f[1]);
    }
    Ok(serde_json::json!({ "id": id, "type": f[1] }))
}

fn parse_u16(s: &str) -> Result<u16> {
    let v = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(h, 16)
    } else {
        s.parse()
    };
    v.map_err(|_| anyhow::anyhow!("bad number '{s}'"))
}

/// CLI-flag bundle for the advertiser spec (keeps the builder arg list sane).
struct AdvArgs<'a> {
    raw: &'a Option<String>,
    name: &'a Option<String>,
    mfg: &'a Option<String>,
    service_uuid: &'a Option<String>,
    connectable: bool,
    interval_ms: &'a Option<u32>,
    tx: &'a Option<i32>,
    ibeacon: &'a Option<String>,
    eddystone_url: &'a Option<String>,
    phy: &'a Option<String>,
    mac: &'a Option<String>,
    random_mac: bool,
    scan_resp: &'a Option<String>,
    duration_ms: &'a Option<u32>,
    appearance: &'a Option<u16>,
}

/// Assemble the advertiser spec JSON from CLI flags.
fn build_adv_spec(a: AdvArgs) -> Result<serde_json::Value> {
    let mut s = JsonMap::new();
    insert_opt(&mut s, "raw", a.raw.as_deref());
    insert_opt(&mut s, "name", a.name.as_deref());
    insert_opt(&mut s, "mfg", a.mfg.as_deref());
    insert_opt(&mut s, "service_uuid", a.service_uuid.as_deref());
    if a.connectable {
        s.insert("connectable".into(), true.into());
    }
    insert_opt(&mut s, "interval_ms", *a.interval_ms);
    insert_opt(&mut s, "tx", *a.tx);
    if let Some(ib) = a.ibeacon {
        let p: Vec<&str> = ib.split(':').collect();
        if p.len() != 3 {
            anyhow::bail!("--ibeacon must be UUID:major:minor");
        }
        let major: u16 = p[1]
            .parse()
            .map_err(|_| anyhow::anyhow!("bad ibeacon major"))?;
        let minor: u16 = p[2]
            .parse()
            .map_err(|_| anyhow::anyhow!("bad ibeacon minor"))?;
        s.insert(
            "ibeacon".into(),
            serde_json::json!({ "uuid": p[0].replace('-', ""), "major": major, "minor": minor }),
        );
    }
    insert_opt(&mut s, "eddystone_url", a.eddystone_url.as_deref());
    insert_opt(&mut s, "phy", a.phy.as_deref());
    insert_mac(&mut s, a.mac, a.random_mac);
    insert_opt(&mut s, "scan_resp", a.scan_resp.as_deref());
    insert_opt(&mut s, "duration_ms", *a.duration_ms);
    insert_opt(&mut s, "appearance", *a.appearance);
    Ok(serde_json::Value::Object(s))
}

/// Assemble the GATT-server spec JSON from repeated `--char
/// SVC/CHAR:props=hex`.
fn build_serve_spec(
    chars: &[String],
    name: &Option<String>,
    mac: &Option<String>,
    random_mac: bool,
) -> Result<serde_json::Value> {
    let mut order: Vec<String> = Vec::new();
    let mut by_svc: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for c in chars {
        let (path, rest) = c
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("bad --char '{c}': expected SVC/CHAR:props[=hex]"))?;
        let (svc, chr) = path
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("bad --char '{c}': expected SVC/CHAR"))?;
        let (props, value) = match rest.split_once('=') {
            Some((p, v)) => (p, Some(v)),
            None => (rest, None),
        };
        let mut cobj = serde_json::Map::new();
        cobj.insert("uuid".into(), serde_json::json!(chr));
        cobj.insert("props".into(), serde_json::json!(props));
        if let Some(v) = value {
            cobj.insert("value".into(), serde_json::json!(v));
        }
        if hex::reserved_sig_service(svc) {
            anyhow::bail!(
                "service UUID {svc} is a Bluetooth SIG reserved service (0x18xx); use a custom UUID such as 1234"
            );
        }
        if !by_svc.contains_key(svc) {
            order.push(svc.to_string());
        }
        by_svc
            .entry(svc.to_string())
            .or_default()
            .push(serde_json::Value::Object(cobj));
    }
    let services: Vec<serde_json::Value> = order
        .iter()
        .map(|svc| serde_json::json!({ "uuid": svc, "chars": by_svc[svc] }))
        .collect();
    let mut spec = JsonMap::new();
    spec.insert("services".into(), serde_json::json!(services));
    let mut adv = JsonMap::new();
    insert_opt(&mut adv, "name", name.as_deref());
    insert_mac(&mut adv, mac, random_mac);
    if !adv.is_empty() {
        spec.insert("adv".into(), serde_json::Value::Object(adv));
    }
    Ok(serde_json::Value::Object(spec))
}

fn warn_if_mesh_active(dev: &mut Device) {
    if let Ok(v) = dev.mesh_status() {
        if v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false) {
            eprintln!(
                "note: mesh is active; it is suspended for the duration of this connection and may reduce link stability"
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_mitm(
    cli: &Cli,
    db: &DbOpts,
    address: &Option<String>,
    addr_type: u8,
    name: &Option<String>,
    mac: &Option<String>,
    no_spoof: bool,
    no_pair: bool,
    io_cap: Option<u8>,
    passkey: Option<u32>,
    connect_timeout_ms: Option<u32>,
    pcap_arg: Option<&str>,
) -> Result<()> {
    let timeout = cli
        .timeout_ms
        .max(connect_timeout_ms.unwrap_or(0) as u64 + 120_000);
    let mut dev = cli.open(timeout)?;
    let (address, addr_type) = match address {
        Some(a) => (a.clone(), addr_type),
        None => pick_ble_target(&mut dev, db)?,
    };
    let mut spec = serde_json::Map::new();
    spec.insert("address".into(), address.clone().into());
    infishark::json::insert_flag(&mut spec, "addr_type", addr_type != 0, addr_type.into());
    insert_opt(&mut spec, "name", name.as_deref());
    if no_spoof {
        spec.insert("spoof".into(), false.into());
    } else if let Some(m) = mac {
        spec.insert("mac".into(), m.clone().into());
    } else {
        spec.insert("mac".into(), address.clone().into());
    }
    if no_pair {
        spec.insert("bond".into(), false.into());
        spec.insert("mitm".into(), false.into());
        spec.insert("sc".into(), false.into());
    }
    insert_opt(&mut spec, "io_cap", io_cap);
    insert_opt(&mut spec, "passkey", passkey);
    insert_opt(&mut spec, "timeout_ms", connect_timeout_ms);
    warn_if_mesh_active(&mut dev);
    let label = LAST_BLE
        .lock()
        .ok()
        .and_then(|devs| {
            devs.iter()
                .find(|d| d.address.eq_ignore_ascii_case(&address))
                .and_then(|d| d.name.clone())
        })
        .filter(|s| !s.is_empty());
    if !cli.json {
        match &label {
            Some(n) => eprintln!("connecting to {n} ({address}, addr-type {addr_type})..."),
            None => eprintln!("connecting to {address} (addr-type {addr_type})..."),
        }
    }
    let ident = dev.ble_mitm_start(&serde_json::Value::Object(spec), |v| {
        if cli.json {
            let _ = writeln!(std::io::stdout(), "{}", v);
        } else {
            print_mitm_event(&v);
        }
    })?;
    if cli.json {
        println!("{}", serde_json::to_string(&ident)?);
    } else {
        let n = ident.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let m = ident.get("mac").and_then(|x| x.as_str()).unwrap_or("?");
        let chars = ident.get("chars").and_then(|x| x.as_u64()).unwrap_or(0);
        eprintln!("cloned {n} {m}  {chars} chars  peer={address}");
        eprintln!("waiting for a central... Ctrl-C stops");
    }

    let pcap_path = pcap_arg.map(|s| {
        if s.is_empty() || s == "AUTO" {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("ble-mitm-{t}.pcap")
        } else {
            s.to_string()
        }
    });
    let mut pcap_out: Option<Box<dyn std::io::Write>> = match pcap_path.as_deref() {
        Some("-") => Some(Box::new(std::io::stdout())),
        Some(path) => {
            let mut f = std::io::BufWriter::new(ui::create_secure(path)?);
            pcap::write_global_header(&mut f, pcap::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR)?;
            f.flush()?;
            if !cli.json {
                eprintln!("writing ATT pcap to {path}");
            }
            Some(Box::new(f))
        }
        None => None,
    };
    if pcap_path.as_deref() == Some("-") {
        if let Some(w) = pcap_out.as_mut() {
            pcap::write_global_header(w, pcap::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR)?;
            w.flush()?;
        }
    }
    let mut pcap_n: u64 = 0;

    crate::signals::install_sigint();
    crate::signals::RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    dev.set_read_timeout(std::time::Duration::from_millis(300))?;
    loop {
        if !crate::signals::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        match dev.next_event() {
            Ok((id, payload)) if id == infishark::protocol::EVT_BLE_MITM => {
                let v: serde_json::Value =
                    serde_json::from_slice(&payload).unwrap_or_else(|_| serde_json::json!({}));
                if let (Some(w), Some(frame)) = (pcap_out.as_mut(), pcap::mitm_event_to_hci(&v)) {
                    pcap::write_record(w, &frame)?;
                    w.flush()?;
                    pcap_n += 1;
                }
                if cli.json {
                    if pcap_path.as_deref() != Some("-") {
                        println!("{}", serde_json::to_string(&v)?);
                    }
                } else {
                    print_mitm_event(&v);
                }
            }
            Ok(_) => {}
            Err(infishark::Error::Timeout) => continue,
            Err(e) => {
                let _ = dev.stop_current_task();
                return Err(e.into());
            }
        }
    }
    let _ = dev.stop_current_task();
    if !cli.json {
        if let Some(path) = pcap_path.as_deref() {
            if path != "-" {
                eprintln!("wrote {pcap_n} ATT PDUs to {path}");
            }
        }
        eprintln!("mitm stopped");
    }
    Ok(())
}

fn print_mitm_event(v: &serde_json::Value) {
    let op = v.get("op").and_then(|x| x.as_str()).unwrap_or("?");
    if op == "status" {
        let step = v.get("step").and_then(|x| x.as_str()).unwrap_or("?");
        let heap = v.get("heap").and_then(|x| x.as_u64());
        let heap_s = heap.map(|h| format!("  heap={h}")).unwrap_or_default();
        if step == "passkey" {
            if let Some(pin) = v.get("pin").and_then(|x| x.as_u64()) {
                let compare = v.get("compare").and_then(|x| x.as_bool()).unwrap_or(false);
                if compare {
                    eprintln!("  confirm this PIN (or type it on the keyboard): {pin:06}");
                } else {
                    eprintln!("  type this PIN on the keyboard: {pin:06}");
                }
                return;
            }
        }
        let msg = match step {
            "connect" => "connecting to peripheral...",
            "connected" => "connected to peripheral",
            "snapshot" => "reading GATT table...",
            "gatts" => "building local GATT server...",
            "reconnect" => "reconnecting to peripheral...",
            "bonded" => "using stored bond (no PIN)",
            "pair" => "waiting for pairing (type the PIN on the keyboard)...",
            "advertise" => "advertising as the clone...",
            "ready" => "ready — waiting for a central",
            other => other,
        };
        eprintln!("  {msg}{heap_s}");
        return;
    }
    let dir = v.get("dir").and_then(|x| x.as_str()).unwrap_or("?");
    let chr = v.get("char").and_then(|x| x.as_str()).unwrap_or("");
    let hex = v.get("hex").and_then(|x| x.as_str()).unwrap_or("");
    let addr = v.get("addr").and_then(|x| x.as_str()).unwrap_or("");
    if !chr.is_empty() {
        eprintln!("{dir:<6} {op:<12} {chr}  {hex}");
    } else if !addr.is_empty() {
        if let Some(r) = v.get("reason").and_then(|x| x.as_i64()) {
            eprintln!("{dir:<6} {op:<12} {addr}  reason={r}");
        } else {
            eprintln!("{dir:<6} {op:<12} {addr}");
        }
    } else {
        eprintln!("{dir:<6} {op}");
    }
}

fn cmd_gatt(cli: &Cli, db: &DbOpts, action: &GattCmd) -> Result<()> {
    // connect/enum can take a few seconds (cold discovery); later ATT ops use
    // the on-device cache and should be fast.
    let base = cli.timeout_ms.max(12_000);
    let timeout = match action {
        GattCmd::Connect {
            connect_timeout_ms, ..
        } => base.max(connect_timeout_ms.unwrap_or(0) as u64 + 3_000),
        GattCmd::Enum => base.max(30_000),
        // A subscription streams indefinitely; wait a long time between values
        // (Ctrl-C ends it).
        GattCmd::Subscribe { .. } => 3_600_000,
        _ => base,
    };
    let mut dev = cli.open(timeout)?;
    match action {
        GattCmd::Connect {
            address,
            addr_type,
            connect_timeout_ms,
            min_interval,
            max_interval,
            latency,
            supervision_timeout,
            secure,
            bond,
            mitm,
            sc,
            io_cap,
            passkey,
        } => {
            let (address, addr_type) = match address {
                Some(a) => (a.clone(), *addr_type),
                None => pick_ble_target(&mut dev, db)?,
            };
            let opts = GattConnectOpts {
                addr_type,
                timeout_ms: *connect_timeout_ms,
                min_interval: *min_interval,
                max_interval: *max_interval,
                latency: *latency,
                supervision_timeout: *supervision_timeout,
                secure: *secure,
                bond: *bond,
                mitm: *mitm,
                sc: *sc,
                io_cap: *io_cap,
                passkey: *passkey,
            };
            warn_if_mesh_active(&mut dev);
            match dev.gatt_connect(&address, &opts) {
                Ok(()) => print_ok(cli.json),
                Err(e) if matches!(addr_type, 0 | 1) => {
                    let alt = if addr_type == 0 { 1 } else { 0 };
                    let mut flipped = opts.clone();
                    flipped.addr_type = alt;
                    match dev.gatt_connect(&address, &flipped) {
                        Ok(()) => {
                            if !cli.json {
                                eprintln!("connected with --addr-type {alt}");
                            }
                            print_ok(cli.json)
                        }
                        Err(_) => {
                            if !cli.json {
                                eprintln!(
                                    "hint: link-layer connect failed before GATT. \
retry {address} with --addr-type {alt}"
                                );
                            }
                            Err(e.into())
                        }
                    }
                }
                Err(e) => Err(e.into()),
            }
        }
        GattCmd::Enum => {
            let services = dev.gatt_enum()?;
            if cli.json {
                print_items("services", &services, true)
            } else {
                ui::gatt_services(&services);
                Ok(())
            }
        }
        GattCmd::Read { uuid } => {
            let bytes = dev.gatt_read(uuid)?;
            if cli.json {
                print_value(&serde_json::json!({ "hex": hex::encode(&bytes) }), true)
            } else {
                println!("{}", hex::encode(&bytes));
                Ok(())
            }
        }
        GattCmd::Write {
            uuid,
            data,
            no_response,
        } => {
            let bytes = hex::decode(data)?;
            dev.gatt_write(uuid, &bytes, !no_response)?;
            print_ok(cli.json)
        }
        GattCmd::Subscribe { uuids, indicate } => {
            for u in uuids {
                dev.gatt_subscribe(u, *indicate)?;
            }
            stream_ndjson(|| dev.next_notification().map_err(Into::into))
        }
        GattCmd::Unsubscribe { uuid } => {
            dev.gatt_unsubscribe(uuid)?;
            print_ok(cli.json)
        }
        GattCmd::Disconnect => {
            dev.gatt_disconnect()?;
            print_ok(cli.json)
        }
    }
}

/// Load a reference database, emitting `note` (not an error) if absent so recon
/// still works without it.
fn load_db<T>(open: impl FnOnce() -> Result<T>, note: &str) -> Option<T> {
    match open() {
        Ok(db) => Some(db),
        Err(_) => {
            eprintln!("{note}");
            None
        }
    }
}

fn load_oui(oui_db: Option<&str>) -> Option<oui::Db> {
    load_db(
        || {
            oui::db_path(oui_db)
                .and_then(|p| oui::Db::load(&p))
                .map_err(Into::into)
        },
        "note: OUI database not installed; run `infishark manage oui update` for vendor names",
    )
}

fn load_company(company_db: Option<&str>) -> Option<company::Db> {
    load_db(
        || {
            company::db_path(company_db)
                .and_then(|p| company::Db::load(&p))
                .map_err(Into::into)
        },
        "note: BLE company database not installed; run `infishark manage company update` for manufacturer names",
    )
}

pub(crate) fn enrich_wifi(oui_db: Option<&str>, nets: &mut [infishark::model::Network]) {
    let oui = load_oui(oui_db);
    for n in nets {
        n.enrich(oui.as_ref());
    }
}

fn enrich_ble(db: &DbOpts, devices: &mut [infishark::model::BleDevice]) {
    let oui = load_oui(db.oui_db.as_deref());
    let company = load_company(db.company_db.as_deref());
    for d in devices {
        d.enrich(oui.as_ref(), company.as_ref());
    }
}

fn print_networks(nets: &[infishark::model::Network], as_json: bool, verbose: bool) -> Result<()> {
    if as_json {
        // Host-only enrichment (posture/flags/summary) stays off the device wire;
        // attach it here for machine consumers of `--json`.
        let summary = wifi_analysis::scan_summary(nets);
        let mut order: Vec<usize> = (0..nets.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(nets[i].rssi));
        let enriched: Vec<serde_json::Value> = order
            .iter()
            .map(|&i| {
                let n = &nets[i];
                let mut v = serde_json::to_value(n).unwrap_or_else(|_| serde_json::json!({}));
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("posture".into(), wifi_analysis::posture(n).as_str().into());
                    let flags = wifi_analysis::risk_flags(n);
                    if !flags.is_empty() {
                        obj.insert("flags".into(), flags.into());
                    }
                }
                v
            })
            .collect();
        let mut body = serde_json::json!({
            "count": nets.len(),
            "networks": enriched,
            "summary": {
                "total": summary.total,
                "open": summary.open,
                "wep": summary.wep,
                "wpa2": summary.wpa2,
                "wpa3": summary.wpa3,
                "enterprise": summary.enterprise,
                "wps": summary.wps,
                "hidden": summary.hidden,
                "by_channel": summary.by_channel,
            },
        });
        if verbose {
            if let Some(obj) = body.as_object_mut() {
                obj.insert(
                    "hidden_correlations".into(),
                    wifi_analysis::hidden_correlations(nets, 8)
                        .iter()
                        .map(|h| {
                            serde_json::json!({
                                "hidden_bssid": h.hidden_bssid,
                                "named_ssid": h.named_ssid,
                                "named_bssid": h.named_bssid,
                                "rssi_delta": h.rssi_delta,
                                "same_channel": h.same_channel,
                            })
                        })
                        .collect(),
                );
            }
        }
        print_value(&body, true)
    } else {
        ui::network_table(nets, verbose);
        Ok(())
    }
}

fn print_devices(devs: &[infishark::model::BleDevice], as_json: bool) -> Result<()> {
    if as_json {
        print_items("devices", devs, true)
    } else {
        ui::ble_table(devs);
        Ok(())
    }
}

fn print_items<T: Serialize>(key: &str, items: &[T], as_json: bool) -> Result<()> {
    let body = serde_json::json!({ "count": items.len(), key: items });
    print_value(&body, as_json)
}

fn char_set_spec(char: &str, value: &str, notify: bool) -> serde_json::Value {
    serde_json::json!({ "char": char, "value": value, "notify": notify })
}

/// Write each item from `next` as one line of NDJSON to stdout, flushed for
/// live pipes, until it errors (connection drop / interrupt).
fn stream_ndjson<T: Serialize>(mut next: impl FnMut() -> Result<T>) -> Result<()> {
    let mut out = std::io::stdout();
    loop {
        let ev = next()?;
        writeln!(out, "{}", serde_json::to_string(&ev)?)?;
        out.flush()?;
    }
}

/// Print a JSON value: compact with `--json`, pretty-printed for humans.
fn print_value(v: &serde_json::Value, as_json: bool) -> Result<()> {
    if as_json {
        println!("{v}");
    } else {
        println!("{}", serde_json::to_string_pretty(v)?);
    }
    Ok(())
}

/// Print the outcome of an action: the JSON object under `--json`, otherwise a
/// human sentence. Keeps success output uniform across every mutating command.
fn print_action(v: serde_json::Value, human: impl std::fmt::Display, as_json: bool) -> Result<()> {
    if as_json {
        println!("{v}");
    } else {
        println!("{human}");
    }
    Ok(())
}

fn print_ok(as_json: bool) -> Result<()> {
    print_action(serde_json::json!({ "ok": true }), "ok", as_json)
}
