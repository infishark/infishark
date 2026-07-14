//! InfiShark device SDK: framed transport, a typed [`Device`] client.
//! Talk to a device with a few lines:
//!
//! ```no_run
//! let mut dev = infishark::Device::open(None, 12_000)?;
//! for d in dev.ble_scan(&infishark::BleScanOpts::default())? {
//!     println!("{} {}", d.address, d.rssi);
//! }
//! # Ok::<(), infishark::Error>(())
//! ```

#[macro_use]
mod error;

pub mod client;
pub mod company;
pub(crate) mod crc;
pub(crate) mod demux;
pub(crate) mod frame;
pub mod handshake;
pub mod hex;
pub mod ieee80211;
pub mod ir;
pub mod ir_file;
pub mod json;
pub mod model;
pub mod monitor;
pub mod oui;
pub mod paths;
pub mod pcap;
pub mod protocol;
mod registry;
pub(crate) mod response;
pub mod serial;
pub(crate) mod transport;

pub use client::Device;
pub use error::{Context, Error, Result};
pub use transport::Response;
pub use handshake::Handshake;
pub use ieee80211::{Akm, Cipher};
pub use ir::{IrCapture, IrCode, Protocol, RawIr};
pub use ir_file::{IrButton, IrRemote};
pub use model::{
    AdapterConfig, AdapterTarget, BleDevice, BleScanOpts, GattChar, GattConnectOpts,
    GattNotification, GattService, Network, PortalOpts, SavedNetwork, WifiScanOpts,
};
pub use monitor::MonitorFilter;
