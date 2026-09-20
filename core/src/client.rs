//! High-level device facade. Typed client over the framed transport

use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use serialport::SerialPort;

use crate::hex;
use crate::ieee80211;
use crate::ir::{IrCapture, IrCode, RawIr};
use crate::model::{
    AdapterConfig, AdapterTarget, BleDevice, BleScanOpts, GattConnectOpts, GattNotification,
    GattService, Network, SavedNetwork, WifiScanOpts,
};
use crate::protocol;
use crate::serial;
use crate::transport::{Response, Transport};

pub struct Device {
    transport: Transport<Box<dyn SerialPort>>,
    port: String,
}

impl Device {
    /// Open the device's serial port (auto-selected when `port` is `None`).
    /// `timeout_ms` bounds every blocking read including event waits
    pub fn open(port: Option<&str>, timeout_ms: u64) -> Result<Self> {
        let (port, transport) = serial::open_device(port, timeout_ms)?;
        Ok(Self { transport, port })
    }

    /// Path of the serial node this client opened.
    pub fn port(&self) -> &str {
        &self.port
    }

    /// Send a raw opcode + arg bytes and wait for the correlated response.
    pub fn transact(&mut self, opcode: u16, args: &[u8]) -> Result<Response> {
        self.transport.transact(opcode, args)
    }

    /// Block for the next reassembled device event `(id, json)`.
    pub fn next_event(&mut self) -> Result<(u16, Vec<u8>)> {
        self.transport.next_event()
    }

    /// Device identity (serial, firmware, MAC, flash).
    pub fn device_info(&mut self) -> Result<serde_json::Value> {
        self.json_command(protocol::CMD_DEVICE_INFO, b"")
    }

    pub fn firmware_identity(&mut self) -> Result<crate::fw::DeviceFw> {
        crate::fw::DeviceFw::from_info(&self.device_info()?)
    }

    /// Live status (uptime, heap, battery, mesh).
    pub fn system_status(&mut self) -> Result<serde_json::Value> {
        self.json_command(protocol::CMD_SYSTEM_STATUS, b"")
    }

    /// Mesh (Shiver) status, incl. `enabled` and `paused`.
    pub fn mesh_status(&mut self) -> Result<serde_json::Value> {
        self.json_command(protocol::CMD_MESH_STATUS, b"")
    }

    /// Run a Wi-Fi scan, aggregating streamed sightings by BSSID (latest wins).
    pub fn wifi_scan(&mut self, opts: &WifiScanOpts) -> Result<Vec<Network>> {
        if let Some(ch) = opts.channel {
            if ch != 0 {
                ieee80211::channel::require(ch)?;
            }
        }
        let _ = self.stop_current_task();
        let _ = self.transport.drain_events();
        self.command_ok_local(protocol::CMD_WIFI_SCAN, &opts.to_json())?;
        let _ = self.transport.drain_events();
        let mut nets: std::collections::BTreeMap<String, Network> =
            std::collections::BTreeMap::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if Instant::now() >= deadline {
                break;
            }
            match self.transport.next_event() {
                Ok((protocol::EVT_WIFI_DEVICE, payload)) => {
                    if let Ok(n) = serde_json::from_slice::<Network>(&payload) {
                        nets.insert(n.bssid.clone(), n);
                    }
                }
                Ok((protocol::EVT_SCAN_DONE, _)) => break,
                Ok(_) => {}
                Err(Error::Timeout) => continue,
                Err(e) => return Err(e),
            }
        }
        let _ = self.stop_current_task();
        Ok(nets.into_values().collect())
    }

    /// Join `target` (a saved slot or explicit credentials) and switch the
    /// serial link into a SLIP tunnel.
    pub fn wifi_adapter_start(
        &mut self,
        target: AdapterTarget,
        config: &AdapterConfig,
    ) -> Result<serde_json::Value> {
        let mut params = serde_json::Map::new();
        match &target {
            AdapterTarget::Saved(index) => {
                params.insert("index".into(), (*index).into());
            }
            AdapterTarget::Explicit { ssid, pass } => {
                params.insert("ssid".into(), ssid.as_str().into());
                params.insert("pass".into(), pass.as_str().into());
            }
        }
        if config.randomize_mac {
            params.insert("randomize_mac".into(), true.into());
        }
        if let Some(hostname) = &config.hostname {
            params.insert("hostname".into(), hostname.as_str().into());
        }
        self.command_ok_local(
            protocol::CMD_WIFI_ADAPTER,
            &serde_json::Value::Object(params),
        )?;
        let payload = self.wait_for_event(protocol::EVT_ADAPTER_UP)?;
        let v: serde_json::Value = serde_json::from_slice(&payload)?;
        if v.get("up").and_then(|u| u.as_bool()) != Some(true) {
            bail!("adapter failed to associate with {target}");
        }
        Ok(v)
    }

    /// Consume the device and return its raw serial port, for SLIP once the
    /// adapter tunnel is up (see [`Device::wifi_adapter_start`]).
    pub fn into_port(self) -> Box<dyn SerialPort> {
        self.transport.into_stream()
    }

    /// List the device's saved networks (SSIDs only).
    pub fn wifi_saved_list(&mut self) -> Result<Vec<SavedNetwork>> {
        let v = self.json_command(protocol::CMD_WIFI_SAVED_LIST, b"")?;
        parse_array(&v, "networks")
    }

    /// Add or update a saved network. Return the store's new entry count.
    pub fn wifi_saved_add(&mut self, ssid: &str, pass: &str) -> Result<u8> {
        let args = serde_json::json!({ "ssid": ssid, "pass": pass }).to_string();
        let v = self.json_command(protocol::CMD_WIFI_SAVED_ADD, args.as_bytes())?;
        Ok(count_field(&v))
    }

    /// Delete a saved network by slot index. Out: the store's new count.
    pub fn wifi_saved_delete(&mut self, index: u8) -> Result<u8> {
        let args = serde_json::json!({ "index": index }).to_string();
        let v = self.json_command(protocol::CMD_WIFI_SAVED_DELETE, args.as_bytes())?;
        Ok(count_field(&v))
    }

    /// Enter promiscuous capture. When `associate` is `Some((ssid, pass))`, the
    /// device joins that network first and keeps the STA link up (channel
    /// follows the AP). `pass` may be empty for open networks. When `None`,
    /// classic channel-locked sniff (no association). Drain with
    /// [`Device::next_wifi_frame`].
    pub fn wifi_monitor_start(
        &mut self,
        channel: u8,
        filter: &crate::monitor::MonitorFilter,
        associate: Option<(&str, &str)>,
    ) -> Result<()> {
        ieee80211::channel::require(channel)?;
        let mut params = filter.to_json();
        params["channel"] = channel.into();
        if let Some((ssid, pass)) = associate {
            params["ssid"] = ssid.into();
            params["pass"] = pass.into();
        }
        let _ = self.stop_current_task();
        self.command_ok(protocol::CMD_WIFI_RAW_MONITOR, &params)
    }

    /// Like [`wifi_monitor_start`] but join a saved-network slot before
    /// promisc.
    pub fn wifi_monitor_start_saved(
        &mut self,
        channel: u8,
        filter: &crate::monitor::MonitorFilter,
        saved_index: u8,
    ) -> Result<()> {
        ieee80211::channel::require(channel)?;
        let mut params = filter.to_json();
        params["channel"] = channel.into();
        params["index"] = saved_index.into();
        let _ = self.stop_current_task();
        self.command_ok(protocol::CMD_WIFI_RAW_MONITOR, &params)
    }

    /// Block for the next captured 802.11 frame (MAC frame, FCS stripped).
    pub fn next_wifi_frame(&mut self) -> Result<Vec<u8>> {
        self.wait_for_event(protocol::EVT_WIFI_FRAME)
    }

    /// Like `next_wifi_frame`, but returns None on a read timeout so a capture
    /// loop can fire its own TX timers between frames.
    pub fn next_wifi_frame_opt(&mut self) -> Result<Option<Vec<u8>>> {
        match self.wait_for_event(protocol::EVT_WIFI_FRAME) {
            Ok(f) => Ok(Some(f)),
            Err(Error::Timeout) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Set the serial read timeout that bounds each blocking read. A capture
    /// loop uses a short timeout to interleave frame reads with its TX timers.
    pub fn set_read_timeout(&mut self, timeout: std::time::Duration) -> Result<()> {
        self.transport.stream_mut().set_timeout(timeout)?;
        Ok(())
    }

    /// Inject one raw 802.11 MAC frame (no FCS) on `channel` (0 = leave
    /// current).
    pub fn wifi_raw_tx(&mut self, frame: &[u8], channel: u8) -> Result<bool> {
        let (ok, fail) = self.wifi_raw_tx_burst(frame, channel, 1, 0)?;
        Ok(ok >= 1 && fail == 0)
    }

    /// On-device burst. `count` 0 = until stop.
    pub fn wifi_raw_tx_burst(
        &mut self,
        frame: &[u8],
        channel: u8,
        count: u16,
        interval_ms: u16,
    ) -> Result<(u32, u32)> {
        ieee80211::channel::require_tx(channel)?;
        if frame.is_empty() {
            return Err(Error::msg("empty 802.11 frame"));
        }
        if 5 + frame.len() > protocol::MAX_PAYLOAD {
            return Err(Error::msg(format!(
                "802.11 frame too long ({} bytes, max {})",
                frame.len(),
                protocol::MAX_PAYLOAD - 5
            )));
        }
        let mut args = Vec::with_capacity(5 + frame.len());
        args.push(channel);
        args.extend_from_slice(&count.to_le_bytes());
        args.extend_from_slice(&interval_ms.to_le_bytes());
        args.extend_from_slice(frame);
        let v = self.json_command(protocol::CMD_WIFI_RAW_TX, &args)?;
        if count == 1 && interval_ms == 0 {
            let ok = v.get("tx_ok").and_then(|x| x.as_bool()).unwrap_or(false);
            return Ok(if ok { (1, 0) } else { (0, 1) });
        }
        Ok((0, 0))
    }

    /// Next EVT_WIFI_TX: (sent, fail, total, done). total 0 = until-stop mode.
    pub fn wait_wifi_tx(&mut self) -> Result<(u32, u32, u16, bool)> {
        let body = self.wait_for_event(protocol::EVT_WIFI_TX)?;
        let ev: serde_json::Value = serde_json::from_slice(&body)?;
        if ev.get("sent").is_none() && ev.get("fail").is_none() && ev.get("done").is_none() {
            return Err(Error::msg("EVT_WIFI_TX missing fields"));
        }
        let sent = ev.get("sent").and_then(|s| s.as_u64()).unwrap_or(0) as u32;
        let fail = ev.get("fail").and_then(|s| s.as_u64()).unwrap_or(0) as u32;
        let total = ev.get("total").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
        let done = ev.get("done").and_then(|d| d.as_bool()).unwrap_or(false);
        Ok((sent, fail, total, done))
    }

    /// Transmit a decoded IR code. `repeats` 0 uses the protocol's minimum.
    /// Returns a note when the device stopped a conflicting IR receive session.
    pub fn ir_tx(&mut self, code: &IrCode, repeats: u16) -> Result<Option<String>> {
        let params = serde_json::json!({
            "protocol": code.protocol.id(),
            "data": format!("{:X}", code.data),
            "bits": code.bits,
            "repeats": repeats,
        });
        self.command_ok_local_note(protocol::CMD_IR_TX, &params)
    }

    /// Transmit raw IR carrier timings.
    /// Returns a note when the device stopped a conflicting IR receive session.
    pub fn ir_raw_tx(&mut self, raw: &RawIr) -> Result<Option<String>> {
        let params = serde_json::json!({ "khz": raw.khz, "timings": raw.timings });
        self.command_ok_local_note(protocol::CMD_IR_RAW_TX, &params)
    }

    /// Transmit an [`IrCapture`] (code or raw).
    pub fn ir_tx_capture(&mut self, cap: &IrCapture, repeats: u16) -> Result<Option<String>> {
        match cap {
            IrCapture::Code(c) => self.ir_tx(c, repeats),
            IrCapture::Raw(r) => self.ir_raw_tx(r),
        }
    }

    /// Blast the TV-B-Gone power-off sweep.
    /// Returns a note when the device stopped a conflicting IR receive session.
    pub fn ir_tvbgone(&mut self) -> Result<Option<String>> {
        self.command_ok_local_note(protocol::CMD_IR_TVBGONE, &serde_json::json!({}))
    }

    /// Start the device IR receiver; drain captures with [`Device::next_ir`].
    /// Returns a note when the device stopped TV-B-Gone (or other IR LED work).
    pub fn ir_rx_start(&mut self) -> Result<Option<String>> {
        self.command_ok_local_note(protocol::CMD_IR_RX, &serde_json::json!({}))
    }

    /// Block for the next usable IR capture (skips noise / unmapped protocols).
    pub fn next_ir(&mut self) -> Result<IrCapture> {
        loop {
            if let Some(c) = self.next_ir_opt()? {
                return Ok(c);
            }
        }
    }

    /// Next usable IR capture, or None on a read timeout. Skippable noise does
    /// not surface as an error; the wait continues until timeout or a keep.
    pub fn next_ir_opt(&mut self) -> Result<Option<IrCapture>> {
        loop {
            match self.wait_for_event(protocol::EVT_IR) {
                Ok(payload) => {
                    let v: serde_json::Value = serde_json::from_slice(&payload)?;
                    match IrCapture::from_event_json(&v)? {
                        Some(c) => return Ok(Some(c)),
                        None => continue,
                    }
                }
                Err(Error::Timeout) => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Start the IR receiver, wait for one capture, then stop listening.
    pub fn ir_rx(&mut self) -> Result<IrCapture> {
        let _ = self.ir_rx_start()?;
        let hit = self.next_ir();
        let _ = self.stop_current_task();
        hit
    }

    /// List host-visible device files plus flash-storage usage (`{spiffs,
    /// files}`).
    pub fn file_list(&mut self) -> Result<serde_json::Value> {
        self.json_command(protocol::CMD_FILES_LIST, b"")
    }

    /// Delete a file (only files the device marks deletable).
    pub fn file_delete(&mut self, path: &str) -> Result<()> {
        let path = canonical_device_path(path);
        let args = serde_json::json!({ "path": path }).to_string();
        match self.json_command(protocol::CMD_FILES_DELETE, args.as_bytes()) {
            Ok(_) => Ok(()),
            Err(e) => Err(self.explain_file_error("delete", &path, e)),
        }
    }

    /// Read a whole file, paging chunks until the device signals the end.
    pub fn file_read(&mut self, path: &str) -> Result<Vec<u8>> {
        let path = canonical_device_path(path);
        // Device flash is small; cap the read so a bogus `total` can't drive host OOM.
        const MAX_FILE: usize = 8 * 1024 * 1024;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let args = serde_json::json!({ "path": path, "offset": out.len() }).to_string();
            let (hdr, data) =
                self.transact_chunk_retry(protocol::CMD_FILES_READ_CHUNK, args.as_bytes())?;
            if hdr.error != protocol::ERR_OK {
                let err = Error::Device {
                    code: hdr.error,
                    message: String::from_utf8_lossy(&data).into_owned(),
                };
                return Err(self.explain_file_error("read", &path, err));
            }
            // Each chunk leads with an 8-byte offset/total header.
            if data.len() < 8 {
                bail!("short file chunk");
            }
            let total = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
            if total > MAX_FILE {
                bail!("device reports file size {total} over the {MAX_FILE}-byte limit");
            }
            out.extend_from_slice(&data[8..]);
            if !hdr.has_more() || out.len() >= total {
                break;
            }
        }
        Ok(out)
    }

    /// Upload bytes to a device file
    pub fn file_write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let path = canonical_device_path(path);
        if path.is_empty() || path.len() > 47 {
            bail!("device path must be 1..=47 bytes (got {})", path.len());
        }
        const WRITE_CHUNK: usize = 384;
        let mut offset = 0usize;
        loop {
            let end = (offset + WRITE_CHUNK).min(data.len());
            let chunk = &data[offset..end];
            let mut args = Vec::with_capacity(5 + path.len() + chunk.len());
            args.push(path.len() as u8);
            args.extend_from_slice(path.as_bytes());
            args.extend_from_slice(&(offset as u32).to_le_bytes());
            args.extend_from_slice(chunk);
            let resp = self.transact_retry(protocol::CMD_FILES_WRITE, &args)?;
            if let Err(e) = check(&resp) {
                return Err(self.explain_file_error("write", &path, e));
            }
            offset = end;
            if offset >= data.len() {
                break;
            }
        }
        Ok(())
    }

    /// Run a BLE scan, aggregating streamed sightings by address. Identity
    /// sticks across reports
    pub fn ble_scan(&mut self, opts: &BleScanOpts) -> Result<Vec<BleDevice>> {
        let _ = self.stop_current_task();
        let result = self.collect_ble_sightings(opts);
        let _ = self.stop_current_task();
        result
    }

    fn collect_ble_sightings(&mut self, opts: &BleScanOpts) -> Result<Vec<BleDevice>> {
        self.command_ok_local(protocol::CMD_BLE_SCAN, &opts.to_json())?;
        let mut devices: std::collections::BTreeMap<String, BleDevice> =
            std::collections::BTreeMap::new();
        let dwell_ms = opts.duration_ms.unwrap_or(10_000) as u64;
        let deadline = Instant::now() + Duration::from_millis(dwell_ms.saturating_add(5_000));
        loop {
            if Instant::now() >= deadline {
                break;
            }
            match self.transport.next_event() {
                Ok((protocol::EVT_BLE_DEVICE, payload)) => {
                    if let Ok(d) = serde_json::from_slice::<BleDevice>(&payload) {
                        devices
                            .entry(d.address.clone())
                            .and_modify(|e| e.merge_from(&d))
                            .or_insert(d);
                    }
                }
                Ok((protocol::EVT_SCAN_DONE, _)) => break,
                Ok(_) => {}
                Err(Error::Timeout) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(devices.into_values().collect())
    }

    /// Fetch the device's retained BLE snapshot (unenriched).
    pub fn ble_list(&mut self) -> Result<Vec<BleDevice>> {
        let v = self.json_command(protocol::CMD_BLE_LIST, b"")?;
        parse_array(&v, "devices")
    }

    /// Pin the device's BLE stack up (or release it) across a workflow, so
    /// rapid scan/connect cycling reuses one init instead of re-initing.
    pub fn ble_keepalive(&mut self, on: bool) -> Result<()> {
        self.command_ok(
            protocol::CMD_BLE_KEEPALIVE,
            &serde_json::json!({ "enabled": on }),
        )
    }

    /// Force a clean BLE stack reset on the device
    pub fn ble_reset(&mut self) -> Result<()> {
        self.json_command(protocol::CMD_BLE_RESET, b"").map(|_| ())
    }

    /// Start the custom advertiser (broadcast). spec is the adv JSON
    pub fn ble_adv(&mut self, spec: &serde_json::Value) -> Result<()> {
        self.command_ok(protocol::CMD_BLE_ADV, spec)
    }

    /// Start a connectable GATT server from a table spec.
    pub fn ble_serve(&mut self, spec: &serde_json::Value) -> Result<()> {
        reject_reserved_serve_uuids(spec)?;
        self.command_ok(protocol::CMD_BLE_SERVE, spec)
    }

    /// Update a served characteristic's value (+ optional notify to
    /// subscribers).
    pub fn ble_char_set(&mut self, spec: &serde_json::Value) -> Result<()> {
        self.command_ok(protocol::CMD_BLE_CHAR_SET, spec)
    }

    /// Start a generic HID peripheral from a host-supplied report map +
    /// reports. Out: the device's resolved identity (name, mac,
    /// appearance, ...).
    pub fn ble_hid_start(&mut self, spec: &serde_json::Value) -> Result<serde_json::Value> {
        self.json_command(protocol::CMD_BLE_HID, spec.to_string().as_bytes())
    }

    /// Push an input report (notify) or set a feature report on the HID device.
    pub fn ble_hid_send(&mut self, spec: &serde_json::Value) -> Result<()> {
        self.command_ok(protocol::CMD_BLE_HID_SEND, spec)
    }

    /// Dual-link GATT proxy: connect to `spec.address`, clone its table, advertise.
    /// Out: cloned identity (`name`, `mac`, `peer`, `chars`). Progress and ATT
    /// traffic arrive as [`protocol::EVT_BLE_MITM`]; `on_event` is called for
    /// progress frames that arrive before the command completes.
    pub fn ble_mitm_start(
        &mut self,
        spec: &serde_json::Value,
        mut on_event: impl FnMut(serde_json::Value),
    ) -> Result<serde_json::Value> {
        let args = spec.to_string();
        let resp = self.transport.transact_with_events(
            protocol::CMD_BLE_MITM,
            args.as_bytes(),
            |id, payload| {
                if id == protocol::EVT_BLE_MITM {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
                        on_event(v);
                    }
                }
            },
        )?;
        check(&resp)?;
        if resp.body.is_empty() {
            return Ok(serde_json::json!({}));
        }
        Ok(serde_json::from_slice(&resp.body)?)
    }

    /// Block for the next peripheral event (a central write/connect/subscribe),
    /// returning its JSON tagged with an `event` field.
    pub fn next_ble_event(&mut self) -> Result<serde_json::Value> {
        loop {
            let (id, payload) = self.transport.next_event()?;
            let kind = match id {
                protocol::EVT_BLE_WRITE => "write",
                protocol::EVT_BLE_CONNECT => "connect",
                protocol::EVT_BLE_SUBSCRIBE => "subscribe",
                protocol::EVT_BLE_HID_OUTPUT => "hid_output",
                protocol::EVT_BLE_MITM => "mitm",
                _ => continue,
            };
            let mut v: serde_json::Value =
                serde_json::from_slice(&payload).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("event".into(), serde_json::json!(kind));
            }
            return Ok(v);
        }
    }

    /// Connect to a peripheral as a GATT central. Holds the BLE radio until
    /// [`Device::gatt_disconnect`].
    pub fn gatt_connect(&mut self, address: &str, opts: &GattConnectOpts) -> Result<()> {
        let args = opts.to_json(address);
        let mut last = Error::msg("gatt connect failed");
        for attempt in 0..4u32 {
            match self.command_ok(protocol::CMD_BLE_GATT_CONNECT, &args) {
                Ok(()) => return Ok(()),
                Err(e) if gatt_connect_retryable(&e) && attempt < 3 => {
                    let _ = self.stop_current_task();
                    std::thread::sleep(Duration::from_millis(200 * (attempt as u64 + 1)));
                    last = e;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }

    /// Discover and return the service/characteristic tree of the connected
    /// peer.
    pub fn gatt_enum(&mut self) -> Result<Vec<GattService>> {
        let v = self.json_command(protocol::CMD_BLE_GATT_ENUM, b"")?;
        parse_array(&v, "services")
    }

    /// Read a characteristic value by UUID.
    pub fn gatt_read(&mut self, char_uuid: &str) -> Result<Vec<u8>> {
        let uuid = hex::bluetooth_uuid(char_uuid)?;
        let args = serde_json::json!({ "char": uuid }).to_string();
        let v = self.json_command(protocol::CMD_BLE_GATT_READ, args.as_bytes())?;
        let h = v.get("hex").and_then(|x| x.as_str()).unwrap_or("");
        hex::decode(h)
    }

    /// Write bytes to a characteristic by UUID.
    pub fn gatt_write(&mut self, char_uuid: &str, data: &[u8], with_response: bool) -> Result<()> {
        let uuid = hex::bluetooth_uuid(char_uuid)?;
        self.command_ok(
            protocol::CMD_BLE_GATT_WRITE,
            &serde_json::json!({
                "char": uuid,
                "data": hex::encode(data),
                "response": with_response,
            }),
        )
    }

    /// Enable notifications (or indications) on a characteristic.
    pub fn gatt_subscribe(&mut self, char_uuid: &str, indicate: bool) -> Result<()> {
        let uuid = hex::bluetooth_uuid(char_uuid)?;
        self.command_ok(
            protocol::CMD_BLE_GATT_SUBSCRIBE,
            &serde_json::json!({ "char": uuid, "indicate": indicate }),
        )
    }

    /// Stop notifications/indications on a characteristic.
    pub fn gatt_unsubscribe(&mut self, char_uuid: &str) -> Result<()> {
        let uuid = hex::bluetooth_uuid(char_uuid)?;
        self.command_ok(
            protocol::CMD_BLE_GATT_UNSUBSCRIBE,
            &serde_json::json!({ "char": uuid }),
        )
    }

    /// Block for the next notification/indication from any subscription. The
    /// wait is bounded by this device's open timeout.
    pub fn next_notification(&mut self) -> Result<GattNotification> {
        let payload = self.wait_for_event(protocol::EVT_BLE_NOTIFY)?;
        Ok(serde_json::from_slice(&payload)?)
    }

    /// Drop the GATT session.
    pub fn gatt_disconnect(&mut self) -> Result<()> {
        self.stop_current_task()
    }

    pub fn stop_current_task(&mut self) -> Result<()> {
        self.command_ok_local(protocol::CMD_STOP, &serde_json::json!({}))
    }

    /// Start the captive portal with SoftAP / content options. Returns the
    /// device's effective AP identity (`ssid`, `mac`, `channel`, `ip`, etc).
    /// When `opts.host_content` is true, bodies are streamed from the host via
    /// [`Device::portal_resp_chunk`] after each
    /// [`protocol::EVT_PORTAL_REQUEST`].
    pub fn wifi_portal_start(
        &mut self,
        opts: &crate::model::PortalOpts,
    ) -> Result<serde_json::Value> {
        self.json_command(protocol::CMD_WIFI_PORTAL, &local_args(&opts.to_json()))
    }

    /// One body chunk for an outstanding portal request (see device
    /// `CMD_PORTAL_RESP`). `offset == 0` carries HTTP status + content-type;
    /// later chunks use `offset == bytes already sent`. `total` is
    /// Content-Length.
    pub fn portal_resp_chunk(
        &mut self,
        req_id: u16,
        offset: u32,
        total: u32,
        status: u16,
        content_type: &str,
        data: &[u8],
    ) -> Result<()> {
        let ct = content_type.as_bytes();
        let ct_len = ct.len().min(255);
        // opcode is outside args; args must fit protocol::MAX_PAYLOAD - 2.
        const HEAD: usize = 2 + 4 + 4 + 2 + 1; // id, off, total, status, ctype_len
        if HEAD + ct_len + data.len() > protocol::MAX_PAYLOAD - 2 {
            bail!(
                "portal chunk too large ({} bytes data; max {})",
                data.len(),
                protocol::MAX_PAYLOAD - 2 - HEAD - ct_len
            );
        }
        let mut args = Vec::with_capacity(HEAD + ct_len + data.len());
        args.extend_from_slice(&req_id.to_le_bytes());
        args.extend_from_slice(&offset.to_le_bytes());
        args.extend_from_slice(&total.to_le_bytes());
        args.extend_from_slice(&status.to_le_bytes());
        args.push(ct_len as u8);
        args.extend_from_slice(&ct[..ct_len]);
        args.extend_from_slice(data);
        let resp = self.transport.transact(protocol::CMD_PORTAL_RESP, &args)?;
        check(&resp)
    }

    /// Stream a whole response body as sequential [`portal_resp_chunk`]s.
    pub fn portal_resp_body(
        &mut self,
        req_id: u16,
        status: u16,
        content_type: &str,
        body: &[u8],
    ) -> Result<()> {
        const DATA_MAX: usize = 384;
        let total = body.len() as u32;
        if body.is_empty() {
            return self.portal_resp_chunk(req_id, 0, 0, status, content_type, &[]);
        }
        let mut offset = 0u32;
        while (offset as usize) < body.len() {
            let end = ((offset as usize) + DATA_MAX).min(body.len());
            let chunk = &body[offset as usize..end];
            // ctype only needs to be correct on the first chunk; later ones
            // send empty ctype to save payload space.
            let ct = if offset == 0 { content_type } else { "" };
            let st = if offset == 0 { status } else { 0 };
            self.portal_resp_chunk(req_id, offset, total, st, ct, chunk)?;
            offset = end as u32;
        }
        Ok(())
    }

    /// Send a JSON command whose only reply is success/error (no body used).
    fn command_ok(&mut self, opcode: u16, spec: &serde_json::Value) -> Result<()> {
        let resp = self.transact_retry(opcode, spec.to_string().as_bytes())?;
        check(&resp)
    }

    /// `command_ok` for a scopable command: wraps `params` with the local scope
    /// prefix.
    fn command_ok_local(&mut self, opcode: u16, params: &serde_json::Value) -> Result<()> {
        let resp = self.transact_retry(opcode, &local_args(params))?;
        check(&resp)
    }

    /// Like `command_ok_local`, but returns an optional `note` string from a
    /// JSON body (used when IR RX/TX preempt each other).
    fn command_ok_local_note(
        &mut self,
        opcode: u16,
        params: &serde_json::Value,
    ) -> Result<Option<String>> {
        let resp = self.transact_retry(opcode, &local_args(params))?;
        check(&resp)?;
        if resp.body.is_empty() {
            return Ok(None);
        }
        let v: serde_json::Value = serde_json::from_slice(&resp.body)?;
        Ok(v.get("note")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()))
    }

    fn transact_retry(&mut self, opcode: u16, args: &[u8]) -> Result<Response> {
        let mut delay_ms = 50u64;
        let mut last = None;
        for _ in 0..4 {
            let resp = self.transport.transact(opcode, args)?;
            if resp.error != protocol::ERR_BUSY {
                return Ok(resp);
            }
            last = Some(resp);
            std::thread::sleep(Duration::from_millis(delay_ms));
            delay_ms = (delay_ms * 2).min(400);
        }
        Ok(last.expect("BUSY retry left a response"))
    }

    fn transact_chunk_retry(
        &mut self,
        opcode: u16,
        args: &[u8],
    ) -> Result<(crate::response::ResponseHeader, Vec<u8>)> {
        let mut delay_ms = 50u64;
        for _ in 0..4 {
            let (hdr, data) = self.transport.transact_chunk(opcode, args)?;
            if hdr.error != protocol::ERR_BUSY {
                return Ok((hdr, data));
            }
            std::thread::sleep(Duration::from_millis(delay_ms));
            delay_ms = (delay_ms * 2).min(400);
        }
        self.transport.transact_chunk(opcode, args)
    }

    fn explain_file_error(&mut self, op: &str, path: &str, err: Error) -> Error {
        let Ok(list) = self.file_list() else {
            return err;
        };
        let files = list
            .get("files")
            .and_then(|f| f.as_array())
            .cloned()
            .unwrap_or_default();
        let matches_path = |f: &serde_json::Value| {
            f.get("path").and_then(|p| p.as_str()).is_some_and(|p| {
                p == path || p.trim_start_matches('/') == path.trim_start_matches('/')
            })
        };
        if !files.iter().any(matches_path) {
            if op == "write" {
                let writable: Vec<String> = files
                    .iter()
                    .filter(|f| f.get("write").and_then(|w| w.as_bool()) == Some(true))
                    .filter_map(|f| f.get("path").and_then(|p| p.as_str()).map(str::to_string))
                    .collect();
                return Error::msg(format!(
                    "{path} is not a writable device path (aliases: remote1-5, ducky). writable: {}",
                    if writable.is_empty() {
                        "(none)".into()
                    } else {
                        writable.join(", ")
                    }
                ));
            }
            return Error::msg(format!("no such file {path}"));
        }
        err
    }

    /// Block (bounded by the open timeout) until an event with id `want`
    /// arrives, returning its payload.
    fn wait_for_event(&mut self, want: u16) -> Result<Vec<u8>> {
        loop {
            let (id, payload) = self.transport.next_event()?;
            if id == want {
                return Ok(payload);
            }
        }
    }

    fn json_command(&mut self, opcode: u16, args: &[u8]) -> Result<serde_json::Value> {
        let resp = self.transact_retry(opcode, args)?;
        check(&resp)?;
        if resp.body.is_empty() {
            return Ok(serde_json::json!({}));
        }
        Ok(serde_json::from_slice(&resp.body)?)
    }
}

fn canonical_device_path(path: &str) -> String {
    let p = path.trim();
    if p.is_empty() {
        return String::new();
    }
    if p.starts_with('/') {
        return p.to_string();
    }
    if is_device_alias(p) {
        return p.to_string();
    }
    format!("/{p}")
}

fn is_device_alias(p: &str) -> bool {
    matches!(
        p,
        "ducky" | "remote1" | "remote2" | "remote3" | "remote4" | "remote5"
    )
}

fn reject_reserved_serve_uuids(spec: &serde_json::Value) -> Result<()> {
    let Some(svcs) = spec.get("services").and_then(|s| s.as_array()) else {
        return Ok(());
    };
    for svc in svcs {
        if let Some(u) = svc.get("uuid").and_then(|x| x.as_str()) {
            if hex::reserved_sig_service(u) {
                bail!(
                    "service UUID {u} is a Bluetooth SIG reserved service (0x18xx); use a custom UUID such as 1234"
                );
            }
        }
    }
    Ok(())
}

fn gatt_connect_retryable(e: &Error) -> bool {
    match e {
        Error::Timeout => true,
        Error::Device { code, message } => {
            *code == protocol::ERR_BUSY
                || *code == protocol::ERR_INTERNAL
                || message.contains("connect failed")
        }
        _ => false,
    }
}

/// Frame a scopable command's payload for local execution.
fn local_args(params: &serde_json::Value) -> Vec<u8> {
    let mut v = vec![protocol::SCOPE_LOCAL];
    if params.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        v.extend_from_slice(params.to_string().as_bytes());
    }
    v
}

fn check(resp: &Response) -> Result<()> {
    if !resp.is_ok() {
        return Err(Error::Device {
            code: resp.error,
            message: resp.json().into_owned(),
        });
    }
    Ok(())
}

/// Read the `count` field from a mutation reply, defaulting to 0.
fn count_field(v: &serde_json::Value) -> u8 {
    v.get("count").and_then(|c| c.as_u64()).unwrap_or(0) as u8
}

fn parse_array<T: serde::de::DeserializeOwned>(v: &serde_json::Value, key: &str) -> Result<Vec<T>> {
    let Some(arr) = v.get(key).and_then(|a| a.as_array()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(serde_json::from_value(item.clone())?);
    }
    Ok(out)
}
