//! Request/response transport over any byte stream

use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::sync::OnceLock;

use crate::error::{Error, Result};

use crate::demux::{Demuxer, Event};
use crate::frame::{self, Frame};
use crate::protocol::{ERR_OK, PKT_ERROR, PKT_EVENT, PKT_RESPONSE, RESP_MORE};
use crate::response::{ResponseHeader, parse_response_header};

fn debug_serial() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("ISHARK_DEBUG_SERIAL").is_some())
}

/// reassembled device response (the data after the 4-byte response header)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub cmd: u16,
    pub error: u8,
    pub body: Vec<u8>,
}

impl Response {
    pub fn is_ok(&self) -> bool {
        self.error == ERR_OK
    }
    pub fn json(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

// A stuck stream must not grow without bound.
const MAX_REASSEMBLY: usize = 4 * 1024 * 1024;
const MAX_BUFFERED_EVENTS: usize = 1024;

pub struct Transport<S> {
    stream: S,
    demux: Demuxer,
    seq: u16,
    events: Vec<Frame>,
    inbox: VecDeque<Frame>,
    ev_acc: Vec<u8>,
    ev_id: Option<u16>,
}

impl<S: Read + Write> Transport<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            demux: Demuxer::new(),
            seq: 0,
            events: Vec::new(),
            inbox: VecDeque::new(),
            ev_acc: Vec::new(),
            ev_id: None,
        }
    }

    /// Consume the transport and return the underlying byte stream. Used by the
    /// Wi-Fi adapter, which takes the raw serial port to run SLIP directly once
    /// the device has switched the link out of framed-CLI mode.
    pub fn into_stream(self) -> S {
        self.stream
    }

    /// Mutable access to the underlying stream (e.g. to change the read
    /// timeout).
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Buffered EVENT frames seen while awaiting responses (oldest first).
    pub fn drain_events(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.events)
    }

    /// Block for the next complete event, reassembling multi-frame chunks.
    /// returns (event_id, json_bytes)
    pub fn next_event(&mut self) -> Result<(u16, Vec<u8>)> {
        let mut parked = Vec::new();
        loop {
            let f = if self.events.is_empty() {
                match self.next_inbound() {
                    Ok(f) => f,
                    Err(e) => {
                        self.restore_events(parked);
                        return Err(e);
                    }
                }
            } else {
                self.events.remove(0)
            };
            if f.typ != PKT_EVENT || f.payload.len() < 3 {
                continue;
            }
            let fid = u16::from_le_bytes([f.payload[0], f.payload[1]]);
            if let Some(want) = self.ev_id {
                if fid != want {
                    if parked.len() + self.events.len() >= MAX_BUFFERED_EVENTS {
                        self.ev_acc.clear();
                        self.ev_id = None;
                        self.inbox.push_front(f);
                        self.restore_events(parked);
                        return Err(Error::msg("too many buffered events"));
                    }
                    parked.push(f);
                    continue;
                }
            } else {
                self.ev_id = Some(fid);
            }
            self.ev_acc.extend_from_slice(&f.payload[3..]);
            if self.ev_acc.len() > MAX_REASSEMBLY {
                self.ev_acc.clear();
                self.ev_id = None;
                self.restore_events(parked);
                return Err(Error::msg(format!(
                    "event reassembly exceeded {MAX_REASSEMBLY} bytes"
                )));
            }
            if f.payload[2] & RESP_MORE == 0 {
                let id = self.ev_id.take().unwrap();
                let body = std::mem::take(&mut self.ev_acc);
                self.restore_events(parked);
                return Ok((id, body));
            }
        }
    }

    fn restore_events(&mut self, mut parked: Vec<Frame>) {
        parked.append(&mut self.events);
        self.events = parked;
    }

    fn buffer_event(&mut self, frame: Frame) -> Result<()> {
        if self.events.len() >= MAX_BUFFERED_EVENTS {
            self.inbox.push_front(frame);
            bail!("too many buffered events");
        }
        self.events.push(frame);
        Ok(())
    }

    fn next_seq(&mut self) -> u16 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Return the next inbound control frame, reading + demuxing as needed.
    /// Frames are queued, so a read that yields several (e.g. a response plus a
    /// trailing frame) loses none.
    fn next_inbound(&mut self) -> Result<Frame> {
        let mut buf = [0u8; 512];
        loop {
            if let Some(f) = self.inbox.pop_front() {
                return Ok(f);
            }
            let n = match self.stream.read(&mut buf) {
                Ok(0) => return Err(Error::Closed),
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::TimedOut => {
                    return Err(Error::Timeout);
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {
                    return Err(Error::Interrupted);
                }
                Err(e) => return Err(e.into()),
            };
            for ev in self.demux.feed(&buf[..n]) {
                match ev {
                    Event::Cli(f) => self.inbox.push_back(f),
                    // Device debug text: surfaced to stderr with ISHARK_DEBUG_SERIAL set.
                    Event::Log(bytes) => {
                        if debug_serial() {
                            let _ = std::io::stderr().write_all(&bytes);
                        }
                    }
                }
            }
        }
    }

    /// Send a command (opcode + raw arg bytes) and return the correlated,
    /// reassembled response.
    pub fn transact(&mut self, opcode: u16, args: &[u8]) -> Result<Response> {
        let seq = self.next_seq();
        let frame = frame::encode_command(seq, opcode, args);
        self.stream.write_all(&frame)?;
        self.stream.flush()?;

        let mut acc: Vec<u8> = Vec::new();
        let mut cmd = opcode;
        let mut error = ERR_OK;
        let mut have_header = false;
        loop {
            let f = self.next_inbound()?;
            if (f.typ == PKT_RESPONSE || f.typ == PKT_ERROR) && f.seq == seq {
                let Some((h, data)) = parse_response_header(&f.payload) else {
                    bail!("malformed response header (seq {seq})");
                };
                if !have_header {
                    cmd = h.cmd;
                    error = h.error;
                    have_header = true;
                }
                acc.extend_from_slice(data);
                if acc.len() > MAX_REASSEMBLY {
                    bail!("response reassembly exceeded {MAX_REASSEMBLY} bytes");
                }
                if !h.has_more() {
                    return Ok(Response {
                        cmd,
                        error,
                        body: acc,
                    });
                }
            } else {
                // Unsolicited event or out-of-band frame: keep it, keep waiting.
                self.buffer_event(f)?;
            }
        }
    }

    /// Like [`Self::transact`], but delivers EVENT frames to `on_event` as they
    /// arrive instead of buffering them. Used by long commands (BLE MITM) that
    /// emit progress while the response is still outstanding.
    pub fn transact_with_events(
        &mut self,
        opcode: u16,
        args: &[u8],
        mut on_event: impl FnMut(u16, &[u8]),
    ) -> Result<Response> {
        let seq = self.next_seq();
        let frame = frame::encode_command(seq, opcode, args);
        self.stream.write_all(&frame)?;
        self.stream.flush()?;

        let mut acc: Vec<u8> = Vec::new();
        let mut cmd = opcode;
        let mut error = ERR_OK;
        let mut have_header = false;
        loop {
            let f = self.next_inbound()?;
            if (f.typ == PKT_RESPONSE || f.typ == PKT_ERROR) && f.seq == seq {
                let Some((h, data)) = parse_response_header(&f.payload) else {
                    bail!("malformed response header (seq {seq})");
                };
                if !have_header {
                    cmd = h.cmd;
                    error = h.error;
                    have_header = true;
                }
                acc.extend_from_slice(data);
                if acc.len() > MAX_REASSEMBLY {
                    bail!("response reassembly exceeded {MAX_REASSEMBLY} bytes");
                }
                if !h.has_more() {
                    return Ok(Response {
                        cmd,
                        error,
                        body: acc,
                    });
                }
            } else if f.typ == PKT_EVENT && f.payload.len() >= 3 {
                let id = u16::from_le_bytes([f.payload[0], f.payload[1]]);
                on_event(id, &f.payload[3..]);
            } else {
                self.buffer_event(f)?;
            }
        }
    }

    /// Send a command and return the first correlated response frame.
    pub fn transact_chunk(
        &mut self,
        opcode: u16,
        args: &[u8],
    ) -> Result<(ResponseHeader, Vec<u8>)> {
        let seq = self.next_seq();
        let frame = frame::encode_command(seq, opcode, args);
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        loop {
            let f = self.next_inbound()?;
            if (f.typ == PKT_RESPONSE || f.typ == PKT_ERROR) && f.seq == seq {
                let Some((h, data)) = parse_response_header(&f.payload) else {
                    bail!("malformed response header (seq {seq})");
                };
                return Ok((h, data.to_vec()));
            }
            self.buffer_event(f)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        CMD_DEVICE_INFO, CMD_WIFI_SCAN, ERR_BUSY, EVT_SCAN_DONE, PKT_EVENT, RESP_JSON, RESP_MORE,
    };
    use std::io::Cursor;

    struct MockStream {
        written: Vec<u8>,
        to_read: Cursor<Vec<u8>>,
    }
    impl MockStream {
        fn new(to_read: Vec<u8>) -> Self {
            Self {
                written: Vec::new(),
                to_read: Cursor::new(to_read),
            }
        }
    }
    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.to_read.read(buf)
        }
    }
    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn resp(seq: u16, cmd: u16, error: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&cmd.to_le_bytes());
        payload.push(error);
        payload.push(flags);
        payload.extend_from_slice(body);
        frame::encode(PKT_RESPONSE, seq, &payload)
    }

    #[test]
    fn transact_returns_single_frame_json_and_sends_the_command() {
        let wire = resp(0, CMD_DEVICE_INFO, ERR_OK, RESP_JSON, b"{\"a\":1}");
        let mut t = Transport::new(MockStream::new(wire));
        let r = t.transact(CMD_DEVICE_INFO, b"").unwrap();
        assert_eq!(r.cmd, CMD_DEVICE_INFO);
        assert!(r.is_ok());
        assert_eq!(r.json(), "{\"a\":1}");
        // The command we sent is exactly encode_command(seq=0, DEVICE_INFO, "").
        assert_eq!(
            t.stream.written,
            frame::encode_command(0, CMD_DEVICE_INFO, b"")
        );
    }

    #[test]
    fn transact_reassembles_resp_more_chunks() {
        let mut wire = resp(
            0,
            CMD_WIFI_SCAN,
            ERR_OK,
            RESP_JSON | RESP_MORE,
            b"{\"count\"",
        );
        wire.extend(resp(0, CMD_WIFI_SCAN, ERR_OK, RESP_JSON, b":2}"));
        let mut t = Transport::new(MockStream::new(wire));
        let r = t.transact(CMD_WIFI_SCAN, b"").unwrap();
        assert_eq!(r.json(), "{\"count\":2}");
    }

    #[test]
    fn transact_with_events_delivers_progress_before_response() {
        let mut ev_payload = Vec::new();
        ev_payload.extend_from_slice(&EVT_SCAN_DONE.to_le_bytes());
        ev_payload.push(RESP_JSON);
        ev_payload.extend_from_slice(b"{\"step\":\"connect\"}");
        let mut wire = frame::encode(PKT_EVENT, 99, &ev_payload);
        wire.extend(resp(0, CMD_WIFI_SCAN, ERR_OK, RESP_JSON, b"{\"ok\":true}"));
        let mut t = Transport::new(MockStream::new(wire));
        let mut seen = Vec::new();
        let r = t
            .transact_with_events(CMD_WIFI_SCAN, b"", |id, body| {
                seen.push((id, body.to_vec()));
            })
            .unwrap();
        assert_eq!(r.json(), "{\"ok\":true}");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, EVT_SCAN_DONE);
        assert_eq!(seen[0].1, b"{\"step\":\"connect\"}");
        assert!(t.drain_events().is_empty());
    }

    #[test]
    fn transact_buffers_interleaved_event_and_still_correlates() {
        // An unsolicited EVENT (different seq) arrives before the response.
        let mut ev_payload = Vec::new();
        ev_payload.extend_from_slice(&EVT_SCAN_DONE.to_le_bytes());
        ev_payload.push(RESP_JSON);
        ev_payload.extend_from_slice(b"{\"kind\":\"wifi\"}");
        let mut wire = frame::encode(PKT_EVENT, 99, &ev_payload);
        wire.extend(resp(0, CMD_WIFI_SCAN, ERR_OK, RESP_JSON, b"{\"count\":0}"));
        let mut t = Transport::new(MockStream::new(wire));
        let r = t.transact(CMD_WIFI_SCAN, b"").unwrap();
        assert_eq!(r.json(), "{\"count\":0}");
        assert_eq!(
            t.drain_events().len(),
            1,
            "the event was buffered, not dropped"
        );
    }

    #[test]
    fn transact_surfaces_device_error_code() {
        let wire = resp(
            0,
            CMD_WIFI_SCAN,
            ERR_BUSY,
            RESP_JSON,
            b"{\"error\":\"busy\"}",
        );
        let mut t = Transport::new(MockStream::new(wire));
        let r = t.transact(CMD_WIFI_SCAN, b"").unwrap();
        assert!(!r.is_ok());
        assert_eq!(r.error, ERR_BUSY);
    }

    #[test]
    fn seq_increments_across_transactions() {
        let mut wire = resp(0, CMD_DEVICE_INFO, ERR_OK, RESP_JSON, b"{}");
        wire.extend(resp(1, CMD_DEVICE_INFO, ERR_OK, RESP_JSON, b"{}"));
        let mut t = Transport::new(MockStream::new(wire));
        t.transact(CMD_DEVICE_INFO, b"").unwrap();
        t.transact(CMD_DEVICE_INFO, b"").unwrap();
        let first = frame::encode_command(0, CMD_DEVICE_INFO, b"");
        let second = frame::encode_command(1, CMD_DEVICE_INFO, b"");
        let mut expect = first;
        expect.extend(second);
        assert_eq!(t.stream.written, expect);
    }

    #[test]
    fn transact_errors_when_stream_closes_before_response() {
        let mut t = Transport::new(MockStream::new(Vec::new()));
        assert!(t.transact(CMD_DEVICE_INFO, b"").is_err());
    }

    fn event(id: u16, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = id.to_le_bytes().to_vec();
        payload.push(flags);
        payload.extend_from_slice(body);
        frame::encode(PKT_EVENT, 0, &payload)
    }

    #[test]
    fn event_reassembly_bounds_parked_frames() {
        let mut wire = event(1, RESP_MORE, b"{");
        for _ in 0..MAX_BUFFERED_EVENTS + 1 {
            wire.extend(event(2, RESP_JSON, b"{}"));
        }
        let mut t = Transport::new(MockStream::new(wire));
        let err = t.next_event().unwrap_err().to_string();
        assert!(err.contains("too many buffered events"), "{err}");
        assert_eq!(t.events.len(), MAX_BUFFERED_EVENTS);
        assert!(t.ev_acc.is_empty());
        assert!(t.ev_id.is_none());
        for _ in 0..MAX_BUFFERED_EVENTS + 1 {
            assert_eq!(t.next_event().unwrap(), (2, b"{}".to_vec()));
        }
    }

    #[test]
    fn command_retries_cannot_grow_a_full_event_queue() {
        let mut wire = Vec::new();
        for _ in 0..MAX_BUFFERED_EVENTS + 1 {
            wire.extend(event(2, RESP_JSON, b"{}"));
        }
        let mut t = Transport::new(MockStream::new(wire));
        for _ in 0..3 {
            let err = t.transact(CMD_DEVICE_INFO, b"").unwrap_err();
            assert!(err.to_string().contains("too many buffered events"));
            assert_eq!(t.events.len(), MAX_BUFFERED_EVENTS);
        }
        t.drain_events();
        assert_eq!(t.next_event().unwrap(), (2, b"{}".to_vec()));
    }

    #[test]
    fn oversized_event_preserves_parked_frames() {
        let mut wire = event(1, RESP_MORE, b"{");
        wire.extend(event(2, RESP_JSON, b"{}"));
        let chunk = vec![b'x'; crate::protocol::MAX_PAYLOAD - 3];
        for _ in 0..MAX_REASSEMBLY / chunk.len() + 1 {
            wire.extend(event(1, RESP_MORE, &chunk));
        }
        let mut t = Transport::new(MockStream::new(wire));
        let err = t.next_event().unwrap_err().to_string();
        assert!(err.contains("event reassembly exceeded"), "{err}");
        assert_eq!(t.next_event().unwrap(), (2, b"{}".to_vec()));
    }

    #[test]
    fn fragmented_event_keeps_other_events_in_order() {
        let mut wire = event(1, RESP_MORE, b"{");
        wire.extend(event(2, RESP_JSON, b"2"));
        wire.extend(event(3, RESP_JSON, b"3"));
        wire.extend(event(1, RESP_JSON, b"}"));
        let mut t = Transport::new(MockStream::new(wire));
        assert_eq!(t.next_event().unwrap(), (1, b"{}".to_vec()));
        assert_eq!(t.next_event().unwrap(), (2, b"2".to_vec()));
        assert_eq!(t.next_event().unwrap(), (3, b"3".to_vec()));
    }

    #[test]
    fn interrupted_read_is_not_retried() {
        struct OnceThenTimeout {
            hit: bool,
        }
        impl Read for OnceThenTimeout {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.hit {
                    self.hit = true;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "interrupted",
                    ));
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out",
                ))
            }
        }
        impl Write for OnceThenTimeout {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut t = Transport::new(OnceThenTimeout { hit: false });
        assert!(matches!(t.next_inbound(), Err(Error::Interrupted)));
    }
}
