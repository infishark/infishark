//! Request/response transport over any byte stream

use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};

use crate::error::{Error, Result};

use crate::demux::{Demuxer, Event};
use crate::frame::{self, Frame};
use crate::protocol::{ERR_OK, PKT_ERROR, PKT_EVENT, PKT_RESPONSE, RESP_MORE};
use crate::response::{ResponseHeader, parse_response_header};

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

// Ceilings that bound host memory if a hostile or malfunctioning device never ends a multi-frame stream.
const MAX_REASSEMBLY: usize = 4 * 1024 * 1024;
const MAX_BUFFERED_EVENTS: usize = 1024;

pub struct Transport<S> {
    stream: S,
    demux: Demuxer,
    seq: u16,
    events: Vec<Frame>,
    inbox: VecDeque<Frame>,
}

impl<S: Read + Write> Transport<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            demux: Demuxer::new(),
            seq: 0,
            events: Vec::new(),
            inbox: VecDeque::new(),
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
    #[allow(dead_code)]
    pub fn drain_events(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.events)
    }

    /// Block for the next complete event, reassembling multi-frame chunks.
    /// returns (event_id, json_bytes)
    pub fn next_event(&mut self) -> Result<(u16, Vec<u8>)> {
        let mut acc: Vec<u8> = Vec::new();
        let mut id: Option<u16> = None;
        loop {
            let f = if self.events.is_empty() {
                self.next_inbound()?
            } else {
                self.events.remove(0)
            };
            if f.typ != PKT_EVENT || f.payload.len() < 3 {
                continue;
            }
            if id.is_none() {
                id = Some(u16::from_le_bytes([f.payload[0], f.payload[1]]));
            }
            acc.extend_from_slice(&f.payload[3..]);
            if acc.len() > MAX_REASSEMBLY {
                bail!("event reassembly exceeded {MAX_REASSEMBLY} bytes");
            }
            if f.payload[2] & RESP_MORE == 0 {
                return Ok((id.unwrap(), acc));
            }
        }
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
                Err(e) if e.kind() == ErrorKind::Interrupted => continue, // EINTR (e.g. Ctrl-C)
                Err(e) => return Err(e.into()),
            };
            for ev in self.demux.feed(&buf[..n]) {
                match ev {
                    Event::Cli(f) => self.inbox.push_back(f),
                    // Device debug text: surfaced to stderr with ISHARK_DEBUG_SERIAL set.
                    Event::Log(bytes) => {
                        if std::env::var_os("ISHARK_DEBUG_SERIAL").is_some() {
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
                self.events.push(f);
                if self.events.len() > MAX_BUFFERED_EVENTS {
                    bail!("too many buffered events ({})", self.events.len());
                }
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
            self.events.push(f);
            if self.events.len() > MAX_BUFFERED_EVENTS {
                bail!("too many buffered events ({})", self.events.len());
            }
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
}
