//! Streaming demuxer for the device -> host direction.
//!
//! The USB-CDC stream has three different channels. There are the framed control packets (magic B5
//! 5A C1), the display stream (magic AA 55 F0), and bare debug text. This demuxer extracts control
//! frames and emits everything else as log bytes

#![allow(dead_code)]

use crate::crc::crc16_ccitt;
use crate::frame::Frame;
use crate::protocol::{HDR_LEN, MAGIC, MAX_PAYLOAD, VERSION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A validated control frame
    Cli(Frame),
    /// Bytes that are not part of a control frame (debug text, pixel stream,
    /// noise)
    Log(Vec<u8>),
}

#[derive(Default)]
pub struct Demuxer {
    buf: Vec<u8>,
}

impl Demuxer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed received bytes; return any complete events. Incomplete trailing
    /// data is retained for the next call.
    pub fn feed(&mut self, data: &[u8]) -> Vec<Event> {
        self.buf.extend_from_slice(data);
        let mut events: Vec<Event> = Vec::new();

        loop {
            let Some(idx) = find_subslice(&self.buf, &MAGIC) else {
                // No full magic anywhere. Flush everything except a possible
                // partial magic prefix at the tail.
                let keep = tail_keep_for_magic(&self.buf);
                let flush_len = self.buf.len() - keep;
                if flush_len > 0 {
                    let drained: Vec<u8> = self.buf.drain(..flush_len).collect();
                    push_log(&mut events, drained);
                }
                return events;
            };

            if idx > 0 {
                let drained: Vec<u8> = self.buf.drain(..idx).collect();
                push_log(&mut events, drained);
            }

            // buf now starts with MAGIC. Peek the version to reject a false
            // magic cheaply, before waiting on a (possibly bogus) length.
            if self.buf.len() < MAGIC.len() + 1 {
                return events;
            }
            if self.buf[MAGIC.len()] != VERSION {
                let b = self.buf.remove(0);
                push_log(&mut events, vec![b]);
                continue;
            }

            // Need the whole fixed header (magic + version,type,seq_le,len_le).
            let header_total = MAGIC.len() + HDR_LEN;
            if self.buf.len() < header_total {
                return events;
            }
            let typ = self.buf[MAGIC.len() + 1];
            let seq = u16::from_le_bytes([self.buf[MAGIC.len() + 2], self.buf[MAGIC.len() + 3]]);
            let plen =
                u16::from_le_bytes([self.buf[MAGIC.len() + 4], self.buf[MAGIC.len() + 5]]) as usize;
            if plen > MAX_PAYLOAD {
                let b = self.buf.remove(0);
                push_log(&mut events, vec![b]);
                continue;
            }

            let covered_end = header_total + plen;
            let total = covered_end + 2; // + crc_le
            if self.buf.len() < total {
                return events; // wait for the rest of the frame
            }

            // CRC covers version..payload, i.e. everything after the magic.
            let crc_calc = crc16_ccitt(&self.buf[MAGIC.len()..covered_end], 0xFFFF);
            let crc_rx = u16::from_le_bytes([self.buf[covered_end], self.buf[covered_end + 1]]);
            if crc_calc != crc_rx {
                let b = self.buf.remove(0);
                push_log(&mut events, vec![b]);
                continue;
            }

            let payload = self.buf[header_total..covered_end].to_vec();
            self.buf.drain(..total);
            events.push(Event::Cli(Frame { typ, seq, payload }));
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// How many trailing bytes match prefix of magic, so a magic split across two
/// feeds is not lost. Return 0 if the tail is not a magic prefix
fn tail_keep_for_magic(buf: &[u8]) -> usize {
    let upper = (MAGIC.len() - 1).min(buf.len());
    for k in (1..=upper).rev() {
        if buf[buf.len() - k..] == MAGIC[..k] {
            return k;
        }
    }
    0
}

/// Append log bytes, coalescing with a trailing Log event so a `feed` yields at
/// most one Log run between frames.
fn push_log(events: &mut Vec<Event>, bytes: Vec<u8>) {
    if bytes.is_empty() {
        return;
    }
    if let Some(Event::Log(last)) = events.last_mut() {
        last.extend_from_slice(&bytes);
    } else {
        events.push(Event::Log(bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::encode;
    use crate::protocol::PKT_RESPONSE;

    fn sample_frame() -> (Vec<u8>, Frame) {
        let payload = vec![0x01, 0x00, 0x00, 0x01, b'o', b'k'];
        let bytes = encode(PKT_RESPONSE, 7, &payload);
        (
            bytes,
            Frame {
                typ: PKT_RESPONSE,
                seq: 7,
                payload,
            },
        )
    }

    #[test]
    fn decodes_a_clean_frame() {
        let (bytes, want) = sample_frame();
        let mut d = Demuxer::new();
        assert_eq!(d.feed(&bytes), vec![Event::Cli(want)]);
    }

    #[test]
    fn flushes_leading_text_then_frame() {
        let (bytes, want) = sample_frame();
        let mut input = b"booting...".to_vec();
        input.extend_from_slice(&bytes);
        let mut d = Demuxer::new();
        assert_eq!(
            d.feed(&input),
            vec![Event::Log(b"booting...".to_vec()), Event::Cli(want)]
        );
    }

    #[test]
    fn reassembles_frame_split_across_two_feeds() {
        let (bytes, want) = sample_frame();
        let mut d = Demuxer::new();
        assert_eq!(d.feed(&bytes[..4]), vec![], "waits for the rest");
        assert_eq!(d.feed(&bytes[4..]), vec![Event::Cli(want)]);
    }

    #[test]
    fn keeps_partial_trailing_magic_for_next_feed() {
        let mut d = Demuxer::new();
        // A lone first magic byte at the tail must not be flushed as log yet.
        assert_eq!(d.feed(&[b'x', 0xB5]), vec![Event::Log(b"x".to_vec())]);
        let (bytes, want) = sample_frame();
        // Supply the remaining magic + frame; the held 0xB5 completes it.
        assert_eq!(d.feed(&bytes[1..]), vec![Event::Cli(want)]);
    }

    #[test]
    fn resyncs_past_false_magic_with_bad_version() {
        let (bytes, want) = sample_frame();
        // B5 5A C1 followed by a, for example, non-0x01 version byte is not in fact a real frame
        let mut input = vec![0xB5, 0x5A, 0xC1, 0x99];
        input.extend_from_slice(&bytes);
        let mut d = Demuxer::new();
        assert_eq!(
            d.feed(&input),
            vec![Event::Log(vec![0xB5, 0x5A, 0xC1, 0x99]), Event::Cli(want)]
        );
    }

    #[test]
    fn drops_a_crc_corrupted_frame_to_log() {
        let (mut bytes, _want) = sample_frame();
        let last = bytes.len() - 3; // a payload byte, before the 2 crc bytes
        bytes[last] ^= 0xFF;
        let mut d = Demuxer::new();
        let events = d.feed(&bytes);
        assert!(
            !events.iter().any(|e| matches!(e, Event::Cli(_))),
            "corrupt frame must not surface as a Cli event"
        );
    }
}
