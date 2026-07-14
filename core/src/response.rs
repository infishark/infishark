//! Parsing of `PKT_RESPONSE` / `PKT_EVENT` payload prefixes.

use crate::protocol::{RESP_BINARY, RESP_JSON, RESP_MORE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    pub cmd: u16,
    pub error: u8,
    pub flags: u8,
}

impl ResponseHeader {
    pub fn is_json(&self) -> bool {
        self.flags & RESP_JSON != 0
    }
    pub fn is_binary(&self) -> bool {
        self.flags & RESP_BINARY != 0
    }
    pub fn has_more(&self) -> bool {
        self.flags & RESP_MORE != 0
    }
}

pub fn parse_response_header(payload: &[u8]) -> Option<(ResponseHeader, &[u8])> {
    if payload.len() < 4 {
        return None;
    }
    let hdr = ResponseHeader {
        cmd: u16::from_le_bytes([payload[0], payload[1]]),
        error: payload[2],
        flags: payload[3],
    };
    Some((hdr, &payload[4..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CMD_WIFI_SCAN, ERR_OK, RESP_JSON, RESP_MORE};

    #[test]
    fn parses_header_and_returns_json_tail() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&CMD_WIFI_SCAN.to_le_bytes());
        payload.push(ERR_OK);
        payload.push(RESP_JSON | RESP_MORE);
        payload.extend_from_slice(b"{\"count\":2");
        let (hdr, data) = parse_response_header(&payload).unwrap();
        assert_eq!(hdr.cmd, CMD_WIFI_SCAN);
        assert_eq!(hdr.error, ERR_OK);
        assert!(hdr.is_json());
        assert!(hdr.has_more());
        assert!(!hdr.is_binary());
        assert_eq!(data, b"{\"count\":2");
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse_response_header(&[0x01, 0x00, 0x00]).is_none());
    }

    #[test]
    fn empty_tail_is_allowed() {
        let payload = [0x01, 0x00, ERR_OK, RESP_JSON];
        let (hdr, data) = parse_response_header(&payload).unwrap();
        assert_eq!(hdr.cmd, 0x0001);
        assert!(data.is_empty());
    }
}
