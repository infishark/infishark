//! IR codes: host names a protocol + data; the device encodes/decodes.

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum Protocol {
    Rc5 = 1,
    Rc6 = 2,
    Nec = 3,
    Sony = 4,
    Panasonic = 5,
    Jvc = 6,
    Samsung = 7,
    Whynter = 8,
    Aiwa = 9,
    Lg = 10,
    Sanyo = 11,
    Mitsubishi = 12,
    Dish = 13,
    Sharp = 14,
    Denon = 17,
    Sherwood = 19,
    Rcmm = 21,
    Nikai = 29,
    Magiquest = 35,
    Lasertag = 36,
    Mitsubishi2 = 39,
    Gicable = 43,
    Lutron = 47,
    Pioneer = 50,
    Samsung36 = 56,
    LegoPf = 58,
    Inax = 64,
    Epson = 75,
    Symphony = 76,
    Doshisha = 81,
    Multibrackets = 82,
    Metz = 91,
    Elitescreens = 95,
    Milestag2 = 97,
    Xmp = 99,
    Bose = 106,
    Arris = 107,
    Toto = 117,
}

pub const PROTOCOLS: &[(&str, Protocol)] = &[
    ("nec", Protocol::Nec),
    ("sony", Protocol::Sony),
    ("rc5", Protocol::Rc5),
    ("rc6", Protocol::Rc6),
    ("samsung", Protocol::Samsung),
    ("samsung36", Protocol::Samsung36),
    ("panasonic", Protocol::Panasonic),
    ("lg", Protocol::Lg),
    ("jvc", Protocol::Jvc),
    ("whynter", Protocol::Whynter),
    ("aiwa", Protocol::Aiwa),
    ("sanyo", Protocol::Sanyo),
    ("mitsubishi", Protocol::Mitsubishi),
    ("mitsubishi2", Protocol::Mitsubishi2),
    ("dish", Protocol::Dish),
    ("sharp", Protocol::Sharp),
    ("denon", Protocol::Denon),
    ("sherwood", Protocol::Sherwood),
    ("rcmm", Protocol::Rcmm),
    ("nikai", Protocol::Nikai),
    ("magiquest", Protocol::Magiquest),
    ("lasertag", Protocol::Lasertag),
    ("gicable", Protocol::Gicable),
    ("lutron", Protocol::Lutron),
    ("pioneer", Protocol::Pioneer),
    ("legopf", Protocol::LegoPf),
    ("inax", Protocol::Inax),
    ("epson", Protocol::Epson),
    ("symphony", Protocol::Symphony),
    ("doshisha", Protocol::Doshisha),
    ("multibrackets", Protocol::Multibrackets),
    ("metz", Protocol::Metz),
    ("elitescreens", Protocol::Elitescreens),
    ("milestag2", Protocol::Milestag2),
    ("xmp", Protocol::Xmp),
    ("bose", Protocol::Bose),
    ("arris", Protocol::Arris),
    ("toto", Protocol::Toto),
];

impl Protocol {
    pub fn id(self) -> u8 {
        self as u8
    }

    pub fn from_name(s: &str) -> Option<Protocol> {
        PROTOCOLS
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(s))
            .map(|(_, p)| *p)
    }

    pub fn from_id(id: u8) -> Option<Protocol> {
        PROTOCOLS.iter().map(|(_, p)| *p).find(|p| p.id() == id)
    }

    pub fn name(self) -> &'static str {
        PROTOCOLS
            .iter()
            .find(|(_, p)| *p == self)
            .map(|(n, _)| *n)
            .unwrap_or("unknown")
    }
}

/// A protocol-level IR command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrCode {
    pub protocol: Protocol,
    pub data: u64,
    pub bits: u16,
}

/// A raw IR waveform. Carrier frequency in kHz + alternating mark/space
/// microsecond durations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawIr {
    pub khz: u16,
    pub timings: Vec<u16>,
}

/// One capture from the device IR receiver (decoded code or raw waveform).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrCapture {
    Code(IrCode),
    Raw(RawIr),
}

impl IrCapture {
    /// Parse an `EVT_IR` JSON body. `Ok(None)` = skippable noise (not an error).
    pub fn from_event_json(v: &serde_json::Value) -> Result<Option<Self>> {
        let proto_id = v.get("protocol").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
        if let Some(protocol) = Protocol::from_id(proto_id) {
            let data_s = v.get("data").and_then(|x| x.as_str()).unwrap_or("0");
            let data = crate::hex::parse_u64(data_s)?;
            let bits = v.get("bits").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            // Zero data / zero bits / all-ones are almost always decoder noise.
            if data == 0 || bits == 0 || data == u64::MAX {
                return Ok(None);
            }
            return Ok(Some(IrCapture::Code(IrCode {
                protocol,
                data,
                bits,
            })));
        }
        let timings = parse_timings(v)?;
        if timings.is_empty() {
            // Device-known protocol we don't map, with no raw payload: skip.
            return Ok(None);
        }
        let khz = v.get("khz").and_then(|x| x.as_u64()).unwrap_or(38) as u16;
        Ok(Some(IrCapture::Raw(RawIr { khz, timings })))
    }
}

fn parse_timings(v: &serde_json::Value) -> Result<Vec<u16>> {
    let Some(arr) = v.get("timings").and_then(|x| x.as_array()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(arr.len());
    for t in arr {
        let n = t
            .as_u64()
            .ok_or_else(|| Error::msg("non-integer IR timing"))?;
        if n > u16::MAX as u64 {
            bail!("IR timing out of range: {n}");
        }
        out.push(n as u16);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn protocol_ids_are_stable_wire_values() {
        assert_eq!(Protocol::Nec.id(), 3);
        assert_eq!(Protocol::Sony.id(), 4);
        assert_eq!(Protocol::Panasonic.id(), 5);
        assert_eq!(Protocol::Toto.id(), 117);
    }

    #[test]
    fn name_and_id_round_trip() {
        assert_eq!(Protocol::from_name("NEC"), Some(Protocol::Nec));
        assert_eq!(Protocol::from_name("samsung36"), Some(Protocol::Samsung36));
        assert_eq!(Protocol::from_name("nope"), None);
        assert_eq!(Protocol::from_id(3), Some(Protocol::Nec));
        assert_eq!(Protocol::from_id(200), None);
        assert_eq!(Protocol::Denon.name(), "denon");
    }

    #[test]
    fn capture_from_decoded_event() {
        let v = json!({"protocol": 3, "name": "NEC", "data": "20DF10EF", "bits": 32});
        match IrCapture::from_event_json(&v).unwrap() {
            Some(IrCapture::Code(c)) => {
                assert_eq!(c.protocol, Protocol::Nec);
                assert_eq!(c.data, 0x20DF10EF);
                assert_eq!(c.bits, 32);
            }
            other => panic!("expected code, got {other:?}"),
        }
    }

    #[test]
    fn capture_from_raw_event() {
        let v = json!({
            "protocol": 0,
            "name": "unknown",
            "data": "0",
            "bits": 0,
            "khz": 38,
            "timings": [9000, 4500, 560]
        });
        match IrCapture::from_event_json(&v).unwrap() {
            Some(IrCapture::Raw(r)) => {
                assert_eq!(r.khz, 38);
                assert_eq!(r.timings, vec![9000, 4500, 560]);
            }
            other => panic!("expected raw, got {other:?}"),
        }
    }

    #[test]
    fn skips_noise_and_unmapped() {
        assert!(
            IrCapture::from_event_json(&json!({"protocol": 3, "data": "0", "bits": 32}))
                .unwrap()
                .is_none()
        );
        assert!(
            IrCapture::from_event_json(&json!({"protocol": 3, "data": "FF", "bits": 0}))
                .unwrap()
                .is_none()
        );
        assert!(
            IrCapture::from_event_json(
                &json!({"protocol": 3, "data": "FFFFFFFFFFFFFFFF", "bits": 32})
            )
            .unwrap()
            .is_none()
        );
        // protocol 22 not in our set, no timings → skip (not error)
        assert!(
            IrCapture::from_event_json(&json!({"protocol": 22, "data": "1", "bits": 16}))
                .unwrap()
                .is_none()
        );
    }
}
