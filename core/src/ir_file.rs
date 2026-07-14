//! `.ir` remote files (signals / library). Host-side parse and write.
//!
//! Buttons store [`IrCapture`], the same type used for RX and TX.

use std::path::Path;

use crate::error::{Context, Result};

use crate::hex;
use crate::ir::{IrCapture, IrCode, Protocol, RawIr};

const SIGNALS_HEADER: &str = "IR signals file";
const LIBRARY_HEADER: &str = "IR library file";
const MAX_RAW_TIMINGS: usize = 512;

/// A remote: header + ordered buttons.
#[derive(Debug, Clone, PartialEq)]
pub struct IrRemote {
    pub filetype: String,
    pub version: u32,
    pub buttons: Vec<IrButton>,
}

/// One named button; payload is a normal IR capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrButton {
    pub name: String,
    pub capture: IrCapture,
}

impl IrRemote {
    pub fn parse(text: &str) -> Result<Self> {
        parse_ir_text(text)
    }

    /// Like [`parse`] -- but requires a `Filetype:` header up front (the
    /// filename/extension is not trusted). Rejects non-`.ir` content early.
    pub fn parse_strict(text: &str) -> Result<Self> {
        let header = text.lines().map(str::trim).find(|l| !l.is_empty());
        let filetype = header
            .and_then(|l| l.strip_prefix("Filetype:"))
            .map(str::trim);
        if filetype != Some(SIGNALS_HEADER) && filetype != Some(LIBRARY_HEADER) {
            bail!("not a .ir file (missing or unrecognized 'Filetype:' header)");
        }
        parse_ir_text(text)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        Self::parse(&text)
    }

    /// [`load`] with the strict header check of [`parse_strict`].
    pub fn load_strict(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        Self::parse_strict(&text)
    }

    pub fn to_device_csv(&self) -> (String, Vec<String>) {
        let mut csv = String::new();
        let mut skipped = Vec::new();
        for b in &self.buttons {
            match &b.capture {
                IrCapture::Code(c) => {
                    csv.push_str(&format!(
                        "{},0x{:X},{}\n",
                        device_button_name(&b.name),
                        c.data,
                        c.protocol.id()
                    ));
                }
                IrCapture::Raw(_) => skipped.push(b.name.clone()),
            }
        }
        (csv, skipped)
    }

    /// Serialize to `.ir` text.
    pub fn to_ir_string(&self) -> String {
        write_ir(self)
    }

    /// Build a signals-file remote from RX captures (`Capture_1`, …).
    pub fn from_captures(caps: &[IrCapture]) -> Self {
        let buttons = caps
            .iter()
            .enumerate()
            .map(|(i, c)| IrButton {
                name: format!("Capture_{}", i + 1),
                capture: c.clone(),
            })
            .collect();
        Self {
            filetype: SIGNALS_HEADER.into(),
            version: 1,
            buttons,
        }
    }

    pub fn find_button(&self, key: &str) -> Result<&IrButton> {
        if let Ok(n) = key.parse::<usize>() {
            if n >= 1 && n <= self.buttons.len() {
                return Ok(&self.buttons[n - 1]);
            }
            bail!("button #{n} out of range (1..{})", self.buttons.len());
        }
        self.buttons
            .iter()
            .find(|b| b.name.eq_ignore_ascii_case(key))
            .with_context(|| format!("no button named '{key}'"))
    }
}

fn device_button_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if matches!(c, ',' | '\n' | '\r') {
                ' '
            } else {
                c
            }
        })
        .take(23)
        .collect()
}

/// Fields of the button currently being parsed; flushed on `#` or next `name`.
#[derive(Default)]
struct Pending {
    name: Option<String>,
    typ: Option<String>,
    protocol: Option<String>,
    address: Option<u32>,
    command: Option<u32>,
    frequency: Option<u32>,
    timings: Option<Vec<u32>>,
}

impl Pending {
    fn flush(&mut self, buttons: &mut Vec<IrButton>) -> Result<()> {
        let Some(n) = self.name.take() else {
            *self = Pending::default();
            return Ok(());
        };
        let capture = match self
            .typ
            .take()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "parsed" => {
                let p = self
                    .protocol
                    .take()
                    .context("parsed button missing protocol")?;
                let a = self
                    .address
                    .take()
                    .context("parsed button missing address")?;
                let c = self
                    .command
                    .take()
                    .context("parsed button missing command")?;
                IrCapture::Code(parsed_to_code(&p, a, c).with_context(|| format!("button '{n}'"))?)
            }
            "raw" => {
                let f = self.frequency.take().unwrap_or(38_000);
                let tm = self.timings.take().context("raw button missing data")?;
                IrCapture::Raw(raw_from_file(f, &tm).with_context(|| format!("button '{n}'"))?)
            }
            "" => bail!("button '{n}' missing type"),
            other => bail!("button '{n}': unknown type '{other}'"),
        };
        *self = Pending::default();
        buttons.push(IrButton { name: n, capture });
        Ok(())
    }
}

fn parse_ir_text(text: &str) -> Result<IrRemote> {
    let mut filetype = String::new();
    let mut version = 1u32;
    let mut buttons = Vec::new();
    let mut cur = Pending::default();

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            cur.flush(&mut buttons)
                .with_context(|| format!("line {}", lineno + 1))?;
            continue;
        }
        let Some((key, val)) = line.split_once(':') else {
            bail!("line {}: expected key: value", lineno + 1);
        };
        let key = key.trim();
        let val = val.trim();
        match key {
            "Filetype" => filetype = val.to_string(),
            "Version" => {
                version = val
                    .parse()
                    .with_context(|| format!("line {}: bad Version", lineno + 1))?;
            }
            "name" => {
                if cur.name.is_some() {
                    cur.flush(&mut buttons)
                        .with_context(|| format!("line {}", lineno + 1))?;
                }
                cur.name = Some(val.to_string());
            }
            "type" => cur.typ = Some(val.to_string()),
            "protocol" => cur.protocol = Some(val.to_string()),
            "address" => {
                cur.address = Some(
                    hex::parse_le_u32_bytes(val)
                        .with_context(|| format!("line {}: address", lineno + 1))?,
                )
            }
            "command" => {
                cur.command = Some(
                    hex::parse_le_u32_bytes(val)
                        .with_context(|| format!("line {}: command", lineno + 1))?,
                )
            }
            "frequency" => {
                cur.frequency = Some(
                    val.parse()
                        .with_context(|| format!("line {}: frequency", lineno + 1))?,
                )
            }
            "duty_cycle" => {} // ignored
            "data" => {
                cur.timings = Some(
                    parse_timings_line(val)
                        .with_context(|| format!("line {}: data", lineno + 1))?,
                )
            }
            _ => {}
        }
    }
    cur.flush(&mut buttons)?;

    if filetype.is_empty() {
        filetype = SIGNALS_HEADER.into();
    } else if filetype != SIGNALS_HEADER && filetype != LIBRARY_HEADER {
        bail!("unsupported Filetype '{filetype}'");
    }
    if buttons.is_empty() {
        bail!("no buttons in .ir file");
    }
    Ok(IrRemote {
        filetype,
        version,
        buttons,
    })
}

fn parse_timings_line(s: &str) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    for p in s.split_whitespace() {
        out.push(
            p.parse::<u32>()
                .with_context(|| format!("bad timing '{p}'"))?,
        );
    }
    if out.is_empty() {
        bail!("empty timing list");
    }
    Ok(out)
}

fn raw_from_file(frequency_hz: u32, timings: &[u32]) -> Result<RawIr> {
    if timings.is_empty() {
        bail!("empty raw timings");
    }
    let khz = (frequency_hz / 1000).max(1) as u16;
    let mut out = Vec::with_capacity(timings.len().min(MAX_RAW_TIMINGS));
    for (i, &t) in timings.iter().enumerate() {
        if i >= MAX_RAW_TIMINGS {
            break;
        }
        if t > u16::MAX as u32 {
            bail!("timing {t} exceeds u16");
        }
        out.push(t as u16);
    }
    Ok(RawIr { khz, timings: out })
}

fn write_ir(r: &IrRemote) -> String {
    let mut s = String::new();
    s.push_str("Filetype: ");
    s.push_str(&r.filetype);
    s.push('\n');
    s.push_str(&format!("Version: {}\n", r.version));
    for b in &r.buttons {
        s.push_str("#\n");
        s.push_str("name: ");
        s.push_str(&b.name);
        s.push('\n');
        match &b.capture {
            IrCapture::Code(code) => {
                let (protocol, address, command) = code_to_file(code);
                s.push_str("type: parsed\n");
                s.push_str("protocol: ");
                s.push_str(&protocol);
                s.push('\n');
                s.push_str("address: ");
                s.push_str(&hex::encode_le_u32_bytes(address));
                s.push('\n');
                s.push_str("command: ");
                s.push_str(&hex::encode_le_u32_bytes(command));
                s.push('\n');
            }
            IrCapture::Raw(raw) => {
                s.push_str("type: raw\n");
                s.push_str(&format!("frequency: {}\n", (raw.khz as u32) * 1000));
                s.push_str("duty_cycle: 0.330000\n");
                s.push_str("data:");
                for t in &raw.timings {
                    s.push_str(&format!(" {t}"));
                }
                s.push('\n');
            }
        }
    }
    s
}

/// How address/command pack into [`IrCode::data`] for a file protocol.
#[derive(Clone, Copy, Debug)]
enum Pack {
    Nec8,
    Nec16,
    Sirc12,
    Sirc15,
    Sirc20,
    Rc5,
    Rc6,
    Kaseikyo,
    Pioneer,
    Generic,
}

/// One row: file aliases + write name + device protocol + pack/unpack rules.
struct FileProto {
    aliases: &'static [&'static str],
    wire_name: &'static str,
    device: Protocol,
    pack: Pack,
}

const FILE_PROTOS: &[FileProto] = &[
    FileProto {
        aliases: &["nec"],
        wire_name: "NEC",
        device: Protocol::Nec,
        pack: Pack::Nec8,
    },
    FileProto {
        aliases: &["necext"],
        wire_name: "NECext",
        device: Protocol::Nec,
        pack: Pack::Nec16,
    },
    FileProto {
        aliases: &["nec42", "nec42ext"],
        wire_name: "NEC",
        device: Protocol::Nec,
        pack: Pack::Nec8,
    },
    FileProto {
        aliases: &["samsung32", "samsung"],
        wire_name: "Samsung32",
        device: Protocol::Samsung,
        pack: Pack::Nec8,
    },
    FileProto {
        aliases: &["rc5", "rc5x"],
        wire_name: "RC5",
        device: Protocol::Rc5,
        pack: Pack::Rc5,
    },
    FileProto {
        aliases: &["rc6"],
        wire_name: "RC6",
        device: Protocol::Rc6,
        pack: Pack::Rc6,
    },
    FileProto {
        aliases: &["sirc", "sony"],
        wire_name: "SIRC",
        device: Protocol::Sony,
        pack: Pack::Sirc12,
    },
    FileProto {
        aliases: &["sirc15"],
        wire_name: "SIRC15",
        device: Protocol::Sony,
        pack: Pack::Sirc15,
    },
    FileProto {
        aliases: &["sirc20"],
        wire_name: "SIRC20",
        device: Protocol::Sony,
        pack: Pack::Sirc20,
    },
    FileProto {
        aliases: &["kaseikyo", "panasonic"],
        wire_name: "Kaseikyo",
        device: Protocol::Panasonic,
        pack: Pack::Kaseikyo,
    },
    FileProto {
        aliases: &["pioneer"],
        wire_name: "Pioneer",
        device: Protocol::Pioneer,
        pack: Pack::Pioneer,
    },
];

fn lookup_file_proto(name: &str) -> Option<&'static FileProto> {
    let n = name.to_ascii_lowercase();
    FILE_PROTOS
        .iter()
        .find(|p| p.aliases.iter().any(|a| *a == n))
}

fn by_pack(kind: Pack) -> &'static FileProto {
    FILE_PROTOS
        .iter()
        .find(|p| std::mem::discriminant(&p.pack) == std::mem::discriminant(&kind))
        .unwrap()
}

fn pack_for_code(code: &IrCode) -> (Pack, &'static str) {
    match code.protocol {
        Protocol::Nec => {
            let d = code.data as u32;
            let b3 = (d >> 24) & 0xFF;
            let b2 = (d >> 16) & 0xFF;
            let fp = if b2 == (b3 ^ 0xFF) {
                by_pack(Pack::Nec8)
            } else {
                by_pack(Pack::Nec16)
            };
            (fp.pack, fp.wire_name)
        }
        Protocol::Sony if code.bits == 15 => {
            let fp = by_pack(Pack::Sirc15);
            (fp.pack, fp.wire_name)
        }
        Protocol::Sony if code.bits == 20 => {
            let fp = by_pack(Pack::Sirc20);
            (fp.pack, fp.wire_name)
        }
        Protocol::Sony => {
            let fp = by_pack(Pack::Sirc12);
            (fp.pack, fp.wire_name)
        }
        Protocol::Samsung => {
            let fp = FILE_PROTOS
                .iter()
                .find(|p| p.device == Protocol::Samsung)
                .unwrap();
            (fp.pack, fp.wire_name)
        }
        Protocol::Rc5 => {
            let fp = by_pack(Pack::Rc5);
            (fp.pack, fp.wire_name)
        }
        Protocol::Rc6 => {
            let fp = by_pack(Pack::Rc6);
            (fp.pack, fp.wire_name)
        }
        Protocol::Panasonic => {
            let fp = by_pack(Pack::Kaseikyo);
            (fp.pack, fp.wire_name)
        }
        Protocol::Pioneer => {
            let fp = by_pack(Pack::Pioneer);
            (fp.pack, fp.wire_name)
        }
        _ => (Pack::Generic, code.protocol.name()),
    }
}

fn parsed_to_code(protocol: &str, address: u32, command: u32) -> Result<IrCode> {
    if let Some(fp) = lookup_file_proto(protocol) {
        let (data, bits) = pack(fp.pack, address, command);
        return Ok(IrCode {
            protocol: fp.device,
            data,
            bits,
        });
    }
    let proto = Protocol::from_name(protocol)
        .with_context(|| format!("unsupported IR protocol '{protocol}'"))?;
    let (data, bits) = pack(Pack::Generic, address, command);
    Ok(IrCode {
        protocol: proto,
        data,
        bits,
    })
}

fn code_to_file(code: &IrCode) -> (String, u32, u32) {
    let (kind, wire_name) = pack_for_code(code);
    let (address, command) = unpack(kind, code.data, code.bits);
    (wire_name.to_string(), address, command)
}

fn pack(kind: Pack, address: u32, command: u32) -> (u64, u16) {
    match kind {
        Pack::Nec8 => (
            encode_nec((address & 0xFF) as u16, (command & 0xFF) as u16),
            32,
        ),
        Pack::Nec16 => (
            encode_nec((address & 0xFFFF) as u16, (command & 0xFFFF) as u16),
            32,
        ),
        Pack::Sirc12 => (
            ((command & 0x7F) as u64) | (((address & 0x1F) as u64) << 7),
            12,
        ),
        Pack::Sirc15 => (
            ((command & 0x7F) as u64) | (((address & 0xFF) as u64) << 7),
            15,
        ),
        Pack::Sirc20 => (
            ((command & 0x7F) as u64) | (((address & 0x1FFF) as u64) << 7),
            20,
        ),
        Pack::Rc5 => (((address & 0x1F) << 6) as u64 | (command & 0x3F) as u64, 12),
        Pack::Rc6 => (((address & 0xFF) as u64) << 8 | (command & 0xFF) as u64, 20),
        Pack::Kaseikyo => ((address as u64) | ((command as u64) << 32), 48),
        Pack::Pioneer => (
            (address as u64) & 0xFFFF | ((command as u64) & 0xFFFF) << 16,
            32,
        ),
        Pack::Generic => ((address as u64) | ((command as u64) << 32), 0),
    }
}

fn unpack(kind: Pack, data: u64, _bits: u16) -> (u32, u32) {
    match kind {
        Pack::Nec8 | Pack::Nec16 => decode_nec(data),
        Pack::Sirc12 => ((data >> 7) as u32 & 0x1F, data as u32 & 0x7F),
        Pack::Sirc15 => ((data >> 7) as u32 & 0xFF, data as u32 & 0x7F),
        Pack::Sirc20 => ((data >> 7) as u32 & 0x1FFF, data as u32 & 0x7F),
        Pack::Rc5 => (((data >> 6) as u32) & 0x1F, data as u32 & 0x3F),
        Pack::Rc6 => (((data >> 8) as u32) & 0xFF, data as u32 & 0xFF),
        Pack::Kaseikyo => (data as u32, (data >> 32) as u32),
        Pack::Pioneer => (data as u32 & 0xFFFF, (data >> 16) as u32 & 0xFFFF),
        Pack::Generic => (data as u32, (data >> 32) as u32),
    }
}

/// Pack address/command the way the device stack expects for NEC-family TX.
fn encode_nec(address: u16, command: u16) -> u64 {
    let mut command = (command & 0xFF) as u32;
    command = reverse_bits(command, 8);
    command = (command << 8) + (command ^ 0xFF);
    if address > 0xFF {
        let address = reverse_bits(address as u32, 16);
        ((address as u64) << 16) + command as u64
    } else {
        let address = reverse_bits(address as u32, 8);
        ((address as u64) << 24) + (((address as u64) ^ 0xFF) << 16) + command as u64
    }
}

/// Inverse of [`encode_nec`] for 8-bit and 16-bit address forms.
fn decode_nec(data: u64) -> (u32, u32) {
    let d = data as u32;
    let b3 = (d >> 24) & 0xFF;
    let b2 = (d >> 16) & 0xFF;
    let b1 = (d >> 8) & 0xFF;
    // Normal NEC: byte3 = rev(addr), byte2 = ~byte3.
    if b2 == (b3 ^ 0xFF) {
        let address = reverse_bits(b3, 8);
        let command = reverse_bits(b1, 8);
        (address, command)
    } else {
        // Extended: high 16 bits are rev(address).
        let address = reverse_bits((d >> 16) & 0xFFFF, 16);
        let command = reverse_bits(b1, 8);
        (address, command)
    }
}

fn reverse_bits(v: u32, n: u8) -> u32 {
    let mut x = v & ((1u32 << n) - 1);
    let mut r = 0u32;
    for _ in 0..n {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"Filetype: IR signals file
Version: 1
#
name: Power
type: parsed
protocol: NECext
address: 00 DF 00 00
command: 10 EF 00 00
#
name: Custom
type: raw
frequency: 38000
duty_cycle: 0.330000
data: 9000 4500 560 560 560 1690
"#;

    #[test]
    fn parse_sample_remote() {
        let r = IrRemote::parse(SAMPLE).unwrap();
        assert_eq!(r.filetype, SIGNALS_HEADER);
        assert_eq!(r.version, 1);
        assert_eq!(r.buttons.len(), 2);
        assert_eq!(r.buttons[0].name, "Power");
        match &r.buttons[0].capture {
            IrCapture::Code(c) => {
                assert_eq!(c.protocol, Protocol::Nec);
                assert_eq!(c.bits, 32);
                assert_ne!(c.data, 0);
            }
            _ => panic!("expected code"),
        }
        match &r.buttons[1].capture {
            IrCapture::Raw(raw) => {
                assert_eq!(raw.khz, 38);
                assert_eq!(raw.timings, vec![9000, 4500, 560, 560, 560, 1690]);
            }
            _ => panic!("expected raw"),
        }
    }

    #[test]
    fn nec_button_is_code() {
        let b = IrRemote::parse(SAMPLE).unwrap().buttons.remove(0);
        match b.capture {
            IrCapture::Code(c) => assert_eq!(c.protocol, Protocol::Nec),
            _ => panic!("expected code"),
        }
    }

    #[test]
    fn parse_strict_requires_header() {
        assert!(IrRemote::parse_strict(SAMPLE).is_ok());
        // Valid buttons but no Filetype header -> rejected.
        assert!(IrRemote::parse_strict("name: X\ntype: parsed\nprotocol: NEC\n").is_err());
        assert!(IrRemote::parse_strict("Filetype: something else\n").is_err());
    }

    #[test]
    fn device_csv_skips_raw() {
        let (csv, skipped) = IrRemote::parse(SAMPLE).unwrap().to_device_csv();
        // Power (NEC=3) is emitted; Custom (raw) is skipped.
        assert!(csv.starts_with("Power,0x"));
        assert!(csv.trim_end().ends_with(",3"));
        assert_eq!(skipped, vec!["Custom".to_string()]);
    }

    #[test]
    fn raw_roundtrip_write() {
        let r = IrRemote::parse(SAMPLE).unwrap();
        let text = r.to_ir_string();
        let r2 = IrRemote::parse(&text).unwrap();
        assert_eq!(r.buttons.len(), r2.buttons.len());
        assert_eq!(r.buttons[1].name, r2.buttons[1].name);
        assert_eq!(r.buttons[1].capture, r2.buttons[1].capture);
    }

    #[test]
    fn nec_parsed_roundtrip_keeps_data() {
        let r = IrRemote::parse(SAMPLE).unwrap();
        let text = r.to_ir_string();
        let r2 = IrRemote::parse(&text).unwrap();
        assert_eq!(r.buttons[0].capture, r2.buttons[0].capture);
    }

    #[test]
    fn pack_unpack_nec8() {
        let (data, bits) = pack(Pack::Nec8, 0x20, 0xDF);
        assert_eq!(bits, 32);
        let (a, c) = unpack(Pack::Nec8, data, bits);
        assert_eq!((a, c), (0x20, 0xDF));
    }

    #[test]
    fn pack_unpack_roundtrips() {
        let cases = [
            (Pack::Nec8, 0x20, 0xDF),
            (Pack::Nec16, 0x1234, 0x56),
            (Pack::Sirc12, 0x1F, 0x7F),
            (Pack::Sirc15, 0xFF, 0x7F),
            (Pack::Sirc20, 0x1FFF, 0x7F),
            (Pack::Rc5, 0x1F, 0x3F),
            (Pack::Rc6, 0xFF, 0xFF),
            (Pack::Kaseikyo, 0xDEAD, 0xBEEF),
            (Pack::Pioneer, 0xABCD, 0x1234),
            (Pack::Generic, 0x1122, 0x3344),
        ];
        for (kind, a, c) in cases {
            let (data, _) = pack(kind, a, c);
            assert_eq!(unpack(kind, data, 0), (a, c), "roundtrip {kind:?}");
        }
    }

    #[test]
    fn find_button_by_name_and_index() {
        let r = IrRemote::parse(SAMPLE).unwrap();
        assert_eq!(r.find_button("Power").unwrap().name, "Power");
        assert_eq!(r.find_button("2").unwrap().name, "Custom");
    }

    #[test]
    fn from_captures_raw() {
        let caps = vec![IrCapture::Raw(RawIr {
            khz: 38,
            timings: vec![100, 200],
        })];
        let r = IrRemote::from_captures(&caps);
        assert_eq!(r.buttons[0].name, "Capture_1");
        let text = r.to_ir_string();
        assert!(text.contains("type: raw"));
        assert!(text.contains("frequency: 38000"));
    }
}
