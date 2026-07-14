//! HID report descriptors, parameterized by report ID. Presets and the live-input bridge assemble
//! the same composite maps from these, so a single device can carry keyboard + mouse + gamepad on
//! distinct report IDs.

use infishark::hex;

/// One HID input class the CLI can emulate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidClass {
    Keyboard,
    Mouse,
    Gamepad,
    Consumer,
    Tablet,
    System,
}

// report IDs are assigned by position in this list, so a standalone preset stays report 1 and
// `keyboard+mouse` stays 1,2.
const CANON: [HidClass; 6] = [
    HidClass::Keyboard,
    HidClass::Mouse,
    HidClass::Gamepad,
    HidClass::Consumer,
    HidClass::Tablet,
    HidClass::System,
];

/// GAP HID appearance codes (Bluetooth Assigned Numbers, category 0x00F).
pub const APPEARANCE_GENERIC: u16 = 0x03C0;
pub const APPEARANCE_KEYBOARD: u16 = 0x03C1;
pub const APPEARANCE_MOUSE: u16 = 0x03C2;
pub const APPEARANCE_JOYSTICK: u16 = 0x03C3;
pub const APPEARANCE_GAMEPAD: u16 = 0x03C4;
pub const APPEARANCE_DIGITIZER: u16 = 0x03C5;

impl HidClass {
    pub fn label(self) -> &'static str {
        match self {
            HidClass::Keyboard => "keyboard",
            HidClass::Mouse => "mouse",
            HidClass::Gamepad => "gamepad",
            HidClass::Consumer => "consumer",
            HidClass::Tablet => "tablet",
            HidClass::System => "system",
        }
    }

    pub fn appearance(self) -> u16 {
        match self {
            HidClass::Keyboard => APPEARANCE_KEYBOARD,
            HidClass::Mouse => APPEARANCE_MOUSE,
            HidClass::Gamepad => APPEARANCE_GAMEPAD,
            HidClass::Consumer => APPEARANCE_GENERIC,
            HidClass::Tablet => APPEARANCE_DIGITIZER,
            HidClass::System => APPEARANCE_GENERIC,
        }
    }

    // The report-map collection (hex) for this class, minus the report-ID byte. `collection(id)`
    // inserts `85 <id>` right after the top-level collection.
    fn descriptor(self) -> (&'static str, &'static str) {
        match self {
            // 8-byte keyboard input (modifier + reserved + 6 keys) + 1-byte LED output.
            HidClass::Keyboard => (
                "05010906a101",
                "050719e029e7150025017501950881029501750881039505750105081901290591029501750391039506750815002565050719002965\
                 8100c0",
            ),
            // 4-byte mouse input: buttons + dx + dy + wheel.
            HidClass::Mouse => (
                "05010902a101",
                "0901a1000509190129051500250175019505810275039501810305010930093109381581257f750895038106c0c0",
            ),
            // 6-byte gamepad input: 16 buttons + 4 axes (X, Y, Z, Rz), signed -127..127.
            HidClass::Gamepad => (
                "05010905a101",
                "05091901291015002501951075018102050109300931093209351581257f750895048102c0",
            ),
            // 2-byte consumer-control input (a single usage code).
            HidClass::Consumer => ("050c0901a101", "150026ff0319002aff03751095018100c0"),
            // 5-byte pen digitizer: tip + in-range flags (+6 pad), then absolute X/Y (0..32767).
            HidClass::Tablet => (
                "050d0902a101",
                "094209321500250175019502810295068103050109300931150026ff7f751095028102c0",
            ),
            // 1-byte system control: power / sleep / wake bits (+5 pad).
            HidClass::System => ("05010980a101", "0981098209831500250175019503810295058103c0"),
        }
    }

    fn collection(self, id: u8) -> String {
        let (prefix, rest) = self.descriptor();
        format!("{prefix}85{id:02x}{}", rest.replace([' ', '\n'], ""))
    }

    // Reports this class declares at the given ID (keyboard adds an LED output).
    fn reports(self, id: u8) -> Vec<serde_json::Value> {
        let mut r = vec![serde_json::json!({ "id": id, "type": "input" })];
        if self == HidClass::Keyboard {
            r.push(serde_json::json!({ "id": id, "type": "output" }));
        }
        r
    }
}

/// Name for a GAP HID appearance code. Emulated classes come from the single source in `HidClass`; joystick/tablet are recognized for display but aren't emulated.
pub fn appearance_label(appearance: u16) -> &'static str {
    if let Some(c) = CANON.iter().find(|c| c.appearance() == appearance) {
        return c.label();
    }
    match appearance {
        APPEARANCE_JOYSTICK => "joystick",
        _ => "device",
    }
}

/// JSON for an input report sent to the device.
pub fn input_report(id: u8, bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({ "id": id, "type": "input", "hex": hex::encode(bytes) })
}

/// An 8-byte boot-keyboard input report as a HID_SEND spec.
pub fn hid_key_report(id: u8, modifier: u8, usage: u8) -> serde_json::Value {
    input_report(id, &[modifier, 0, usage, 0, 0, 0, 0, 0])
}

/// Map a printable ASCII character to (modifier, HID usage); SHIFT = 0x02.
pub fn ascii_to_hid(c: char) -> Option<(u8, u8)> {
    const SHIFT: u8 = 0x02;
    Some(match c {
        'a'..='z' => (0, 0x04 + (c as u8 - b'a')),
        'A'..='Z' => (SHIFT, 0x04 + (c as u8 - b'A')),
        '1'..='9' => (0, 0x1e + (c as u8 - b'1')),
        '0' => (0, 0x27),
        '\n' => (0, 0x28),
        '\t' => (0, 0x2b),
        ' ' => (0, 0x2c),
        '!' => (SHIFT, 0x1e),
        '@' => (SHIFT, 0x1f),
        '#' => (SHIFT, 0x20),
        '$' => (SHIFT, 0x21),
        '%' => (SHIFT, 0x22),
        '^' => (SHIFT, 0x23),
        '&' => (SHIFT, 0x24),
        '*' => (SHIFT, 0x25),
        '(' => (SHIFT, 0x26),
        ')' => (SHIFT, 0x27),
        '-' => (0, 0x2d),
        '_' => (SHIFT, 0x2d),
        '=' => (0, 0x2e),
        '+' => (SHIFT, 0x2e),
        '[' => (0, 0x2f),
        '{' => (SHIFT, 0x2f),
        ']' => (0, 0x30),
        '}' => (SHIFT, 0x30),
        '\\' => (0, 0x31),
        '|' => (SHIFT, 0x31),
        ';' => (0, 0x33),
        ':' => (SHIFT, 0x33),
        '\'' => (0, 0x34),
        '"' => (SHIFT, 0x34),
        '`' => (0, 0x35),
        '~' => (SHIFT, 0x35),
        ',' => (0, 0x36),
        '<' => (SHIFT, 0x36),
        '.' => (0, 0x37),
        '>' => (SHIFT, 0x37),
        '/' => (0, 0x38),
        '?' => (SHIFT, 0x38),
        _ => return None,
    })
}

/// Canonicalize + dedup a class set and assign 1-based report IDs by position.
pub fn assign(classes: &[HidClass]) -> Vec<(HidClass, u8)> {
    let mut out = Vec::new();
    let mut id = 1u8;
    for c in CANON {
        if classes.contains(&c) {
            out.push((c, id));
            id += 1;
        }
    }
    out
}

/// Assemble a composite spec of (report_map_hex, reports, appearance) for the given classes.
/// Appearance follows the first (highest-priority) class.
pub fn composite(classes: &[HidClass]) -> (String, Vec<serde_json::Value>, u16) {
    let assigned = assign(classes);
    let mut map = String::new();
    let mut reports = Vec::new();
    for (c, id) in &assigned {
        map.push_str(&c.collection(*id));
        reports.extend(c.reports(*id));
    }
    let appearance = assigned
        .first()
        .map(|(c, _)| c.appearance())
        .unwrap_or(0x03C1);
    (map, reports, appearance)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The proven keyboard(ID 1) + mouse(ID 2) composite descriptor, verbatim.
    const GOLDEN_COMBO: &str = "05010906a1018501050719e029e7150025017501950881029501750881039505750105081901290591029501750391039506750815002565050719002965 8100c0\
 05010902a10185020901a1000509190129051500250175019505810275039501810305010930093109381581257f750895038106c0c0";

    #[test]
    fn combo_matches_known_descriptor_byte_for_byte() {
        let (map, reports, appearance) = composite(&[HidClass::Keyboard, HidClass::Mouse]);
        assert_eq!(map, GOLDEN_COMBO.replace([' ', '\n'], ""));
        assert_eq!(appearance, 0x03C1);
        // keyboard input(1) + keyboard LED output(1) + mouse input(2)
        assert_eq!(reports.len(), 3);
        assert_eq!(reports[0]["id"], 1);
        assert_eq!(reports[1]["type"], "output");
        assert_eq!(reports[2]["id"], 2);
    }

    #[test]
    fn assign_is_canonical_and_deduped() {
        let ids = assign(&[HidClass::Gamepad, HidClass::Keyboard, HidClass::Keyboard]);
        assert_eq!(ids, vec![(HidClass::Keyboard, 1), (HidClass::Gamepad, 2)]);
    }

    #[test]
    fn standalone_class_uses_report_id_1() {
        assert_eq!(assign(&[HidClass::Mouse]), vec![(HidClass::Mouse, 1)]);
    }

    #[test]
    fn tablet_and_system_compose_after_the_core_classes() {
        let (map, reports, appearance) =
            composite(&[HidClass::Keyboard, HidClass::Tablet, HidClass::System]);
        assert_eq!(appearance, HidClass::Keyboard.appearance());
        // keyboard input(1) + keyboard LED output(1) + tablet input(2) + system input(3)
        assert_eq!(reports.len(), 4);
        assert!(map.contains("050d0902a1018502"));
        assert!(map.contains("05010980a1018503"));
        assert_eq!(appearance_label(HidClass::Tablet.appearance()), "tablet");
    }
}
