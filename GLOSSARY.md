# InfiShark CLI

Language for inspecting BLE GATT values and reusing IR captures with a BLEShark Nano.

## Language

**Characteristic value**:
The ordered bytes read from a GATT characteristic or received in a notification or indication. A display of those bytes does not change the value.

**ASCII display**:
A view of a characteristic value that shows printable ASCII bytes as text and represents other bytes with visible escapes.
_Avoid_: Raw text

**Readable ASCII value**:
A nonempty characteristic value containing only printable ASCII bytes, tabs, carriage returns, or newlines. This is a byte-level test for a useful text preview, not an interpretation of the characteristic's meaning.

**Automatic inspection display**:
A view that always shows a characteristic value in hexadecimal and adds a quoted text preview when it is a readable ASCII value.

**Spaced hex display**:
A view of a characteristic value that shows each byte as two hexadecimal digits, with spaces between bytes.

**Bits display**:
A view of a characteristic value as groups of eight textual zero and one digits, one group per byte with the most significant bit first.
_Avoid_: Binary output

**Raw value**:
The exact bytes of a characteristic value, without text conversion, escapes, labels, or added separators.
_Avoid_: Binary output

**Characteristic polling**:
Repeated host-initiated reads of a GATT characteristic to inspect its value over time.
_Avoid_: Notifications, subscription

**Read cycle**:
One ordered pass through the selected GATT characteristics, reading each resolved characteristic once.
_Avoid_: Sample, when referring to an entire selected group

**IR capture**:
A decoded infrared code or raw carrier waveform retained from the most recent receive session.

**Capture index**:
The one-based number of an IR capture in the retained receive table.
