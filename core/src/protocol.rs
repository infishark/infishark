//! Wire constants

#![allow(dead_code)]

pub const MAGIC: [u8; 3] = [0xB5, 0x5A, 0xC1];
pub const VERSION: u8 = 0x01;
pub const MAX_PAYLOAD: usize = 512;

pub const PIXEL_MAGIC: [u8; 3] = [0xAA, 0x55, 0xF0];

// version, type, seq_le, len_le
pub const HDR_LEN: usize = 6;

pub const PKT_COMMAND: u8 = 0x10;
pub const PKT_RESPONSE: u8 = 0x11;
pub const PKT_EVENT: u8 = 0x12;
pub const PKT_ERROR: u8 = 0x7F;

// Opcode groups (high byte). group<<8 | index.
pub const GRP_SYSTEM: u8 = 0x00;
pub const GRP_WIFI: u8 = 0x01;
pub const GRP_BLE: u8 = 0x02;
pub const GRP_IR: u8 = 0x03;
pub const GRP_MESH: u8 = 0x04;
pub const GRP_FILES: u8 = 0x05;
pub const GRP_CONTROL: u8 = 0x7F;

// Command opcodes
// 0x00 SYSTEM
pub const CMD_DEVICE_INFO: u16 = 0x0001;
pub const CMD_SYSTEM_STATUS: u16 = 0x0002;
// Planned; not yet wired into the SDK.
pub const CMD_TELEMETRY_SUBSCRIBE: u16 = 0x0003;
pub const CMD_OLED_STREAM_SET: u16 = 0x0004;
pub const CMD_REBOOT: u16 = 0x0005;
pub const CMD_OTA_UPDATE: u16 = 0x0006;
pub const CMD_SETTINGS_GET: u16 = 0x0007;
pub const CMD_SETTINGS_SET: u16 = 0x0008;
// 0x01 WIFI
pub const CMD_WIFI_SCAN: u16 = 0x0100;
pub const CMD_WIFI_SAVED_LIST: u16 = 0x0101;
pub const CMD_WIFI_SAVED_ADD: u16 = 0x0102;
pub const CMD_WIFI_SAVED_DELETE: u16 = 0x0103;
pub const CMD_WIFI_PORTAL: u16 = 0x0113;
/// Host → device body chunk for [`EVT_PORTAL_REQUEST`].
pub const CMD_PORTAL_RESP: u16 = 0x0116;
pub const CMD_WIFI_RAW_TX: u16 = 0x0120;
pub const CMD_WIFI_RAW_MONITOR: u16 = 0x0121;
pub const CMD_WIFI_ADAPTER: u16 = 0x0122;
// 0x02 BLE
pub const CMD_BLE_SCAN: u16 = 0x0200;
pub const CMD_BLE_LIST: u16 = 0x0201;
pub const CMD_BLE_KEEPALIVE: u16 = 0x0202;
pub const CMD_BLE_RESET: u16 = 0x0203;
pub const CMD_BLE_HID: u16 = 0x0211;
pub const CMD_BLE_HID_SEND: u16 = 0x0212;
pub const CMD_BLE_ADV: u16 = 0x0213;
pub const CMD_BLE_SERVE: u16 = 0x0214;
pub const CMD_BLE_CHAR_SET: u16 = 0x0215;
pub const CMD_BLE_GATT_CONNECT: u16 = 0x0220;
pub const CMD_BLE_GATT_ENUM: u16 = 0x0221;
pub const CMD_BLE_GATT_READ: u16 = 0x0222;
pub const CMD_BLE_GATT_WRITE: u16 = 0x0223;
pub const CMD_BLE_GATT_SUBSCRIBE: u16 = 0x0224;
pub const CMD_BLE_GATT_UNSUBSCRIBE: u16 = 0x0225;
// 0x03 IR
pub const CMD_IR_RX: u16 = 0x0300;
pub const CMD_IR_TX: u16 = 0x0310;
pub const CMD_IR_TVBGONE: u16 = 0x0311;
pub const CMD_IR_RAW_TX: u16 = 0x0320;
// 0x04 MESH
pub const CMD_MESH_STATUS: u16 = 0x0400;
// Planned; not yet wired into the SDK.
pub const CMD_MESH_NODES: u16 = 0x0401;
pub const CMD_MESH_PING: u16 = 0x0402;
// 0x05 FILES
pub const CMD_FILES_LIST: u16 = 0x0500;
pub const CMD_FILES_READ_CHUNK: u16 = 0x0501;
pub const CMD_FILES_WRITE: u16 = 0x0502;
pub const CMD_FILES_DELETE: u16 = 0x0503;
// 0x7F CONTROL
pub const CMD_STOP: u16 = 0x7F00;

// Mesh scope prefix mode
pub const SCOPE_LOCAL: u8 = 0;
pub const SCOPE_FLEET: u8 = 1;
pub const SCOPE_LIST: u8 = 2;

// Response flags
pub const RESP_JSON: u8 = 1 << 0;
pub const RESP_MORE: u8 = 1 << 1;
pub const RESP_BINARY: u8 = 1 << 2;

// Error codes
pub const ERR_OK: u8 = 0;
pub const ERR_BAD_FRAME: u8 = 1;
pub const ERR_UNSUPPORTED_VERSION: u8 = 2;
pub const ERR_FORBIDDEN: u8 = 3;
pub const ERR_UNKNOWN_COMMAND: u8 = 4;
pub const ERR_BUSY: u8 = 5;
pub const ERR_INTERNAL: u8 = 6;
pub const ERR_BAD_ARGS: u8 = 7;
pub const ERR_NOT_FOUND: u8 = 8;

// Event ids
pub const EVT_TELEMETRY: u16 = 0x0001; // planned; not yet wired
pub const EVT_SCAN_DONE: u16 = 0x0002;
pub const EVT_TASK_DONE: u16 = 0x0003; // planned; not yet wired
pub const EVT_BLE_DEVICE: u16 = 0x0004;
pub const EVT_BLE_NOTIFY: u16 = 0x0005;
pub const EVT_WIFI_FRAME: u16 = 0x0006;
pub const EVT_ADAPTER_UP: u16 = 0x0007;
pub const EVT_BLE_WRITE: u16 = 0x0008;
pub const EVT_BLE_CONNECT: u16 = 0x0009;
pub const EVT_BLE_SUBSCRIBE: u16 = 0x000A;
pub const EVT_BLE_HID_OUTPUT: u16 = 0x000B;
pub const EVT_WIFI_DEVICE: u16 = 0x000C;
pub const EVT_IR: u16 = 0x000D;
pub const EVT_PORTAL_REQUEST: u16 = 0x000E;
