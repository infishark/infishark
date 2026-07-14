//! CRC16-CCITT / CCITT-FALSE
pub fn crc16_ccitt(data: &[u8], init: u16) -> u16 {
    let mut crc = init;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccitt_false_check_vector() {
        assert_eq!(crc16_ccitt(b"123456789", 0xFFFF), 0x29B1);
    }

    #[test]
    fn empty_input_returns_init() {
        assert_eq!(crc16_ccitt(b"", 0xFFFF), 0xFFFF);
    }

    #[test]
    fn single_zero_byte_from_default_init() {
        assert_eq!(crc16_ccitt(&[0x00], 0xFFFF), 0xE1F0);
    }
}
