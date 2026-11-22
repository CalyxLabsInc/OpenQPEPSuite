//! Official OpenQPEP 1.0.0 Wire Format v5 (\x89QPE\x05\x00) and Compact TLV v5.1 (\x89QPE\x05\x01).
//! Hard Clean Break: Zero Backwards Compatibility with legacy -rc (\x04), -pc (\x03), or -beta (\x01/\x02) frames.
pub const WIRE_MAGIC_V5: [u8; 6] = *b"\x89QPE\x05\x00";
pub const WIRE_MAGIC_V5_1: [u8; 6] = *b"\x89QPE\x05\x01";
pub const LEGACY_WIRE_MAGIC_V4: [u8; 6] = *b"\x89QPE\x04\x00";
pub const LEGACY_WIRE_MAGIC_V4_1: [u8; 6] = *b"\x89QPE\x04\x01";
pub const LEGACY_WIRE_MAGIC_V3: [u8; 6] = *b"\x89QPE\x03\x00";
pub const LEGACY_WIRE_MAGIC_V3_1: [u8; 6] = *b"\x89QPE\x03\x01";

pub fn is_supported_magic(hdr: &[u8]) -> bool {
    hdr.len() >= 6 && (hdr[..6] == WIRE_MAGIC_V5_1 || hdr[..6] == WIRE_MAGIC_V5)
}

pub fn is_legacy_prerelease_magic(hdr: &[u8]) -> bool {
    hdr.len() >= 6
        && (hdr[..6] == LEGACY_WIRE_MAGIC_V4
            || hdr[..6] == LEGACY_WIRE_MAGIC_V4_1
            || hdr[..6] == LEGACY_WIRE_MAGIC_V3
            || hdr[..6] == LEGACY_WIRE_MAGIC_V3_1
            || (hdr[..4] == *b"\x89QPE" && (hdr[4] == 0x01 || hdr[4] == 0x02)))
}
