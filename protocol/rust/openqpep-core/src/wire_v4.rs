//! Frozen OpenQPEP Release Candidate 1.0.0 (v1.0.0-rc) Wire Format v4 (\x89QPE\x04\x00) and Compact v4.1 (\x89QPE\x04\x01).
//! Hard Clean Break: Zero Backwards Compatibility with legacy Production Candidate (-pc: \x89QPE\x03\x00 / \x03\x01).
pub const WIRE_MAGIC_V4: [u8; 6] = *b"\x89QPE\x04\x00";
pub const WIRE_MAGIC_V4_1: [u8; 6] = *b"\x89QPE\x04\x01";
pub const LEGACY_WIRE_MAGIC_V3: [u8; 6] = *b"\x89QPE\x03\x00";
pub const LEGACY_WIRE_MAGIC_V3_1: [u8; 6] = *b"\x89QPE\x03\x01";

pub fn is_supported_magic(hdr: &[u8]) -> bool {
    hdr.len() >= 6 && (hdr[..6] == WIRE_MAGIC_V4_1 || hdr[..6] == WIRE_MAGIC_V4)
}

pub fn is_legacy_pc_magic(hdr: &[u8]) -> bool {
    hdr.len() >= 6 && (hdr[..6] == LEGACY_WIRE_MAGIC_V3 || hdr[..6] == LEGACY_WIRE_MAGIC_V3_1)
}
