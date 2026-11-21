//! Frozen OpenQPEP Production Candidate 1.1.7 Wire Format v3 (\x89QPE\x03\x00) and Compact v3.1 (\x89QPE\x03\x01).
pub const WIRE_MAGIC_V3: [u8; 6] = *b"\x89QPE\x03\x00";
pub const WIRE_MAGIC_V3_1: [u8; 6] = *b"\x89QPE\x03\x01";

pub fn is_supported_magic(hdr: &[u8]) -> bool {
    hdr.len() >= 6 && (hdr[..6] == WIRE_MAGIC_V3_1 || hdr[..6] == WIRE_MAGIC_V3)
}
