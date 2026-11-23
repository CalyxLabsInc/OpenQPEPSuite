//! OpenQPEP Memory-Safe Rust Core (`openqpep-core` v1.1.0, CPOSLS-1.0).
#![forbid(unsafe_code)]
pub mod ntt;
pub mod wire_v5;

/// Compiler-barrier slice zeroization for secret lattice vectors and session keys (v1.1.0).
pub fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(buf);
}

/// Constant-time byte-slice comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
