//! OpenQPEP Memory-Safe Rust Core (`openqpep-core` v1.0.0-rc, CPOSLS-1.0).
#![forbid(unsafe_code)]
pub mod ntt;
pub mod wire_v4;

/// Compiler-barrier slice zeroization for secret lattice vectors and session keys (v1.0.0-rc).
pub fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(buf);
}
