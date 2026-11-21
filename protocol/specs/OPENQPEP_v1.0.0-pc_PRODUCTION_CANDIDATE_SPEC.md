# OpenQPEP Production Candidate 1.0.0 (`v1.0.0-pc`) — Frozen Specification

**Release Channel:** `PC` (Production Candidate)  
**Version:** `1.0.0-pc` (`OpenQPEP/PC-1.0.0`)  
**Publisher:** Calyx Labs Inc. (`support@calyxlabsinc.org`)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

## Breaking Production Candidate 1.0.0 Security Baseline
- **Zero Legacy Beta Compatibility:** All pre-PC `-beta` wire magics (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`), raw unframed JSON armor fallbacks, and legacy `kdf_version: 1` (Scrypt-only) `.qpkrf` key rings are **strictly rejected**.
- **Strict Frozen Wire Format v3 & Compact TLV v3.1:** Every packet emits and verifies `\x89QPE\x03\x00` (canonical) or `\x89QPE\x03\x01` (compact TLV).
- **Mandatory Memory-Hard KDF (`kdf_version: 2`):** Every encrypted `.qpkrf` private key ring uses RFC 9106 `QPKD-Argon2id + qSponge-512` with hardware-calibrated memory parameters.
- **Complete 8-Suite & 12-Protocol Stack:** `QLX-768`..`QLX-16384`, `QVS-65`..`QVS-1024`, Tier 10 `Calyx Sovereign-Pentad (CSP-Omega)`, Tier 11 `CGM-8192`, Tier 12 `RMT-512`, `QPEP-Ratchet`, `QPEP-MLS`, `QPEP-AKE`, `QPEP-KT`, `FIDO2-PRF`, `QVS-Ring`, `BlindSearchVault`, `TKEM`, `Sphinx-PQ`, `LT-QR`, `DeniableVault`, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.
- **5-Language Runtime Conformance:** Python Reference, C99/AVX2/NEON (`libopenqpep`), Rust (`openqpep-core`), WASM SIMD128 (`wasm_bridge.mjs`), and Go (`go/openqpep`).
