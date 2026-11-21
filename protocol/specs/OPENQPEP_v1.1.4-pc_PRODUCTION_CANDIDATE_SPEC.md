# OpenQPEP Production Candidate 1.1.4 (`v1.1.4-pc`) — Frozen Specification

**Release Channel:** `PC` (Production Candidate)  
**Version:** `1.1.0-pc` (`OpenQPEP/PC-1.1.4`)  
**Publisher:** Calyx Labs Inc. (`support@calyxlabsinc.org`)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

## Breaking Production Candidate 1.1.4 Security Baseline
- **Zero Legacy Beta Compatibility:** All pre-PC `-beta` wire magics (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`), raw unframed JSON armor fallbacks, and legacy `kdf_version: 1` (Scrypt-only) `.qpkrf` key rings are **strictly rejected**.
- **Strict Frozen Wire Format v3 & Compact TLV v3.1:** Every packet emits and verifies `\x89QPE\x03\x00` (canonical) or `\x89QPE\x03\x01` (compact TLV).
- **Mandatory Memory-Hard KDF (`kdf_version: 2`):** Every encrypted `.qpkrf` private key ring uses RFC 9106 `QPKD-Argon2id + qSponge-512` with hardware-calibrated memory parameters.
- **Complete 8-Suite & 12-Protocol Stack:** `QLX-768`..`QLX-16384`, `QVS-65`..`QVS-1024`, Calyx Sovereign-Pentad `Calyx Sovereign-Pentad (CSP-Omega)`, Calyx Goppa-Monolith `CGM-8192`, Calyx Rank-Metric Tensor `CRT-RSD512`, `QPEP-Ratchet`, `QPEP-MLS`, `QPEP-AKE`, `QPEP-KT`, `FIDO2-PRF`, `QVS-Ring`, `BlindSearchVault`, `TKEM`, `Sphinx-PQ`, `LT-QR`, `DeniableVault`, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.
- **5-Language Runtime Conformance:** Python Reference, C99/AVX2/NEON (`libopenqpep`), Rust (`openqpep-core`), WASM SIMD128 (`wasm_bridge.mjs`), and Go (`go/openqpep`).

## All 10 OpenQPEP Post-Quantum Suites (`v1.1.4-pc`)

Every OpenQPEP suite uses the canonical naming standard `"Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"` paired with **CC-512 AEAD**, **RFC 9106 QPKD-Argon2id + qSponge-512 (`kdf_version: 2`)**, and **Frozen Wire Format v3 (`\x89QPE\x03\x00`) / Compact TLV v3.1 (`\x89QPE\x03\x01`)**.

| Canonical Suite Name | KEM + Signature | Mathematical Family | Hardware Classification | Primary Role |
| :--- | :--- | :--- | :--- | :--- |
| **Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)** | `QLX-4096` + `QVS-256` | Structured Module-LWE (`k=16`, 4,096-dim) + Hybrid X448 | **All Devices** | Default flagship security for mobile & desktop |
| **Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)** | `QLX-768` + `QVS-65` | Structured Module-LWE (`k=3`, 768-dim) + Hybrid X448 | **All Devices** | Lowest-latency mobile messaging & constrained links |
| **Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)** | `QLX-1024` + `QVS-87` | Structured Module-LWE (`k=4`, 1,024-dim) + Hybrid X448 | **All Devices** | Balanced NIST-Level-5-class lattice security |
| **Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)** | `QLX-2048` + `QVS-128` | Structured Module-LWE (`k=8`, 2,048-dim) + Hybrid X448 | **All Devices** | Elevated 2,048-dimensional lattice margin |
| **Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)** | `CIF-SQI-512` + `QHS-512` | 2D Supersingular Abelian Isogeny + Stateless Hash-Based Hypertree | **All Devices** | Beyond-LWE compact isogeny key exchange & hash signatures |
| **Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)** | `CRT-RSD512` + `QMQ-512` | Rank-Metric Syndrome Decoding + Multivariate Quadratic (`MQ`) | **All Devices** | Beyond-LWE rank-metric code & multivariate diversity |
| **Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)** | `QLX-16384` + `QVS-1024` | 4-Manifold Coupled Module-LWE (`k=64`, 16,384-dim) + `16×14` QVS | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Maximum structured-lattice dimension (~69 KB secret vectors) |
| **Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)** | `CGM-8192` + `QHS-512` | Classic McEliece-class Binary Goppa Code (`n=8192`) + Hash Hypertree | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Beyond-LWE conservative code-based encryption (large public matrix) |
| **Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)** | `CULC-2048` + `CGM-8192` | Unstructured Plain-LWE (`n×n` ring-free) + Binary Goppa Code | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Zero algebraic ring-structure defense against ring/ideal-lattice attacks |
| **Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)** | `CSP-Omega` + `QHS-512` | 5-Family Combiner (Plain-LWE + Goppa + 2D Isogeny + MQ + Hash + X448) | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Ultimate multi-assumption citadel; secure if any 1 of 5 families holds |
