# OpenQPEP Suite — Production Candidate 1.2.0 (`v1.0.0`)

Official unified public repository for the **OpenQPEP Suite** by **Calyx Labs Inc.** (`https://github.com/CalyxLabsInc/OpenQPEPSuite/`), licensed universally under the **Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)**.

> **Proprietary Infrastructure Notice:** All Calyx Labs Inc. backend servers (`website_server`, `directory_server`, `messenger_server`, `calyxmail_backend`) and signing keystores are strictly proprietary and are intentionally excluded from this repository.

---

## Repository Structure

| Directory | Component | Version | Description |
| :--- | :--- | :--- | :--- |
| [`protocol/`](protocol/) | **OpenQPEP Core Protocol** | `1.0.0-pc` | Python reference engine, C99/AVX2/NEON `libopenqpep` source, WASM SIMD128 bridge, Rust `openqpep-core` crate, Go conformance port, formal Tamarin/ProVerif/Cryptol specs, 5 golden KAT suites, and 63 unit/audit tests |
| [`apps/calyx-qpep-client/`](apps/calyx-qpep-client/) | **Calyx QPEP Client** | `PC 1.2.0` (`vc263`) | Zero-telemetry post-quantum encryption/signing client for Android (`.apk` + source) and iOS (`.mobileconfig` + PWA) |
| [`apps/calyx-encrypted-messenger/`](apps/calyx-encrypted-messenger/) | **Calyx Encrypted Messenger (QPEM)** | `PC 1.2.0` (`vc26`) | End-to-end post-quantum encrypted messenger for Android (`.apk` + source) and iOS (`.mobileconfig`) |
| [`apps/calyx-encrypted-email/`](apps/calyx-encrypted-email/) | **Calyx Encrypted Email** | `PC 1.2.0` (`vc10`) | Post-quantum encrypted email client (`@calyxmail.org`) for Android (`.apk` + source) and iOS (`.mobileconfig`) |
| [`docs/`](docs/) | **Suite Documentation & Theses** | `1.0.0-pc` | Architecture guides, hypothetical beyond-LWE key tier theses, and public compliance documents |

---

## Cryptographic Baseline (`OpenQPEP/PC-1.2.0`)
- **Strict Frozen Wire Format v3 (`\x89QPE\x03\x00`) & Compact TLV v3.1 (`\x89QPE\x03\x01`):** Zero legacy `-beta` backwards compatibility.
- **Mandatory Memory-Hard KDF (`kdf_version: 2`):** RFC 9106 `QPKD-Argon2id + qSponge-512` cascade.
- **10 Post-Quantum Suites:** `QLX-768`..`QLX-16384` + `QVS-65`..`QVS-1024`, Calyx Sovereign-Pentad `Calyx Sovereign-Pentad (CSP-Omega)`, Calyx Goppa-Monolith `CGM-8192`, and Calyx Rank-Metric Tensor `CRT-RSD512`.
- **Full Protocol Stack:** `QPEP-Ratchet`, `QPEP-MLS` TreeKEM, `QPEP-AKE`, `QPEP-KT`, `FIDO2-PRF`, `QVS-Ring`, `BlindSearchVault`, `t`-of-`n` `ThresholdKEM`, `Sphinx-PQ`, `LT-QR` air-gapped fountain transfer, `DeniableVault`, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.

---

## Quick Start (Protocol Verification)
```bash
cd protocol
make -C calyx_qpep/native/csrc   # Optional: build C99/AVX2/NEON libopenqpep accelerator
python3 -m calyx_qpep.cli verify-vectors
python3 -m unittest discover -s tests -v
```

## Official Links
- **Website:** https://calyxlabsinc.org/ (Mirror: https://calyxlabsinc.github.io/)
- **Public Key Directory:** https://qpepkeys.calyxlabsinc.org
- **Encrypted Messenger:** https://messenger.calyxlabsinc.org
- **Encrypted Email:** https://mail.calyxlabsinc.org
- **Contact:** support@calyxlabsinc.org

## All 10 OpenQPEP Post-Quantum Suites (`v1.0.0`)

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
