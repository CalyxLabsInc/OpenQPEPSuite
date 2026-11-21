# OpenQPEP Suite — Production Candidate 1.1.0 (`v1.1.0-pc`)

Official unified public repository for the **OpenQPEP Suite** by **Calyx Labs Inc.** (`https://github.com/CalyxLabsInc/OpenQPEPSuite/`), licensed universally under the **Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)**.

> **Proprietary Infrastructure Notice:** All Calyx Labs Inc. backend servers (`website_server`, `directory_server`, `messenger_server`, `calyxmail_backend`) and signing keystores are strictly proprietary and are intentionally excluded from this repository.

---

## Repository Structure

| Directory | Component | Version | Description |
| :--- | :--- | :--- | :--- |
| [`protocol/`](protocol/) | **OpenQPEP Core Protocol** | `1.0.0-pc` | Python reference engine, C99/AVX2/NEON `libopenqpep` source, WASM SIMD128 bridge, Rust `openqpep-core` crate, Go conformance port, formal Tamarin/ProVerif/Cryptol specs, 5 golden KAT suites, and 63 unit/audit tests |
| [`apps/calyx-qpep-client/`](apps/calyx-qpep-client/) | **Calyx QPEP Client** | `PC 1.1.0` (`vc220`) | Zero-telemetry post-quantum encryption/signing client for Android (`.apk` + source) and iOS (`.mobileconfig` + PWA) |
| [`apps/calyx-encrypted-messenger/`](apps/calyx-encrypted-messenger/) | **Calyx Encrypted Messenger (QPEM)** | `PC 1.1.0` (`vc20`) | End-to-end post-quantum encrypted messenger for Android (`.apk` + source) and iOS (`.mobileconfig`) |
| [`apps/calyx-encrypted-email/`](apps/calyx-encrypted-email/) | **Calyx Encrypted Email** | `PC 1.1.0` (`vc4`) | Post-quantum encrypted email client (`@calyxmail.org`) for Android (`.apk` + source) and iOS (`.mobileconfig`) |
| [`docs/`](docs/) | **Suite Documentation & Theses** | `1.0.0-pc` | Architecture guides, hypothetical beyond-LWE key tier theses, and public compliance documents |

---

## Cryptographic Baseline (`OpenQPEP/PC-1.1.0`)
- **Strict Frozen Wire Format v3 (`\x89QPE\x03\x00`) & Compact TLV v3.1 (`\x89QPE\x03\x01`):** Zero legacy `-beta` backwards compatibility.
- **Mandatory Memory-Hard KDF (`kdf_version: 2`):** RFC 9106 `QPKD-Argon2id + qSponge-512` cascade.
- **10 Post-Quantum Suites:** `QLX-768`..`QLX-16384` + `QVS-65`..`QVS-1024`, Tier 10 `Calyx Sovereign-Pentad (CSP-Omega)`, Tier 11 `CGM-8192`, and Tier 12 `RMT-512`.
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
