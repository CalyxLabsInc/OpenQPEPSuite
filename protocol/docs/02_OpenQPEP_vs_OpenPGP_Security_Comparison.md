# 02 — OpenQPEP (`v1.0.0-pc`) vs. Legacy OpenPGP Security Comparison

**Protocol:** `OpenQPEP/PC-1.0.0` (`Production Candidate 1.0.0`)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## Side-by-Side Cryptographic & Architectural Comparison

| Security Property | Legacy OpenPGP (RFC 4880 / 9580) | OpenQPEP Production Candidate 1.0.0 (`v1.0.0-pc`) |
| :--- | :--- | :--- |
| **Quantum Resistance** | Vulnerable classical RSA / ECC (broken by Shor's algorithm) | **8 Post-Quantum Suites:** 5 Module-LWE + `HGC-448` tiers (`QLX-768`..`QLX-16384`) + **3 Beyond-LWE suites** (`CSP-Omega` 5-Family Citadel, `CGM-8192` Goppa, `RMT-512` Rank-Metric) |
| **Symmetric Cipher** | Single-cipher CFB / OCB / EAX | Dual-stream **`CC-512` (`AES-256-GCM` + `ChaCha20-Poly1305`)** with independent 256-bit keys and nonces |
| **Secret Key KDF** | Weak S2K / iterated SHA-1/SHA-256; allows empty passphrases | **Mandatory `kdf_version: 2` (`RFC 9106 QPKD-Argon2id + qSponge-512`)** with hardcoded 12+ char passphrase witness; legacy `kdf_version: 1` rejected |
| **Metadata Privacy** | Cleartext Key IDs in packet headers & ASCII armor | **Zero cleartext identity headers**, `qSponge-XOF` wire whitening, blinded 64-bit multi-recipient slot tags, power-of-2 dummy slots, and `4/16/64 KiB` bucket padding |
| **Wire Format Hygiene** | Decades of legacy packet versions & downgrade surfaces | **Strict Frozen Wire Format v3 (`\x89QPE\x03\x00`) & Compact TLV v3.1 (`\x89QPE\x03\x01`)** — zero legacy `-beta` backwards compatibility |
| **Forward Secrecy & PCS** | None (static key compromise decrypts all historical traffic) | Native **`QPEP-Ratchet`** (per-message FS + periodic hybrid `QLX` + `HGC-448` PCS), **`QPEP-MLS`** $O(\log N)$ group TreeKEM, and **`QPEP-AKE`** 1-RTT PQ-Noise-XX |
| **Key Lifecycle & Recovery** | Complex WoT / manual revocation | Rotatable encryption/signing subkeys, self-authenticating **`.qrev`** revocations, verifiable $t$-of-$n$ **`.qshare`** Shamir recovery, proactive **`ThresholdKEM`**, and **`QPEP-KT`** Merkle key transparency |
| **Large-File & Privacy Tools** | Whole-file streaming without random-access seek | $O(1)$-RAM 64 KiB streaming AEAD + **Merkle-tree seekable byte-range decryption**, **`QVS-Ring`**, **`Sphinx-PQ`** onion packets, **`DeniableVault`**, **`TimeLockCapsule`**, **`LT-QR`** air-gap fountain |
| **Auditability & Verification** | Fragmented test suites | **5 bit-exact `v1.0.0-pc` KAT suites**, 63/63 unit & adversarial tests (fuzzer, attack simulator, DudeCT Welch's $t$-test), Tamarin/ProVerif/Cryptol formal models, and SPDX SBOM |
