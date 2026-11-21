# 02 — OpenQPEP (`v1.1.7-pc`) vs. Legacy OpenPGP Security Comparison

**Protocol:** `OpenQPEP/PC-1.1.7` (`Production Candidate 1.1.7`)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## Side-by-Side Cryptographic & Architectural Comparison

| Security Property | Legacy OpenPGP (RFC 4880 / 9580) | OpenQPEP Production Candidate 1.1.7 (`v1.1.7-pc`) |
| :--- | :--- | :--- |
| **Quantum Resistance** | Vulnerable classical RSA / ECC (broken by Shor's algorithm) | **10 Post-Quantum Suites:** 5 Module-LWE + `HGC-448` tiers (`QLX-768`..`QLX-16384`) + **3 Beyond-LWE suites** (`CSP-Omega` 5-Family Citadel, `CGM-8192` Goppa, `CRT-RSD512` Rank-Metric) |
| **Symmetric Cipher** | Single-cipher CFB / OCB / EAX | Dual-stream **`CC-512` (`AES-256-GCM` + `ChaCha20-Poly1305`)** with independent 256-bit keys and nonces |
| **Secret Key KDF** | Weak S2K / iterated SHA-1/SHA-256; allows empty passphrases | **Mandatory `kdf_version: 2` (`RFC 9106 QPKD-Argon2id + qSponge-512`)** with hardcoded 12+ char passphrase witness; legacy `kdf_version: 1` rejected |
| **Metadata Privacy** | Cleartext Key IDs in packet headers & ASCII armor | **Zero cleartext identity headers**, `qSponge-XOF` wire whitening, blinded 64-bit multi-recipient slot tags, power-of-2 dummy slots, and `4/16/64 KiB` bucket padding |
| **Wire Format Hygiene** | Decades of legacy packet versions & downgrade surfaces | **Strict Frozen Wire Format v3 (`\x89QPE\x03\x00`) & Compact TLV v3.1 (`\x89QPE\x03\x01`)** — zero legacy `-beta` backwards compatibility |
| **Forward Secrecy & PCS** | None (static key compromise decrypts all historical traffic) | Native **`QPEP-Ratchet`** (per-message FS + periodic hybrid `QLX` + `HGC-448` PCS), **`QPEP-MLS`** $O(\log N)$ group TreeKEM, and **`QPEP-AKE`** 1-RTT PQ-Noise-XX |
| **Key Lifecycle & Recovery** | Complex WoT / manual revocation | Rotatable encryption/signing subkeys, self-authenticating **`.qrev`** revocations, verifiable $t$-of-$n$ **`.qshare`** Shamir recovery, proactive **`ThresholdKEM`**, and **`QPEP-KT`** Merkle key transparency |
| **Large-File & Privacy Tools** | Whole-file streaming without random-access seek | $O(1)$-RAM 64 KiB streaming AEAD + **Merkle-tree seekable byte-range decryption**, **`QVS-Ring`**, **`Sphinx-PQ`** onion packets, **`DeniableVault`**, **`TimeLockCapsule`**, **`LT-QR`** air-gap fountain |
| **Auditability & Verification** | Fragmented test suites | **5 bit-exact `v1.1.7-pc` KAT suites**, 63/63 unit & adversarial tests (fuzzer, attack simulator, DudeCT Welch's $t$-test), Tamarin/ProVerif/Cryptol formal models, and SPDX SBOM |

## All 10 OpenQPEP Post-Quantum Suites (`v1.1.7-pc`)

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
