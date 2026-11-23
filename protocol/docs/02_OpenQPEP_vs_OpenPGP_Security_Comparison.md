# 02 — OpenQPEP (`v1.1.0`) vs. Legacy OpenPGP Security Comparison

**Protocol:** `OpenQPEP/1.1.0` (`Official Release 1.1.0`)  
**API Stability:** `v1.1.0-stable`  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## Side-by-Side Cryptographic & Architectural Comparison

| Security Property | Legacy OpenPGP (RFC 4880 / 9580) | OpenQPEP Official Release 1.1.0 (`v1.1.0`) |
| :--- | :--- | :--- |
| **Quantum Resistance** | Vulnerable classical RSA / ECC (broken by Shor's algorithm) | **10 Post-Quantum Suites:** 5 Module-LWE + `HGC-448` tiers (`QLX-768`..`QLX-16384`) + **5 genuine Beyond-LWE suites** (`CSP-Omega` 5-Family Citadel, `CGM-8192` Goppa Patterson, `CRT-RSD512` LRPC Rank-Metric + UOV, `CIF-SQI-512` CSIDH-512 Isogeny, `CULC-2048` Unstructured-Citadel) |
| **Symmetric Cipher & Key Commitment** | Single-cipher CFB / OCB / EAX (vulnerable to Invisible Salamanders) | **CMT-4 Key-Committing `CC-512` (`AES-256-GCM` + `ChaCha20-Poly1305` + 32-byte `qSponge-512` CMT-4 commitment tag)** with independent 256-bit keys and nonces |
| **Secret Key KDF** | Weak S2K / iterated SHA-1/SHA-256; allows empty passphrases | **Mandatory `kdf_version: 4` (`RFC 9106 QPKD-Argon2id + qSponge-512`)** bound to `"OpenQPEP/1.1.0"` with hardcoded 12+ char passphrase witness & optional `FIDO2-PRF` hardware passkey secret; all legacy `kdf_version < 4` rejected |
| **Metadata Privacy** | Cleartext Key IDs in packet headers & ASCII armor | **Zero cleartext identity headers** (including zero `Encrypting-Key-Hash:` in encrypted packets), `qSponge-XOF` wire whitening, blinded 64-bit multi-recipient slot tags, power-of-2 dummy slots, and `4/16/64 KiB` bucket padding |
| **Wire Format & Parser Hardening** | Decades of legacy packet versions, decompression bombs, malleable CRC | **Strict Official Wire Format v5 (`\x89QPE\x05\x00`), Compact TLV v5.1 (`\x89QPE\x05\x01`), & Stream v5 (`\x89QPS\x05\x00`)** — zero `-rc`, `-pc`, or `-beta` backwards compatibility (`QPEPLegacyProtocolError`), mandatory constant-time armor CRC, duplicate-TLV rejection, and 128 MiB decompression-bomb ceiling |
| **Forward Secrecy & PCS** | None (static key compromise decrypts all historical traffic) | Native **`QPEP-Ratchet`** (atomic AEAD-before-commit state + rotating-ephemeral hybrid `QLX` + `HGC-448` PCS), **`QPEP-MLS`** $O(\log N)$ group TreeKEM with per-`(epoch, sender)` replay defense, and **`QPEP-AKE`** bidirectional PQ-Noise-XX |
| **Key Lifecycle & Transparency** | Complex WoT / manual revocation / trust-on-first-use | Rotatable encryption/signing subkeys, self-authenticating **`.qrev`** revocations, verifiable $t$-of-$n$ **`.qshare`** Shamir recovery, zero-reconstruction HJKY proactive **`ThresholdKEM`**, and **`QPEP-KT`** Ed448-signed Merkle STHs + RFC 9162 consistency proofs |
| **Large-File & Privacy Tools** | Whole-file streaming without random-access seek | $O(1)$-RAM 64 KiB streaming AEAD + **full-ciphertext Merkle-tree seekable byte-range decryption**, genuine Module-SIS **`QVS-Ring`**, fixed-size **`Sphinx-PQ`** onion packets, masked-header **`DeniableVault`**, **`TimeLockCapsule`**, **`LT-QR`** air-gap fountain |
| **Auditability & Verification** | Fragmented test suites | **10 bit-exact `v1.0.0` KAT suites** (Native C99 & Pure-Python parity), adversarial unit & cryptanalytic verification suite (fuzzer, attack simulator, DudeCT Welch's $t$-test, 5-language interop matrix), Tamarin/ProVerif/Cryptol formal models, and SPDX SBOM |

## All 10 OpenQPEP Post-Quantum Suites (`v1.1.0`)

Every OpenQPEP suite uses the canonical naming standard `"Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"` paired with **CMT-4 CC-512 AEAD**, **RFC 9106 QPKD-Argon2id + qSponge-512 (`kdf_version: 4`)**, and **Official Wire Format v5 (`\x89QPE\x05\x00`) / Compact TLV v5.1 (`\x89QPE\x05\x01`)**.

| Canonical Suite Name | KEM + Signature | Mathematical Family | Hardware Classification | Primary Role |
| :--- | :--- | :--- | :--- | :--- |
| **Calyx Lattice-Apex: QLX-4096 + QVS-256 (4,096-Dim Module-LWE — All Devices)** | `QLX-4096` + `QVS-256` | Structured Module-LWE (`k=16`, 4,096-dim) + Hybrid X448 | **All Devices** | Default flagship security for mobile & desktop |
| **Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)** | `QLX-768` + `QVS-65` | Structured Module-LWE (`k=3`, 768-dim) + Hybrid X448 | **All Devices** | Lowest-latency mobile messaging & constrained links |
| **Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)** | `QLX-1024` + `QVS-87` | Structured Module-LWE (`k=4`, 1,024-dim) + Hybrid X448 | **All Devices** | Balanced NIST-Level-5-class lattice security |
| **Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)** | `QLX-2048` + `QVS-128` | Structured Module-LWE (`k=8`, 2,048-dim) + Hybrid X448 | **All Devices** | Elevated 2,048-dimensional lattice margin |
| **Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)** | `CIF-SQI-512` + `QHS-512` | CSIDH-512 Supersingular Isogeny + Stateless Hash-Based Hypertree | **All Devices** | Beyond-LWE compact isogeny key exchange & hash signatures |
| **Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (All-Devices Signature Default — All Devices)** | `CRT-RSD512` + `QMQ-512` | LRPC Rank-Metric Syndrome Decoding + UOV Multivariate Quadratic | **All Devices** | Beyond-LWE rank-metric code & multivariate diversity |
| **Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)** | `QLX-16384` + `QVS-1024` | 4-Manifold Coupled Module-LWE (`k=64`, 16,384-dim) + `16×14` QVS | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Maximum structured-lattice dimension (~69 KB secret vectors) |
| **Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)** | `CGM-8192` + `QHS-512` | Classic McEliece / Patterson Binary Goppa Code + Hash Hypertree | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Beyond-LWE conservative code-based encryption |
| **Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)** | `CULC-2048` + `CGM-8192` | Unstructured Plain-LWE (`n×n` ring-free) + Binary Goppa Code | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Zero algebraic ring-structure defense against ring/ideal-lattice attacks |
| **Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (High-Tier Signature Default — HIGH-TIER HARDWARE ONLY)** | `CSP-Omega` + `QHS-512` | 5-Family Combiner (Plain-LWE + Goppa + CSIDH-512 + UOV + Hash + X448) | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Ultimate multi-assumption citadel; secure if any 1 of 5 families holds |
