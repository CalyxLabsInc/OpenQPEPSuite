# OpenQPEP Suite — Official Release 1.1.0 (`v1.1.0`)

**Organization:** Calyx Labs Inc. (Cleveland, Ohio)  
**Founder & Lead Architect:** Tristen Martinez (aka Calyxia)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)  
**Protocol Identifier:** `OpenQPEP/1.1.0` • **Wire Format:** Official Wire v5 (`\x89QPE\x05\x00`) / Compact Binary TLV v5.1 (`\x89QPE\x05\x01`) / Stream v5 (`\x89QPS\x05\x00`) • **Mandatory KDF:** `kdf_version: 4` (RFC 9106 `QPKD-Argon2id` + `qSponge-512`)

---

## Ecosystem Overview

OpenQPEP is Calyx Labs Inc.'s sovereign, post-quantum cryptographic standard engineered to replace OpenPGP across messaging, email, files, key directories, and multi-platform applications.

| Component | Package / Domain | Version (`v1.1.0`) | Platforms |
| :--- | :--- | :--- | :--- |
| **Core OpenQPEP Protocol** | `protocol/` (`calyx-openqpep`) | `1.1.0` | Python 3, C99/AVX2/NEON (`libopenqpep`), Rust (`openqpep-core`), Go (`go/openqpep`), WASM/JS |
| **Calyx QPEP Client** | `apps/calyx-qpep-client/` (`com.calyxlabs.qpepclient`) | `1.1.0` (`vc229`) | Android (`.apk`), iOS (`.mobileconfig` + unified HTML), Desktop (Tauri) |
| **Calyx Encrypted Messenger** | `apps/calyx-encrypted-messenger/` (`com.calyxlabs.qpem`) • `messenger.calyxlabsinc.org` | `1.1.0` (`vc29`) | Web, Android (`.apk`), iOS (`.mobileconfig`), Desktop (Tauri) |
| **Calyx Encrypted Email** | `apps/calyx-encrypted-email/` (`com.calyxlabs.mail`) • `mail.calyxlabsinc.org` / `calyxmail.org` | `1.1.0` (`vc13`) | Web, Android (`.apk`), iOS (`.mobileconfig`), Desktop (Tauri), SMTP/IMAP4rev1 |
| **OpenQPEP Key Directory** | `qpepkeys.calyxlabsinc.org` (`QPEP-KT`) | `1.1.0` | RFC 9162 Binary Merkle Log + Ed448 Signed Tree Heads + Consistency Proofs |

---

## Cryptographic Architecture (`v1.1.0`)

- **10 Canonical Post-Quantum Suites:**
  - *All-Devices Suites (6):* `QLX-4096 + QVS-256` (Default Apex), `QLX-768 + QVS-65`, `QLX-1024 + QVS-87`, `QLX-2048 + QVS-128`, `CIF-SQI-512 + QHS-512` (CSIDH-512 Isogeny), and `CRT-RSD512 + QMQ-512` (Rank-Metric LRPC + UOV).
  - *High-Tier Hardware Only (`>= 12 GB RAM`, 4):* `QLX-16384 + QVS-1024` (Calyx Hyper-Tesseract), `CGM-8192 + QHS-512` (Binary Goppa), `CULC-2048 + CGM-8192` (Unstructured Plain-LWE + Goppa), and `CSP-Omega + QHS-512` (5-Family Sovereign Pentad).
- **CMT-4 Key-Committing `CC-512` AEAD:** Nested `AES-256-GCM` + `ChaCha20-Poly1305` with a 256-bit `qSponge-512` commitment tag verified in constant time before decryption.
- **RFC 9106 `QPKD-Argon2id` (`kdf_version: 4`):** Mandatory memory-hard key derivation with hardware auto-tuning and optional `FIDO2-PRF` hardware passkey mixing.
- **Wire Compatibility Policy:** `v1.1.0` maintains **100% interoperability with all `v1.0.0`–`v1.0.2` Official Release Wire Format v5/v5.1 & Stream v5 artifacts**, while continuing to strictly reject all retired pre-release (`-rc`, `-pc`, `-beta`, `kdf_version < 4`, Wire v1–v4) artifacts with `QPEPLegacyProtocolError`.

---

## Quick Verification

```bash
cd protocol
make -C calyx_qpep/native/csrc clean all
python3 -m calyx_qpep.cli verify-vectors
python3 -m unittest discover -s tests -v
cd ..
python3 verify_suite.py
```
