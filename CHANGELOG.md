# OpenQPEP Suite Changelog

All notable synchronized public releases of **OpenQPEPSuite** and **OpenQPEP_ServerFiles** are documented here.

---

## Official Release `v1.1.0` (2026-11-23) — Upgraded from Official Release `v1.0.2`

Synchronized full-ecosystem stabilization, critical bug fixes, cryptographic stub remediation, and unified parity across all 7 pillars (upgraded directly from **Official Release `v1.0.2`**):

### 1. Core Protocol (`OpenQPEP/1.1.0`)
- Upgraded from **Official Release `1.0.2`** to **Official Release `1.1.0`** (`OpenQPEP/1.1.0`, `pyproject.toml`, `rust/openqpep-core/Cargo.toml`, `go/openqpep/wire_v5.go`) while maintaining **100% backwards compatibility with Official Releases `1.0.0`–`1.0.2` Wire Format v5 (`\x89QPE\x05\x00`), Compact Binary TLV v5.1 (`\x89QPE\x05\x01`), Stream v5 (`\x89QPS\x05\x00`), and `kdf_version: 4`** key rings and packets.
- Continued strict `QPEPLegacyProtocolError` rejection of all retired pre-release wire frames and `kdf_version < 4` key rings.
- Added `calyx_qpep.compat_server` shared server adapter (`SlidingWindowRateLimiter`, strict Wire v5 verification, pre-release token guard, and directory `.qpkrf` validator) and unit suite `tests/test_v110_official_release_stabilization.py`.
- Rebuilt C99/AVX2 `libopenqpep.so` (`-O3 -std=c99 -Wall -Wextra -Werror`) and regenerated all 10 deterministic Golden KAT vectors for `v1.1.0`.

### 2. Calyx QPEP Client (`v1.1.0`, Android `vc229` ← upgraded from `v1.0.2` `vc228`)
- Replaced plaintext client helper stubs in `calyx_qpep_app.html`: upgraded `DeniableVaultEngine` to genuine dual-slot `WebCrypto AES-256-GCM` + independent PBKDF2-SHA256 keys + fixed-size CSPRNG-padded slots (`sealDualVolume` + `openSlot`), and upgraded `ThresholdKEMEngine` to genuine $\text{GF}(256)$ (`0x11B`) Shamir Secret Sharing (`splitShards` + Lagrange interpolation `reconstructSecret`).
- Deduplicated repeated `detectDeviceRamInfo()` blocks, aligned all runtime constants to Wire v5 / `kdf_version: 4`, and achieved 100% byte-for-byte parity across Android `calyx_qpep_app.html` and iOS `qpep-client-ios.html`.
- Registered `@JavascriptInterface CalyxHardwareBridge.getDeviceRamGiB()` in `MainActivity.java`; synchronized `build.gradle.kts`, `AndroidManifest.xml`, Desktop `Cargo.toml`/`tauri.conf.json`, rebuilt `CalyxQPEPClient.apk` (`vc229`, `versionName="1.1.0"`), and CMS-signed `CalyxQPEPClient.mobileconfig`.

### 3. Calyx Encrypted Email (`v1.1.0`, Android `vc13` ← upgraded from `v1.0.2` `vc12`) & `CalyxMail_Backend` / `CalyxMail_Frontend`
- Replaced raw chunk uploads in `StreamingAttachmentEngine` with client-side `WebCrypto AES-256-GCM` per-chunk encryption, Stream v5 (`\x89QPS\x05\x00`) nonces/AAD, ciphertext Merkle root, per-recipient wrapped CEKs, and `decryptMultiRecipientStream`.
- Upgraded `CalyxMail_Backend/calyx_qpep.py` to genuine **CMT-4 `AES-256-GCM` + `ChaCha20-Poly1305` `CC-512` AEAD** and **RFC 9106 `QPKD-Argon2id`** (with seamless `v1.0.x` decrypt compatibility).
- Added sliding-window rate limiting to `api_server.py` (`/api/v1/auth/*`, `/api/v1/messages/send`), deduplicated `detectDeviceRamInfo()`, fixed 3 corrupted literal binary NULL-byte sequences in `CalyxMail_Frontend/index.html`, registered `@JavascriptInterface CalyxHardwareBridge` in `MainActivity.java`, updated `test_calyxmail.py` (9/9 passing), and rebuilt `CalyxEncryptedEmail.apk` (`vc13`, `versionName="1.1.0"`) & `.mobileconfig`.

### 4. Calyx Encrypted Messenger (`v1.1.0`, Android `vc29` ← upgraded from `v1.0.2` `vc28`) & `Messenger_Server`
- Fixed `/api/v1/messages/burn` (`body` + `db.burn_message(...)` against `qpep_messages.message_id` with sender/recipient ownership enforcement) and added missing `import hashlib` for `/api/v1/safety-number`.
- Replaced 32-bit FNV-1a in `computeSafetyNumberV100` with 512-bit cryptographic `qSponge512Hex`, deduplicated `detectDeviceRamInfo()`, aligned runtime constants to Wire v5 / `kdf_version: 4`, and upgraded `Messenger_Server/calyx_qpep.py` to real CMT-4 `AES-256-GCM` + `ChaCha20-Poly1305` + RFC 9106 `QPKD-Argon2id`.
- Closed SQLite connections cleanly via `@contextlib.contextmanager`, added POST sliding-window rate limiting, updated `systemd/*.service` units to `Official Release 1.1.0`, exposed `@JavascriptInterface CalyxHardwareBridge`, rebuilt `CalyxEncryptedMessenger.apk` (`vc29`, `versionName="1.1.0"`) & `.mobileconfig`, and verified `test_messenger.py` (7/7 passing).

### 5. Key Directory (`Directory_Server` — `qpepkeys.calyxlabsinc.org` `v1.1.0`)
- Replaced hardcoded symmetric STH secret with persistent **Ed448 asymmetric STH signing** (`0600` PEM, publishing `log_public_key_hex` / `sth_public_key_hex`).
- Upgraded tree hashing to canonical **RFC 9162 Binary Merkle Trees**, implemented **`GET /api/v1/kt/consistency?first=<m>&second=<n>`** and interactive consistency-proof verification in `/kt-audit`, added per-IP sliding-window rate limiting, and verified `test_directory.py` (4/4 passing).

### 6. Website & GitHub Mirror (`Website_Server` + `GitHub_Mirror` `v1.1.0`)
- Fixed HTTP response framing bugs on `/api/v1/releases/latest` and `410 Gone` routes plus `/api/health` Wire Format reporting in `Website_Server/server.py` (and `app.py`).
- Updated all website pages, legal/ToS files, and `GitHub_Mirror` to **Official Release `v1.1.0`**, synchronized all 6 rebuilt binaries & `SHA256SUMS.txt`, and added automated `Website_Server/test_website.py` (5/5 passing).

---

## Official Release `v1.0.2` (2026-11-22) — Previous Public Stable Release Baseline
- Synchronized **Official Release `v1.0.2`** across `OpenQPEPSuite` and `OpenQPEP_ServerFiles` (Calyx QPEP Client `vc228`, Calyx Encrypted Messenger `vc28`, Calyx Encrypted Email `vc12`), Wire Format v5 (`\x89QPE\x05\x00`), Compact Binary TLV v5.1 (`\x89QPE\x05\x01`), Stream v5 (`\x89QPS\x05\x00`), CMT-4 Key-Committing `CC-512` AEAD, mandatory `kdf_version: 4` (`RFC 9106 QPKD-Argon2id`), and all 10 post-quantum suites.

## Official Release `v1.0.0` (2026-11-21) — Initial Public Stable Launch
- Permanent public launch of the OpenQPEP worldwide post-quantum encryption standard under `CPOSLS-1.0`.
