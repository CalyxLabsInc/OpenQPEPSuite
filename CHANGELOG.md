# OpenQPEP Suite Changelog (`v0.1.0` → `v1.0.0`)

Unified public version history for the **OpenQPEP Suite** by **Calyx Labs Inc.** (`https://github.com/CalyxLabsInc/OpenQPEPSuite/`), licensed universally under the **Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)**.

> **Proprietary Infrastructure Notice:** Backend server infrastructure and private signing keystores are strictly proprietary and are excluded from this public repository and changelog.

---

## Calyx QPEP Client — Changelog Section 1

Zero-telemetry post-quantum encryption, decryption, and digital signature client (`com.calyxlabs.qpepclient`) for Android (`.apk`), iOS (`.mobileconfig` + PWA), and Desktop (Tauri).

### Beta Series (`v0.1.1` → `v0.5.0`)
- **`Beta v0.1.1` → `v0.1.6`:** Initial Android release of **Calyx QPEP Client** with multi-tier `QLX`/`QVS` key generation, `.qpkrf` key-ring import/export, 64-character `Key Hash` addressing, text encryption/decryption, and attached-only digital signatures.
- **`Beta v0.1.7`:** Added universal multi-extension binary file encryption and decryption covering 165+ file extensions, binary magic-byte header detection, and live decrypted image previews directly in the Android client.
- **`Beta v0.1.8`:** Promoted **`Calyx Signature` (`QLX-4096 + QVS-256`)** as the default key tier with Verify-Before-Emit `Fault-Guard` signing protection.
- **`Beta v0.1.9`:** Added **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)** with mandatory High-Tier Hardware notices and launched **Calyx QPEP Client for iOS** via CMS-signed `.mobileconfig` profile.
- **`Beta v0.2.0` (`vc207`) → `v0.2.9` (`vc216`):** Synchronized client builds with the unified OpenQPEP Suite versioning, integrating modular kernel updates, deterministic KAT vector parity, `QPKD-Argon2id` passphrase derivation, anonymous multi-recipient encryption, key lifecycle/Shamir recovery, streaming AEAD, `Calyx Sovereign-Pentad` support, and multi-party cosigning.
- **`Beta v0.3.0` (`vc217`) → `v0.5.0` (`vc218`):** Aligned Android and iOS clients with native C99 acceleration parity, WASM SIMD128 readiness, standalone Beyond-LWE suites (`CGM-8192` & Rank-Metric), Compact Binary TLV v3.1, air-gapped QR fountain transfer, and the Beta Spec Freeze.

### Production Candidate Series (`v1.0.0-pc` → `v1.2.0-pc`)
- **`PC v1.0.0` (`vc219`):** Promoted to Production Candidate (`pc`), removing all legacy beta wire and KDF fallbacks, enforcing Frozen Wire Format v3 / Compact TLV v3.1 and `kdf_version: 2`, and consolidating source and release assets under `apps/calyx-qpep-client/`.
- **`PC v1.1.0` (`vc220`) → `v1.1.4` (`vc221`):** Added **`Calyx Isogeny-Forge` (`CIF-SQI-512 + QHS-512`)** and **`Calyx Unstructured-Citadel` (`CULC-2048 + CGM-8192`)**, completing all 10 canonical suites with unified `"Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"` labels.
- **`PC v1.1.6` (`vc222`) → `v1.1.7` (`vc223`):** Standardized all UI KDF copy to `QPKD-Argon2id + qSponge-512` and enabled full native `.qpkrf` key generation, encryption, decryption, signing, and verification parity across all 5 Beyond-LWE suites.
- **`PC v1.2.0` (`vc224`):** Added WASM SIMD128 + Web Worker offloading (`qpep_worker.js`), added the native Android `CalyxHardwareBridge` (`ActivityManager.MemoryInfo`) for $\ge 12\text{ GB}$ RAM high-tier gating, hardened `detected.filename` rendering with `.textContent` (`AUD-01`), added strict `Content-Security-Policy` headers (`AUD-03`), and synchronized `AndroidManifest.xml` version codes (`AUD-05`).

### Official Release `1.0.0` (`v1.0.0`, `vc226`) — 2026-11-21
- Upgraded Android, iOS (`.mobileconfig`), and Desktop (`Cargo.toml` / `tauri.conf.json`) clients to **Official Release 1.0.0 (`OpenQPEP/1.0.0`)** with **Official Wire Format v5 (`\x89QPE\x05\x00`)**, **Compact Binary TLV v5.1 toggle (`\x89QPE\x05\x01`)**, and mandatory `kdf_version: 4`.
- Added the built-in **Wire v5 & CMT-4 Packet Inspector**, on-device **10-Suite Self-Test**, and strict rejection of all legacy `-rc`, `-pc`, and `-beta` packets and keys.
- Rebuilt `CalyxQPEPClient.apk` (`vc226`) as a pure ABI-independent JAR v1 + APK Signature Scheme v2 package (resolving `INSTALL_FAILED_NO_MATCHING_ABIS` on ARM64 devices).
- Fixed the W3C `navigator.deviceMemory` 8 GB browser cap bug in `enforceOpenQPEPHardwareGate()` so 12 GB+ flagship devices (such as Samsung Galaxy Z Fold) properly unlock all 4 High-Tier Hardware suites while continuing to lock low-RAM ($\le 4\text{ GB}$) devices.

---

## Calyx Encrypted Messenger — Changelog Section 2

End-to-end post-quantum encrypted messenger (`com.calyxlabs.qpem`) for Android (`.apk`), iOS (`.mobileconfig`), and Desktop (Tauri).

### Beta Series (`v1.0.0` → `v0.5.0`)
- **`v1.0.0` → `v1.0.4` (`vc1`–`vc6`, OpenQPEP Beta `v0.1.9`):** Initial Android, iOS, and Web releases of **Calyx Encrypted Messenger (QPEM)** featuring post-quantum end-to-end encryption, native in-app SC Code camera scanning, Neon Blue/Pink Sent/Delivered/Read status indicators, **`Calyx Signature`** default tier, and **`Calyx Hyper-Tesseract`** with High-Tier Hardware Notice.
- **`Beta v0.2.0` (`vc7`) → `v0.3.0` (`vc17`) → `v0.5.0` (`vc18`):** Unified version numbering with the OpenQPEP Suite, synchronized `QPKD-Argon2id` key derivation, `QPEP-Ratchet` forward-secret messaging foundations, `QPEP-MLS` group architecture alignment, `QPEP-KT` key transparency support, and updated CMS-signed iOS `.mobileconfig` profiles.

### Production Candidate Series (`v1.0.0-pc` → `v1.2.0-pc`)
- **`PC v1.0.0` (`vc19`):** Promoted to Production Candidate (`pc`), removing legacy beta wire/KDF compatibility, enforcing Frozen Wire Format v3 and `kdf_version: 2`, and consolidating under `apps/calyx-encrypted-messenger/`.
- **`PC v1.1.0` (`vc20`) → `v1.1.4` (`vc21`) → `v1.1.6` (`vc22`) → `v1.1.7` (`vc23`):** Expanded suite selection to all 10 canonical post-quantum suites (adding `Calyx Isogeny-Forge` and `Calyx Unstructured-Citadel`), standardized `QPKD-Argon2id + qSponge-512` terminology, and enabled full Beyond-LWE `.qpkrf` key parity.
- **`PC v1.2.0` (`vc24`):** Added WASM SIMD128 + Web Worker offloading, integrated Android `CalyxHardwareBridge` ($\ge 12\text{ GB}$ RAM detection), enforced `usesCleartextTraffic="false"` and `allowBackup="false"` in `AndroidManifest.xml` (`AUD-02`), added strict `Content-Security-Policy` headers (`AUD-03`), replaced fallback `Math.random()` calls with fail-closed WebCrypto CSPRNG (`AUD-04`), and synchronized manifest version codes (`AUD-05`).

### Official Release `1.0.0` (`v1.0.0`, `vc26`) — 2026-11-21
- Upgraded Android, iOS (`.mobileconfig`), and Desktop (`Cargo.toml` / `tauri.conf.json`) clients to **Official Release 1.0.0 (`OpenQPEP/1.0.0`)** enforcing Wire Format v5 (`\x89QPE\x05\x00`), mandatory `kdf_version: 4`, and strict legacy `-rc`/`-pc`/`-beta` rejection.
- Added the **Safety Number Verification** modal, **CMT-4 Key-Commitment Inspector** drawer, and **Burn Now** ephemeral message destruction controls.
- Rebuilt `CalyxEncryptedMessenger.apk` (`vc26`) as an ABI-independent JAR v1 + APK Signature Scheme v2 release and fixed the W3C `navigator.deviceMemory` 8 GB cap bug so 12 GB+ flagship devices properly unlock all 4 High-Tier Hardware suites.

---

## Calyx Encrypted Email — Changelog Section 3

Post-quantum encrypted `@calyxmail.org` email client (`com.calyxlabs.mail`) with automatic OpenQPEP end-to-end encryption and standard email interoperability for Android (`.apk`), iOS (`.mobileconfig`), and Desktop (Tauri).

### Beta Series (`v0.1.0` → `v0.5.0`)
- **`Beta v0.1.0` → `v0.5.0` (`vc1`–`vc2`):** Initial release of **Calyx Encrypted Email** providing sovereign `@calyxmail.org` mailboxes, automatic OpenQPEP E2EE between `@calyxmail.org` users, standard SMTP/IMAP interoperability with third-party providers (Gmail, Yahoo, Outlook), and initial Android `.apk` + iOS `.mobileconfig` packaging.

### Production Candidate Series (`v1.0.0-pc` → `v1.2.0-pc`)
- **`PC v1.0.0` (`vc3`):** Integrated into the unified `OpenQPEPSuite` monorepo under `apps/calyx-encrypted-email/`, promoted to Production Candidate 1.0.0 with Frozen Wire Format v3, `kdf_version: 2`, zero beta backwards compatibility, and CMS-signed iOS `.mobileconfig`.
- **`PC v1.1.0` (`vc4`) → `v1.1.4` (`vc5`) → `v1.1.6` (`vc6`) → `v1.1.7` (`vc7`):** Added all 10 canonical post-quantum suites (including `Calyx Isogeny-Forge` and `Calyx Unstructured-Citadel`), standardized suite naming and `QPKD-Argon2id + qSponge-512` copy, and added full Beyond-LWE `.qpkrf` key-ring parity.
- **`PC v1.2.0` (`vc8`):** Added WASM SIMD128 + Web Worker offloading, integrated Android `CalyxHardwareBridge` ($\ge 12\text{ GB}$ RAM detection), enforced `usesCleartextTraffic="false"` and `allowBackup="false"` (`AUD-02`), added strict `Content-Security-Policy` headers (`AUD-03`), enforced fail-closed WebCrypto CSPRNG (`AUD-04`), and synchronized manifest version codes (`AUD-05`).

### Official Release `1.0.0` (`v1.0.0`, `vc10`) — 2026-11-21
- Upgraded Android, iOS (`.mobileconfig`), and Desktop (`Cargo.toml` / `tauri.conf.json`) clients to **Official Release 1.0.0 (`OpenQPEP/1.0.0`)** with Official Wire Format v5 (`\x89QPE\x05\x00`), CMT-4 key-committing authenticated envelopes, mandatory `kdf_version: 4`, and strict rejection of legacy `-rc`/`-pc`/`-beta` formats.
- Rebuilt `CalyxEncryptedEmail.apk` (`vc10`) as an ABI-independent JAR v1 + APK Signature Scheme v2 release signed with the Calyx Labs Universal Release Key (resolving Android installation failures caused by missing APK v2 signature blocks).
- Fixed the W3C `navigator.deviceMemory` 8 GB cap bug in `enforceOpenQPEPHardwareGate()` so 12 GB+ flagship devices properly unlock all 4 High-Tier Hardware suites.

---

## OpenQPEP Protocol — Changelog Section 4

Core cryptographic protocol (`protocol/`), Python reference SDK, C99/AVX2/NEON `libopenqpep`, WASM SIMD128 bridge, Rust `openqpep-core` crate, Go conformance port, formal Tamarin/ProVerif/Cryptol specs, and Golden KAT vectors.

### Beta Series (`v0.1.0` → `v0.5.0`)
- **`Beta v0.1.0` — Genesis Protocol Prototype:** Established the foundational post-quantum encryption and digital signature architecture: `qSponge-512` XOF, `CC-512` cascaded dual-stream AEAD (`AES-256-GCM` + `ChaCha20-Poly1305`), `QLX` Module-LWE KEM hybridized with `HGC-448`, `QVS` lattice vector signatures, and the initial `.qpkrf` armored key-ring format.
- **`Beta v0.1.1` — Multi-Tier Reference Engine & Key Addressing:** Shipped the initial multi-tier `QLX`/`QVS` Python reference implementation (`Velocity`, `Sovereign-Hybrid`, `Ultra-Grid`), 64-character `Key Hash` addressing, `.qpkrf` key rings, and attached-only signature envelopes.
- **`Beta v0.1.2` — Official Protocol Branding:** Officially renamed the protocol and core repository to **OpenQPEP by Calyx Labs Inc.** (`OpenQPEP`).
- **`Beta v0.1.3` — Security Audit Fix #1 (Key Ring Integrity):** Enforced constant-time recomputation and verification of the 512-bit `integrity_mac` and 64-character `Key Hash` public-key binding during `import_qpkrf`.
- **`Beta v0.1.4` — Security Audit Fix #2 (Chunk Truncation & Auto-Verify):** Enforced terminal-frame truncation checks (`final == 1` on the last 64 KiB `CC-512` chunk and `final == 0` on preceding chunks) and automatic embedded sender signature verification on packet decryption.
- **`Beta v0.1.5` — Interactive OpenQPEP CLI:** Released the interactive English-command `openqpep` CLI with guided `Create Key`, `Export Private/Public`, `Import Key`, encryption/decryption, attached signing/verification, and persistent `~/.openqpep/keyring.json` storage.
- **`Beta v0.1.6` — Technical Specification Suite & Licensing:** Authored and expanded the `docs/` technical specification manuals and formalized the Calyx Public Open Source License.
- **`Beta v0.1.7` — Universal Binary File Encryption Registry:** Added a hardcoded registry of 165+ supported file extensions (`SUPPORTED_FILE_EXTENSIONS`), binary magic-byte header detection (`detect_file_extension_and_mime`), and raw binary `bytes` file encryption/decryption.
- **`Beta v0.1.8` — `Calyx Signature` Default Tier & Fault-Guard:** Introduced **`Calyx Signature` (`QLX-4096 + QVS-256`)** as the default key tier ($k = 16$, 4,096-dimensional Module-LWE + $8 \times 7$ lattice vector signatures), added Verify-Before-Emit `Fault-Guard` protection, and published the 6-vector Quantum & AI-Cryptanalysis Immunity Matrix.
- **`Beta v0.1.9` — `Calyx Hyper-Tesseract` High-Tier Hardware Suite:** Introduced **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)** ($k = 64$, 16,384-dimensional 4-Manifold Coupled Hyper-Tesseract Module-LWE + $16 \times 14$ `QVS-1024` signatures) with mandatory flagship hardware warnings.
- **`Beta v0.2.0` — Protocol Synchronization & Verification Pass:** Resolved cross-module serialization and encoding edge cases across the core Python SDK, CLI, docs, and unit tests.
- **`Beta v0.2.1` — Modular Cryptographic Kernel & `CPOSLS-1.0`:** Refactored the reference engine into 13 clean modules under `calyx_qpep/primitives/` and `calyx_qpep/lattice/` with backward-compatible facades and migrated licensing to `CPOSLS-1.0`.
- **`Beta v0.2.2` — Deterministic KAT Vector Engine:** Added `calyx_qpep/vectors/`, golden JSON KAT vectors, and `openqpep verify-vectors` CLI verification.
- **`Beta v0.2.3` — Memory-Hard `QPKD-Argon2id` & Hardware Auto-Tuner:** Added `calyx_qpep/kdf/` (`passphrase_policy.py`, `hardware_tuner.py`, `argon2id_cascade.py`) implementing RFC 9106 `Argon2id` + `qSponge-512` cascade (`kdf_version: 2`).
- **`Beta v0.2.4` — Anonymous Multi-Recipient Encryption & Traffic Padding:** Added `calyx_qpep/wire/` (`file_registry.py`, `framing.py`, `armor.py`, `multi_recipient.py`) with anonymous multi-recipient encapsulation and traffic-analysis padding.
- **`Beta v0.2.5` — Post-Quantum Double Ratchet (`QPEP-Ratchet`):** Added `calyx_qpep/ratchet/` (`kdf_chain.py`, `pq_rekey.py`, `session_state.py`) for Forward Secrecy (FS) and Post-Compromise Security (PCS).
- **`Beta v0.2.6` — Cryptographic Key Lifecycle & Threshold Recovery:** Added `calyx_qpep/keyring/` (subkeys and signed revocation certificates) and `calyx_qpep/recovery/` ($t$-of-$n$ Shamir Secret Sharing over $\mathbb{F}_{256}$).
- **`Beta v0.2.7` — Streaming Merkle-Tree AEAD & `Calyx Sovereign-Pentad`:** Added $O(1)$-RAM chunked streaming AEAD (`calyx_qpep/wire/streaming.py`) and the 5-family **`Calyx Sovereign-Pentad` (`CSP-Omega`)** beyond-LWE architecture (`CULC-2048`, `CGM-8192`, `CRT-RSD512`, `CIF-SQI-512`, `QMQ-512`, `QHS-512`).
- **`Beta v0.2.8` — Threshold Multi-Party Cosigning & Timestamp Proofs:** Added `calyx_qpep/signatures/` supporting $m$-of-$n$ multi-party `QVS + Ed448` cosigning and cryptographic timestamp proofs.
- **`Beta v0.2.9` — Adversarial Audit Suite, Fuzzing & Benchmarks:** Added `calyx_qpep/audit/` (wire fuzzing, active attack simulations, Welch's $t$-test timing audit) and `benchmarks/bench_suites.py`.
- **`Beta v0.3.0` — Native C99/AVX2/NEON `libopenqpep` Acceleration:** Added `calyx_qpep/native/` (`ntt_3329.c`, `ntt_8380417.c`, `cbd.c`, `Makefile`, `loader.py`) with bit-exact parity against Python.
- **`Beta v0.3.1` — WebAssembly SIMD128 Engine:** Added `calyx_qpep/native/wasm/` (`build_wasm.sh`, `wasm_bridge.js`).
- **`Beta v0.3.2` — Memory-Safe Rust `openqpep-core` Crate:** Added `rust/openqpep-core` implementing core primitives, NTT arithmetic, and wire framing.
- **`Beta v0.3.3` — `QPEP-MLS` Post-Quantum Group Messaging:** Implemented TreeKEM post-quantum group messaging up to 256 members.
- **`Beta v0.3.4` — Hardware Security Key & Enclave Backing:** Added hardware security key and platform enclave abstraction interfaces.
- **`Beta v0.3.5` — `QPEP-AKE` (1-RTT PQ-Noise-XX Handshake):** Implemented 1-RTT post-quantum authenticated key exchange with mutual identity protection.
- **`Beta v0.3.6` — Verifiable Key Transparency Log (`QPEP-KT`):** Implemented append-only Merkle transparency logs with Signed Tree Heads (STHs) and consistency proofs.
- **`Beta v0.3.7` — Deniable & Linkable Ring Signatures (`QVS-Ring`):** Implemented lattice-based ring signatures.
- **`Beta v0.3.8` — Standalone Beyond-LWE Suites:** Promoted **`Calyx Goppa-Monolith` (`CGM-8192 + QHS-512`)** and **`Calyx Rank-Metric Tensor` (`CRT-RSD512 + QMQ-512`)** to standalone suites.
- **`Beta v0.3.9` — Verifiable Encrypted Search (`QPEP-Vault`):** Implemented keyed blind indexing for encrypted search.
- **`Beta v0.4.0` — Native Pentad C99 Kernel & Compact Binary TLV v3.1:** Added `pentad_accel.c` and Compact Binary TLV Wire Format v3.1 (`\x89QPE\x03\x01`).
- **`Beta v0.4.1` — Distributed Proactive Threshold Decryption (`ThresholdKEM`):** Added $t$-of-$n$ proactive threshold decapsulation with share refresh.
- **`Beta v0.4.2` — Post-Quantum Onion Routing (`Sphinx-PQ`):** Implemented fixed-size post-quantum mixnet onion packets.
- **`Beta v0.4.3` — Offline Air-Gapped QR Fountain Transfer:** Added Luby-Transform fountain coding (`lt_fountain.py`) for animated QR transfers.
- **`Beta v0.4.4` — Plausible-Deniability Dual-Volume Containers (`DeniableVault`):** Implemented indistinguishable outer/inner dual-volume containers.
- **`Beta v0.4.5` — Post-Quantum Time-Lock Puzzles & VDF Capsules:** Added sequential time-lock and VDF capsules.
- **`Beta v0.4.6` — Lattice Zero-Knowledge Key-Ownership Proofs (`LatticeZKProof`):** Implemented non-interactive lattice ZK proofs of secret-key ownership.
- **`Beta v0.4.7` — Encrypted Multi-Device CRDT State Sync:** Added E2EE CRDT state synchronization primitives.
- **`Beta v0.4.8` — Formal Symbolic Verification Models:** Added Tamarin, ProVerif, and Cryptol formal models.
- **`Beta v0.4.9` — Reproducible Build & SPDX SBOM Generator:** Added deterministic build checks and automated SPDX SBOM generation.
- **`Beta v0.5.0` — Go Conformance Port & Pre-PC Spec Freeze:** Added the Go conformance port (`go/`), verified 5-language vector parity, and froze the Beta specification.

### Production Candidate Series (`v1.0.0-pc` → `v1.2.0-pc`)
- **`PC v1.0.0`:** Promoted from `beta` to `pc`, removing all legacy beta wire magics (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`) and `kdf_version: 1`, enforcing Frozen Wire Format v3 (`\x89QPE\x03\x00`), Compact TLV v3.1 (`\x89QPE\x03\x01`), and `kdf_version: 2`.
- **`PC v1.1.0`:** Added **`Calyx Isogeny-Forge` (`CIF-SQI-512 + QHS-512`)** and **`Calyx Unstructured-Citadel` (`CULC-2048 + CGM-8192`)**, completing all 10 canonical suites under unified naming and hardware policies.
- **`PC v1.1.4`:** Expanded `benchmarks/bench_suites.py` to all 10 suites and unified protocol documentation.
- **`PC v1.1.6`:** Replaced all bare `QPKD-Argon` strings with `QPKD-Argon2id + qSponge-512` and upgraded CLI key generation to numbered `1–10` suite selection.
- **`PC v1.1.7`:** Unified `OpenQPEPProtocol.generate_keypair()` for native `.qpkrf` v3 parity across all 5 Beyond-LWE suites, expanded `vectors/` to **10/10 deterministic Golden KATs**, and added CLI `Switch Suite`, `Benchmark All 10`, and `Inspect Packet` commands.
- **`PC v1.2.0`:** Generated `WebAssembly.validate()`-verified `openqpep_wasm.wasm`, upgraded Rust `openqpep-core` with SIMD128 & Beyond-LWE support, added Android NDK JNI (`openqpep_jni.c` + `CMakeLists.txt`), and remediated all core protocol audit findings.

### Release Candidate Bridge (`v1.0.0-rc`)
- **`RC v1.0.0-rc`:** Introduced transitional Wire Format v4 (`\x89QPE\x04\x00` / `\x89QPE\x04\x01`) and `kdf_version: 3` during final pre-launch cryptographic hardening prior to locking the permanent `v1.0.0` specification.

### Official Release `1.0.0` (`v1.0.0`) — Permanent Public Launch Baseline (2026-11-21)
- **Clean-Slate Public Starting Point (`v1.0.0`, `OpenQPEP/1.0.0`, PEP 440 `1.0.0`, branch `main`):** Official public release of the OpenQPEP Core Protocol by Calyx Labs Inc.
- **Zero Legacy Pre-Release Backwards Compatibility:** Strictly enforces **Official Wire Format v5 (`\x89QPE\x05\x00`)**, **Compact Binary TLV v5.1 (`\x89QPE\x05\x01`)**, **Streaming AEAD v5 (`\x89QPS\x05\x00`)**, and **Mandatory `kdf_version: 4` (`RFC 9106 QPKD-Argon2id + qSponge-512` bound to `"OpenQPEP/1.0.0"`)**. All legacy Release Candidate (`-rc`), Production Candidate (`-pc`), and Beta (`-beta`) wire frames, streams, and `kdf_version < 4` key rings are hard-rejected immediately with `QPEPLegacyProtocolError`.
- **Cryptographically Genuine 10-Suite Architecture:**
  - **5 Structured Module-LWE + HGC-448 Suites** (`QLX-768`..`QLX-16384`, `QVS-65`..`QVS-1024`) with branchless `ct_cmov` FO implicit rejection and Verify-Before-Emit Fault-Guard.
  - **5 Genuine Beyond-LWE Suites:** Classic McEliece/Niederreiter **Binary Goppa Patterson** (`CGM-8192`), **LRPC / ROLLO-I** Rank-Metric Syndrome Decoding over $\mathbb{F}_{2^{127}}[X]/(X^{47}+X^5+1)$ (`CRT-RSD512`), **Unbalanced Oil-and-Vinegar (UOV)** Multivariate Signatures over $\mathbb{F}_{256}$ (`QMQ-512`), exact 511-bit **CSIDH-512** Supersingular Isogeny Class-Group Action + SeaSign (`CIF-SQI-512`), Stateless Hash Hypertree (`QHS-512`), Zero-Ring Plain-LWE (`CULC-2048`), and the 5-Family Citadel (`CSP-Omega`).
- **CMT-4 Key-Committing `CC-512` AEAD & Unified Authenticated Envelopes:** Dual-stream `AES-256-GCM` + `ChaCha20-Poly1305` + 256-bit `qSponge-512` commitment tag, suite-bound self-certified key hashes, unified sender-authenticated envelopes across all 10 suites, mandatory constant-time armor CRC verification, zero cleartext identity headers, and 128 MiB zlib decompression-bomb defense.
- **Hardened Stateful, Privacy & Transparency Stack:** Rotating-ephemeral atomic `QPEP-Ratchet`, replay-protected `QPEP-MLS` (256 members), bidirectional PQ `QPEP-AKE`, Ed448-signed `QPEP-KT` STHs with RFC 9162 Merkle Consistency Proofs, genuine Module-SIS AOS `QVS-Ring` lattice ring signatures, masked-header Argon2id `DeniableVault`, zero-reconstruction HJKY `ThresholdKEM`, fixed-size `Sphinx-PQ` onions, and canonical uniform `LatticeZKProof`.
- **5-Language Conformance, Native C99 Hardening & Production CLI:** Thread-safe compile-time `const` C99 NTT tables (`-Wall -Wextra -Werror`), fixed Android JNI `int32_t` bridge, constant-time C99 primitives (`openqpep_ct_eq`, `openqpep_ct_cmov`, `openqpep_verify_wire_v5_magic`, `openqpep_explicit_bzero`), synchronized Rust/Go/WASM ports, `0600` CLI keystore permissions + full scriptable subcommands, 10/10 regenerated deterministic Golden KATs, and full unit/adversarial/fuzz/timing verification (89/89 tests passing).
- **Universal License:** Licensed exclusively under Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`).
