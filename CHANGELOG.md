# OpenQPEP Core Protocol Changelog (`v0.1.0` → `v1.0.0`)

Complete incremental version history of the **OpenQPEP Core Protocol** by **Calyx Labs Inc.** (`https://github.com/CalyxLabsInc/OpenQPEP/`), licensed universally under the **Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)**.

---

## Beta Series (`v0.1.0` → `v0.5.0`)

### Beta `v0.1.0` — Genesis Protocol Prototype
- Established the foundational post-quantum encryption and digital signature architecture: `qSponge-512` extendable-output function, `CC-512` cascaded dual-stream AEAD (`AES-256-GCM` + `ChaCha20-Poly1305`), `QLX` Module-LWE KEM hybridized with `HGC-448`, `QVS` lattice vector signatures, and the initial `.qpkrf` armored key-ring format.

### Beta `v0.1.1` — Multi-Tier Reference Engine & Key Addressing
- Shipped the initial multi-tier `QLX`/`QVS` Python reference implementation (`Velocity`, `Sovereign-Hybrid`, `Ultra-Grid`), 64-character `Key Hash` addressing, `.qpkrf` key rings, and attached-only signature envelopes.

### Beta `v0.1.2` — Official Protocol Branding
- Officially renamed the protocol and core repository to **OpenQPEP by Calyx Labs Inc.** (`OpenQPEP`).

### Beta `v0.1.3` — Security Audit Fix #1 (Key Ring Integrity)
- Enforced constant-time recomputation and verification of the 512-bit `integrity_mac` and 64-character `Key Hash` public-key binding during `import_qpkrf`.

### Beta `v0.1.4` — Security Audit Fix #2 (Chunk Truncation & Auto-Verify)
- Enforced terminal-frame truncation checks (`final == 1` on the last 64 KiB `CC-512` chunk and `final == 0` on all preceding chunks) and automatic embedded sender signature verification during packet decryption.

### Beta `v0.1.5` — Interactive OpenQPEP CLI
- Released the interactive English-command `openqpep` CLI with guided `Create Key`, `Export Private/Public`, `Import Key`, encryption/decryption, attached signing/verification, and persistent `~/.openqpep/keyring.json` storage.

### Beta `v0.1.6` — Technical Specification Suite & Licensing
- Authored and expanded the `docs/` technical specification manuals (mathematical specification, threat model, wire format, and architecture guides) and formalized the Calyx Public Open Source License.

### Beta `v0.1.7` — Universal Binary File Encryption Registry
- Added a hardcoded registry of 165+ supported file extensions (`SUPPORTED_FILE_EXTENSIONS`), binary magic-byte header detection (`detect_file_extension_and_mime`), and raw binary `bytes` file encryption/decryption.

### Beta `v0.1.8` — `Calyx Signature` Default Tier & Fault-Guard
- Introduced **`Calyx Signature` (`QLX-4096 + QVS-256`)** as the default key tier ($k = 16$, 4,096-dimensional Module-LWE + $8 \times 7$ lattice vector signatures), added Verify-Before-Emit `Fault-Guard` fault-injection protection on signing, and published the 6-vector Quantum & AI-Cryptanalysis Immunity Matrix.

### Beta `v0.1.9` — `Calyx Hyper-Tesseract` High-Tier Hardware Suite
- Introduced **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)** ($k = 64$, 16,384-dimensional 4-Manifold Coupled Hyper-Tesseract Module-LWE with dense cross-manifold seed coupling, unit-variance $\text{CBD}_1$ sampling, and $16 \times 14$ `QVS-1024` signatures) alongside mandatory flagship hardware RAM warnings.

### Beta `v0.2.0` — Protocol Synchronization & Verification Pass
- Resolved cross-module serialization and encoding edge cases across the core Python SDK, CLI, documentation, and automated unit test suite, establishing a unified version baseline across all protocol modules.

### Beta `v0.2.1` — Modular Cryptographic Kernel & `CPOSLS-1.0`
- Refactored the monolithic reference engine into 13 clean, modular packages under `calyx_qpep/primitives/` and `calyx_qpep/lattice/` with backward-compatible public facades and migrated licensing to `CPOSLS-1.0`.

### Beta `v0.2.2` — Deterministic KAT Vector Engine
- Added `calyx_qpep/vectors/` with deterministic Known-Answer Test (KAT) generation and verification, published golden JSON test vectors under `vectors/`, and wired `openqpep verify-vectors` into the CLI.

### Beta `v0.2.3` — Memory-Hard `QPKD-Argon2id` & Hardware Auto-Tuner
- Added `calyx_qpep/kdf/` (`passphrase_policy.py`, `hardware_tuner.py`, `argon2id_cascade.py`) implementing RFC 9106 `Argon2id` cascaded with `qSponge-512` (`kdf_version: 2`) and automatic memory/iteration tuning based on host hardware.

### Beta `v0.2.4` — Anonymous Multi-Recipient Encryption & Traffic Padding
- Added `calyx_qpep/wire/` (`file_registry.py`, `framing.py`, `armor.py`, `multi_recipient.py`) supporting anonymous multi-recipient packet encapsulation and bucketed traffic-analysis padding.

### Beta `v0.2.5` — Post-Quantum Double Ratchet (`QPEP-Ratchet`)
- Added `calyx_qpep/ratchet/` (`kdf_chain.py`, `pq_rekey.py`, `session_state.py`) delivering asynchronous Post-Quantum Double Ratchet sessions with Forward Secrecy (FS) and Post-Compromise Security (PCS).

### Beta `v0.2.6` — Cryptographic Key Lifecycle & Threshold Recovery
- Added `calyx_qpep/keyring/` (`qpkrf_model.py`, `qpkrf_codec.py`, `subkeys.py`, `revocation.py`) for subkey delegation and signed revocation certificates, plus `calyx_qpep/recovery/` (`sss_gf256.py`, `qshare_codec.py`) implementing $t$-of-$n$ Shamir Secret Sharing over $\mathbb{F}_{256}$.

### Beta `v0.2.7` — Streaming Merkle-Tree AEAD & `Calyx Sovereign-Pentad`
- Added `calyx_qpep/wire/streaming.py` for $O(1)$-RAM chunked streaming encryption with seekable Merkle-tree integrity verification.
- Introduced the **`Calyx Sovereign-Pentad` (`CSP-Omega`)** 5-family beyond-LWE cryptographic architecture spanning Plain-LWE (`CULC-2048`), Binary Goppa codes (`CGM-8192`), Rank-Metric syndrome decoding (`CRT-RSD512`), 2D Supersingular Isogenies (`CIF-SQI-512`), Multivariate Quadratic signatures (`QMQ-512`), and Stateless Hash Hypertrees (`QHS-512`).

### Beta `v0.2.8` — Threshold Multi-Party Cosigning & Timestamp Proofs
- Added `calyx_qpep/signatures/` (`attached.py`, `multisig.py`, `timestamp_proof.py`) supporting $m$-of-$n$ multi-party `QVS + Ed448` cosigning and verifiable cryptographic timestamp proofs.

### Beta `v0.2.9` — Adversarial Audit Suite, Fuzzing & Benchmarks
- Added `calyx_qpep/audit/` (`fuzz_wire.py`, `attack_sim.py`, `timing_audit.py`) with wire-format fuzzing, active attack simulations, Welch's $t$-test side-channel timing checks, and the `benchmarks/bench_suites.py` performance harness.

### Beta `v0.3.0` — Native C99/AVX2/NEON `libopenqpep` Acceleration
- Added `calyx_qpep/native/` (`csrc/ntt_3329.c`, `csrc/ntt_8380417.c`, `csrc/cbd.c`, `csrc/Makefile`, `loader.py`) delivering a compiled C99 native acceleration library with ctypes auto-loading and bit-exact parity against the pure-Python engine.

### Beta `v0.3.1` — WebAssembly SIMD128 Engine
- Added `calyx_qpep/native/wasm/` (`build_wasm.sh`, `wasm_bridge.js`) compiling `libopenqpep` C99 NTT/CBD kernels to standalone WebAssembly SIMD128 for browser and WebView runtimes.

### Beta `v0.3.2` — Memory-Safe Rust `openqpep-core` Crate
- Added the `rust/openqpep-core` crate providing memory-safe Rust implementations of core OpenQPEP primitives, NTT arithmetic, and wire framing.

### Beta `v0.3.3` — `QPEP-MLS` Post-Quantum Group Messaging
- Implemented `QPEP-MLS` TreeKEM post-quantum group messaging supporting forward-secret, post-compromise-secure group epochs up to 256 members.

### Beta `v0.3.4` — Hardware Security Key & Enclave Backing
- Added hardware security key and platform enclave abstraction interfaces for isolating long-term signing and decryption secrets.

### Beta `v0.3.5` — `QPEP-AKE` (1-RTT PQ-Noise-XX Handshake)
- Implemented `QPEP-AKE`, a 1-RTT post-quantum authenticated key-exchange handshake modeled on Noise-XX with mutual identity protection.

### Beta `v0.3.6` — Verifiable Key Transparency Log (`QPEP-KT`)
- Implemented `QPEP-KT` append-only Merkle transparency logs with Signed Tree Heads (STHs), inclusion proofs, and consistency verification.

### Beta `v0.3.7` — Deniable & Linkable Ring Signatures (`QVS-Ring`)
- Implemented `QVS-Ring` lattice-based ring signatures providing signer anonymity and optional linkability.

### Beta `v0.3.8` — Standalone Beyond-LWE Suites (`CGM-8192` & Rank-Metric)
- Promoted **`Calyx Goppa-Monolith` (`CGM-8192 + QHS-512`)** and **`Calyx Rank-Metric Tensor` (`CRT-RSD512 + QMQ-512`)** to standalone selectable protocol suites outside the Pentad combiner.

### Beta `v0.3.9` — Verifiable Encrypted Search & Blind Indexing (`QPEP-Vault`)
- Implemented `QPEP-Vault` encrypted search with keyed blind indexing so encrypted archives can be queried without exposing plaintext metadata.

### Beta `v0.4.0` — Native Pentad C99 Kernel & Compact Binary TLV v3.1
- Added native C99 acceleration (`pentad_accel.c`) for `CULC-2048` Plain-LWE inner products and introduced Compact Binary TLV Wire Format v3.1 (`\x89QPE\x03\x01`).

### Beta `v0.4.1` — Distributed Proactive Threshold Decryption (`ThresholdKEM`)
- Added `calyx_qpep/threshold/` implementing $t$-of-$n$ proactive threshold decapsulation with periodic share refresh so no single device holds a full decryption secret.

### Beta `v0.4.2` — Post-Quantum Onion Routing (`Sphinx-PQ`)
- Implemented `Sphinx-PQ` fixed-size post-quantum mixnet onion packets for metadata-resistant multi-hop routing.

### Beta `v0.4.3` — Offline Air-Gapped Animated QR Fountain Transfer
- Added Luby-Transform fountain coding (`lt_fountain.py`) for rateless, unidirectional air-gapped transfer of encrypted payloads and `.qpkrf` keys via animated QR frames.

### Beta `v0.4.4` — Plausible-Deniability Dual-Volume Containers (`DeniableVault`)
- Implemented dual-passphrase `DeniableVault` containers where an outer decoy volume and an inner hidden volume are cryptographically indistinguishable.

### Beta `v0.4.5` — Post-Quantum Time-Lock Puzzles & VDF Capsules
- Implemented sequential time-lock puzzle and verifiable delay function (VDF) capsules for delayed cryptographic disclosure.

### Beta `v0.4.6` — Lattice Zero-Knowledge Key-Ownership Proofs (`LatticeZKProof`)
- Implemented non-interactive lattice zero-knowledge proofs of secret-key ownership without revealing secret material.

### Beta `v0.4.7` — Encrypted Multi-Device CRDT State Sync
- Added end-to-end encrypted conflict-free replicated data type (CRDT) state synchronization primitives for multi-device keyrings and metadata.

### Beta `v0.4.8` — Formal Symbolic Verification Models
- Added formal verification specifications in Tamarin Prover, ProVerif, and Cryptol covering `QPEP-AKE`, `QPEP-Ratchet`, and core KEM/AEAD composition.

### Beta `v0.4.9` — Reproducible Build & SPDX SBOM Generator
- Added deterministic build verification tooling and automated SPDX Software Bill of Materials (SBOM) generation.

### Beta `v0.5.0` — Go Conformance Port & Pre-PC Spec Freeze
- Added the Go conformance port (`go/`), finalized cross-language vector parity across Python, C99, Rust, WASM, and Go, and completed the Beta feature freeze ahead of Production Candidate promotion.

---

## Production Candidate Series (`v1.0.0-pc` → `v1.2.0-pc`)

### Production Candidate `v1.0.0-pc` — Clean Break from Beta & Wire Format v3 Freeze
- Promoted the protocol from `beta` to `pc` with a strict clean break: removed all legacy beta wire magics (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`), unframed JSON fallbacks, and `kdf_version: 1` key-ring support across Python, Rust, and Go.
- Enforced Frozen Wire Format v3 (`\x89QPE\x03\x00`), Compact Binary TLV v3.1 (`\x89QPE\x03\x01`), and `kdf_version: 2` (`QPKD-Argon2id + qSponge-512`), regenerating deterministic KATs under `v1.0.0-pc` domain separation.

### Production Candidate `v1.1.0-pc` — Full 10-Suite Taxonomy & Canonical Naming
- Added **`Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512`** and **`Calyx Unstructured-Citadel: CULC-2048 + CGM-8192`** as standalone selectable suites, completing the canonical 10-suite catalog (6 All-Devices suites + 4 High-Tier $\ge 12\text{ GB}$ RAM suites).
- Standardized all suite labels to `"Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"` with explicit per-suite hardware policies.

### Production Candidate `v1.1.4-pc` — 10-Suite Benchmarks & Audit Cleanup
- Expanded `benchmarks/bench_suites.py` to benchmark all 10 canonical suites, unified documentation across all modules, and removed remaining legacy suite-naming strings.

### Production Candidate `v1.1.6-pc` — KDF Terminology Cleanup & 1–10 CLI Selection
- Replaced all remaining bare `QPKD-Argon` references with `QPKD-Argon2id + qSponge-512` across code and specifications.
- Upgraded `calyx_qpep/cli.py` key generation to numbered `1–10` suite selection with explicit High-Tier hardware warnings.

### Production Candidate `v1.1.7-pc` — Native Beyond-LWE `.qpkrf` Parity & 10/10 KATs
- Unified `OpenQPEPProtocol.generate_keypair()` so all 5 Beyond-LWE suites (`CIF-SQI-512`, `CRT-RSD512`, `CGM-8192`, `CULC-2048`, `CSP-Omega`) serialize directly into native `.qpkrf` armored key rings with full `encrypt_bytes`, `decrypt_packet`, `encrypt_text`, `decrypt_text`, `sign_bytes`, and `verify_signature` parity.
- Expanded `vectors/` from 5 to **10/10 deterministic Golden KATs** covering every canonical suite, and added interactive CLI `Switch Suite`, `Benchmark All 10`, and `Inspect Packet` commands.

### Production Candidate `v1.2.0-pc` — WASM SIMD128, Android NDK JNI & Audit Remediation
- Generated `WebAssembly.validate()`-verified `openqpep_wasm.wasm`, upgraded `rust/openqpep-core` with SIMD128 and Beyond-LWE support, and added Android NDK JNI bindings (`openqpep_jni.c` + `CMakeLists.txt` for `arm64-v8a` NEON and `x86_64` AVX2).
- Remediated all core protocol audit findings: automatic Beyond-LWE dispatch in `OpenQPEPProtocol`, narrowed exception handlers replacing broad `except Exception` blocks, and explicit documentation of non-cryptographic LT-fountain RNG and constant-time guarantees.

---

## Release Candidate Bridge (`v1.0.0-rc`)

### Release Candidate `v1.0.0-rc` — Pre-Launch Hardening Candidate
- Introduced transitional Wire Format v4 (`\x89QPE\x04\x00` / `\x89QPE\x04\x01`) and `kdf_version: 3` during final pre-launch cryptographic hardening and deep-audit review prior to locking the permanent `v1.0.0` wire specification.

---

## Official Release `1.0.0` (`v1.0.0`) — Permanent Public Launch Baseline (2026-11-21)

- **Clean-Slate Public Starting Point (`v1.0.0`, `OpenQPEP/1.0.0`, PEP 440 `1.0.0`, branch `main`):** Official public release of the OpenQPEP Core Protocol by Calyx Labs Inc.
- **Zero Legacy Pre-Release Backwards Compatibility:** Strictly enforces **Official Wire Format v5 (`\x89QPE\x05\x00`)**, **Compact Binary TLV v5.1 (`\x89QPE\x05\x01`)**, **Streaming AEAD v5 (`\x89QPS\x05\x00`)**, and **Mandatory `kdf_version: 4` (`RFC 9106 QPKD-Argon2id + qSponge-512` bound to `"OpenQPEP/1.0.0"`)**. All legacy Release Candidate (`-rc`), Production Candidate (`-pc`), and Beta (`-beta`) wire frames, streams, and `kdf_version < 4` key rings are hard-rejected immediately with `QPEPLegacyProtocolError`.
- **Cryptographically Genuine 10-Suite Architecture:**
  - **5 Structured Module-LWE + HGC-448 Suites** (`QLX-768`..`QLX-16384`, `QVS-65`..`QVS-1024`) with branchless `ct_cmov` FO implicit rejection and Verify-Before-Emit Fault-Guard.
  - **5 Genuine Beyond-LWE Suites:** Classic McEliece/Niederreiter **Binary Goppa Patterson** (`CGM-8192`), **LRPC / ROLLO-I** Rank-Metric Syndrome Decoding over $\mathbb{F}_{2^{127}}[X]/(X^{47}+X^5+1)$ (`CRT-RSD512`), **Unbalanced Oil-and-Vinegar (UOV)** Multivariate Signatures over $\mathbb{F}_{256}$ (`QMQ-512`), exact 511-bit **CSIDH-512** Supersingular Isogeny Class-Group Action + SeaSign (`CIF-SQI-512`), Stateless Hash Hypertree (`QHS-512`), Zero-Ring Plain-LWE (`CULC-2048`), and the 5-Family Citadel (`CSP-Omega`).
- **CMT-4 Key-Committing `CC-512` AEAD & Unified Authenticated Envelopes:** Dual-stream `AES-256-GCM` + `ChaCha20-Poly1305` + 256-bit `qSponge-512` commitment tag, suite-bound self-certified key hashes, unified sender-authenticated envelopes across all 10 suites, mandatory constant-time armor CRC verification, zero cleartext identity headers, and 128 MiB zlib decompression-bomb defense.
- **Hardened Stateful, Privacy & Transparency Stack:** Rotating-ephemeral atomic `QPEP-Ratchet`, replay-protected `QPEP-MLS` (256 members), bidirectional PQ `QPEP-AKE`, Ed448-signed `QPEP-KT` STHs with RFC 9162 Merkle Consistency Proofs, genuine Module-SIS AOS `QVS-Ring` lattice ring signatures, masked-header Argon2id `DeniableVault`, zero-reconstruction HJKY `ThresholdKEM`, fixed-size `Sphinx-PQ` onions, and canonical uniform `LatticeZKProof`.
- **5-Language Conformance, Native C99 Hardening & Production CLI:** Thread-safe compile-time `const` C99 NTT tables (`-Wall -Wextra -Werror`), fixed Android JNI `int32_t` bridge, constant-time C99 primitives (`openqpep_ct_eq`, `openqpep_ct_cmov`, `openqpep_verify_wire_v5_magic`, `openqpep_explicit_bzero`), synchronized Rust/Go/WASM ports, `0600` CLI keystore permissions + full scriptable subcommands, 10/10 regenerated deterministic Golden KATs, and full unit/adversarial/fuzz/timing verification (89/89 tests passing).
- **Universal License:** Licensed exclusively under Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`).
