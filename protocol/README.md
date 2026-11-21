# OpenQPEP by Calyx Labs Inc. — Release Candidate 1.0.0 (`v1.0.0-rc`)

**Protocol Version:** `OpenQPEP/RC-1.0.0` (`v1.0.0-rc`, branch `rc`)  
**Publisher:** Calyx Labs Inc. (Cleveland, Ohio) — `support@calyxlabsinc.org`  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)  
**Unified Suite Monorepo:** https://github.com/CalyxLabsInc/OpenQPEPSuite/

OpenQPEP (Open Quantum-Proof Encryption Protocol) is a post-quantum hybrid cryptographic protocol and multi-language reference engine engineered to replace legacy OpenPGP with modern, constant-time, memory-hard, and beyond-LWE post-quantum cryptography.

> **Breaking Release Candidate 1.0.0 Baseline:** All legacy `-pc` (`\x89QPE\x03\x00`, `\x89QPE\x03\x01`, `kdf_version: 2`) and `-beta` backwards compatibility has been completely removed. OpenQPEP `v1.0.0-rc` strictly enforces **Frozen Wire Format v4 (`\x89QPE\x04\x00`)**, **Compact Binary TLV Wire Format v4.1 (`\x89QPE\x04\x01`)**, and **Mandatory `kdf_version: 3` (`RFC 9106 QPKD-Argon2id + qSponge-512` bound to `"OpenQPEP/RC-1.0.0"`)**. Any legacy `-pc` or `-beta` wire magic or `kdf_version < 3` key ring is strictly rejected with `QPEPLegacyProtocolError`.

---

## 1. Ten Post-Quantum Cryptographic Suites (`v1.0.0-rc`)

| Suite Tier | Canonical Suite Name | Mathematical Foundation | Hardware Policy |
| :--- | :--- | :--- | :---: |
| **Tier 1** | `Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)` | Module-LWE ($k=3$) + `HGC-448` + `CC-512` | **All Devices** |
| **Tier 2** | `Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)` | Module-LWE ($k=4$) + `HGC-448` + `CC-512` | **All Devices** |
| **Tier 3** | `Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)` | Module-LWE ($k=8$) + `HGC-448` + `CC-512` | **All Devices** |
| **Tier 4 (Default)** | **`Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)`** | Module-LWE ($k=16$) + `HGC-448` + `CC-512` | **All Devices** |
| **Tier 5** | **`Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)`** | 4-Manifold Coupled Lattice ($k=64$, $\text{CBD}_1$) + `HGC-448` | **High-Tier (`>= 12 GB RAM`)** |
| **Tier 6** | **`Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)`** | NP-Complete Binary Goppa Syndrome Decoding + `QHS-512` | **High-Tier (`>= 12 GB RAM`)** |
| **Calyx Isogeny-Forge** | **`Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)`** | 2D Supersingular Abelian Isogeny + `QHS-512` (Compact 256 B PK) | **All Devices** |
| **Tier 8** | **`Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)`** | Rank-Metric Syndrome Decoding over $\mathbb{F}_{2^{127}}$ + `QMQ-512` | **All Devices** |
| **Calyx Unstructured-Citadel** | **`Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)`** | Zero-Ring Plain-LWE $\oplus$ Binary Goppa + `QHS-512` | **High-Tier (`>= 12 GB RAM`)** |
| **Calyx Sovereign-Pentad** | **`Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)`** | 5 Disjoint Families in Parallel (Plain-LWE + Goppa + Isogeny + `QMQ` + `QHS` + `X448`) | **High-Tier (`>= 12 GB RAM`)** |

---

## 2. Core Security & Protocol Architecture (`v1.0.0-rc`)

- **Strict Frozen Wire Format v4 (`\x89QPE\x04\x00`) & Compact TLV v4.1 (`\x89QPE\x04\x01`):** Stream-whitened binary framing (`CALYX-WIRE-WHITEN-v4|` / `CALYX-WIRE-MAC-v4|`) with 256-bit `qSponge-512` MACs, standardized bucket payload padding (`4 KiB` / `16 KiB` / `64 KiB`), and zero cleartext `Sender-Key-Hash`, `Recipient-Key-Hash`, or `Signer-Key-Hash` armor headers.
- **Mandatory Memory-Hard KDF (`kdf_version: 3`):** RFC 9106 **QPKD-Argon2id + qSponge-512** cascade (`m=65536 KiB` standard / `m=262144 KiB` high-tier, `t=3`, `p=4`, `"personalization": "OpenQPEP/RC-1.0.0"`) mathematically bound to the 64-byte hardcoded passphrase policy witness (`>= 12` chars, `>= 2` digits, `>= 4` specials, `>= 2` upper, `>= 4` lower) and optional `FIDO2-PRF` hardware passkey secret.
- **Dual-Stream Symmetric AEAD (`CC-512`):** Cascaded `AES-256-GCM` + `ChaCha20-Poly1305` with independent 256-bit subkeys and nonces.
- **Full 12-Protocol Stack:**
  - `calyx_qpep/wire/multi_recipient.py` — Anonymous mixed-tier $N$-recipient broadcast with 64-bit blinded slot tags & power-of-2 dummy slots
  - `calyx_qpep/wire/streaming.py` — $O(1)$-RAM 64 KiB chunked AEAD & Merkle-tree seekable byte-range decryption
  - `calyx_qpep/ratchet/` — `QPEP-Ratchet` forward secrecy + periodic hybrid `QLX` + `HGC-448` post-compromise security (`MAX_SKIP = 256`)
  - `calyx_qpep/group/` — `QPEP-MLS` $O(\log N)$ post-quantum TreeKEM group messaging up to `MAX_GROUP_MEMBERS = 256` with immediate eviction
  - `calyx_qpep/transport/` — `QPEP-AKE` 1-RTT identity-hiding PQ-Noise-XX handshake with SAS channel binding
  - `calyx_qpep/directory_kt/` — `QPEP-KT` verifiable append-only `qSponge-512` Merkle key transparency log with Signed Tree Heads (STH) & ownership proofs
  - `calyx_qpep/keyring/` & `recovery/` — Rotatable subkeys, `.qrev` self-authenticating revocations, and verifiable $t$-of-$n$ `.qshare` Shamir recovery
  - `calyx_qpep/signatures/` — Attached signatures, $m$-of-$n$ threshold cosigning, and cryptographic timestamp proofs
  - `calyx_qpep/hardware/` — `FIDO2-PRF` / StrongBox / Secure Enclave hardware key wrapping with mandatory `.qshare` guardrail
  - `calyx_qpep/privacy/` — `QVS-Ring` 1-of-$N$ deniable/linkable ring signatures & `DeniableVault` dual-volume containers
  - `calyx_qpep/vault/`, `threshold/`, `mixnet/`, `airgap/`, `timelock/`, `zkp/`, `sync/` — `BlindSearchVault`, proactive $t$-of-$n$ `ThresholdKEM`, `Sphinx-PQ` onion routing & sealed sender, `LT-QR` air-gapped fountain transfer, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.

---

## 3. Multi-Language Native Runtimes & Verification (`v1.0.0-rc`)

- **C99 / AVX2 / NEON (`calyx_qpep/native/csrc/`):** Portable C99 accelerators for `NTT_3329`, `NTT_8380417`, `CBD_1`/`CBD_2`, Plain-LWE, Sovereign-Pentad kernels, compiler-barrier `openqpep_explicit_bzero`, and constant-time `openqpep_verify_wire_v4_magic` (`libopenqpep.so`).
- **WASM SIMD128 (`calyx_qpep/native/wasm/`):** `@calyxlabs/openqpep-wasm` (`1.0.0-rc.1`), `wasm_bridge.mjs`, and non-blocking `qpep_worker.js`.
- **Rust (`rust/openqpep-core/`) & Go (`go/openqpep/`):** Memory-safe `#![forbid(unsafe_code)]` Rust crate (`1.0.0-rc.1`) and Go Wire v4/v4.1 conformance port, verified via `calyx_qpep/audit/interop_matrix.py`.
- **Formal & Audit Suite (`formal/`, `calyx_qpep/audit/`, `vectors/`):** Tamarin/ProVerif/Cryptol symbolic models (`qpep_ake.pv`, `qpep_ratchet.spthy`, `qpep_mls.spthy`, `csp_omega_combiner.cry`), SPDX SBOM generator, wire fuzzer + WebView IPC schema validator, active attack simulator, DudeCT Welch's $t$-test timing audit across all 10 suites, **10 bit-exact `v1.0.0-rc` golden KAT suites**, and **79/79 passing tests**.

```bash
make -C calyx_qpep/native/csrc
pip install -e .
python3 -m calyx_qpep.cli verify-vectors
python3 -m unittest discover -s tests -v
```

---

## 4. Technical Documentation (`docs/` & `specs/`)

1. [`docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md`](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Complete mathematical specification of all 10 suites, `CC-512`, `QPKD-Argon2id + qSponge-512` (`kdf_version: 3`), and `CSP-Omega`.
2. [`docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md`](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — Architectural security comparison against legacy OpenPGP.
3. [`docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md`](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — `.qpkrf` (`kdf_version: 3`), Frozen Wire Format v4 (`\x89QPE\x04\x00`), Compact TLV v4.1 (`\x89QPE\x04\x01`), `.qrev`, and `.qshare`.
4. [`docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md`](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — CLI, Calyx QPEP Client, Calyx Encrypted Messenger, Calyx Encrypted Email, and Key Directory guide.
5. [`WIRE_FORMAT_V4_SPEC.md`](WIRE_FORMAT_V4_SPEC.md) & [`specs/OPENQPEP_v1.0.0-rc_RELEASE_CANDIDATE_SPEC.md`](specs/OPENQPEP_v1.0.0-rc_RELEASE_CANDIDATE_SPEC.md) — Frozen Release Candidate 1.0.0 wire and API specifications.

<!-- OpenQPEP Release Candidate 1.0.0 (v1.0.0-rc) -->

## Live 10-Suite Benchmarks (`v1.0.0-rc`)

| OpenQPEP Suite (`v1.0.0-rc`) | Hardware Tier | Keygen (ms) | Encaps (ms) | Decaps (ms) | Sign (ms) | Verify (ms) | Peak RSS (MiB) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices) | All Devices | 41.62 | 19.12 | 21.79 | 11.94 | 5.25 | 17.69 |
| Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices) | All Devices | 7.90 | 1.22 | 1.79 | 2.29 | 0.95 | 17.69 |
| Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices) | All Devices | 10.95 | 1.83 | 2.47 | 3.65 | 1.58 | 17.69 |
| Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices) | All Devices | 20.02 | 5.49 | 6.64 | 7.27 | 3.17 | 17.69 |
| Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY) | HIGH-TIER HARDWARE ONLY (>= 12 GB RAM) | 124.28 | 79.69 | 85.60 | 104.03 | 18.00 | 21.95 |
| Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices) | All Devices | 25.27 | 6.36 | 3.12 | 23.36 | 0.92 | 21.95 |
| Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices) | All Devices | 4.30 | 0.17 | 0.20 | 5.18 | 5.27 | 21.95 |
| Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY) | HIGH-TIER HARDWARE ONLY (>= 12 GB RAM) | 22.53 | 0.31 | 0.30 | 23.19 | 0.69 | 21.95 |
| Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY) | HIGH-TIER HARDWARE ONLY (>= 12 GB RAM) | 26.16 | 4.24 | 4.42 | 24.59 | 0.96 | 21.95 |
| Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY) | HIGH-TIER HARDWARE ONLY (>= 12 GB RAM) | 28.02 | 9.55 | 7.45 | 32.15 | 12.70 | 21.95 |
