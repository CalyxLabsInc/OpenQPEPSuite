# OpenQPEP by Calyx Labs Inc. — Production Candidate 1.0.0 (`v1.0.0-pc`)

**Protocol Version:** `OpenQPEP/PC-1.0.0` (`v1.0.0-pc`, branch `pc`)  
**Publisher:** Calyx Labs Inc. (Cleveland, Ohio) — `support@calyxlabsinc.org`  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)  
**Unified Suite Monorepo:** https://github.com/CalyxLabsInc/OpenQPEPSuite/

OpenQPEP (Open Quantum-Proof Encryption Protocol) is a post-quantum hybrid cryptographic protocol and multi-language reference engine engineered to replace legacy OpenPGP with modern, constant-time, memory-hard, and beyond-LWE post-quantum cryptography.

> **Breaking Production Candidate 1.0.0 Baseline:** All legacy `-beta` backwards compatibility has been completely removed. OpenQPEP `v1.0.0-pc` strictly enforces **Frozen Wire Format v3 (`\x89QPE\x03\x00`)**, **Compact Binary TLV Wire Format v3.1 (`\x89QPE\x03\x01`)**, and **Mandatory `kdf_version: 2` (`RFC 9106 QPKD-Argon2id + qSponge-512`)**. Legacy beta wire magics (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`), raw unframed JSON fallbacks, and `kdf_version: 1` key rings are strictly rejected.

---

## 1. Eight Post-Quantum Cryptographic Suites

| Tier | Suite Name | Mathematical Foundation | KEM Ciphertext | Signature / Auth | Target Hardware |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **Tier 1** | `QLX-768 + QVS-65` (Velocity) | Module-LWE ($k=3$) + `HGC-448` + `CC-512` | `1,088 B` | `1,600 B` + `Ed448` | All devices / IoT |
| **Tier 2** | `QLX-1024 + QVS-87` (Sovereign Hybrid) | Module-LWE ($k=4$) + `HGC-448` + `CC-512` | `1,568 B` | `2,368 B` + `Ed448` | All devices |
| **Tier 3** | `QLX-2048 + QVS-128` (Ultra-Grid) | Module-LWE ($k=8$) + `HGC-448` + `CC-512` | `2,976 B` | `3,904 B` + `Ed448` | All devices |
| **Tier 4 (Default)** | **Calyx Signature (`QLX-4096 + QVS-256`)** | Module-LWE ($k=16$) + `HGC-448` + `CC-512` | `5,792 B` | `5,440 B` + `Ed448` | Recommended Default (All Devices) |
| **Tier 5** | **Calyx Hyper-Tesseract (`QLX-16384 + QVS-1024`)** | 4-Manifold Coupled Lattice ($k=64$, $\text{CBD}_1$) + `HGC-448` | `23,168 B` | `10,816 B` + `Ed448` | High-Tier Hardware (`12 GB+` RAM) |
| **Tier 10** | **Calyx Sovereign-Pentad (`CSP-Omega`)** | **5 Disjoint Families in Parallel:** Unstructured Plain-LWE + Binary Goppa (`CGM-8192`) + 2D Isogenies (`SQI-512`) + `QMQ-512` + `QHS-512` + `X448` | Multi-family parallel | Conjunctive Triple-Family (`QHS` + `QMQ` + `SQI`) | Flagship Hardware Guardrail (`>= 12 GB` RAM) |
| **Tier 11** | **Calyx Goppa-Monolith (`CGM-8192`)** | Standalone Binary Goppa Syndrome Decoding (Zero LWE) + `CC-512` | Code-based | Attached / Detached Auth | All devices (Pure Non-Lattice) |
| **Tier 12** | **Calyx Rank-Metric Tensor (`RMT-512`)** | Standalone Rank-Metric Syndrome Decoding over $\mathbb{F}_{2^{127}}$ (Zero LWE) + `CC-512` | Rank-metric | Attached / Detached Auth | All devices (Pure Non-Lattice) |

---

## 2. Core Security & Protocol Architecture (`v1.0.0-pc`)

- **Strict Frozen Wire Format v3 (`\x89QPE\x03\x00`) & Compact TLV v3.1 (`\x89QPE\x03\x01`):** Stream-whitened binary framing with 256-bit `qSponge-512` MACs, standardized bucket payload padding (`4 KiB` / `16 KiB` / `64 KiB`), and zero cleartext `Sender-Key-Hash`, `Recipient-Key-Hash`, or `Signer-Key-Hash` armor headers.
- **Mandatory Memory-Hard KDF (`kdf_version: 2`):** RFC 9106 **QPKD-Argon2id + qSponge-512** cascade (`m=65536 KiB` standard / `m=262144 KiB` high-tier, `t=3`, `p=4`) mathematically bound to the 64-byte hardcoded passphrase policy witness (`>= 12` chars, `>= 2` digits, `>= 4` specials, `>= 2` upper, `>= 4` lower).
- **Dual-Stream Symmetric AEAD (`CC-512`):** Cascaded `AES-256-GCM` + `ChaCha20-Poly1305` with independent 256-bit subkeys and nonces.
- **Full 12-Protocol Stack:**
  - `calyx_qpep/wire/multi_recipient.py` — Anonymous mixed-tier $N$-recipient broadcast with 64-bit blinded slot tags & power-of-2 dummy slots
  - `calyx_qpep/wire/streaming.py` — $O(1)$-RAM 64 KiB chunked AEAD & Merkle-tree seekable byte-range decryption
  - `calyx_qpep/ratchet/` — `QPEP-Ratchet` forward secrecy + periodic hybrid `QLX` + `HGC-448` post-compromise security (`MAX_SKIP = 256`)
  - `calyx_qpep/group/` — `QPEP-MLS` $O(\log N)$ post-quantum TreeKEM group messaging with immediate eviction
  - `calyx_qpep/transport/` — `QPEP-AKE` 1-RTT identity-hiding PQ-Noise-XX handshake with SAS channel binding
  - `calyx_qpep/directory_kt/` — `QPEP-KT` verifiable append-only `qSponge-512` Merkle key transparency log
  - `calyx_qpep/keyring/` & `recovery/` — Rotatable subkeys, `.qrev` self-authenticating revocations, and verifiable $t$-of-$n$ `.qshare` Shamir recovery
  - `calyx_qpep/signatures/` — Attached signatures, $m$-of-$n$ threshold cosigning, and cryptographic timestamp proofs
  - `calyx_qpep/hardware/` — `FIDO2-PRF` / StrongBox / Secure Enclave hardware key wrapping with mandatory `.qshare` guardrail
  - `calyx_qpep/privacy/` — `QVS-Ring` 1-of-$N$ deniable/linkable ring signatures & `DeniableVault` dual-volume containers
  - `calyx_qpep/vault/`, `threshold/`, `mixnet/`, `airgap/`, `timelock/`, `zkp/`, `sync/` — `BlindSearchVault`, proactive $t$-of-$n$ `ThresholdKEM`, `Sphinx-PQ` onion routing, `LT-QR` air-gapped fountain transfer, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.

---

## 3. Multi-Language Native Runtimes & Verification

- **C99 / AVX2 / NEON (`calyx_qpep/native/csrc/`):** Portable C99 accelerators for `NTT_3329`, `NTT_8380417`, `CBD_1`/`CBD_2`, Plain-LWE, and Sovereign-Pentad kernels (`libopenqpep.so`) loaded via zero-copy `array.array` `ctypes` with automatic pure-Python fallback.
- **WASM SIMD128 (`calyx_qpep/native/wasm/`):** Browser/WebView WASM build & `wasm_bridge.mjs`.
- **Rust (`rust/openqpep-core/`) & Go (`go/openqpep/`):** Memory-safe `#![forbid(unsafe_code)]` Rust crate (PyO3/UniFFI) and Go Wire v3/v3.1 conformance port.
- **Formal & Audit Suite (`formal/`, `calyx_qpep/audit/`, `vectors/`):** Tamarin/ProVerif/Cryptol symbolic models, SPDX SBOM generator, wire fuzzer, active attack simulator, DudeCT Welch's $t$-test timing audit, **5 bit-exact `v1.0.0-pc` golden KAT suites**, and **63/63 passing tests**.

```bash
make -C calyx_qpep/native/csrc
pip install -e .
python3 -m calyx_qpep.cli verify-vectors
python3 -m unittest discover -s tests -v
```

---

## 4. Technical Documentation (`docs/` & `specs/`)

1. [`docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md`](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Complete mathematical specification of all 8 suites, `CC-512`, `QPKD-Argon2id + qSponge-512`, and `CSP-Omega`.
2. [`docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md`](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — Architectural security comparison against legacy OpenPGP.
3. [`docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md`](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — `.qpkrf` (`kdf_version: 2`), Frozen Wire Format v3 (`\x89QPE\x03\x00`), Compact TLV v3.1 (`\x89QPE\x03\x01`), `.qrev`, and `.qshare`.
4. [`docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md`](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — CLI, Calyx QPEP Client, Calyx Encrypted Messenger, Calyx Encrypted Email, and Key Directory guide.
5. [`WIRE_FORMAT_V3_SPEC.md`](WIRE_FORMAT_V3_SPEC.md) & [`specs/OPENQPEP_v1.0.0-pc_PRODUCTION_CANDIDATE_SPEC.md`](specs/OPENQPEP_v1.0.0-pc_PRODUCTION_CANDIDATE_SPEC.md) — Frozen Production Candidate 1.0.0 wire and API specifications.
