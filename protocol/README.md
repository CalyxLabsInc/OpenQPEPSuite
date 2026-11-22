# OpenQPEP by Calyx Labs Inc. — Official Release 1.0.0 (`v1.0.0`)

**Protocol Version:** `OpenQPEP/1.0.0` (`Official Release 1.0.0`, PEP 440 `1.0.0`)  
**Creator & Lead Architect:** Tristen Martinez (Calyx Labs Inc., Cleveland, Ohio)  
**Repository:** https://github.com/CalyxLabsInc/OpenQPEP  
**Public Key Directory & QPEP-KT:** https://qpepkeys.calyxlabsinc.org  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

OpenQPEP is a modern, clean-slate, quantum-proof encryption, authentication, and messaging protocol engineered to replace legacy OpenPGP (RFC 4880 / RFC 9580) as a worldwide standard—with zero legacy cryptographic baggage, provable multi-assumption post-quantum security, constant-time native C99/Rust/WASM/Go performance, and 100% deterministic Known Answer Test (KAT) verification.

## Official Release 1.0.0 Security Highlights

- **Zero Legacy Pre-Release Backwards Compatibility:** Official Release `v1.0.0` is the permanent public starting point of the OpenQPEP ecosystem. All pre-release Release Candidate (`-rc`, Wire v4/v4.1, `kdf_version: 3`), Production Candidate (`-pc`, Wire v3/v3.1, `kdf_version: 2`), Beta (`-beta`, Wire v1/v2, `kdf_version: 1`), and legacy stream (`\x89QPS\x02\x07`) artifacts are strictly rejected with `QPEPLegacyProtocolError`.
- **Frozen Official Wire Format v5 (`\x89QPE\x05\x00`), Compact TLV v5.1 (`\x89QPE\x05\x01`) & Stream v5 (`\x89QPS\x05\x00`):** Mandatory constant-time `={crc}` armor verification, zero cleartext sender/recipient identity headers, duplicate-tag rejection, and 128 MiB decompression-bomb protection.
- **CMT-4 Key-Committing `CC-512` AEAD:** Dual-stream `AES-256-GCM` + `ChaCha20-Poly1305` + 256-bit `qSponge-512` key/nonce/AAD/ciphertext commitment verified in constant time prior to decryption.
- **Mandatory `kdf_version: 4` (`RFC 9106 QPKD-Argon2id + qSponge-512`):** Bound to `"personalization": "OpenQPEP/1.0.0"`, hardcoded 64-byte structural passphrase witness, hardware auto-tuner, and optional `FIDO2-PRF` hardware passkey secret mixing.
- **10 Cryptographically Genuine Post-Quantum Suites:**
  - **5 Structured Module-LWE + HGC-448 Suites:** `QLX-768`, `QLX-1024`, `QLX-2048`, `QLX-4096` (default), `QLX-16384` paired with `QVS-65`..`QVS-1024` (with Verify-Before-Emit Fault-Guard).
  - **5 Genuine Beyond-LWE Suites:** **CSIDH-512** Supersingular Isogeny (`CIF-SQI-512`), **LRPC / ROLLO-I** Rank-Metric Syndrome Decoding (`CRT-RSD512`) + **UOV** Multivariate Quadratic (`QMQ-512`), **Classic McEliece / Niederreiter Binary Goppa Patterson** (`CGM-8192`), **Zero-Ring Plain-LWE + Goppa** (`CULC-2048`), and **5-Family Citadel** (`CSP-Omega`).
- **Complete Hardened Sub-Protocol Stack:** `QPEP-Ratchet` (rotating-ephemeral PCS + atomic state commits), `QPEP-MLS` (256-member TreeKEM with replay protection), `QPEP-AKE` (bidirectional post-quantum mutual authentication), `QPEP-KT` (Ed448 publicly verifiable STHs + RFC 9162 Merkle Consistency Proofs), `QVS-Ring` (Module-SIS AOS lattice ring signatures), `DeniableVault`, `ThresholdKEM` (zero-reconstruction HJKY proactive refresh), `Sphinx-PQ` (fixed-size onion frames & sealed sender), `LT-QR`, `BlindSearchVault`, `TimeLockCapsule`, `LatticeZKProof`, and `EncryptedLWWMapCRDT`.

## All 10 Canonical OpenQPEP Post-Quantum Suites (`v1.0.0`)

| Canonical Suite Name | KEM + Signature | Mathematical Family | Hardware Classification |
| :--- | :--- | :--- | :--- |
| **Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)** | `QLX-4096` + `QVS-256` | Module-LWE (`k=16`) + Hybrid X448 | **All Devices** |
| **Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)** | `QLX-768` + `QVS-65` | Module-LWE (`k=3`) + Hybrid X448 | **All Devices** |
| **Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)** | `QLX-1024` + `QVS-87` | Module-LWE (`k=4`) + Hybrid X448 | **All Devices** |
| **Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)** | `QLX-2048` + `QVS-128` | Module-LWE (`k=8`) + Hybrid X448 | **All Devices** |
| **Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)** | `CIF-SQI-512` + `QHS-512` | CSIDH-512 Isogeny + Stateless Hash Hypertree | **All Devices** |
| **Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)** | `CRT-RSD512` + `QMQ-512` | LRPC Rank-Metric Code + UOV Multivariate | **All Devices** |
| **Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)** | `QLX-16384` + `QVS-1024` | 4-Manifold Module-LWE (`k=64`) + `16×14` QVS | **HIGH-TIER (`>= 12 GB RAM`)** |
| **Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)** | `CGM-8192` + `QHS-512` | Binary Goppa Patterson + Hash Hypertree | **HIGH-TIER (`>= 12 GB RAM`)** |
| **Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)** | `CULC-2048` + `CGM-8192` | Plain-LWE + Binary Goppa Patterson | **HIGH-TIER (`>= 12 GB RAM`)** |
| **Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)** | `CSP-Omega` + `QHS-512` | 5-Family Combiner + X448 | **HIGH-TIER (`>= 12 GB RAM`)** |

## Quickstart & Conformance Verification

```bash
# 1. Build Native C99 / SIMD Accelerator (zero warnings with -Werror)
make -C calyx_qpep/native/csrc clean all

# 2. Install OpenQPEP Official Release 1.0.0
pip install -e .

# 3. Verify All 10 Deterministic Golden KAT Suites (Native C99 & Pure-Python)
python3 -m calyx_qpep.cli verify-vectors
OPENQPEP_DISABLE_NATIVE=1 python3 -m calyx_qpep.cli verify-vectors

# 4. Run Full Cryptographic, Adversarial, Fuzzing & 5-Language Interop Suite
python3 -m unittest discover -s tests -v

# 5. Launch Interactive Shell or Scriptable CLI
openqpep --version
openqpep
```

## Specifications & Roadmap

- [UpdateRoadmap_NewFeaturesAndIdeasFor_v1.0.0-rc-v2.0.0-release.md](UpdateRoadmap_NewFeaturesAndIdeasFor_v1.0.0-rc-v2.0.0-release.md) — Complete pre-1.0.0 audit closure & post-1.0.0 to v2.0.0 global standardization roadmap
- [specs/OPENQPEP_v1.0.0_OFFICIAL_RELEASE_SPEC.md](specs/OPENQPEP_v1.0.0_OFFICIAL_RELEASE_SPEC.md) — Frozen Official Release 1.0.0 Specification
- [WIRE_FORMAT_V5_SPEC.md](WIRE_FORMAT_V5_SPEC.md) — Official Binary Wire Format v5 / Compact TLV v5.1 / Stream v5 Specification
- [docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md](docs/01_OpenQPEP_Mathematical_and_Cryptographic_Specification.md) — Mathematical & Cryptographic Specification
- [docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md](docs/02_OpenQPEP_vs_OpenPGP_Security_Comparison.md) — OpenQPEP vs. OpenPGP Security Comparison
- [docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md](docs/03_QPKRF_Key_Ring_and_Binary_Wire_Format.md) — `.qpkrf` Key Ring & Wire Format Guide
- [docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md](docs/04_Interactive_CLI_Android_Client_and_Directory_Guide.md) — CLI, Client Ecosystem & Key Transparency Guide
