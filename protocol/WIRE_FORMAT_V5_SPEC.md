# OpenQPEP Official Wire Format v5 (`\x89QPE\x05\x00`), Compact TLV v5.1 (`\x89QPE\x05\x01`) & Stable API Specification

**Version:** Official Release 1.0.0 (`OpenQPEP/1.0.0`, `v1.0.0`)  
**Publisher:** Calyx Labs Inc. (Cleveland, Ohio)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## 1. Unified Binary Wire Format v5 (`\x89QPE\x05\x00`) & Compact TLV v5.1 (`\x89QPE\x05\x01`)

All OpenQPEP Official Release 1.0.0 packets—single-recipient, multi-recipient broadcast, streaming AEAD, Post-Quantum Double Ratchet, $m$-of-$n$ threshold multisig, Calyx Sovereign-Pentad (`CSP-Omega`), key rings (`.qpkrf`), revocations (`.qrev`), Shamir shards (`.qshare`), attached signatures, and `QPEP-MLS` group packets—share one frozen Official binary envelope:

| Byte Offset | Length | Field | Description |
|---|---|---|---|
| `0..5` | 6 B | `WIRE_MAGIC_V5` | `0x89 0x51 0x50 0x45 0x05 0x00` (`\x89QPE\x05\x00`) or Compact TLV `0x89 0x51 0x50 0x45 0x05 0x01` (`\x89QPE\x05\x01`) |
| `6` | 1 B | `packet_type` | `0x01` Single, `0x02` Multi-Recipient, `0x03` Stream, `0x04` Ratchet, `0x05` Multisig, `0x06` Sovereign-Pentad, `0x07` Keyring/Lifecycle, `0x08` Signature/Timestamp, `0x09` Group MLS |
| `7` | 1 B | `flags` | Bit 0: standardized bucket payload padding active (`4 KiB` / `16 KiB` / `64 KiB`); Bits 1–7 strictly `0x00` |
| `8..23` | 16 B | `wire_nonce` | Per-frame CSPRNG whitening nonce |
| `24..-32` | Variable | `whitened_payload` | `payload ^ qSponge-XOF("CALYX-WIRE-WHITEN-v5-1.0.0|" \|\| hdr \|\| wire_nonce \|\| label, len(payload))` |
| `-32..end` | 32 B | `wire_mac` | `qSponge-512("CALYX-WIRE-MAC-v5-1.0.0|" \|\| hdr \|\| wire_nonce \|\| label \|\| whitened_payload)[:32]` |

### Streaming AEAD Magic (`\x89QPS\x05\x00`)
`StreamingEncryptor` / `StreamingDecryptor` emit and require `STREAM_MAGIC_V5 = b"\x89QPS\x05\x00"` with full-ciphertext `qSponge-512` Merkle leaves and CMT-4 Key-Committing `CC-512`.

### Zero Legacy Pre-Release Compatibility (`QPEPLegacyProtocolError`)
Official Release 1.0.0 is the clean-slate public starting point of the OpenQPEP ecosystem. **All** pre-release Release Candidate (`-rc`: `\x89QPE\x04\x00`, `\x89QPE\x04\x01`, `kdf_version: 3`), Production Candidate (`-pc`: `\x89QPE\x03\x00`, `\x89QPE\x03\x01`, `kdf_version: 2`), Beta (`-beta`: `\x89QPE\x01\x01`, `\x01\x09`, `\x02\x00`, `kdf_version: 1`), and legacy stream (`\x89QPS\x02\x07`) artifacts are strictly rejected with `QPEPLegacyProtocolError`.

---

## 2. CMT-4 Key-Committing `CC-512` AEAD & Mandatory `kdf_version: 4`

- **CMT-4 Key-Committing `CC-512`:** Derives `(k_aes, k_chacha, k_commit)` via `qSponge-XOF("CALYX-CC512-CMT4-KEYS-v1.0.0|" || key64 || nonce24, 96)`, nests `AES-256-GCM` inside `ChaCha20-Poly1305`, and appends a 256-bit `qSponge-512` key+nonce+AAD+ciphertext commitment tag verified in constant time prior to decryption (64 B total overhead).
- **Mandatory `kdf_version: 4`:** RFC 9106 `QPKD-Argon2id + qSponge-512` bound to `"personalization": "OpenQPEP/1.0.0"`, mandatory 64-byte structural passphrase witness, and optional `FIDO2-PRF` hardware passkey secret.

---

## 3. Native C99 / SIMD Acceleration (`libopenqpep`)

Compiles cleanly with `-O3 -std=c99 -fPIC -Wall -Wextra -Werror` (AVX2 on `x86_64`, NEON on `ARM64`) with thread-safe compile-time `const` twiddle tables, branchless reductions, constant-time `openqpep_ct_eq` / `openqpep_ct_cmov` / `openqpep_verify_wire_v5_magic`, and compiler-barrier `openqpep_explicit_bzero`.

---

## 4. All 10 Official OpenQPEP Post-Quantum Suites (`v1.0.0`)

Every OpenQPEP suite uses the canonical naming standard `"Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"` paired with **CMT-4 Key-Committing CC-512 AEAD**, **RFC 9106 QPKD-Argon2id + qSponge-512 (`kdf_version: 4`)**, and **Official Wire Format v5 (`\x89QPE\x05\x00`) / Compact TLV v5.1 (`\x89QPE\x05\x01`)**.

| Canonical Suite Name | KEM + Signature | Mathematical Family | Hardware Classification | Primary Role |
| :--- | :--- | :--- | :--- | :--- |
| **Calyx Lattice-Apex: QLX-4096 + QVS-256 (4,096-Dim Module-LWE — All Devices)** | `QLX-4096` + `QVS-256` | Structured Module-LWE (`k=16`, 4,096-dim) + Hybrid X448 | **All Devices** | Default flagship security for mobile & desktop |
| **Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)** | `QLX-768` + `QVS-65` | Structured Module-LWE (`k=3`, 768-dim) + Hybrid X448 | **All Devices** | Lowest-latency mobile messaging & constrained links |
| **Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)** | `QLX-1024` + `QVS-87` | Structured Module-LWE (`k=4`, 1,024-dim) + Hybrid X448 | **All Devices** | Balanced NIST-Level-5-class lattice security |
| **Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)** | `QLX-2048` + `QVS-128` | Structured Module-LWE (`k=8`, 2,048-dim) + Hybrid X448 | **All Devices** | Elevated 2,048-dimensional lattice margin |
| **Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)** | `CIF-SQI-512` + `QHS-512` | CSIDH-512 Supersingular Isogeny + Stateless Hash Hypertree | **All Devices** | Beyond-LWE compact isogeny key exchange & hash signatures |
| **Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (All-Devices Signature Default — All Devices)** | `CRT-RSD512` + `QMQ-512` | LRPC Rank-Metric Syndrome Decoding + UOV Multivariate (`GF(256)`) | **All Devices** | Beyond-LWE rank-metric code & multivariate diversity |
| **Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)** | `QLX-16384` + `QVS-1024` | 4-Manifold Coupled Module-LWE (`k=64`, 16,384-dim) + `16×14` QVS | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Maximum structured-lattice dimension (~69 KB secret vectors) |
| **Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)** | `CGM-8192` + `QHS-512` | Classic McEliece / Niederreiter Binary Goppa Patterson + Hash Hypertree | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Beyond-LWE conservative code-based encryption |
| **Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)** | `CULC-2048` + `CGM-8192` | Unstructured Plain-LWE (`n×n` ring-free) + Binary Goppa Patterson | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Zero algebraic ring-structure defense against ideal-lattice attacks |
| **Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (High-Tier Signature Default — HIGH-TIER HARDWARE ONLY)** | `CSP-Omega` + `QHS-512` | 5-Family Combiner (Plain-LWE + Goppa + CSIDH-512 + UOV + QHS-512 + X448) | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Ultimate multi-assumption citadel; secure if any 1 of 5 families holds |
