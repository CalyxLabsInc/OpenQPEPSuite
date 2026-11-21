# OpenQPEP Frozen Wire Format v4 (`\x89QPE\x04\x00`), Compact TLV v4.1 (`\x89QPE\x04\x01`) & Stable API Freeze Specification

**Version:** Release Candidate 1.0.0 (`OpenQPEP/RC-1.0.0`, `v1.0.0-rc`)  
**Publisher:** Calyx Labs Inc. (Cleveland, Ohio)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## 1. Unified Binary Wire Format v4 (`\x89QPE\x04\x00`) & Compact TLV v4.1 (`\x89QPE\x04\x01`)

All OpenQPEP packets—single-recipient, multi-recipient broadcast, streaming AEAD, Post-Quantum Double Ratchet, $m$-of-$n$ threshold multisig, Calyx Sovereign-Pentad (`CSP-Omega`), key rings (`.qpkrf`), revocations (`.qrev`), Shamir shards (`.qshare`), detached/attached signatures, and `QPEP-MLS` group packets—share one frozen binary envelope:

| Byte Offset | Length | Field | Description |
|---|---|---|---|
| `0..5` | 6 B | `WIRE_MAGIC_V4` | Constant `0x89 0x51 0x50 0x45 0x04 0x00` (`\x89QPE\x04\x00`) or Compact TLV `0x89 0x51 0x50 0x45 0x04 0x01` (`\x89QPE\x04\x01`) |
| `6` | 1 B | `packet_type` | `0x01` Single, `0x02` Multi-Recipient, `0x03` Stream, `0x04` Ratchet, `0x05` Multisig, `0x06` Sovereign-Pentad, `0x07` Keyring/Lifecycle, `0x08` Signature/Timestamp, `0x09` Group MLS |
| `7` | 1 B | `flags` | Bit 0: standardized bucket payload padding active (`4 KiB` / `16 KiB` / `64 KiB`); Bits 1–7 reserved (`0x00`) |
| `8..23` | 16 B | `wire_nonce` | Per-frame CSPRNG whitening nonce |
| `24..-32` | Variable | `whitened_payload` | `payload ^ qSponge-XOF("CALYX-WIRE-WHITEN-v4|" \|\| hdr \|\| wire_nonce \|\| label, len(payload))` |
| `-32..end` | 32 B | `wire_mac` | `qSponge-512("CALYX-WIRE-MAC-v4|" \|\| hdr \|\| wire_nonce \|\| label \|\| whitened_payload)[:32]` |

### Zero Legacy `-pc` / `-beta` Compatibility (`QPEPLegacyProtocolError`)
`unpack_wire_frame`, `unpack_compact_v41_packet`, and `OpenQPEPProtocol` strictly enforce Wire Format v4 (`\x89QPE\x04\x00`) and Compact TLV v4.1 (`\x89QPE\x04\x01`). All historical `-pc` (`\x89QPE\x03\x00`, `\x89QPE\x03\x01`) and `-beta` (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`) wire magics and `kdf_version < 3` key rings are rejected immediately with `QPEPLegacyProtocolError`.

---

## 2. Native C99 / SIMD Vectorized Acceleration (`libopenqpep`)

The `calyx_qpep/native/` package provides portable C99 implementations (with optional AVX2 on `x86_64` and NEON on `ARM64`) of:
- 7-layer `NTT_3329`, `InvNTT_3329`, `BaseMul_3329`, `PolyAdd_3329`, `PolySub_3329`
- 8-layer `NTT_8380417`, `InvNTT_8380417`, `PointwiseMul_8380417`
- `CBD_1` (`QLX-16384`) and `CBD_2` (`QLX-768..4096`, `QVS-65..1024`) samplers
- Calyx Sovereign-Pentad Unstructured Plain-LWE inner-loop row accumulators
- Compiler-barrier `openqpep_explicit_bzero` and constant-time `openqpep_verify_wire_v4_magic`

When `libopenqpep.so`/`.dylib`/`.dll` is compiled via `make -C calyx_qpep/native/csrc`, `calyx_qpep.native.loader` loads it automatically via `ctypes`. When absent (or when `OPENQPEP_DISABLE_NATIVE=1`), OpenQPEP falls back seamlessly to the bit-exact pure-Python reference engine with zero build dependencies.

## All 10 OpenQPEP Post-Quantum Suites (`v1.0.0-rc`)

Every OpenQPEP suite uses the canonical naming standard `"Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"` paired with **CC-512 AEAD**, **RFC 9106 QPKD-Argon2id + qSponge-512 (`kdf_version: 3`)**, and **Frozen Wire Format v4 (`\x89QPE\x04\x00`) / Compact TLV v4.1 (`\x89QPE\x04\x01`)**.

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
