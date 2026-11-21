# OpenQPEP Frozen Wire Format v3 (`\x89QPE\x03\x00`) & Stable API Freeze Specification

**Version:** Production Candidate 1.0.0 (`OpenQPEP/Beta-1.0.0-pc`)  
**Publisher:** Calyx Labs Inc. (Cleveland, Ohio)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## 1. Unified Binary Wire Format v3 (`\x89QPE\x03\x00`)

All OpenQPEP packets—single-recipient, multi-recipient broadcast, streaming AEAD, Post-Quantum Double Ratchet, $m$-of-$n$ threshold multisig, Tier 10 Calyx Sovereign-Pentad (`CSP-Omega`), key rings (`.qpkrf`), revocations (`.qrev`), Shamir shards (`.qshare`), and detached/attached signatures—share one frozen binary envelope:

| Byte Offset | Length | Field | Description |
|---|---|---|---|
| `0..5` | 6 B | `WIRE_MAGIC_V3` | Constant `0x89 0x51 0x50 0x45 0x03 0x00` (`\x89QPE\x03\x00`) |
| `6` | 1 B | `packet_type` | `0x01` Single, `0x02` Multi-Recipient, `0x03` Stream, `0x04` Ratchet, `0x05` Multisig, `0x06` Sovereign-Pentad, `0x07` Keyring/Lifecycle, `0x08` Signature/Timestamp |
| `7` | 1 B | `flags` | Bit 0: standardized bucket payload padding active (`4 KiB` / `16 KiB` / `64 KiB`); Bits 1–7 reserved (`0x00`) |
| `8..23` | 16 B | `wire_nonce` | Per-frame CSPRNG whitening nonce |
| `24..-32` | Variable | `whitened_payload` | `payload ^ qSponge-XOF("CALYX-WIRE-WHITEN-v3|" \|\| hdr \|\| wire_nonce \|\| label, len(payload))` |
| `-32..end` | 32 B | `wire_mac` | `qSponge-512("CALYX-WIRE-MAC-v3|" \|\| hdr \|\| wire_nonce \|\| label \|\| whitened_payload)[:32]` |

### Legacy Read Compatibility (Guaranteed)
`unpack_wire_frame` and `OpenQPEPProtocol` retain 100% read compatibility for all historical OpenQPEP wire magics:
- `\x89QPE\x01\x01` (v0.1.x – v1.0.0-pc)
- `\x89QPE\x01\x09` (v1.0.0-pc)
- `\x89QPE\x02\x00` (v1.0.0-pc)
- `\x89QPE\x03\x00` (v1.0.0-pc Frozen Default)

---

## 2. Native C99 / SIMD Vectorized Acceleration (`libopenqpep`)

The `calyx_qpep/native/` package provides portable C99 implementations (with optional AVX2 on `x86_64` and NEON on `ARM64`) of:
- 7-layer `NTT_3329`, `InvNTT_3329`, `BaseMul_3329`, `PolyAdd_3329`, `PolySub_3329`
- 8-layer `NTT_8380417`, `InvNTT_8380417`, `PointwiseMul_8380417`
- `CBD_1` (`QLX-16384`) and `CBD_2` (`QLX-768..4096`, `QVS-65..1024`) samplers
- Tier 10 `Calyx Sovereign-Pentad` Unstructured Plain-LWE inner-loop row accumulators

When `libopenqpep.so`/`.dylib`/`.dll` is compiled via `make -C calyx_qpep/native/csrc`, `calyx_qpep.native.loader` loads it automatically via `ctypes`. When absent (or when `OPENQPEP_DISABLE_NATIVE=1`), OpenQPEP falls back seamlessly to the bit-exact pure-Python reference engine with zero build dependencies.
