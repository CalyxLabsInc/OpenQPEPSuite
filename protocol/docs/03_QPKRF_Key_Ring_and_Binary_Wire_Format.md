# 03 — `.qpkrf` Key Ring, Frozen Wire Format v4 (`\x89QPE\x04\x00`) & Compact TLV v4.1 (`\x89QPE\x04\x01`)

**Protocol:** `OpenQPEP/RC-1.0.0` (`Release Candidate 1.0.0`)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## 1. Strict Release Candidate 1.0.0 Wire Policy (Zero Legacy `-pc` / `-beta` Compatibility)

OpenQPEP `v1.0.0-rc` strictly accepts **only** two binary wire magics across Python, C99, Rust, WASM/JS, and Go:
- **`WIRE_MAGIC_V4 = 0x89 0x51 0x50 0x45 0x04 0x00` (`\x89QPE\x04\x00`)** — Canonical Frozen Wire Format v4
- **`WIRE_MAGIC_V4_1 = 0x89 0x51 0x50 0x45 0x04 0x01` (`\x89QPE\x04\x01`)** — Compact Binary TLV Wire Format v4.1

All legacy `-pc` wire magics (`\x89QPE\x03\x00`, `\x89QPE\x03\x01`), legacy `-beta` wire magics (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`), and raw unframed JSON armor blocks are **strictly rejected** with `QPEPLegacyProtocolError`.

---

## 2. Frozen Wire Format v4 (`\x89QPE\x04\x00`) Binary Layout

| Offset | Size | Field | Specification |
| :--- | :---: | :--- | :--- |
| `0..5` | 6 B | `WIRE_MAGIC_V4` | `\x89QPE\x04\x00` |
| `6` | 1 B | `packet_type` | `0x01` Single, `0x02` Multi-Recipient, `0x03` Stream, `0x04` Ratchet, `0x05` Multisig, `0x06` Sovereign-Pentad, `0x07` Keyring/Lifecycle, `0x08` Signature/Timestamp, `0x09` Group MLS |
| `7` | 1 B | `flags` | Bit 0: standardized bucket payload padding active (`4 KiB` / `16 KiB` / `64 KiB`); Bits 1–7 reserved (`0x00`) |
| `8..23` | 16 B | `wire_nonce` | Per-frame CSPRNG whitening nonce |
| `24..-32` | Var | `whitened_payload` | `payload ^ qSponge-XOF("CALYX-WIRE-WHITEN-v4|" \|\| hdr \|\| wire_nonce \|\| label)` |
| `-32..end` | 32 B | `wire_mac` | `qSponge-512("CALYX-WIRE-MAC-v4|" \|\| hdr \|\| wire_nonce \|\| label \|\| whitened)[:32]` |

### Compact Binary TLV v4.1 (`\x89QPE\x04\x01`)
Uses the exact same 8-byte header + 16-byte nonce + whitening + 32-byte MAC structure (domain tags `CALYX-WIRE-WHITEN-v41|` / `CALYX-WIRE-MAC-v41|`), replacing inner JSON + Base64 with sorted length-prefixed `[tag:1B][length:4B BE][value]` TLV records to cut packet overhead by ~28–35%.

---

## 3. `.qpkrf` Key Ring Format (`kdf_version: 3` Mandatory)

Every `.qpkrf` key ring carries:
- **64-character uppercase Key Hash** (`qSponge-512` over canonical public key bundle)
- **Self-Certifying `integrity_mac`** verified strictly on every `import_qpkrf`
- **Mandatory `kdf_version: 3` Envelope** for private key rings:
  ```json
  {
    "kdf_version": 3,
    "kdf_params": {
      "kdf_version": 3,
      "algorithm": "QPKD-Argon2id+qSponge-512",
      "personalization": "OpenQPEP/RC-1.0.0",
      "m_kib": 65536,
      "t_cost": 3,
      "p_lanes": 4
    }
  }
  ```
  Any key ring with `kdf_version < 3` is immediately rejected with `QPEPLegacyProtocolError`.

---

## 4. Lifecycle Artifacts (`.qrev`, `.qshare`, & Multi-Recipient Slots)
- **`.qrev` Revocation Certificates:** Signed by the Master `QVS + Ed448` key with reason codes `KEY_COMPROMISED`, `KEY_SUPERSEDED`, or `KEY_RETIRED`.
- **`.qshare` Shamir Recovery Shards:** Verifiable $t$-of-$n$ $\text{GF}(256)$ secret-sharing shards with per-shard `qSponge-512` integrity commitments.
- **Anonymous Multi-Recipient Slots:** Encrypt payload once with a 512-bit `CC-512` CEK, encapsulate into $N$ mixed-tier slots (across all 10 suites) using blinded 64-bit slot tags `H_slot` or pure trial-decapsulation, plus power-of-2 dummy slots.

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
