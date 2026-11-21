# 03 — `.qpkrf` Key Ring, Frozen Wire Format v3 (`\x89QPE\x03\x00`) & Compact TLV v3.1 (`\x89QPE\x03\x01`)

**Protocol:** `OpenQPEP/PC-1.1.0` (`Production Candidate 1.1.0`)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## 1. Strict Production Candidate 1.1.0 Wire Policy (Zero Beta Compatibility)

OpenQPEP `v1.1.0-pc` strictly accepts **only** two binary wire magics across Python, C99, Rust, WASM/JS, and Go:
- **`WIRE_MAGIC_V3 = 0x89 0x51 0x50 0x45 0x03 0x00` (`\x89QPE\x03\x00`)** — Canonical Frozen Wire Format v3
- **`WIRE_MAGIC_V3_1 = 0x89 0x51 0x50 0x45 0x03 0x01` (`\x89QPE\x03\x01`)** — Compact Binary TLV Wire Format v3.1

All legacy `-beta` wire magics (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`) and raw unframed JSON armor blocks are **strictly rejected** with `QPEPWireFormatError`.

---

## 2. Frozen Wire Format v3 (`\x89QPE\x03\x00`) Binary Layout

| Offset | Size | Field | Specification |
| :--- | :---: | :--- | :--- |
| `0..5` | 6 B | `WIRE_MAGIC_V3` | `\x89QPE\x03\x00` |
| `6` | 1 B | `packet_type` | `0x01` Single, `0x02` Multi-Recipient, `0x03` Stream, `0x04` Ratchet, `0x05` Multisig, `0x06` Sovereign-Pentad, `0x07` Keyring/Lifecycle, `0x08` Signature/Timestamp, `0x09` Group MLS |
| `7` | 1 B | `flags` | Bit 0: standardized bucket payload padding active (`4 KiB` / `16 KiB` / `64 KiB`); Bits 1–7 reserved (`0x00`) |
| `8..23` | 16 B | `wire_nonce` | Per-frame CSPRNG whitening nonce |
| `24..-32` | Var | `whitened_payload` | `payload ^ qSponge-XOF("CALYX-WIRE-WHITEN-v3|" \|\| hdr \|\| wire_nonce \|\| label)` |
| `-32..end` | 32 B | `wire_mac` | `qSponge-512("CALYX-WIRE-MAC-v3|" \|\| hdr \|\| wire_nonce \|\| label \|\| whitened)[:32]` |

### Compact Binary TLV v3.1 (`\x89QPE\x03\x01`)
Uses the exact same 8-byte header + 16-byte nonce + whitening + 32-byte MAC structure (domain tags `CALYX-WIRE-WHITEN-v31|` / `CALYX-WIRE-MAC-v31|`), replacing inner JSON + Base64 with sorted length-prefixed `[tag:1B][length:4B BE][value]` TLV records to cut packet overhead by ~28–35%.

---

## 3. `.qpkrf` Key Ring Format (`kdf_version: 2` Mandatory)

Every `.qpkrf` key ring carries:
- **64-character uppercase Key Hash** (`qSponge-512` over canonical public key bundle)
- **Self-Certifying `integrity_mac`** verified strictly on every `import_qpkrf`
- **Mandatory `kdf_version: 2` Envelope** for private key rings:
  ```json
  {
    "kdf_version": 2,
    "kdf_params": {
      "kdf_version": 2,
      "algorithm": "QPKD-Argon2id+qSponge-512",
      "m_kib": 65536,
      "t_cost": 3,
      "p_lanes": 4
    }
  }
  ```
  Any key ring with `kdf_version < 2` is immediately rejected.

---

## 4. Lifecycle Artifacts (`.qrev`, `.qshare`, & Multi-Recipient Slots)
- **`.qrev` Revocation Certificates:** Signed by the Master `QVS + Ed448` key with reason codes `KEY_COMPROMISED`, `KEY_SUPERSEDED`, or `KEY_RETIRED`.
- **`.qshare` Shamir Recovery Shards:** Verifiable $t$-of-$n$ $\text{GF}(256)$ secret-sharing shards with per-shard `qSponge-512` integrity commitments.
- **Anonymous Multi-Recipient Slots:** Encrypt payload once with a 512-bit `CC-512` CEK, encapsulate into $N$ mixed-tier slots (including `QLX-768`..`QLX-16384`, `CSP-Omega`, `CGM-8192`, `RMT-512`) using blinded 64-bit slot tags `H_slot` or pure trial-decapsulation, plus power-of-2 dummy slots.
