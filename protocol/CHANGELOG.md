# OpenQPEP Core Protocol Changelog — Official Release `v1.1.0`

## Official Release `v1.1.0` (2026-11-23) — Upgraded from Official Release `v1.0.2`

- **Synchronized `v1.1.0` Protocol Release (`OpenQPEP/1.1.0`, PEP 440 `1.1.0`, `v1.1.0-stable`, branch `main`):** Upgraded directly from **Official Release `v1.0.2`** across Python (`calyx-openqpep`), C99 (`libopenqpep`), Rust (`openqpep-core`), Go (`go/openqpep`), and WASM/JS bindings.
- **100% `v1.0.x` Wire Format v5 Interoperability:** Full interoperability with all Official Release `1.0.0`–`1.0.2` Wire Format v5 (`\x89QPE\x05\x00`), Compact Binary TLV v5.1 (`\x89QPE\x05\x01`), Stream v5 (`\x89QPS\x05\x00`), and `kdf_version: 4` key rings and packets while continuing to strictly reject all retired pre-release wire frames and `kdf_version < 4` key rings with `QPEPLegacyProtocolError`.
- **Shared Server Security Adapter (`calyx_qpep.compat_server`):** Added thread-safe `SlidingWindowRateLimiter`, canonical Wire v5 frame validator, pre-release version-token guard, and directory `.qpkrf` validator, covered by `tests/test_v110_official_release_stabilization.py`.
- **Native C99 & Golden KAT Conformance:** Verified C99/AVX2 `libopenqpep.so` zero-warning `-Wall -Wextra -Werror` build, regenerated all 10 deterministic `v1.1.0` Golden KAT vectors (`10/10` bit-exact), and verified all 92 protocol unit & security regression tests passing.

---

## Official Release `v1.0.2` (2026-11-22) — Previous Public Stable Baseline
- Synchronized ecosystem stabilization release across protocol, apps, and server backends on Official Wire Format v5 / v5.1, CMT-4 `CC-512` AEAD, and mandatory `kdf_version: 4` (`RFC 9106 QPKD-Argon2id`).

## Official Release `v1.0.0` (2026-11-21) — Permanent Public Launch Baseline
- Clean-slate public launch of all 10 post-quantum suites (5 structured Module-LWE + 5 genuine Beyond-LWE), CMT-4 Key-Committing `CC-512` AEAD, mandatory `kdf_version: 4`, Official Wire Format v5 / v5.1 / Stream v5, hardened sub-protocol stack (`QPEP-Ratchet`, `QPEP-MLS`, `QPEP-AKE`, `QPEP-KT` Ed448 + RFC 9162 consistency proofs, `QVS-Ring`, `DeniableVault`, `ThresholdKEM`, `Sphinx-PQ`, `LatticeZKProof`), and `CPOSLS-1.0` licensing.
