# OpenQPEP Changelog — Production Candidate 1.0.0 (`v1.0.0-pc`)

## Production Candidate 1.0.0 (`v1.0.0-pc`) — Clean Production Break & Full Spec Freeze (2026-11-20)
- **Branch & Channel Promotion (`beta` → `pc`):** Promoted the entire OpenQPEP Suite (OpenQPEP Core, Calyx QPEP Client, Calyx Encrypted Messenger, Calyx Encrypted Email, Key Directory, and Web Servers) to **Production Candidate 1.0.0 (`v1.0.0-pc`)**.
- **Complete Removal of Legacy Beta Compatibility:** Removed all legacy beta wire magics (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`), raw unframed JSON fallbacks, and legacy `kdf_version: 1` key-ring fallbacks across Python, Rust, and Go. Only Frozen Wire Format v3 (`\x89QPE\x03\x00`), Compact TLV v3.1 (`\x89QPE\x03\x01`), and `kdf_version: 2` (`QPKD-Argon2id + qSponge-512`) are accepted.
- **Unified Production Candidate Domain Tags & KATs:** Regenerated all 5 deterministic golden KAT suites under `v1.0.0-pc` domain separation and verified bit-for-bit under both C99/AVX2 `libopenqpep` and pure-Python reference engines.
- **Universal License:** Licensed exclusively under Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`).
