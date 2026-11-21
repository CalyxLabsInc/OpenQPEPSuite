# OpenQPEP Changelog — Release Candidate 1.0.0 (`v1.0.0-rc`)

## Release Candidate 1.0.0 (`v1.0.0-rc`) — Clean-Slate Initial Release Candidate Baseline (2026-11-21)
- **Initial Release Candidate Baseline (`v1.0.0-rc`, `OpenQPEP/RC-1.0.0`, PEP 440 `1.0.0rc1`, branch `rc`):** Clean-slate Release Candidate baseline for the OpenQPEP Core Protocol.
- **Zero Legacy `-pc` or `-beta` Compatibility:** Strictly enforces **Frozen Wire Format v4 (`\x89QPE\x04\x00`)**, **Compact TLV v4.1 (`\x89QPE\x04\x01`)**, and **Mandatory `kdf_version: 3` (`RFC 9106 QPKD-Argon2id + qSponge-512` bound to `"OpenQPEP/RC-1.0.0"`)**. All legacy `-pc` and `-beta` wire frames and `kdf_version < 3` key rings are rejected immediately with `QPEPLegacyProtocolError`.
- **10 Golden KAT Suites & 79 Verification Tests:** Deterministic golden KAT vectors for all 10 post-quantum suites under `CALYX-OPENQPEP-KAT-DRBG-v1.0.0-rc|` and Wire Format v4 (`895150450400`), verified bit-for-bit across C99/AVX2 `libopenqpep` and pure-Python reference engines, 5-language interop matrix, 10-suite DudeCT timing audit, compiler-barrier `openqpep_explicit_bzero`, and Tamarin/ProVerif/Cryptol formal verification models.
- **Universal License:** Licensed exclusively under Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`).
