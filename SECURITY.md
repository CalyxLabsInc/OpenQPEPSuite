# Security Policy — OpenQPEP Suite (Official Release `v1.1.0`)

## Supported Versions
Only the **Official Public Stable Release line (`v1.0.0`–`v1.1.0`, currently Official Release `v1.1.0` / `OpenQPEP/1.1.0`)** on branch `main` is supported:
- **Official Wire Format v5** (`\x89QPE\x05\x00`), **Compact Binary TLV v5.1** (`\x89QPE\x05\x01`), and **Stream v5** (`\x89QPS\x05\x00`).
- **CMT-4 Key-Committing `CC-512` AEAD** (`AES-256-GCM` + `ChaCha20-Poly1305` + 256-bit `qSponge-512` commitment tag).
- **Mandatory `kdf_version: 4`** (`RFC 9106 QPKD-Argon2id + qSponge-512`).
- All retired legacy pre-release formats (`-rc`, `-pc`, `-beta`, Wire v1–v4, `kdf_version < 4`) are strictly rejected with `QPEPLegacyProtocolError`.

## Self-Verification & Audit Tools
Run the built-in deterministic KAT verifier, full protocol security regression suite, and unified ecosystem verifier directly from the repository root:
```bash
cd protocol
make -C calyx_qpep/native/csrc clean all
python3 -m calyx_qpep.cli verify-vectors
python3 -m unittest discover -s tests -v
cd ..
python3 verify_suite.py
```

## Responsible Disclosure
Please report any cryptographic or implementation vulnerability privately to **Calyx Labs Inc.** at `support@calyxlabsinc.org`.
