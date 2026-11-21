# Security Policy — OpenQPEP Suite (`v1.0.0-rc`)

## Supported Versions
Only **Release Candidate 1.0.0 (`v1.0.0-rc`, `OpenQPEP/RC-1.0.0`)** on branch `rc` (and synchronized `pc`) is supported. All legacy `-pc` wire formats (`\x89QPE\x03\x00`, `\x89QPE\x03\x01`), legacy `-beta` wire formats (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`), and `kdf_version < 3` key rings are strictly rejected with `QPEPLegacyProtocolError`.

## Self-Verification & Audit Tools
Run the built-in deterministic 10-suite KAT verifier, 5-language interop matrix, and 79-test adversarial security audit suite directly from `protocol/`:
```bash
cd protocol
make -C calyx_qpep/native/csrc
python3 -m calyx_qpep.cli verify-vectors
python3 -m unittest discover -s tests -v
```

## Responsible Disclosure
Please report any cryptographic or implementation vulnerability privately to **Calyx Labs Inc.** at `support@calyxlabsinc.org`.
