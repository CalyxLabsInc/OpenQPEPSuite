# Security Policy — OpenQPEP Suite (`v1.1.4-pc`)

## Supported Versions
Only **Production Candidate 1.1.4 (`v1.1.4-pc`)** on branch `pc` is supported. All legacy `-beta` wire formats (`\x89QPE\x01\x01`, `\x89QPE\x01\x09`, `\x89QPE\x02\x00`) and `kdf_version: 1` key rings are strictly rejected.

## Self-Verification & Audit Tools
Run the built-in deterministic KAT verifier and adversarial security audit suite directly from `protocol/`:
```bash
cd protocol
make -C calyx_qpep/native/csrc
python3 -m calyx_qpep.cli verify-vectors
python3 -m unittest discover -s tests -v
```

## Responsible Disclosure
Please report any cryptographic or implementation vulnerability privately to **Calyx Labs Inc.** at `support@calyxlabsinc.org`.
