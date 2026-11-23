# 04 — CLI Reference, Ecosystem Integration & Verifiable Key Transparency Guide (`v1.1.0`)

**Protocol:** `OpenQPEP/1.1.0` (`Official Release 1.1.0`)  
**Core Protocol Repository:** https://github.com/CalyxLabsInc/OpenQPEP  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## 1. Build, Conformance Verification & Scriptable CLI (`openqpep`)

```bash
# Compile C99/AVX2/NEON libopenqpep accelerator (-Wall -Wextra -Werror)
make -C calyx_qpep/native/csrc

# Install editable Official Release 1.1.0 package
pip install -e .

# Verify all 10 v1.0.0 golden KAT suites bit-for-bit (Native C99 & Pure Python)
python3 -m calyx_qpep.cli verify-vectors
OPENQPEP_DISABLE_NATIVE=1 python3 -m calyx_qpep.cli verify-vectors

# Run full cryptographic & adversarial verification suite
python3 -m unittest discover -s tests -v

# Launch interactive English-command shell (with 0700/0600 keystore permissions)
openqpep
```

### Non-Interactive Automation Subcommands (CI / Scripts / Git Signing)
```bash
# Generate a key ring across any of the 10 suites (default QLX-4096)
openqpep keygen --name "Alice" --email "alice@calyxmail.org" --passphrase "<pass>" --tier QLX-4096 --pub-out alice.pub.qpkrf --priv-out alice.priv.qpkrf

# Encrypt & decrypt files or streams (auto-dispatches Lattice & Beyond-LWE suites)
openqpep encrypt --recipient bob.pub.qpkrf --sender alice.priv.qpkrf --passphrase "<pass>" --in secret.pdf --out secret.pdf.qpep
openqpep decrypt --key bob.priv.qpkrf --sender-pub alice.pub.qpkrf --passphrase "<pass>" --in secret.pdf.qpep --out restored.pdf

# Attached post-quantum signing & verification (detached signatures are prohibited)
openqpep sign --key alice.priv.qpkrf --passphrase "<pass>" --in manifest.txt --out manifest.txt.qsig
openqpep verify --key alice.pub.qpkrf --in manifest.txt.qsig --extract-out verified_manifest.txt

# Key fingerprints, Wire v5/v5.1 inspection, revocation & security audit
openqpep fingerprint alice.pub.qpkrf
openqpep inspect secret.pdf.qpep
openqpep revoke --key alice.priv.qpkrf --passphrase "<pass>" --reason KEY_RETIRED --out alice.qrev
openqpep audit
```

---

## 2. OpenQPEP Official Ecosystem Applications (`v1.1.0`)

The OpenQPEP Core Protocol (`OpenQPEP/1.1.0`) powers the Calyx Labs Inc. post-quantum application ecosystem (developed in dedicated application repositories targeting Official Release `1.0.0`):
1. **Calyx QPEP Client (`com.calyxlabs.qpepclient`):** On-device key management across all 10 suites, `.qpkrf` armor, binary file encryption/signing, `QPEP-KT` Merkle inclusion & consistency proof verification, `LT-QR` air-gap transfer, `FIDO2-PRF` hardware passkey binding, `DeniableVault`, and $t$-of-$n$ `ThresholdKEM`.
2. **Calyx Encrypted Messenger / QPEM (`com.calyxlabs.qpem`):** End-to-end post-quantum messaging (`https://messenger.calyxlabsinc.org`) using `QPEP-Ratchet` (atomic state + rotating-ephemeral PCS), `QPEP-MLS` TreeKEM group rooms (up to 256 members with per-`(epoch, sender)` replay protection), `QPEP-AKE` bidirectional PQ handshake, and fixed-size `Sphinx-PQ` sealed sender.
3. **Calyx Encrypted Email (`com.calyxlabs.mail`):** Post-quantum E2EE email for `@calyxmail.org` (`https://mail.calyxlabsinc.org`) with $O(1)$-RAM Stream v5 multi-recipient attachments, `BlindSearchVault` zero-knowledge search, rotatable subkeys, and `.qrev` revocation certificates.

---

## 3. Public Key Directory & Verifiable Key Transparency (`qpepkeys.calyxlabsinc.org`)

- **Public Key Lookup:** `https://qpepkeys.calyxlabsinc.org` hosts verified `.qpkrf` public key rings indexed by 64-character Key Hash and identity.
- **Verifiable Key Transparency (`QPEP-KT`):** `calyx_qpep/directory_kt/merkle_log.py` provides publicly verifiable **Ed448-signed Tree Heads (`verify_sth`)**, $O(\log N)$ `qSponge-512` Merkle inclusion proofs (`verify_inclusion_proof`), **RFC 9162 append-only Merkle consistency proofs (`consistency_proof` / `verify_consistency_proof`)**, and mandatory ownership signature verification so clients cryptographically detect split-view equivocation or unauthorized key replacement.
- **Proprietary Backend Notice:** Calyx Labs Inc. backend servers (`website_server`, `directory_server`, `messenger_server`, `calyxmail_backend`) are proprietary infrastructure and are intentionally excluded from public GitHub repositories.

## All 10 OpenQPEP Post-Quantum Suites (`v1.1.0`)

Every OpenQPEP suite uses the canonical naming standard `"Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"` paired with **CMT-4 CC-512 AEAD**, **RFC 9106 QPKD-Argon2id + qSponge-512 (`kdf_version: 4`)**, and **Official Wire Format v5 (`\x89QPE\x05\x00`) / Compact TLV v5.1 (`\x89QPE\x05\x01`)**.

| Canonical Suite Name | KEM + Signature | Mathematical Family | Hardware Classification | Primary Role |
| :--- | :--- | :--- | :--- | :--- |
| **Calyx Lattice-Apex: QLX-4096 + QVS-256 (4,096-Dim Module-LWE — All Devices)** | `QLX-4096` + `QVS-256` | Structured Module-LWE (`k=16`, 4,096-dim) + Hybrid X448 | **All Devices** | Default flagship security for mobile & desktop |
| **Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)** | `QLX-768` + `QVS-65` | Structured Module-LWE (`k=3`, 768-dim) + Hybrid X448 | **All Devices** | Lowest-latency mobile messaging & constrained links |
| **Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)** | `QLX-1024` + `QVS-87` | Structured Module-LWE (`k=4`, 1,024-dim) + Hybrid X448 | **All Devices** | Balanced NIST-Level-5-class lattice security |
| **Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)** | `QLX-2048` + `QVS-128` | Structured Module-LWE (`k=8`, 2,048-dim) + Hybrid X448 | **All Devices** | Elevated 2,048-dimensional lattice margin |
| **Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)** | `CIF-SQI-512` + `QHS-512` | CSIDH-512 Supersingular Isogeny + Stateless Hash-Based Hypertree | **All Devices** | Beyond-LWE compact isogeny key exchange & hash signatures |
| **Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (All-Devices Signature Default — All Devices)** | `CRT-RSD512` + `QMQ-512` | LRPC Rank-Metric Syndrome Decoding + UOV Multivariate Quadratic | **All Devices** | Beyond-LWE rank-metric code & multivariate diversity |
| **Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)** | `QLX-16384` + `QVS-1024` | 4-Manifold Coupled Module-LWE (`k=64`, 16,384-dim) + `16×14` QVS | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Maximum structured-lattice dimension (~69 KB secret vectors) |
| **Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)** | `CGM-8192` + `QHS-512` | Classic McEliece / Patterson Binary Goppa Code + Hash Hypertree | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Beyond-LWE conservative code-based encryption |
| **Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)** | `CULC-2048` + `CGM-8192` | Unstructured Plain-LWE (`n×n` ring-free) + Binary Goppa Code | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Zero algebraic ring-structure defense against ring/ideal-lattice attacks |
| **Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (High-Tier Signature Default — HIGH-TIER HARDWARE ONLY)** | `CSP-Omega` + `QHS-512` | 5-Family Combiner (Plain-LWE + Goppa + CSIDH-512 + UOV + Hash + X448) | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Ultimate multi-assumption citadel; secure if any 1 of 5 families holds |
