# 04 — Interactive CLI, Client Suite Applications & Key Directory Guide (`v1.0.0-rc`)

**Protocol:** `OpenQPEP/RC-1.0.0` (`Release Candidate 1.0.0`)  
**Unified Repository:** https://github.com/CalyxLabsInc/OpenQPEPSuite/  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## 1. OpenQPEP Interactive CLI & Conformance Verification

```bash
# Compile C99/AVX2/NEON libopenqpep accelerator
make -C calyx_qpep/native/csrc

# Install editable package (PEP 440 1.0.0rc1)
pip install -e .

# Verify all 10 v1.0.0-rc golden KAT suites bit-for-bit
python3 -m calyx_qpep.cli verify-vectors

# Run full 79-test verification & adversarial audit suite
python3 -m unittest discover -s tests -v

# Launch interactive English-command shell
openqpep
```

---

## 2. Official OpenQPEP Suite Client Applications (`v1.0.0-rc`)

All three client applications run strictly on **OpenQPEP Release Candidate 1.0.0 (`v1.0.0-rc`)** with all **10 Post-Quantum Suites** (`QLX-768`..`QLX-16384`, `CIF-SQI-512`, `CRT-RSD512`, `CGM-8192`, `CULC-2048`, `CSP-Omega`), **`QPKD-Argon2id + qSponge-512 (kdf_version: 3)`**, and **Frozen Wire Format v4 (`\x89QPE\x04\x00`) / Compact TLV v4.1 (`\x89QPE\x04\x01`)**:

1. **Calyx QPEP Client (`com.calyxlabs.qpepclient`, `RC 1.0.0` / `vc225`):**
   - On-device key generation across all 10 suites, `.qpkrf` management, notepad & multi-extension binary file encryption/signing, `QPEP-KT` Merkle inclusion proof verification, `LT-QR` air-gapped animated fountain codes, `FIDO2-PRF` hardware passkey binding, `DeniableVault`, and $t$-of-$n$ `ThresholdKEM`.
   - Android APK (`CalyxQPEPClient-RC-v1.0.0.apk`), Play AAB, signed iOS Web App profile (`CalyxQPEPClient.mobileconfig` → `https://calyxlabsinc.org/qpep-client-ios/`), and Desktop Tauri build (`desktop/`).
2. **Calyx Encrypted Messenger / QPEM (`com.calyxlabs.qpem`, `RC 1.0.0` / `vc25`):**
   - End-to-end post-quantum encrypted messaging (`https://messenger.calyxlabsinc.org`) with `QPEP-Ratchet` double ratchet, `QPEP-MLS` TreeKEM group rooms (up to 256 members), `Sphinx-PQ` sealed sender, and disappearing messages TTL.
   - Android APK, Play AAB, signed iOS profile (`CalyxEncryptedMessenger.mobileconfig`), and Desktop Tauri build (`desktop/`).
3. **Calyx Encrypted Email (`com.calyxlabs.mail`, `RC 1.0.0` / `vc9`):**
   - Post-quantum E2EE email for `@calyxmail.org` (`https://mail.calyxlabsinc.org`) with 100 MB $O(1)$-RAM multi-recipient streaming attachments, `BlindSearchVault` zero-knowledge search, one-click subkey rotation & `.qrev` revocation, and standard RFC 5322 / STARTTLS / DKIM interoperability for external providers.
   - Android APK, Play AAB, signed iOS profile (`CalyxEncryptedEmail.mobileconfig`), and Desktop Tauri build (`desktop/`).

---

## 3. Public Key Directory & Verifiable Key Transparency (`qpepkeys.calyxlabsinc.org`)

- **Public Key Lookup:** `https://qpepkeys.calyxlabsinc.org` hosts verified `.qpkrf` public key rings indexed by 64-character Key Hash and identity.
- **Verifiable Key Transparency (`QPEP-KT`):** `calyx_qpep/directory_kt/merkle_log.py` and the live `/api/v1/kt/sth` & `/api/v1/kt/proof/<key_hash>` endpoints provide $O(\log N)$ `qSponge-512` Merkle inclusion proofs, Signed Tree Heads (STHs), and mandatory ownership signature verification so clients detect any equivocation or unauthorized key replacement.
- **Proprietary Backend Notice:** Calyx Labs Inc. backend servers (`website_server`, `directory_server`, `messenger_server`, `calyxmail_backend`) are proprietary infrastructure and are intentionally excluded from public GitHub repositories.

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
