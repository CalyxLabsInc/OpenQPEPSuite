# 04 — Interactive CLI, Client Suite Applications & Key Directory Guide (`v1.1.0-pc`)

**Protocol:** `OpenQPEP/PC-1.1.0` (`Production Candidate 1.1.0`)  
**Unified Repository:** https://github.com/CalyxLabsInc/OpenQPEPSuite/  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## 1. OpenQPEP Interactive CLI & Conformance Verification

```bash
# Optional: compile C99/AVX2/NEON libopenqpep accelerator
make -C calyx_qpep/native/csrc

# Install editable package (PEP 440 1.1.0rc1)
pip install -e .

# Verify all 5 v1.1.0-pc golden KAT suites bit-for-bit
python3 -m calyx_qpep.cli verify-vectors

# Run full 63-test verification & adversarial audit suite
python3 -m unittest discover -s tests -v

# Launch interactive English-command shell
openqpep
```

---

## 2. Official OpenQPEP Suite Client Applications (`v1.1.0-pc`)

All three client applications run strictly on **OpenQPEP Production Candidate 1.1.0 (`v1.1.0-pc`)** with all **10 Post-Quantum Suites** (`QLX-768`..`QLX-16384`, `CSP-Omega`, `CGM-8192`, `RMT-512`), **`QPKD-Argon2id + qSponge-512 (kdf_version: 2)`**, and **Frozen Wire Format v3 (`\x89QPE\x03\x00`)**:

1. **Calyx QPEP Client (`com.calyxlabs.qpepclient`, `PC 1.1.0` / `vc219`):**
   - On-device key generation, `.qpkrf` management, notepad & multi-extension binary file encryption/signing, and zero-telemetry keystore.
   - Android APK (`CalyxQPEPClient-PC-v1.1.0.apk`), Play AAB, and signed iOS Web App profile (`CalyxQPEPClient.mobileconfig` → `https://calyxlabsinc.org/qpep-client-ios/`).
2. **Calyx Encrypted Messenger / QPEM (`com.calyxlabs.qpem`, `PC 1.1.0` / `vc19`):**
   - End-to-end post-quantum encrypted messaging (`https://messenger.calyxlabsinc.org`), Android APK, Play AAB, and signed iOS profile (`CalyxEncryptedMessenger.mobileconfig`).
3. **Calyx Encrypted Email (`com.calyxlabs.mail`, `PC 1.1.0` / `vc3`):**
   - Post-quantum E2EE email for `@calyxmail.org` (`https://mail.calyxlabsinc.org`) with standard RFC 5322 / STARTTLS / DKIM interoperability for external providers, Android APK, Play AAB, and signed iOS profile (`CalyxEncryptedEmail.mobileconfig`).

---

## 3. Public Key Directory & Transparency (`qpepkeys.calyxlabsinc.org`)

- **Public Key Lookup:** `https://qpepkeys.calyxlabsinc.org` hosts verified `.qpkrf` public key rings indexed by 64-character Key Hash and identity.
- **Verifiable Key Transparency (`QPEP-KT`):** `calyx_qpep/directory_kt/merkle_log.py` provides $O(\log N)$ `qSponge-512` Merkle inclusion proofs and Signed Tree Heads (STHs) so clients detect any equivocation or unauthorized key replacement.
- **Proprietary Backend Notice:** Calyx Labs Inc. backend servers (`website_server`, `directory_server`, `messenger_server`, `calyxmail_backend`) are proprietary infrastructure and are intentionally excluded from public GitHub repositories.
