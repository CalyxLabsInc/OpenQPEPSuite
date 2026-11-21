# Calyx Encrypted Email (`Release Candidate 1.0.0`)

**Post-Quantum Encrypted Email powered by OpenQPEP (Release Candidate 1.0.0, `v1.0.0-rc`) — by Calyx Labs Inc.**

Calyx Encrypted Email (`com.calyxlabs.mail`, `RC 1.0.0` / `vc9`) gives users sovereign `@calyxmail.org` email addresses with automatic **OpenQPEP Release Candidate 1.0.0** end-to-end encryption between `@calyxmail.org` users, 100 MB $O(1)$-RAM chunked streaming attachments, `BlindSearchVault` zero-knowledge search, one-click subkey rotation & `.qrev` revocation, and full standard email compatibility with 3rd-party providers such as Gmail, Yahoo, and Outlook.

- **Web App:** `https://mail.calyxlabsinc.org`
- **Email Domain:** `@calyxmail.org`
- **Encryption Protocol:** OpenQPEP by Calyx Labs Inc. (`Release Candidate 1.0.0`, `v1.0.0-rc`) — `https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/rc/protocol/`
- **Publisher:** Calyx Labs Inc. (Tristen Martinez, Founder & Lead Architect)

## Downloads

| Platform | Package | Details |
| :--- | :--- | :--- |
| **Android** | `CalyxEncryptedEmail.apk` | Direct-install APK (`com.calyxlabs.mail`, `RC 1.0.0` / `vc9`, Android 10–17), signed with the Calyx Labs Inc. Universal Release Key (v1 + v2). |
| **iOS** | `CalyxEncryptedEmail.mobileconfig` | Signed Apple Configuration Profile (DER PKCS#7/CMS by Calyx Labs Inc.) installing a full-screen Home Screen app pointing to `https://mail.calyxlabsinc.org`. |
| **Desktop** | `desktop/` (`Tauri`) | Native Linux (`.AppImage`/`.deb`), macOS (`.dmg`), and Windows (`.msi`) desktop build powered by `rust/openqpep-core`. |
| **Web** | `https://mail.calyxlabsinc.org` | Works directly in any modern desktop or mobile browser with zero installation required. |

## Installation

### Android (`.apk`)
1. Download `CalyxEncryptedEmail.apk` from this repository or the **Releases** page.
2. Open the downloaded `.apk` file on your Android device (allow **Install unknown apps** for your browser or file manager if prompted).
3. Launch **Calyx Encrypted Email** and register a new `@calyxmail.org` account or sign in.

### iOS (`.mobileconfig`)
1. Open **Safari** on your iPhone or iPad and download `CalyxEncryptedEmail.mobileconfig` (or visit `https://mail.calyxlabsinc.org/CalyxEncryptedEmail.mobileconfig`).
2. Tap **Allow** when Safari asks to download the configuration profile.
3. Open **Settings → Profile Downloaded** (or **General → VPN & Device Management**).
4. Tap **Calyx Encrypted Email → Install**, enter your device passcode, and confirm **Install**.
5. Launch **Calyx Mail** directly from your Home Screen in full-screen mode.

## Key Features (`Release Candidate 1.0.0`)

- **Automatic Dual-Mode Transport:**
  - **`@calyxmail.org` → `@calyxmail.org`:** Encrypted client-side using **OpenQPEP Release Candidate 1.0.0** before transmission. Subject lines, message bodies, and attachments are sealed inside whitened binary `.qpep` packets (`\x89QPE\x04\x00` Wire Format v4) with QVS signatures. Legacy `-pc` (`\x89QPE\x03\x00`) and `-beta` packets are rejected with `QPEPLegacyProtocolError`. Private `.qpkrf` key rings never leave your device.
  - **`@calyxmail.org` → 3rd-Party Providers (Gmail, Yahoo, Outlook, etc.):** Sent as standard RFC 5322 email with TLS and 2048-bit RSA DKIM signing (`calyxmail.org`) for universal deliverability.
- **100 MB Multi-Recipient Streaming Attachments (`v1.5.0-pc` → `v1.0.0-rc`):** $O(1)$-RAM 64 KiB chunked AEAD attachments (`/api/v1/attachments/upload`, `GET /api/v1/attachments/<id>`) with `AnonymousMultiRecipient` slots so multiple `@calyxmail.org` recipients share a single encrypted payload stream.
- **Encrypted Zero-Knowledge Search (`BlindSearchVault`):** Client-side HMAC-`qSponge-512` blind index trapdoors (`POST /api/v1/search/blind`) enable instant search over encrypted subjects and bodies without revealing search terms to the server.
- **One-Click Subkey Rotation & `.qrev` Revocation:** Rotate encryption/signing subkeys and publish `.qrev` revocation certificates directly from the Key Vault (`POST /api/v1/account/rotate-key`).
- **All 10 OpenQPEP `v1.0.0-rc` Post-Quantum Key Suites Supported.**

## Standard Mail Client Settings (Optional IMAP/SMTP)

| Protocol | Server | Port | Security |
| :--- | :--- | :--- | :--- |
| **IMAP** | `mail.calyxmail.org` | `993` / `143` | SSL/TLS / STARTTLS |
| **SMTP** | `mail.calyxmail.org` | `465` / `587` | SSL/TLS / STARTTLS |

*(Note: Native OpenQPEP end-to-end decryption is performed inside the Calyx Encrypted Email Web, Android, iOS, and Desktop apps.)*

## Security & Privacy

- Private `.qpkrf` keys are generated on-device under the mandatory `QPKD-Argon2id` (`kdf_version: 3`) passphrase policy (`>=12` characters, `>=2` numbers, `>=4` special characters, `>=2` uppercase, `>=4` lowercase) and are never transmitted to any server.
- Zero telemetry, zero ads, and zero third-party tracking.

## Links

- **Web App:** `https://mail.calyxlabsinc.org`
- **Calyx Labs Inc.:** `https://calyxlabsinc.org`
- **OpenQPEP Protocol:** `https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/rc/protocol/`

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
