# Calyx Encrypted Email

**Post-Quantum Encrypted Email powered by OpenQPEP (Production Candidate 1.1.0) — by Calyx Labs Inc.**

Calyx Encrypted Email (`com.calyxlabs.mail`) gives users sovereign `@calyxmail.org` email addresses with automatic **OpenQPEP Production Candidate 1.1.0** end-to-end encryption between `@calyxmail.org` users and full standard email compatibility with 3rd-party providers such as Gmail, Yahoo, and Outlook.

- **Web App:** `https://mail.calyxlabsinc.org`
- **Email Domain:** `@calyxmail.org`
- **Encryption Protocol:** OpenQPEP by Calyx Labs Inc. (Production Candidate 1.1.0) — `https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/`
- **Publisher:** Calyx Labs Inc. (Tristen Martinez, Founder & Lead Architect)

## Downloads

| Platform | Package | Details |
| :--- | :--- | :--- |
| **Android** | `CalyxEncryptedEmail.apk` | Direct-install APK (`com.calyxlabs.mail`, PC 1.1.0, Android 10–17), signed with the Calyx Labs Inc. Universal Release Key (v1 + v2). |
| **iOS** | `CalyxEncryptedEmail.mobileconfig` | Signed Apple Configuration Profile (DER PKCS#7/CMS by Calyx Labs Inc.) installing a full-screen Home Screen app pointing to `https://mail.calyxlabsinc.org`. |
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

## Key Features

- **Automatic Dual-Mode Transport:**
  - **`@calyxmail.org` → `@calyxmail.org`:** Encrypted client-side using **OpenQPEP Production Candidate 1.1.0** before transmission. Subject lines, message bodies, and attachments are sealed inside whitened binary `.qpep` packets (`\x89QPE\x02\x00`) with detached QVS signatures. Private `.qpkrf` key rings never leave your device.
  - **`@calyxmail.org` → 3rd-Party Providers (Gmail, Yahoo, Outlook, etc.):** Sent as standard RFC 5322 email with TLS and 2048-bit RSA DKIM signing (`calyxmail.org`) for universal deliverability.
- **Five OpenQPEP v1.1.0-pc Post-Quantum Key Suites:**
  - **Signature `QLX-4096 + QVS-256`** (Default Apex)
  - **Calyx Hyper-Tesseract `QLX-16384 + QVS-1024`** (High-Tier Hardware: 12 GB+ RAM devices / PCs)
  - **`QLX-2048 + QVS-128`** Ultra-Grid
  - **`QLX-1024 + QVS-87`** Sovereign Hybrid
  - **`QLX-768 + QVS-65`** Velocity
- **Full Mailbox & Key Vault:** Inbox, Sent, Drafts, Starred, Archive, Spam, and Trash folders, full-text search, binary-safe attachments, `@calyxmail.org` OpenQPEP Key Directory lookup, and `.qpkrf` Public/Private Key Ring export & import.

## Standard Mail Client Settings (Optional IMAP/SMTP)

| Protocol | Server | Port | Security |
| :--- | :--- | :--- | :--- |
| **IMAP** | `mail.calyxmail.org` | `993` / `143` | SSL/TLS / STARTTLS |
| **SMTP** | `mail.calyxmail.org` | `465` / `587` | SSL/TLS / STARTTLS |

*(Note: Native OpenQPEP end-to-end decryption is performed inside the Calyx Encrypted Email Web, Android, and iOS apps.)*

## Security & Privacy

- Private `.qpkrf` keys are generated on-device under the mandatory `QPKD-Argon` passphrase policy (`>=12` characters, `>=2` numbers, `>=4` special characters, `>=2` uppercase, `>=4` lowercase) and are never transmitted to any server.
- Zero telemetry, zero ads, and zero third-party tracking.

## Links

- **Web App:** `https://mail.calyxlabsinc.org`
- **Calyx Labs Inc.:** `https://calyxlabsinc.org`
- **OpenQPEP Protocol:** `https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/`
