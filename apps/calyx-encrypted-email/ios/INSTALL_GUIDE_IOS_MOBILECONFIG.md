# Calyx Encrypted Email — iOS Installation Guide (`.mobileconfig` Profile • Official Release 1.1.0)

Because **Calyx Labs Inc.** distributes the iOS version without requiring an Apple Developer Account or App Store intermediary, **Calyx Encrypted Email (`Official Release 1.1.0` / `OpenQPEP/1.1.0`)** is packaged as a signed Apple Configuration Profile (`CalyxEncryptedEmail.mobileconfig`) that installs a full-screen standalone Home Screen Web Clip pointing directly to **`https://mail.calyxlabsinc.org`**.

## Profile Specifications (`Official Release 1.1.0`)
- **Payload Type:** `com.apple.webClip.managed` (`FullScreen = true`, `IgnoreManifestScope = false`, `Precomposed = true`, `IsRemovable = true`)
- **Web App URL:** `https://mail.calyxlabsinc.org`
- **Email Domain:** `@calyxmail.org`
- **Protocol Engine:** OpenQPEP Official Release 1.1.0 (`OpenQPEP/1.1.0`, Wire Format v5 `\x89QPE\x05\x00`, CMT-4 Key-Committing `CC-512` AEAD, `QPKD-Argon2id` `kdf_version: 4`)
- **Signature:** Signed in DER PKCS#7/CMS format by **Calyx Labs Inc.** (`CN=Tristen Martinez (aka Calyxia), O=Calyx Labs Inc.`)
- **Icon:** Embedded 384×384 PNG Obsidian/Neon-Cyan Hexagonal Shield & Sealed Quantum Envelope icon (unique to Calyx Encrypted Email)

## End-User Installation Steps (iPhone / iPad)
1. Open **Safari** on your iPhone or iPad and tap the download link for `CalyxEncryptedEmail.mobileconfig`.
2. When prompted *"This website is trying to download a configuration profile. Do you want to allow this?"*, tap **Allow**.
3. Open the iOS **Settings** app → tap **Profile Downloaded** (near the top, or go to **General → VPN & Device Management**).
4. Tap **Calyx Encrypted Email (v1.1.0)** → tap **Install** in the top-right corner, enter your device passcode, and confirm **Install**.
5. Return to your Home Screen and tap **Calyx Mail** to launch in full-screen standalone mode.

## Hosting Note for `calyxlabsinc.org` / `mail.calyxlabsinc.org`
- Always serve `CalyxEncryptedEmail.mobileconfig` with HTTP header `Content-Type: application/x-apple-aspen-config`.
- Link directly without the HTML `download` attribute:
  ```html
  <a href="/CalyxEncryptedEmail.mobileconfig">Install Calyx Encrypted Email for iOS (v1.1.0)</a>
  ```
