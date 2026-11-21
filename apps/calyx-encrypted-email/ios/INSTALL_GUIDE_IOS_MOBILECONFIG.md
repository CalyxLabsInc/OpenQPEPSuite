# Calyx Encrypted Email — iOS Installation Guide (`.mobileconfig` Profile)

Because **Calyx Labs Inc.** distributes the iOS version without requiring an Apple Developer Account or App Store intermediary, **Calyx Encrypted Email** is packaged as a signed Apple Configuration Profile (`CalyxEncryptedEmail.mobileconfig`) that installs a full-screen standalone Home Screen Web Clip pointing directly to **`https://mail.calyxlabsinc.org`**.

## Profile Specifications
- **Payload Type:** `com.apple.webClip.managed` (`FullScreen = true`, `IgnoreManifestScope = true`, `Precomposed = true`, `IsRemovable = true`)
- **Web App URL:** `https://mail.calyxlabsinc.org`
- **Email Domain:** `@calyxmail.org`
- **Signature:** Signed in DER PKCS#7/CMS format by **Calyx Labs Inc.** (`calyxlabs_new_cert.pem`, SHA-1 `16:63:D3:55:EC:F5:9D:F9:1F:78:66:6C:1B:A0:39:09:CE:46:49:02`)
- **Icon:** Embedded 384×384 PNG Obsidian/Neon-Blue Shield-Envelope icon

## End-User Installation Steps (iPhone / iPad)
1. Open **Safari** on your iPhone or iPad and tap the download link for `CalyxEncryptedEmail.mobileconfig`.
2. When prompted *"This website is trying to download a configuration profile. Do you want to allow this?"*, tap **Allow**.
3. Open the iOS **Settings** app → tap **Profile Downloaded** (near the top, or go to **General → VPN & Device Management**).
4. Tap **Calyx Encrypted Email** → tap **Install** in the top-right corner, enter your device passcode, and confirm **Install**.
5. Return to your Home Screen and tap **Calyx Mail** to launch in full-screen standalone mode.

## Hosting Note for `calyxlabsinc.org` / `mail.calyxlabsinc.org`
- Always serve `CalyxEncryptedEmail.mobileconfig` with HTTP header `Content-Type: application/x-apple-aspen-config`.
- Link directly without the HTML `download` attribute:
  ```html
  <a href="/CalyxEncryptedEmail.mobileconfig">Install Calyx Encrypted Email for iOS</a>
  ```

<!-- OpenQPEP v1.0.0-rc (Release Candidate 1.0.0) -->
