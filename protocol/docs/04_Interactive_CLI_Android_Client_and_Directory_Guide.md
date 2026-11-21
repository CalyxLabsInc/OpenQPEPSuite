# OpenQPEP Interactive CLI, Android Client & Public Key Directory Guide (`Production Candidate 1.0.0`)

**Protocol:** **OpenQPEP by Calyx Labs Inc.** (`Production Candidate 1.0.0`)  
**Android Application:** **Calyx QPEP Client** (`Production Candidate 1.0.0`)  
**Creator & Lead Architect:** **Tristen Martinez** ([Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/))  
**Public Key Registry:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)  

---

## 1. Using the Interactive Blue-Text OpenQPEP CLI (`openqpep`)

**OpenQPEP** includes an interactive, blue-themed terminal shell (`openqpep`) that lets users and developers execute every cryptographic workflow using plain English commands—without writing boilerplate Python scripts or memorizing long flag strings.

### 1.1 Launching the Interactive CLI
```bash
pip install -e .
openqpep
# Or run directly via Python module:
python3 -m calyx_qpep.cli
```

### 1.2 Plain-English Interactive Commands

| English Command | Interactive Workflow & Behavior |
| :--- | :--- |
| **`Create Key`** | Replies with `Specify Key Type:` across all **5 OpenQPEP Key Tiers**:<br/>`1. Calyx Signature: QLX-4096 + QVS-256 (Default Recommended — 4096-Dim Quantum-Proof + HGC-448 + CC-512)`<br/>`2. Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold Tesseract — HIGH-TIER HARDWARE ONLY)`<br/>`3. QLX-2048 + QVS-128 Ultra-Grid (2048-Dim Hyper-Lattice + HGC-448 + CC-512)`<br/>`4. QLX-1024 + QVS-87 Sovereign Hybrid (1024-Dim Lattice + HGC-448 + CC-512)`<br/>`5. QLX-768 + QVS-65 Velocity (768-Dim High-Speed Lattice + HGC-448 + CC-512)`<br/>Prompts `Set Key Name:`, `Set Key Email:`, `Set Key Comment:`, and `Set Key Passphrase:` (with live character-class validation), generates the lattice + `HGC-448` keypair, saves it to `~/.openqpep/keyring.json`, and offers one-step publishing to `https://qpepkeys.calyxlabsinc.org`. |
| **`List Keys`** | Displays all Personal Key Pairs and Receiver Public Keys stored in your local keyring along with their `QLX`/`QVS` suite and 64-character **Key Hash**. |
| **`Key Details <KeyName>`** | Displays full key health status, identity metadata, 4-character grouped **Key Hash**, and the `.qpkrf` Public Key Block. |
| **`Export Public <KeyName>`** | Exports `<KeyName>_public.qpkrf` without requiring a passphrase. |
| **`Export Private <KeyName>`** | Prompts for the key's mandatory `QPKD-Argon` passphrase, verifies and unlocks the secret key bundle, and writes `<KeyName>_private.qpkrf`. |
| **`Import Key <FilePath.qpkrf>`** | Imports a `.qpkrf` file (automatically prompting for a passphrase only if the file is a `PRIVATE_KEY_RING`), verifies its conjunctive self-signature and `integrity_mac`, and saves it to the keyring. |
| **`Delete Key <KeyName>`** | Confirms and removes the specified key from your local keyring. |
| **`Encrypt Text`** | Prompts you to select your **Encrypting Key**, enter its passphrase, select the **Recipient Key**, and type your plaintext message; outputs an armored `.qpep` packet and optionally saves it to disk. |
| **`Decrypt Text`** | Prompts you to select your **Decrypting Key**, enter its passphrase, and provide a `.qpep` file or armored block; verifies the `qSponge-512` transcript MAC, decrypts the `CC-512` frames, and verifies the sender's embedded signature. |
| **`Encrypt File` / `Decrypt File`** | Encrypts any binary or text file (across 165+ hardcoded extensions including `.jpg`, `.png`, `.pdf`, `.zip`, `.apk`) into a `.qpep` packet or decrypts a `.qpep` packet back to the exact original binary file and extension. |
| **`Create Signature`** | Prompts for your **Signing Key**, passphrase, and message, and produces a self-contained `CALYX QPEP ATTACHED SIGNATURE` verified in RAM by `Fault-Guard` before output. |
| **`Verify Signature`** | Verifies an Attached Signature automatically across all keys in your keyring and extracts the verified message. |
| **`Publish Key <KeyName>`** | Publishes a key's public `.qpkrf` block directly to [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org). |
| **`Search Directory <Query>`** | Searches [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org) by **Key Hash**, owner name, or email. |

---

## 2. Calyx QPEP Client Android Application (`Production Candidate 1.0.0`)

The **Calyx QPEP Client** Android application (`com.calyxlabs.qpepclient`, `versionCode 3`) supports Android 10 (`API 29`) through Android 17 (`API 37`, aligned with modern [Android Target SDK Requirements](https://targetsdk.com/) and [Android 17 Compatibility Guidelines](https://medium.com/@zobaer53/bringing-a-3-year-old-android-app-to-android-17-0da7e2a7c457)):

- **All Five Key Tiers Supported On-Device**: Supports **`Calyx Signature` (`QLX-4096 + QVS-256`, Default)**, **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`, High-Tier Hardware Only)**, **`QLX-2048 + QVS-128 Ultra-Grid`**, **`QLX-1024 + QVS-87 Sovereign Hybrid`**, and **`QLX-768 + QVS-65 Velocity`**.
- **⚠️ High-Tier Hardware Requirement Notice for `Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)**:
  - `Calyx Hyper-Tesseract` computes 16,384 coupled lattice dimensions ($k=64$ polynomials across 4 Tesseract manifolds) and a $(16 \times 14)$ `QVS-1024` signature matrix (`320,000+` NTT butterfly operations and `~69.3 KB` of secret lattice vectors per key ring).
  - It should **only** be used on high-tier flagship devices (such as the **Samsung Galaxy Z Fold 8**, Galaxy S25/S26 Ultra, Pixel 10 Pro with 12 GB+ RAM, or high-RAM desktop/laptop PCs).
  - Using `Calyx Hyper-Tesseract` on low-tier or budget mobile devices ($\le 6\text{ GB}$ RAM or slower single-core processors) will block the main UI thread and cause **UI freezes, Android "Application Not Responding" (`ANR`) timeouts, severe thermal throttling, or WebView Out-Of-Memory (`OOM`) crashes**. Users on standard or budget phones should use **`Calyx Signature` (`QLX-4096 + QVS-256`)** or **`QLX-1024 + QVS-87`**.
- **Native Android Binary File Bridge & Live Image Preview**: Uses `QpepChromeClient.onJsPrompt` (`CALYX_OPEN`, `CALYX_READ_PICKED`, `CALYX_SAVE`) and `MainActivity.onActivityResult` to read and write raw binary `Uint8Array` bytes for 165+ file extensions (such as `.jpg`, `.png`, `.pdf`, `.zip`) and displays a live decrypted image preview when decrypting image files.

---

## 3. Public Key Directory Server (`https://qpepkeys.calyxlabsinc.org`)

The zero-dependency Python 3 + SQLite3 directory server (`app.py`) runs behind a Cloudflare Zero Trust Tunnel (`cloudflared`) on `127.0.0.1:8443` and exposes four REST endpoints:
- `GET /api/v1/health`: Returns live server and protocol status (`OpenQPEP/Beta-1.0.0-pc`).
- `POST /api/v1/keys/publish`: Validates that the uploaded `.qpkrf` block is a `PUBLIC KEY RING` (rejecting any private key ring) and indexes it by 64-character `key_hash`, `name`, `email`, and `suite` (supporting all 5 tiers including `Calyx Signature` and `Calyx Hyper-Tesseract`).
- `GET /api/v1/keys/search?q=<query>`: Searches registered public keys by **Key Hash**, name, or email.
- `GET /api/v1/keys/<KEY_HASH>?download=1`: Downloads the raw `.qpkrf` public key file.


---

## 4. Calyx QPEP Client for iOS (Signed `.mobileconfig` Profile)

In addition to Android, **Calyx QPEP Client (`Production Candidate 1.0.0`)** is available for **iPhone and iPad** as a cryptographically signed Apple Configuration Profile (`.mobileconfig`, MIME type `application/x-apple-aspen-config`, signed by **Calyx Labs Inc.**):
- **Direct Safari Install URL:** [https://calyxlabsinc.org/CalyxQPEPClient.mobileconfig](https://calyxlabsinc.org/CalyxQPEPClient.mobileconfig)
- **Standalone WebClip Endpoint:** [https://calyxlabsinc.org/qpep-client-ios/](https://calyxlabsinc.org/qpep-client-ios/)
- **Installation Steps on iOS:**
  1. Open [https://calyxlabsinc.org/openqpep.html](https://calyxlabsinc.org/openqpep.html) in **Safari** on iPhone or iPad.
  2. Tap **Download for iOS (Install Profile)**.
  3. Tap **Allow** on the iOS configuration profile download prompt.
  4. Open **Settings &rarr; Profile Downloaded &rarr; Install** and confirm.
  5. Launch **Calyx QPEP Client** full-screen from your iOS Home Screen.
- **Feature Parity:** Identical UI, 100% local on-device cryptographic execution (`QLX-768` through `Calyx Signature QLX-4096 + QVS-256` and `Calyx Hyper-Tesseract QLX-16384 + QVS-1024`), native iOS Files app import/export, live decrypted image previews, and `qpepkeys.calyxlabsinc.org` lookup.

---

## 5. Calyx Encrypted Messenger (Android, iOS & Web — Powered by OpenQPEP `Production Candidate 1.0.0`)

**Calyx Encrypted Messenger** (nicknamed **Calyx QPEP Messenger**, Android package `com.calyxlabs.qpem`) is Calyx Labs Inc.'s real-time post-quantum messaging application powered 100% by the **OpenQPEP `Production Candidate 1.0.0`** protocol:
- **Zero Phone Numbers / `.qpkrf` Key Hash Accounts:** Users authenticate and message solely via their self-certified `.qpkrf` Key Ring and **64-character Key Hash**.
- **All Five OpenQPEP v1.0.0-pc Key Suites:** Supports `Calyx Signature` (`QLX-4096 + QVS-256`, default), `Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`, high-tier hardware), `QLX-2048 + QVS-128`, `QLX-1024 + QVS-87`, and `QLX-768 + QVS-65`.
- **Real-Time Sync, 3-State Receipts & Scannable CLX-Code (`SC Code`):** Features Sent/Delivered/Read indicators, an in-app camera scanner for peer SC Codes, and binary-safe file encryption across 165+ file extensions.
- **Platforms & Links:**
  - **Product Page:** [https://calyxlabsinc.org/messenger.html](https://calyxlabsinc.org/messenger.html)
  - **Android APK:** [https://calyxlabsinc.org/downloads/CalyxEncryptedMessenger.apk](https://calyxlabsinc.org/downloads/CalyxEncryptedMessenger.apk)
  - **iOS Signed Profile:** [https://calyxlabsinc.org/CalyxEncryptedMessenger.mobileconfig](https://calyxlabsinc.org/CalyxEncryptedMessenger.mobileconfig)
  - **Web App:** [https://messenger.calyxlabsinc.org](https://messenger.calyxlabsinc.org)
