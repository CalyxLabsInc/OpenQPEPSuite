# Calyx QPEP Client for Android (`Production Candidate 1.0.0`)

**Official Android Application for [OpenQPEP by Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)**  
**Creator & Lead Architect:** **Tristen Martinez**, Founder & Lead Architect at **Calyx Labs Inc.** (`support@calyxlabsinc.org`)  
**Core Protocol Repository:** [https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)  
**Live Public Key Directory:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)  
**Package Name:** `com.calyxlabs.qpepclient`  
**Supported Android Versions:** Android 10 (`API 29`) through Android 17 (`API 37`, compliant with [Android Target SDK Requirements](https://targetsdk.com/))  
**Universal Version:** `Production Candidate 1.0.0` (`0.1.9`)  
**License:** **Calyx Public Open Source License 1.0 (`CPOSLS-1.0`)**  

---

## 1. Overview

**Calyx QPEP Client** (`Production Candidate 1.0.0`) is the official Android client for **OpenQPEP by Calyx Labs Inc.** (the Open Quantum-Proof Encryption Protocol), engineered by **Tristen Martinez** at **Calyx Labs Inc.** as a clean-slate, post-quantum replacement for legacy OpenPGP (`RFC 4880`) and early post-quantum OpenPGP drafts ([IETF RFC 9980](https://datatracker.ietf.org/doc/html/rfc9980)).

Unlike legacy PGP mobile clients that rely on quantum-vulnerable RSA/ECC keys, optional passphrases, collision-prone 64-bit Key IDs, and detached signatures, **Calyx QPEP Client** executes full on-device hybrid post-quantum lattice cryptography, mandatory passphrase-locked key rings (`.qpkrf`), dual-stream authenticated encryption (`CC-512`), and self-contained attached signatures.

---

## 2. Direct APK Installation (`CalyxQPEPClient-PC-v1.0.0.apk`)

1. Download **`CalyxQPEPClient-PC-v1.0.0.apk`** from this repository (or the **Releases** tab) onto your Android device (running Android 10 through Android 17).
2. Open the downloaded `.apk` file in your Android **Files** app and confirm installation.
3. On first launch (or whenever your keyring has `0` keys), **Calyx QPEP Client** automatically opens the **Setup Wizard** so you can generate your first personal `.qpkrf` key pair or import an existing `.qpkrf` key ring.

---

## 3. Core Features of Calyx QPEP Client (`Production Candidate 1.0.0`)

### 3.1 On-Device Post-Quantum Key Generation & Hardware Keyring
- **Three Selectable `QLX` + `QVS` Cryptographic Suites**:
  - **`QLX-1024 + QVS-87 Sovereign Hybrid` (Default)**: 1024-dimension Module-LWE lattice over $R_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ ([ML-KEM-1024 class](https://quantumsequrity.com/blog/ml-kem-1024-deep-dive)) + 87-rank Lattice Fiat-Shamir with Aborts signatures over $R_{8380417} = \mathbb{Z}_{8380417}[X]/(X^{256}+1)$ ([FIPS 204 class](https://www.quantumsecuritydefence.com/insights/fips-204-ml-dsa/)) + `HGC-448` + `CC-512`.
  - **`QLX-2048 + QVS-128 Ultra-Grid`**: 2048-dimension hyper-lattice ($k=8$) + 128-rank lattice vector signatures + `HGC-448` + `CC-512` for multi-decade archival secrecy.
  - **`QLX-768 + QVS-65 Velocity`**: 768-dimension lattice ($k=3$) + 65-rank lattice vector signatures + `HGC-448` + `CC-512` for low-latency mobile messaging.
- **Triple-Redundant Persistent Local Keystore**: Automatically persists your encrypted personal key pairs (**Manage My Keys**) and correspondent public keys (**Manage Receiver Keys**) across app restarts.
- **Instant Live Keyring Search**: Tap the top-right magnifying glass icon (`🔍`) to filter keys in real time by owner name or email address.

### 3.2 Interactive Key Details Screen & Passphrase-Locked Private Key Vault
Tapping any key card in **Manage My Keys** or **Manage Receiver Keys** opens the dedicated **Key Details** screen featuring:
- **Hero Action Banner & Live QR Code**: Displays the key owner's identity, `QLX + QVS` suite badge, a scannable **QPKRF QR Code**, quick **Encrypt File** and **Encrypt Text** shortcuts, a one-tap **Publish / Sync to Directory** button (`↻`), and a **Delete Key** button (`🗑️`).
- **Key Health & Hardware Keyring Status**: Confirms active `QPKD-Argon` + `CC-512` protection and `.qpkrf` `integrity_mac` verification.
- **512-Bit `Key Hash` (Tap to Copy)**: Displays the 64-character hexadecimal `qSponge-512` **Key Hash** formatted in 4-character groups; tapping copies the **Key Hash** and displays an instant confirmation toast.
- **QPKRF Public Key Block**: View, copy, or save the public `.qpkrf` key ring directly to your device via the native Android **Files** app (`Intent.ACTION_CREATE_DOCUMENT`) with no passphrase required.
- **QPKRF Private Key Block (`QPKD-Argon + CC-512` Vault)**: Remains cryptographically locked at rest (`🔒 Locked — Passphrase entry required on every access`). Viewing, copying, or saving your private `.qpkrf` key ring requires entering and verifying your mandatory 12+ character passphrase.

### 3.3 Dual-Key Notepad & File Encryption (`CC-512` Cascade)
- **Encrypt Notepad & Encrypt Files**: Select both your **Encrypting Key (My Personal Key)** (unlocked with your passphrase to authenticate the payload) and the **Recipient's Key (`.qpkrf`)**.
- **Genuine On-Device Cryptography**:
  - Encapsulates a 256-bit shared secret using the 7-layer Number Theoretic Transform (`NTT`, $\zeta = 17 \bmod 3329$) Module-LWE engine (`qlxEncaps`) with Fujisaki-Okamoto IND-CCA2 decapsulation (`qlxDecaps`).
  - Encrypts every 64 KiB frame twice in cascade through **14-round NIST `AES-256-GCM`** ($\text{GF}(2^{128})$ GHASH) and **20-round RFC 8439 `ChaCha20-Poly1305`** ($\bmod\ 2^{130}-5$), authenticated by a 512-bit `qSponge-512` (24-round `Keccak-f[1600]`) transcript MAC and terminal-frame truncation check (`final == 1`).
  - Wraps all armored output in a `\x89QPE\x01\x01` + `qSponge-XOF` whitened binary wire frame so raw Base64 decoding never exposes plaintext or JSON structure.

### 3.4 Attached Signatures Only (`QVS` Lattice Fiat-Shamir with Aborts)
- **Create Attached Signature**: Unlocks your selected **Signing Key** with your passphrase and seals your message directly inside a `CALYX QPEP ATTACHED SIGNATURE` alongside an 8-layer NTT ($\zeta_Q = 1753 \bmod 8380417$) `QVS` lattice signature vector $\mathbf{z} = \mathbf{y} + c\mathbf{s}_1 \pmod{8380417}$ with rejection sampling ($\|\mathbf{z}\|_\infty < \gamma_1 - \beta$). Detached signatures are prohibited across OpenQPEP.
- **Verify Attached Signature**: Supports **Auto (Check All Keys in Keyring)** or single-key verification, verifies the lattice signature vector and `qSponge-512` digest, and extracts the verified message payload automatically.

### 3.5 Native Android Files Integration & Live Public Key Directory Sync
- **Native Android `Files` Picker & Saver**: Tapping **Choose File** launches `Intent.ACTION_OPEN_DOCUMENT` and tapping **Save .qpkrf** launches `Intent.ACTION_CREATE_DOCUMENT` so you can browse and save `.qpkrf` and `.qpep` files directly in the Android **Files** app.
- **One-Tap Publishing to `qpepkeys.calyxlabsinc.org`**: Publish your public `.qpkrf` key ring directly to [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org) during key creation or from any key card.

---

## 4. Mandatory `QPKD-Argon` Passphrase Policy

**Calyx QPEP Client** enforces the protocol-level **OpenQPEP** passphrase policy on every private key operation:
- **Minimum Length**: `12` characters or more
- **Numbers (`0–9`)**: At least `2`
- **Special Characters (`!@#$%^&*...`)**: At least `4`
- **Uppercase Letters (`A–Z`)**: At least `2`
- **Lowercase Letters (`a–z`)**: At least `4`

---

## 5. Support & Contact

- **Creator & Lead Architect**: Tristen Martinez (**Calyx Labs Inc.**)
- **Support Email**: `support@calyxlabsinc.org` (accessible directly in-app via the top-right `⋮` menu &rarr; **Contact Support**)
- **OpenQPEP Protocol & CLI Repository**: [https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)
- **Public Key Directory**: [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)
