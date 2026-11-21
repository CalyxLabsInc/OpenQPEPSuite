# Calyx Encrypted Messenger (`Calyx QPEP Messenger`)

[![OpenQPEP Ecosystem](https://img.shields.io/badge/OpenQPEP%20Ecosystem-Beta%20Version%201.0.0-pc-00E5FF)](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)
[![Android Package](https://img.shields.io/badge/Android-com.calyxlabs.qpem-2563EB)](https://calyxlabsinc.github.io/)
[![Web Client](https://img.shields.io/badge/Web%20Messenger-messenger.calyxlabsinc.org-00E5FF)](https://messenger.calyxlabsinc.org)
[![Key Ring Format](https://img.shields.io/badge/Account%20Identity-.qpkrf%20%7C%2064--Char%20Key%20Hash-10B981)](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)
[![License](https://img.shields.io/badge/License-Calyx%20Public%20Open%20Source%20License%201.0-00E5FF)](https://calyxlabsinc.org/LICENSE.txt)

**Calyx Encrypted Messenger** (nicknamed **Calyx QPEP Messenger**, Android package `com.calyxlabs.qpem`) is the official post-quantum end-to-end encrypted messaging application of the **[OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)** (**Open Quantum-Proof Encryption Protocol** / **Calyx QPEP**) ecosystem, created and engineered by **Tristen Martinez** at **[Calyx Labs Inc.](https://calyxlabsinc.github.io/)**

Built in the signature **Neon Blue & Obsidian Black** colorway of the **[Calyx QPEP Client](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/apps/calyx-qpep-client)** ecosystem, **Calyx Encrypted Messenger** replaces phone-number-based accounts and classical PGP/Signal key agreements with self-certified **Quantum Proof Key Ring Files (`.qpkrf`)** where **your QPEP Key Ring is your user account**. Users can access their accounts both through the native Android application (`com.calyxlabs.qpem`) and directly in the browser at **[messenger.calyxlabsinc.org](https://messenger.calyxlabsinc.org)**.

## 1. Core Design Philosophy: QPEP Keys Are User Accounts

Unlike conventional messengers that tie your identity to a SIM card, phone number, or centralized password database, **Calyx Encrypted Messenger (`Calyx QPEP Messenger`)** operates entirely on **[OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)** (`Production Candidate 1.1.0`) cryptographic identities:

1. **Create Account = Generate `.qpkrf` Key Ring**:
   - Clicking **Create Account** prompts for your **Key Name** (which operates as your `@Username`), **Email Address** (bound to your QPEP UID), optional profile bio, and selectable **QLX + QVS Security Tier** (`QLX-768`, `QLX-1024 Sovereign Hybrid`, or `QLX-2048 Ultra-Grid`).
   - Your device generates a self-certified `.qpkrf` key pair locally and derives your globally unique **64-character hexadecimal Key Hash**.
2. **Search & Message by Unique 64-Character Key Hash**:
   - Every QPEP Key Ring produces a cryptographically unique **64-character Key Hash** bound to the owner's UID and public lattice/curve vectors via `qSponge-512`.
   - Users search and message peers directly by their **64-character Key Hash** (or `@KeyName`) with continuous real-time inbox and directory synchronization across **[messenger.calyxlabsinc.org](https://messenger.calyxlabsinc.org)**.
3. **Full Public & Private `.qpkrf` Key Export & Portability**:
   - Logged-in users can export their **Public Key Ring (`-----BEGIN CALYX QPKRF PUBLIC KEY RING-----`)** to share out-of-band or import into **[Calyx QPEP Client](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/apps/calyx-qpep-client)**.
   - Users can also export their **Private Key Ring (`-----BEGIN CALYX QPKRF PRIVATE KEY RING-----`)** after passing the mandatory **`QPKD-Argon`** passphrase verification gate, allowing seamless account migration between Android devices and the **[messenger.calyxlabsinc.org](https://messenger.calyxlabsinc.org)** web client.

## 2. How End-to-End Encryption Works in Calyx QPEP Messenger

Every account action and chat message in **Calyx Encrypted Messenger** is enforced across the five interlocking layers of **[OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)**:

1. **Layer 1 — Mandatory `QPKD-Argon` Passphrase Gate**:
   - Unencrypted private keys and weak passphrases are rejected at the protocol layer. Before any account key pair is generated, unlocked, imported, or exported as a private `.qpkrf` file, the client enforces the **Calyx QPEP Passphrase Policy**:
     - **Minimum Length:** `12` characters or more (`len >= 12`)
     - **Numbers (`0–9`):** At least `2`
     - **Special Characters (`!@#$%^&*()-_=+...`):** At least `4`
     - **Uppercase Letters (`A–Z`):** At least `2`
     - **Lowercase Letters (`a–z`):** At least `4`
   - **`QPKD-Argon`** (**Quantum-Proof Key Derivation — Memory-Hard Matrix Lock**) stretches the passphrase with a 256-bit random salt through a 24-round `Keccak-f[1600]` **`qSponge-512`** key-wrapping schedule.
2. **Layer 2 — Hybrid Quantum Lattice Key Encapsulation (`QLX` + `HGC-448`)**:
   - Each outgoing message encapsulates a fresh session secret across both a 7-layer Number Theoretic Transform (NTT) **Quantum Lattice Exchange (`QLX`)** polynomial ring $R_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ ($\zeta = 17$) and an ephemeral **448-bit Hyper-Goldilocks Curve (`HGC-448`)** trapdoor, combined via **`qSponge-512`**:
     $$SS_{\text{QPEP}} = \text{qSponge-512}(\text{"CALYX-QPEP-KEM-v1"} \parallel SS_{\text{QLX}} \parallel SS_{\text{HGC-448}} \parallel CT_{\text{QLX}} \parallel EPK_{\text{HGC-448}} \parallel PK_{\text{QLX}} \parallel PK_{\text{HGC-448}})$$
3. **Layer 3 — Cascaded Dual-Stream Matrix Payload Encryption (`Calyx-Cascade-512` / `CC-512`)**:
   - Message payloads are segmented into **64 KiB (`65,536-byte`) frames** and encrypted twice in cascade under **`Calyx-Cascade-512` (`CC-512`)** with frame-index Additional Authenticated Data (`AAD`), a terminal frame truncation gate (`final == 1`), full-packet **`qSponge-512`** MAC authentication, and `\x89QPE\x01\x01` binary stream whitening (`-----BEGIN CALYX QPEP ENCRYPTED MESSAGE-----`).
4. **Layer 4 — Conjunctive Quantum Vector Digital Signatures (`QVS` + `qSponge-512`)**:
   - Every message is signed by the sender's key ring using an 8-layer NTT **Quantum Vector Signature (`QVS`)** over $R_{8380417} = \mathbb{Z}_{8380417}[X]/(X^{256}+1)$ ($\zeta_Q = 1753$) paired conjunctively with a 448-bit Edwards-curve commitment (`-----BEGIN CALYX QPEP SIGNATURE-----`). Users can tap **Inspect `.qpep` Packet** on any chat bubble to view the raw armored ciphertext and `QVS` signature.
5. **Layer 5 — Self-Certified Quantum Proof Key Ring Files (`.qpkrf`)**:
   - Account key rings carry an atomic self-certification signature and `integrity_mac` over the owner UID, 64-character `Key Hash`, and public key vectors.

## 3. Supported OpenQPEP `QLX` + `QVS` Account Tiers

When creating an account in **Calyx Encrypted Messenger**, users can select from all three **[OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)** security tiers:

| OpenQPEP Account Suite | Lattice Module Rank & Ring | Signature Vector Rank | Classical Curve Partner | Symmetric Payload Cipher | Target Messaging Profile |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`QLX-768 + QVS-65 Velocity`** | Rank $k=3$, 768-Dim Polynomial Ring ($n=256, q=3329$) | 65-Rank `QVS-65` Vector Commitment | `HGC-448` (224-Bit Security) | `Calyx-Cascade-512 (CC-512)` | High-frequency mobile messaging & low-latency real-time chat |
| **`QLX-1024 + QVS-87 Sovereign Hybrid` *(Default)*** | Rank $k=4$, 1024-Dim Polynomial Ring ($n=256, q=3329$) | 87-Rank `QVS-87` Vector Commitment | `HGC-448` (224-Bit Security) | `Calyx-Cascade-512 (CC-512)` | Default sovereign standard for **Calyx Encrypted Messenger** & **Calyx QPEP Client** |
| **`QLX-2048 + QVS-128 Ultra-Grid`** | Rank $k=8$, 2048-Dim Hyper-Lattice ($n=256, q=3329$) | 128-Rank `QVS-128` Vector Commitment | `HGC-448` (224-Bit Security) | `Calyx-Cascade-512 (CC-512)` | Maximum-paranoia sovereign accounts & long-horizon archival communications |

## 4. How Calyx Encrypted Messenger Compares to Legacy Messengers & PGP

| Security & Architecture Dimension | Legacy Messengers (Phone / SIM Based) | Legacy PGP Clients (`.asc` / `.gpg`) | Calyx Encrypted Messenger (`com.calyxlabs.qpem`) |
| :--- | :--- | :--- | :--- |
| **Account Identity** | Tied to carrier SIM card / phone number | Manual key rings separate from chat transport | **Self-Certified `.qpkrf` Key Ring = User Account (`64-Char Key Hash`)** |
| **Passphrase Enforcement** | None or optional 4-digit PIN | Permits empty (`""`) or weak passphrases | **Strictly Mandatory `QPKD-Argon` Gate** (`12+` chars: `>=2` digits, `>=4` specials, `>=2` upper, `>=4` lower) |
| **Post-Quantum Key Agreement** | Classical X25519 or single-layer PQ add-on | Legacy RSA / ECC vulnerable to Shor's algorithm | **100% Atomic `QLX-768/1024/2048 + HGC-448` Hybrid KEM** |
| **Symmetric Payload Cipher** | Single-cipher AES-GCM or ChaCha20 | Single-layer CFB / AEAD | **Cascaded Dual-Stream `Calyx-Cascade-512 (CC-512)`** |
| **Cross-Platform Key Portability** | Device-locked or cloud-escrowed | Manual file copy only | **One-Tap `.qpkrf` Public/Private Export + Android & Browser Web Client (`messenger.calyxlabsinc.org`)** |

## 5. Repository Structure & Ecosystem Components

* **`Android Files/` (`com.calyxlabs.qpem`)**:
  - `CalyxEncryptedMessenger.apk` — Direct-install Android release APK (Android 10 `minSdkVersion 29` to Android 17 `targetSdkVersion 37`) signed with the official **[Calyx Labs Inc.](https://calyxlabsinc.github.io/)** release certificate.
  - `CalyxEncryptedMessenger.aab` — Google Play Console Android App Bundle.
  - `android_project_source/` — Complete Android application source code (`AndroidManifest.xml`, `MainActivity.java`, `build.gradle`, and Neon Blue/Black UI assets).
* **`Backend Files/messenger_server/`**:
  - `calyx_qpep.py` — Pure-Python reference implementation of **[OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)** (`Production Candidate 1.1.0`).
  - `server.py` — Multi-threaded Python 3 + SQLite WAL real-time relay, 64-character Key Hash directory server, and browser web client host (default port `8446`, routed to `https://messenger.calyxlabsinc.org`).
  - `static/index.html` — Full browser web application mirroring the Android client so users can create or import `.qpkrf` accounts on the web.
  - `cli.py` & `test_messenger.py` — Command-line client and automated `unittest` verification suite.
  - `install_service.sh` & `systemd/calyx-messenger.service` — One-command Ubuntu Server `systemd` deployment scripts.

## 6. Quick Start & Backend Deployment

### Run the Automated Verification Suite

```bash
cd "Backend Files/messenger_server"
python3 test_messenger.py
```

### Deploy `messenger_server` on Ubuntu Server (Port `8446`)

```bash
cd "Backend Files/messenger_server"
./install_service.sh
```

## 7. Official OpenQPEP & Calyx Labs Inc. Links

* **Live Web Messenger & Key Hash Directory:** [https://messenger.calyxlabsinc.org](https://messenger.calyxlabsinc.org)
* **OpenQPEP Protocol Specification & SDK:** [https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)
* **Calyx QPEP Client (Android Cryptographic Suite):** [https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/apps/calyx-qpep-client](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/apps/calyx-qpep-client)
* **OpenQPEP Public Key Server:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)
* **Calyx Labs Inc. Official Website:** [https://calyxlabsinc.org](https://calyxlabsinc.org) | [https://calyxlabsinc.github.io/](https://calyxlabsinc.github.io/)
* **Terms of Service:** [https://calyxlabsinc.org/CalyxQPEM_TermsOfService.txt](https://calyxlabsinc.org/CalyxQPEM_TermsOfService.txt)
* **Privacy Policy:** [https://calyxlabsinc.org/google_play_privacy_policy.txt](https://calyxlabsinc.org/google_play_privacy_policy.txt)

## 8. License

Licensed under the **Calyx Public Open Source License 1.0 (`CPOSLS-1.0`)**.  
Copyright © 2026 **[Calyx Labs Inc.](https://calyxlabsinc.github.io/)** — Created, Designed & Engineered by **Tristen Martinez** (`support@calyxlabsinc.org` | `calyxlabsinc@gmail.com`).
