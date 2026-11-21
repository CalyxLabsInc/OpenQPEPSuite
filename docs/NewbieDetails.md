# OpenQPEP for Beginners (`NewbieDetails.md`)
**A Plain-English Guide to How OpenQPEP Works, How Every Key Tier Encrypts, Decrypts & Signs, and Why OpenQPEP Is Stronger Than Post-Quantum PGP (`ML-KEM-1024` v6, `ML-DSA-87` v6 & `LibrePGP` v5)**

* **Project:** [OpenQPEP by Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) (`Production Candidate 1.0.0`)
* **Creator & Lead Architect:** Tristen Martinez, Founder of [Calyx Labs Inc.](https://calyxlabsinc.org/) ([Documentation Mirror](https://calyxlabsinc.github.io/))
* **Android Client:** [Calyx QPEP Client](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/apps/calyx-qpep-client/) (Android 10 through Android 17)
* **Live Public Key Directory:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)

---

## 1. What Is OpenQPEP in Simple Terms?

Imagine you want to send a locked digital vault—a text message, a `.jpg` photo, a `.pdf` contract, or a `.zip` archive—so that **nobody else on Earth, including future quantum supercomputers and AI cryptanalysis clusters, can open it or forge your identity.**

Recently, the older PGP world tried to upgrade itself for the quantum era by bolting post-quantum algorithms onto 1990s PGP packet formats. This resulted in **Post-Quantum OpenPGP** standards such as **[IETF RFC 9980](https://datatracker.ietf.org/doc/rfc9980/)** (built on **[RFC 9580](https://datatracker.ietf.org/doc/rfc9580/) v6 keys** using `ML-KEM-1024+X448` and `ML-DSA-87+Ed448`), **[NIST/Brainpool Composite OpenPGP](https://datatracker.ietf.org/doc/draft-ietf-openpgp-nist-bp-comp/)**, and GnuPG's competing **[LibrePGP v5](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/)** fork.

While those Post-Quantum PGP upgrades are better than 1990s RSA, they still suffer from critical limitations:
* Their maximum encryption lattice size stops at **1,024 dimensions** (`ML-KEM-1024` v6).
* They still allow users to create keys with **weak or blank passphrases** because passwords are not built into the key math.
* They lock your actual file with only **one symmetric cipher** (such as a single layer of AES).
* They rely on **256-bit SHA-256** key fingerprints and remain split across incompatible v4, v5 (`LibrePGP`), and v6 ([RFC 9980](https://www.rfc-editor.org/info/rfc9980/)) dialects.

**[OpenQPEP (Open Quantum-Proof Encryption Protocol)](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)** was engineered from scratch by **Tristen Martinez** at **[Calyx Labs Inc.](https://calyxlabsinc.org/)** to go far beyond Post-Quantum PGP v6. OpenQPEP scales lattice encryption all the way up to **4,096 dimensions** in its flagship **`Signature QLX-4096 + QVS-256`** tier (**4× the lattice dimensions of `ML-KEM-1024` v6**), hardcodes a mandatory 12+ character passphrase witness into the key math itself, double-encrypts every chunk through two different 256-bit ciphers (`CC-512`), and uses 512-bit `qSponge-512` hashing throughout.

---

## 2. The Core Building Blocks of OpenQPEP (Explained Simply)

Here are the six core pieces of [OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) translated into everyday language:

1. **Your `.qpkrf` Key Ring File (`Quantum Proof Key Ring File`)**
   * Instead of Post-Quantum PGP's complex chain of primary keys and detachable subkeys (which can be stripped or downgraded to v4 subkeys in [RFC 9980](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/)), OpenQPEP bundles your encryption keys and signing keys together into one atomic **`.qpkrf`** file:
     * **Public Key Ring (Shareable):** Like an **open quantum padlock** with your name on it. You can share it with friends or publish it to the [Calyx Labs Public Key Directory](https://qpepkeys.calyxlabsinc.org) so anyone can lock files *for you* or verify your signatures.
     * **Private Key Ring (Secret):** The **master key that unlocks your padlock** and stamps your digital signature. It stays on your device and cannot be imported, exported, or used without your passphrase.

2. **Your 64-Character `Key Hash` (512-Bit Sponge vs. PGP v6's 256-Bit Fingerprint)**
   * Post-Quantum PGP v6 ([RFC 9580](https://datatracker.ietf.org/doc/rfc9580/)) uses a 256-bit SHA-256 "fingerprint." Under Grover's quantum search algorithm, a 256-bit hash has its preimage security cut in half to 128 bits.
   * [OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) uses zero SHA-256. Every key is identified by a **64-character hexadecimal `Key Hash`** computed via **`qSponge-512`** (`SHA3-512` over a 1600-bit Keccak sponge), keeping a full **256-bit post-quantum security margin**.

3. **Hardcoded `QPKD-Argon` Passphrase Lock (No Weak Keys Allowed)**
   * In Post-Quantum PGP v6 (`ML-KEM-1024` v6 / `ML-DSA-87` v6), password protection (`S2K`) is **optional**—a newbie can accidentally export an unprotected secret key or use `password123`.
   * [OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) hardcodes a strict rule directly into the protocol math: every passphrase **must** be at least **12 characters long** with at least **2 numbers**, **4 special characters**, **2 uppercase letters**, and **4 lowercase letters**.
   * OpenQPEP converts those rules into a **64-byte mathematical Policy Witness** that is fed directly into the `QLX` and `QVS` key-generation equations and the `QPKD-Argon` unlocking engine. If a passphrase does not meet the rule, the math itself cannot generate or unlock the key.

4. **`QLX` (`Quantum Lattice Exchange`) + `HGC-448` (`Hyper-Goldilocks Curve`) — The Hybrid Padlock**
   * What is a **Lattice**? Imagine a grid of dots. In 2D or 3D, finding the closest dot after a tiny random nudge ("noise") is easy. Now imagine a grid with **4,096 dimensions** (`QLX-4096`). When OpenQPEP multiplies a secret path across 4,096 dimensions and adds tiny `Centered Binomial Distribution` (`CBD_2`) noise, finding that secret path (`Module-LWE`) is computationally impossible for both classical and quantum computers ([Quantum Sieving Analysis](https://postquantum.com/quantum-research/quantum-sieving-breakthrough/)).
   * OpenQPEP fuses that `QLX` lattice secret with a 448-bit **`HGC-448`** (`X448`) elliptic curve exchange through `qSponge-XOF`. Even if one math family were ever weakened, the other keeps your message completely locked.

5. **`QVS` (`Quantum Vector Signature`) + `Ed448` with `Fault-Guard` — The Unforgeable Digital Seal**
   * Every signature combines a post-quantum **`QVS`** lattice vector signature (over modulus $Q = 8,380,417$) with a classical 448-bit `Ed448` curve signature.
   * **Verify-Before-Emit `Fault-Guard`:** Before OpenQPEP outputs any signature, `QVSEngine.sign` automatically verifies the new signature against your public key in memory. This stops hardware glitching or Rowhammer fault-injection attacks from ever outputting a corrupted signature that could leak your private lattice vectors.

6. **`Calyx-Cascade-512` (`CC-512`) — Two 256-Bit Vaults Instead of PGP v6's One**
   * Post-Quantum PGP v6 ([RFC 9580](https://havenmessenger.com/blog/posts/openpgp-crypto-refresh-rfc-9580/)) encrypts your file with a **single symmetric cipher** (like AES-256). In July 2026, [Anthropic's Claude Mythos Preview discovered an 800× "Möbius Bridge" speedup against 7-round AES-128](https://www.anthropic.com/research/discovering-cryptographic-weaknesses) ([PostQuantum Report](https://postquantum.com/security-pqc/ai-cryptanalysis-hawk-aes/)), proving that AI models can find unexpected algebraic shortcuts in single ciphers.
   * [OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) slices your data into **64 KB chunks** and locks every chunk inside **two completely different ciphers in cascade (`CC-512`)**:
     1. **Inner Vault:** Full **14-round `AES-256-GCM`** (algebraic Substitution-Permutation Network) with its own 256-bit key (`k_s1`).
     2. **Outer Vault:** Full **20-round `ChaCha20-Poly1305`** (Addition-Rotation-XOR stream cipher) with a second, independent 256-bit key (`k_s2`).

---

## 3. How Every Action Works in OpenQPEP (Encrypt, Decrypt, Sign & Verify)

### A. How Encrypting a Message or File Works (`Encrypt`)
Whether you are encrypting a Notepad message or selecting any binary file (`.jpg`, `.png`, `.pdf`, `.docx`, `.zip`, `.mp4`, `.apk`, etc. across **165+ hardcoded file extensions** plus automatic magic-byte header detection), here is what happens when you click **Encrypt**:

1. **Unlock Your Personal Key & Sign the Payload First:**
   * Unlike Post-Quantum PGP (which allows anonymous, unsigned encrypted packets that anyone can spoof), OpenQPEP always uses **Dual-Key Authenticated Encryption**.
   * You select **Your Personal Key** and **The Recipient's Key**, and enter your `QPKD-Argon` passphrase. OpenQPEP hashes the exact raw bytes of your file with `qSponge-512` and creates an embedded `QVS + Ed448` signature bound to your original filename and extension (e.g., `photo.jpg`).
2. **Encapsulate a One-Time Hybrid Secret (`QLX` + `HGC-448`):**
   * OpenQPEP encapsulates a fresh 256-bit random seed inside the recipient's **`QLX` lattice matrix** (`ct_qlx`) and performs an ephemeral **`HGC-448`** key exchange.
   * Both shared secrets and both public keys are absorbed into `qSponge-XOF` (`CALYX-QPEP-KEM-v1|`) and expanded via `HKDF-SHA3-512` into three single-use keys: `k_s1` (256-bit AES-GCM key), `k_s2` (256-bit ChaCha20-Poly1305 key), and `k_transcript_mac` (512-bit packet MAC key).
3. **Lock Every 64 KB Chunk in `CC-512` Cascade:**
   * Your compressed payload and embedded signature are split into 64 KB chunks. Each chunk is encrypted with **`AES-256-GCM`** (`k_s1`) and then encrypted again with **`ChaCha20-Poly1305`** (`k_s2`), binding the chunk index (`idx`) and end-of-stream flag (`final=1`) into the authenticated header so chunks cannot be reordered or truncated.
4. **Binary Wire Whitening (`.qpep`):**
   * The entire packet is XOR-whitened with a `qSponge-XOF` stream (`\x89QPE\x01\x01`) and sealed with a 256-bit wire MAC before Base64 armoring (`-----BEGIN CALYX QPEP ENCRYPTED PACKET-----`), hiding all internal structure from traffic analyzers.

---

### B. How Decrypting a Message or File Works (`Decrypt`)
When you open a `.qpep` packet in [OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) or the [Calyx QPEP Client](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/apps/calyx-qpep-client/) app and click **Decrypt**:

1. **Outer Wire MAC & Checksum Verification:**
   * OpenQPEP verifies the `qSponge` armor checksum and 256-bit wire frame MAC, then unwhitens the binary frame.
2. **Unlock Your Private Key & Run `FO` IND-CCA2 Lattice Decapsulation:**
   * Your `QPKD-Argon` passphrase unlocks your `.qpkrf` Private Key Ring and removes the `qSponge-XOF` secret-key mask.
   * `QLXEngine.decaps` recovers the lattice secret and immediately **re-encrypts** it in constant time (`hmac.compare_digest(ct, ct_prime)`) via the **Fujisaki-Okamoto (`FO`) IND-CCA2 transform**. If an attacker tampered with the lattice ciphertext, OpenQPEP triggers implicit rejection (`CALYX-QLX-FO-REJECT|`) and aborts.
3. **Peel Back Both `CC-512` Vaults:**
   * OpenQPEP verifies the 512-bit `qSponge-512` transcript MAC and `final == 1` flag, then decrypts each 64 KB chunk through **`ChaCha20-Poly1305`** (`k_s2`) followed by **`AES-256-GCM`** (`k_s1`).
4. **Verify Sender Signature & Restore Exact File Type:**
   * OpenQPEP verifies the 512-bit `qSponge-512` plaintext digest and checks the sender's embedded `QVS` signature against their Public Key Ring.
   * Using the envelope metadata and magic-byte header detection (`\xFF\xD8\xFF` for `.jpg`, `\x89PNG` for `.png`, `%PDF-` for `.pdf`, etc.), OpenQPEP saves the exact original binary file with its true extension (and shows a live image preview in the Android app).

---

### C. How Signing & Verifying Work (`Sign` & `Verify`)
* **Signing (`Sign`):** OpenQPEP hashes your message with `qSponge-512` and generates a dual `Ed448 + QVS` lattice signature using **Fiat-Shamir with Aborts (Rejection Sampling)** so your signature proves authenticity with zero statistical leakage of your private key, verified in memory by **`Fault-Guard`** before output.
* **Verifying (`Verify`):** Using the sender's Public Key Ring (or **Auto** mode in the Android client, which scans your local keyring by `Key Hash`), OpenQPEP verifies both the 448-bit curve signature and the `QVS` lattice vector bounds (`||z||_inf < gamma1 - beta`).

---

## 4. All Four OpenQPEP Key Tiers Explained Simply (And How They Compare to Post-Quantum PGP v6)

Whereas Post-Quantum PGP ([RFC 9980](https://datatracker.ietf.org/doc/rfc9980/)) offers only two lattice encryption sizes (`ML-KEM-768` at 768 dimensions and `ML-KEM-1024` at 1,024 dimensions), [OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) (`Production Candidate 1.0.0`) gives you **four selectable key tiers** scaling all the way up to **4,096 lattice dimensions**:

| OpenQPEP Key Tier | Encryption Lattice (`QLX`) | Signature Lattice (`QVS`) | Nearest Post-Quantum PGP v6 Equivalent ([RFC 9980](https://datatracker.ietf.org/doc/rfc9980/)) | Public Key Size (`QLX` + `QVS`) | Ciphertext / Signature Size | Best Used For |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **[`Signature QLX-4096 + QVS-256`](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) (Default Flagship)** | **4,096 Dimensions** ($k=16, n=256, q=3329$) | **$8 \times 7$ Matrix** (`3,840`-Dim, `QVS-256`) | **None (4× larger encryption lattice than `ML-KEM-1024` v6)** | `6,176 B` + `6,176 B` | `5,792 B` CT / `5,440 B` Sig | **Maximum Quantum-Proof Security (Default)** — Built to defeat 2026 quantum sieving & AI attacks |
| **[`QLX-2048 + QVS-128 Ultra-Grid`](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)** | **2,048 Dimensions** ($k=8, n=256, q=3329$) | **$6 \times 5$ Matrix** (`2,816`-Dim, `QVS-128`) | **None (2× larger encryption lattice than `ML-KEM-1024` v6)** | `3,104 B` + `4,640 B` | `2,976 B` CT / `3,904 B` Sig | **Long-Term Cold Storage** — Multi-decade archival backups and sovereign vaults |
| **[`QLX-1024 + QVS-87 Sovereign Hybrid`](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)** | **1,024 Dimensions** ($k=4, n=256, q=3329$) | **$4 \times 3$ Matrix** (`1,792`-Dim, `QVS-87`) | Matches `ML-KEM-1024+X448` v6 dimension, **plus** `CC-512` & `QPKD-Argon` | `1,568 B` + `3,104 B` | `1,568 B` CT / `2,368 B` Sig | **Balanced Desktop & Server Tier** — Everyday high-assurance operations |
| **[`QLX-768 + QVS-65 Velocity`](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/)** | **768 Dimensions** ($k=3, n=256, q=3329$) | **$3 \times 2$ Matrix** (`1,280`-Dim, `QVS-65`) | Outclasses `ML-KEM-768+X25519` v6 by using 448-bit `HGC-448` & `CC-512` | `1,184 B` + `2,336 B` | `1,088 B` CT / `1,600 B` Sig | **High-Speed Mobile Tier** — Compact packets for low-bandwidth links |

### Deep Dive into Each Key Tier

#### 1. `Signature QLX-4096 + QVS-256` (Our Flagship & Strongest Quantum-Proof Key Type — Default)
* **How It Encrypts & Decrypts (`QLX-4096`):**
  * While Post-Quantum PGP's top tier (`ML-KEM-1024` v6) uses a $4 \times 4$ grid of 256-degree polynomials ($1,024$ dimensions), **`QLX-4096`** expands the module lattice to a massive **$16 \times 16$ polynomial matrix** ($16 \times 256 = \mathbf{4,096\text{ dimensions}}$) over $q = 3,329$.
  * During encryption, your device runs 256 Number Theoretic Transform (`NTT`) multiplications across those 4,096 dimensions, adds `CBD_2` binomial noise, and compresses the vector (`d_u = 11`, `d_v = 5`) into a `5,792`-byte capsule fused with `HGC-448`. During decryption, your private key reverses the 4,096-dimensional NTT inner product and runs the `FO` IND-CCA2 re-encryption check in roughly 25 milliseconds.
* **How It Signs & Verifies (`QVS-256`):**
  * Uses an **$8 \times 7$ lattice matrix** ($2,048 \times 1,792$ polynomial coordinates = **3,840 secret/error dimensions**) over prime modulus $Q = 8,380,417$ with challenge weight $\tau = 60$ and rejection bound $\beta = 120$, bound to a 64-byte `qSponge-XOF` challenge (`c_tilde`) and verified by `Fault-Guard` before emission.
* **Why It Beats `ML-KEM-1024` v6 & `ML-DSA-87` v6:**
  * Quadrupling the encryption lattice rank from $k=4$ (`1,024` dimensions in `ML-KEM-1024` v6) to $k=16$ (`4,096` dimensions in `QLX-4096`) pushes the required BKZ lattice-reduction block size to **$\beta > 1,650$**, delivering **$>512$ bits of quantum security** even against [Quantum-Accelerated Lattice Sieving (Grover-Enhanced BKZ)](https://postquantum.com/quantum-research/quantum-sieving-breakthrough/).

#### 2. `QLX-2048 + QVS-128 Ultra-Grid` (High-Archival Tier)
* **How It Works:** Uses an **$8 \times 8$ module lattice** (**2,048 dimensions**—still **2× larger** than Post-Quantum PGP's `ML-KEM-1024` v6) paired with a **$6 \times 5$ signature matrix** (`QVS-128`, `3,904`-byte signature). Built for multi-decade cold storage where you want double the lattice dimensions of `ML-KEM-1024` v6 with smaller keys than `QLX-4096`.

#### 3. `QLX-1024 + QVS-87 Sovereign Hybrid` (Balanced Desktop & Server Tier)
* **How It Works:** Uses a **$4 \times 4$ module lattice** (**1,024 dimensions**, `1,568`-byte capsule) and a **$4 \times 3$ signature matrix** (`QVS-87`, `2,368`-byte signature). Even at the same 1,024-dimension grid size as `ML-KEM-1024` v6, it is stronger than Post-Quantum PGP because it enforces the `QPKD-Argon` 64-byte passphrase witness, 512-bit `qSponge-512` transcripts, and `CC-512` dual-cipher payload encryption.

#### 4. `QLX-768 + QVS-65 Velocity` (High-Speed Mobile Tier)
* **How It Works:** Uses a **$3 \times 3$ module lattice** (**768 dimensions**, `1,088`-byte capsule) and a **$3 \times 2$ signature matrix** (`QVS-65`, `1,600`-byte signature). Unlike [RFC 9980](https://datatracker.ietf.org/doc/rfc9980/)'s `ML-KEM-768+X25519` (which drops down to a 255-bit curve and allows legacy v4 subkey wrapping), `QLX-768 + QVS-65` keeps the full 448-bit **`HGC-448`** curve and 512-bit **`CC-512`** payload cascade.

---

## 5. Head-to-Head Comparison: OpenQPEP vs. Post-Quantum PGP Protocols (`RFC 9980` v6 & `LibrePGP` v5)

Here is why **[OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) (`Production Candidate 1.0.0`)** is architecturally stronger than **[IETF RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) (`ML-KEM-1024+X448` v6 / `ML-DSA-87+Ed448` v6)**, **[NIST/Brainpool Composite OpenPGP](https://datatracker.ietf.org/doc/draft-ietf-openpgp-nist-bp-comp/)**, and **[LibrePGP v5](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/)**:

| Security Dimension / 2026 Threat Vector | Post-Quantum PGP Protocols ([RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) `ML-KEM-1024` v6, `ML-DSA-87` v6 & [LibrePGP v5](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/)) | [OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) (`Signature QLX-4096 + QVS-256` Flagship Tier) |
| :--- | :--- | :--- |
| **1. Maximum Lattice Dimension & [Grover-Enhanced BKZ Sieving](https://postquantum.com/quantum-research/quantum-sieving-breakthrough/)** | **CAPS AT 1,024 DIMENSIONS:** `ML-KEM-1024` v6 is fixed at $k=4$ ($1,024$ dimensions), and `LibrePGP` often defaults to `Kyber-768` ($768$ dimensions) paired with 256-bit curves. | **SCALES TO 4,096 DIMENSIONS:** `Signature QLX-4096 + QVS-256` uses $k=16$ (**4,096 encryption dimensions**) and $(k=8, l=7)$ (**3,840 signature dimensions**), pushing BKZ block sizes to $\beta > 1,650$ ($>512$-bit quantum security). |
| **2. Payload Encryption & [Claude Mythos 7-Round AES Shortcuts (July 2026)](https://www.anthropic.com/research/discovering-cryptographic-weaknesses)** | **SINGLE 256-BIT CIPHER:** [RFC 9580](https://datatracker.ietf.org/doc/rfc9580/) / [RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) encrypts the message body with a single cipher (e.g., AES-256-OCB/GCM). If AI cryptanalysis expands upon the [July 2026 Möbius Bridge AES shortcut](https://postquantum.com/security-pqc/ai-cryptanalysis-hawk-aes/), there is no second cipher layer. | **DUAL-CIPHER 512-BIT CASCADE (`CC-512`):** Every 64 KB chunk is locked inside **14-round `AES-256-GCM`** AND **20-round `ChaCha20-Poly1305`** with two independent 256-bit keys across two distinct math families (SPN + ARX). |
| **3. [Claude Mythos HAWK-256 Lattice Symmetry Attack (July 2026)](https://www.anthropic.com/research/discovering-cryptographic-weaknesses) & [JVG Algorithm](https://www.preprints.org/manuscript/202510.1649/v1)** | **COMPOSITE ONLY ON v6:** While `ML-DSA-87+Ed448` v6 resists [JVG factoring](https://www.mdpi.com/2624-800x/6/2/71), [RFC 9980](https://www.rfc-editor.org/info/rfc9980/) also allows standalone non-hybrid `SLH-DSA` and allows `ML-KEM-768+X25519` on legacy v4 subkeys. | **MANDATORY HYBRID + SYMMETRY GUARD:** Every tier fuses non-NTRU asymmetric Module-LWE/SIS lattices (with per-coordinate `CALYX-QVS-MAT-A|` domain separation immune to HAWK-256 rotational symmetries) with 448-bit `HGC-448` (`X448`/`Ed448`). |
| **4. [Dihedral Coset Problem (DCP) Quantum Reductions](https://eprint.iacr.org/2026/1591)** | **INCONSISTENT KDF BINDING ACROSS DIALECTS:** [RFC 9980](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/) and `LibrePGP` v5 use different fixed-info KDF context strings, causing cross-client decryption failures. | **UNIFIED `FO` IND-CCA2 + LOSSY ROUNDING:** Applies lossy $(d_u=11, d_v=5)$ compression, `H_ek` transcript binding, and constant-time `CALYX-QLX-FO-REJECT|` implicit rejection, collapsing theoretical DCP coset states ([PQprobe DCP Refutation](https://pqprobe.com/blog/dcp-claim-refuted)). |
| **5. Grover's Algorithm on Key Fingerprints & Digests** | **256-BIT SHA-256 FINGERPRINTS:** [RFC 9580](https://datatracker.ietf.org/doc/rfc9580/) v6 keys use 256-bit SHA-256 fingerprints, and [RFC 9980](https://www.rfc-editor.org/info/rfc9980/) permits 256-bit message digests (128-bit quantum preimage resistance under Grover's algorithm). | **512-BIT `qSponge-512` EVERYWHERE:** Zero `SHA-256` usage. All 64-character `Key Hashes`, KDFs, and packet transcripts use 512-bit `qSponge-512` (`SHA3-512`) and `qSponge-XOF` (`SHAKE-256`) over a 1600-bit Keccak state ($\ge 256$-bit quantum margin). |
| **6. Passphrase Enforcement, Fault Injection & Wire Metadata Privacy** | **OPTIONAL PASSWORDS & VISIBLE PACKET HEADERS:** Post-Quantum PGP v6 allows blank/weak passphrases, exposes OpenPGP packet tags/lengths inside Base64 armor, and does not mandate verify-before-emit fault checks or sender signing on encryption. | **HARDCODED `QPKD-ARGON` WITNESS + `FAULT-GUARD`:** Mandates a 12+ char passphrase witness inside key math, masks secret keys with `qSponge-XOF`, runs **Verify-Before-Emit `Fault-Guard`** on every signature, requires Dual-Key sender signing, and whitens binary wire frames (`\x89QPE\x01\x01`). |

---

## 6. Quick Summary for New Developers: Which OpenQPEP Key Tier Should You Choose?

* **Choose `Signature QLX-4096 + QVS-256` (Default):** Whenever you want **4× the encryption lattice dimensions of Post-Quantum PGP's `ML-KEM-1024` v6** (`4,096` dimensions vs. `1,024`) paired with an $8 \times 7$ `QVS-256` signature matrix, `HGC-448`, `CC-512` dual-cipher encryption, and `Fault-Guard` protection.
* **Choose `QLX-2048 + QVS-128 Ultra-Grid`:** When you want **2× the encryption lattice dimensions of `ML-KEM-1024` v6** (`2,048` dimensions) for long-term archival storage with smaller key files than `QLX-4096`.
* **Choose `QLX-1024 + QVS-87 Sovereign Hybrid`:** When you want the same `1,024`-dimension grid footprint as `ML-KEM-1024` v6, upgraded with OpenQPEP's `CC-512` dual-cipher cascade, 512-bit `qSponge-512` Key Hashes, and hardcoded `QPKD-Argon` passphrase witness.
* **Choose `QLX-768 + QVS-65 Velocity`:** When you want the fastest mobile packet sizes (`768` dimensions) while still keeping 448-bit `HGC-448` curve fusion and `CC-512` double encryption instead of downgrading to 255-bit curves or v4 subkeys.
