# OpenQPEP `.qpkrf` Key Ring & Binary Wire Format Specification (`Production Candidate 1.0.0`)

**Protocol:** **OpenQPEP by Calyx Labs Inc.** (`Production Candidate 1.0.0`)  
**Creator & Lead Architect:** **Tristen Martinez** ([Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/))  
**File Extensions:** `.qpkrf` (Quantum Proof Key Ring File) & `.qpep` (Encrypted Packet)  

---

## 1. Binary Wire Framing (`\x89QPE\x01\x01` + `qSponge-XOF` Whitening)

To prevent passive protocol fingerprinting and ensure that raw Base64 decoding (`base64 -d`) never exposes plaintext JSON keys or metadata in transit, every OpenQPEP armored block (`.qpkrf` Public Key Ring, `.qpkrf` Private Key Ring, `.qpep` Encrypted Packet, and `ATTACHED SIGNATURE`) encapsulates its serialized payload inside a **whitened binary wire frame** before Base64 encoding:

```text
+-----------------------------------------------------------------------+
| Byte Offset | Length | Field Name   | Description                     |
+-------------+--------+--------------+---------------------------------+
| 0..5        | 6 B    | WIRE_MAGIC   | \x89 Q P E \x01 \x01            |
| 6..21       | 16 B   | wire_nonce   | CSPRNG 128-bit per-packet nonce |
| 22..N-33    | Var    | whitened     | payload XOR qSponge-XOF stream  |
| N-32..N-1   | 32 B   | wire_mac     | qSponge-512 frame MAC (256-bit) |
+-----------------------------------------------------------------------+
```

### 1.1 Wire Whitening & Authentication Equations
Given `header_label` (e.g., `"CALYX QPEP ENCRYPTED PACKET"`) and `payload_bytes`:
1. Sample `wire_nonce = os.urandom(16)`.
2. Generate whitening stream:
   $$M = \text{qSponge-XOF}(\text{"CALYX-WIRE-WHITEN-v1|"} \,\|\, \text{wire\_nonce} \,\|\, \text{header\_label}, |\text{payload\_bytes}|)$$
3. Compute whitened body $W = \text{payload\_bytes} \oplus M$.
4. Compute 256-bit frame MAC:
   $$\text{wire\_mac} = \text{qSponge-512}(\text{"CALYX-WIRE-MAC-v1|"} \,\|\, \text{wire\_nonce} \,\|\, \text{header\_label} \,\|\, W)[0:32]$$
5. Concatenate `wire_frame = WIRE_MAGIC || wire_nonce || W || wire_mac`, Base64-encode at 64 characters per line, and append the 48-bit `qSponge-XOF` armor checksum line:
   $$\text{crc\_line} = \text{"="} \,\|\, \text{Base64}(\text{qSponge-XOF}(\text{"CALYX-ARMOR-CRC-v1|"} \,\|\, \text{wire\_frame}, 6))$$

---

## 2. `.qpkrf` (Quantum Proof Key Ring File) Structure Across All Five Key Tiers

All public and private keys in **OpenQPEP** are exported and imported using the `.qpkrf` file extension:
- **Public Key Rings (`PUBLIC_KEY_RING`)**: Do **not** require a passphrase to export or import. Used for sharing with correspondents and publishing to [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org).
- **Private Key Rings (`PRIVATE_KEY_RING`)**: Strictly require the owner's mandatory `QPKD-Argon` passphrase (`>=12` chars, `2+` digits, `4+` specials, `2+` uppercase, `4+` lowercase) on both export and import.

### 2.1 Exact Raw Binary Key & Signature Sizes by Tier inside `.qpkrf`

| OpenQPEP Key Tier & Nickname | `qlx_tier` / `qvs_tier` | `hgc_448_public` (`X448`) | `qlx_public` (`ek`) | `hgc_sig_public` (`Ed448`) | `qvs_public` (`pk`) | `self_signature` (`114 B` `Ed448` + `QVS`) | Raw Secret Keys (`QLX` + `QVS` + `HGC`) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`QLX-768 + QVS-65 Velocity`** | `QLX-768` / `QVS-65` | `56 B` | `1,184 B` | `57 B` | `2,336 B` | `1,714 B` (`114 + 1,600`) | `2,400 B` + `3,712 B` + `113 B` |
| **`QLX-1024 + QVS-87 Sovereign Hybrid`** | `QLX-1024` / `QVS-87` | `56 B` | `1,568 B` | `57 B` | `3,104 B` | `2,482 B` (`114 + 2,368`) | `3,168 B` + `4,992 B` + `113 B` |
| **`QLX-2048 + QVS-128 Ultra-Grid`** | `QLX-2048` / `QVS-128` | `56 B` | `3,104 B` | `57 B` | `4,640 B` | `4,018 B` (`114 + 3,904`) | `6,240 B` + `7,552 B` + `113 B` |
| **`Calyx Signature` (`Signature QLX-4096 + QVS-256` — Default)** | `QLX-4096` / `QVS-256` | `56 B` | `6,176 B` | `57 B` | `6,176 B` | `5,554 B` (`114 + 5,440`) | `12,384 B` + `10,112 B` + `113 B` |
| **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024` — High-Tier Hardware)** | `QLX-16384` / `QVS-1024` | `56 B` | `24,608 B` | `57 B` | `12,320 B` | `10,930 B` (`114 + 10,816`) | `49,248 B` + `20,096 B` + `113 B` |

### 2.2 Self-Certification & `integrity_mac` Verification (`0.1.3+` Hardening)
Every `.qpkrf` file binds its identity metadata and all four public keys (`hgc_448_public_b64`, `qlx_public_b64`, `hgc_sig_public_b64`, `qvs_public_b64`) via three independent cryptographic proofs verified automatically during `OpenQPEPProtocol.import_qpkrf`:
1. **`Key Hash` Binding**:
   $$\text{key\_hash} = \text{HexUpper}(\text{qSponge-512}(\text{"CALYX-QPEP-KEY-HASH-v1|"} \,\|\, \text{pk}_{\text{HGC}} \,\|\, \text{pk}_{\text{QLX}} \,\|\, \text{pk}_{\text{Ed448}} \,\|\, \text{pk}_{\text{QVS}}))[0:64]$$
2. **Conjunctive Self-Certification Signature (`self_signature_b64`)**:
   A 114-byte `Ed448` signature concatenated with a `QVS` lattice Fiat-Shamir with Aborts signature (`1,600` / `2,368` / `3,904` / `5,440` / `10,816` bytes depending on `qvs_tier`) over:
   $$\text{cert\_transcript} = \text{"CALYX-QPEP-SELFCERT|"} \,\|\, \text{key\_hash} \,\|\, \text{created\_at} \,\|\, \text{name} \,\|\, \text{email} \,\|\, \text{qlx\_tier} \,\|\, \text{qvs\_tier} \,\|\, \text{comment} \,\|\, \text{pk}_{\text{all}}$$
3. **Envelope `integrity_mac`**:
   A 512-bit `qSponge-512` digest over the canonical sorted JSON representation of `(key_hash, created_at, name, email, public_bundle)` verified in constant time via `hmac.compare_digest`.

### 2.3 Dual-Layer Secret Key Protection (`encrypted_private_bundle`)
When a private key ring is created, the secret keys are protected by two independent cryptographic layers derived from `(passphrase, kdf_salt)` via `_qpkd_argon_derive`:
1. **Inner Lattice Secret Key Masking**: `qlx_sk` is XOR-masked with $\text{qSponge-XOF}(\text{"CALYX-QPEP-SK-MASK|"} \,\|\, k_{\text{mac}} \,\|\, \text{key\_hash}, |\text{qlx\_sk}|)$.
2. **Outer `CC-512` AEAD Cascade**: The serialized secret bundle `{hgc_448_private_b64, qlx_masked_private_b64, hgc_sig_private_b64, qvs_private_b64}` is encrypted with `AES-256-GCM(k_s1, n1, aad)` followed by `ChaCha20-Poly1305(k_s2, n2, aad)` where `aad = "CALYX-QPEP-PRIVRING|" || key_hash`.

---

## 3. `.qpep` Encrypted Packet Envelope & 165+ Binary File Extension Preservation (`0.1.7+`)

Inside every encrypted `.qpep` packet, the inner authenticated `CC-512` payload (`inner_envelope`) preserves raw binary file bytes (`data_b64`) without UTF-8 string conversion and locks the exact file extension and MIME type into the authenticated envelope:
- **`SUPPORTED_FILE_EXTENSIONS` Registry (`165+` Extensions)**: Covers images (`.jpg`, `.jpeg`, `.png`, `.webp`, `.gif`, `.bmp`, `.svg`, `.heic`, `.ico`, `.tiff`, `.raw`), documents (`.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.odt`, `.rtf`, `.txt`, `.md`, `.csv`, `.json`, `.xml`, `.yaml`, `.html`), archives and binaries (`.zip`, `.tar`, `.gz`, `.7z`, `.rar`, `.apk`, `.aab`, `.jar`, `.dex`, `.so`, `.exe`, `.dmg`, `.iso`, `.db`, `.sqlite`), audio/video (`.mp3`, `.wav`, `.flac`, `.aac`, `.ogg`, `.m4a`, `.mp4`, `.mkv`, `.mov`, `.avi`, `.webm`), and cryptographic formats (`.qpkrf`, `.qpep`, `.asc`, `.pgp`, `.pem`, `.crt`, `.p12`, `.jks`).
- **Magic-Byte Header Inspection (`detect_file_extension_and_mime`)**: Automatically inspects binary magic bytes (`\xFF\xD8\xFF` for `.jpg`, `\x89PNG\r\n\x1a\n` for `.png`, `%PDF-` for `.pdf`, `PK\x03\x04` for `.zip`/`.docx`/`.apk`, etc.) on both encryption and decryption so decrypted files always restore their true original filename and extension.
