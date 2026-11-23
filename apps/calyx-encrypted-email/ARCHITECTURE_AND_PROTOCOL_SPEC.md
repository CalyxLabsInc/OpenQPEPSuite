# Calyx Encrypted Email — System Architecture & OpenQPEP-over-MIME Specification (`Official Release 1.1.0`)

- **Application Name:** Calyx Encrypted Email (`com.calyxlabs.mail`, `vc13`)
- **Version:** Official Release 1.1.0 (`v1.1.0`, Unified OpenQPEP Suite Sync)
- **Publisher:** Tristen Martinez (Founder & Lead Architect) — Calyx Labs Inc.
- **Email Domain:** `@calyxmail.org`
- **Web App Endpoint:** `https://mail.calyxlabsinc.org`
- **Cryptographic Engine:** OpenQPEP by Calyx Labs Inc. (`Official Release 1.1.0`, `OpenQPEP/1.1.0`)

---

## 1. Dual-Mode Email Transport Architecture (`Official Release 1.1.0`)

| Route | Recipients | Encryption / Security Mode | Wire Format |
| :--- | :--- | :--- | :--- |
| **Internal (`@calyxmail.org` → `@calyxmail.org`)** | Registered Calyx Mail users | **OpenQPEP `v1.1.0` End-to-End Encrypted** (`QLX-4096 + QVS-256 + CC-512` default; supports all 10 post-quantum suites) | Client-side whitened binary **Official Wire Format v5** packet (`\x89QPE\x05\x00`) or Compact Binary TLV v5.1 (`\x89QPE\x05\x01`) encapsulating Subject, Body, and Attachments inside **CMT-4 Key-Committing `CC-512`** (`CC512-CMT4-COMMIT-v1.0.0`), wrapped in RFC 5322 MIME (`application/vnd.calyx.openqpep+armor` + `application/vnd.calyx.openqpep-sig+armor`). Zero plaintext stored on server. |
| **External Outbound (`@calyxmail.org` → Gmail, Yahoo, etc.)** | Any 3rd-party email provider | **Standard RFC 5322 + Opportunistic STARTTLS + DKIM RSA-SHA256 + SPF + DMARC** | Standard `text/plain` / `multipart/mixed` RFC 5322 email signed with `calyx2026._domainkey.calyxmail.org` and delivered via MX DNS resolution (or optional SMTP relay). |
| **External Inbound (Gmail, Yahoo, etc. → `@calyxmail.org`)** | Registered Calyx Mail users | **Standard RFC 5321 SMTP MX (Port 25 + STARTTLS)** | Parsed into structured inbox message + binary-safe attachments and stored in the user's SQLite WAL mailbox. |

---

## 2. Server Components & Port Map

| Component | Port(s) | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **SMTP MX Inbound** | `25` | RFC 5321 ESMTP + STARTTLS | Receives internet email from Gmail, Yahoo, Outlook, etc. for `*@calyxmail.org`. |
| **SMTP Submission** | `587` (STARTTLS), `465` (SMTPS) | RFC 5321 + AUTH PLAIN/LOGIN | Authenticated submission from standard mail clients. |
| **IMAP4rev1** | `143` (STARTTLS), `993` (IMAPS) | RFC 3501 IMAP4rev1 | Standard mailbox access (`LIST`, `SELECT`, `FETCH`, `STORE`, `SEARCH`, `EXPUNGE`). |
| **REST API & Web App** | `8448` (Primary), `8449` (HA Replica) | HTTPS via Cloudflare Tunnel / Nginx | Serves `https://mail.calyxlabsinc.org`, OpenQPEP v1.1.0 `.qpkrf` Key Directory, Wire v5 & CMT-4 Packet Inspector (`/api/v1/crypto/inspect`), 100 MB Stream v5 Attachments API, BlindSearchVault API, and JSON Mail API. |

---

## 3. Zero-Knowledge OpenQPEP v1.1.0 E2EE Guarantees (Internal Mail)
1. **Private Key Isolation:** Private `.qpkrf` key rings are generated locally on-device under the mandatory `QPKD-Argon2id + qSponge-512` (`kdf_version: 4`, personalized to `"OpenQPEP/1.1.0"`) passphrase gate (`>=12` chars, `>=2` digits, `>=4` special chars, `>=2` uppercase, `>=4` lowercase) and are **never transmitted** to `calyxmail.org`.
2. **CMT-4 Key-Committing `CC-512` AEAD & Wire Format v5:** For internal `@calyxmail.org` emails, the subject line, message body, and attachments are serialized into an inner JSON envelope and sealed inside **CMT-4 Key-Committing `CC-512`** (Wire Format v5 `\x89QPE\x05\x00`) before leaving the client. The 256-bit `CC512-CMT4-COMMIT-v1.0.0` commitment tag and 24-bit armor CRC are verified in constant time before decryption.
3. **Strict Zero Pre-Release Compatibility (`QPEPLegacyProtocolError`):** All pre-release Release Candidate (`-rc`, Wire v4 `\x89QPE\x04\x00` / `\x89QPE\x04\x01`, `kdf_version: 3`), Production Candidate (`-pc`, Wire v3 `\x89QPE\x03\x00`, `kdf_version: 2`), and Beta (`-beta`, Wire v1/v2, `kdf_version: 1`) packets and key rings are strictly rejected at both the API server and client levels.
4. **Sender Self-Copy & Expiring Mail (`TTL`):** The client encrypts a separate copy to the sender's own public key (`sender_self_packet`) so the `Sent` folder also remains end-to-end encrypted at rest, and optional `ttl_seconds` / `expires_at_utc` timers purge self-destructing emails automatically upon expiry.
5. **100 MB Stream v5 Attachments, BlindSearchVault & Key Rotation:** Supports $O(1)$-RAM 64 KiB chunked Stream v5 (`\x89QPS\x05\x00`) attachments (`/api/v1/attachments/upload`), `qSponge-512` blind index trapdoor search (`/api/v1/search/blind`), and one-click subkey rotation & `.qrev` revocation (`/api/v1/account/rotate-key`).
