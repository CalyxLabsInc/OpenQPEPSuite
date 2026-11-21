# Calyx Encrypted Email — System Architecture & OpenQPEP-over-MIME Specification

- **Application Name:** Calyx Encrypted Email (`com.calyxlabs.mail`)
- **Version:** Production Candidate 1.1.0 (Unified OpenQPEP Suite Sync)
- **Publisher:** Tristen Martinez (Founder & Lead Architect) — Calyx Labs Inc.
- **Email Domain:** `@calyxmail.org`
- **Web App Endpoint:** `https://mail.calyxlabsinc.org`
- **Cryptographic Engine:** OpenQPEP by Calyx Labs Inc. (Production Candidate 1.1.0)

---

## 1. Dual-Mode Email Transport Architecture

| Route | Recipients | Encryption / Security Mode | Wire Format |
| :--- | :--- | :--- | :--- |
| **Internal (`@calyxmail.org` → `@calyxmail.org`)** | Registered Calyx Mail users | **OpenQPEP v1.1.0-pc End-to-End Encrypted** (`QLX-4096 + QVS-256 + CC-512` default; supports `QLX-16384`, `QLX-2048`, `QLX-1024`, `QLX-768`) | Client-side whitened binary wire packet (`\x89QPE\x02\x00`) encapsulating Subject, Body, and Attachments inside `CC-512`, wrapped in RFC 5322 MIME (`application/vnd.calyx.openqpep+armor` + detached `application/vnd.calyx.openqpep-sig+armor`). Zero plaintext stored on server. |
| **External Outbound (`@calyxmail.org` → Gmail, Yahoo, etc.)** | Any 3rd-party email provider | **Standard RFC 5322 + Opportunistic STARTTLS + DKIM RSA-SHA256 + SPF + DMARC** | Standard `text/plain` / `multipart/mixed` RFC 5322 email signed with `calyx2026._domainkey.calyxmail.org` and delivered via MX DNS resolution (or optional SMTP relay). |
| **External Inbound (Gmail, Yahoo, etc. → `@calyxmail.org`)** | Registered Calyx Mail users | **Standard RFC 5321 SMTP MX (Port 25 + STARTTLS)** | Parsed into structured inbox message + binary-safe attachments and stored in the user's SQLite WAL mailbox. |

---

## 2. Server Components & Port Map

| Component | Port(s) | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **SMTP MX Inbound** | `25` | RFC 5321 ESMTP + STARTTLS | Receives internet email from Gmail, Yahoo, Outlook, etc. for `*@calyxmail.org`. |
| **SMTP Submission** | `587` (STARTTLS), `465` (SMTPS) | RFC 5321 + AUTH PLAIN/LOGIN | Authenticated submission from standard mail clients. |
| **IMAP4rev1** | `143` (STARTTLS), `993` (IMAPS) | RFC 3501 IMAP4rev1 | Standard mailbox access (`LIST`, `SELECT`, `FETCH`, `STORE`, `SEARCH`, `EXPUNGE`). |
| **REST API & Web App** | `8448` (Primary), `8449` (HA Replica) | HTTPS via Cloudflare Tunnel / Nginx | Serves `https://mail.calyxlabsinc.org`, OpenQPEP `.qpkrf` Key Directory, and JSON Mail API. |

---

## 3. Zero-Knowledge OpenQPEP E2EE Guarantees (Internal Mail)
1. **Private Key Isolation:** Private `.qpkrf` key rings are generated locally on-device under the mandatory `QPKD-Argon` passphrase gate (`>=12` chars, `>=2` digits, `>=4` special chars, `>=2` uppercase, `>=4` lowercase) and are **never transmitted** to `calyxmail.org`.
2. **Encrypted Metadata & Payload:** For internal `@calyxmail.org` emails, the subject line, message body, and attachments are serialized into an inner JSON envelope and sealed inside `CC-512` before leaving the client. The server only sees the placeholder subject `(OpenQPEP Encrypted Email)` and the whitened binary `.qpep` armor.
3. **Sender Self-Copy:** The client encrypts a separate copy to the sender's own public key (`sender_self_packet`) so the `Sent` folder also remains end-to-end encrypted at rest.
