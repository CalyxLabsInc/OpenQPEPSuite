# Calyx Encrypted Email — System Architecture & OpenQPEP-over-MIME Specification (`v1.0.0-rc`)

- **Application Name:** Calyx Encrypted Email (`com.calyxlabs.mail`, `vc9`)
- **Version:** Release Candidate 1.0.0 (`v1.0.0-rc`, Unified OpenQPEP Suite Sync)
- **Publisher:** Tristen Martinez (Founder & Lead Architect) — Calyx Labs Inc.
- **Email Domain:** `@calyxmail.org`
- **Web App Endpoint:** `https://mail.calyxlabsinc.org`
- **Cryptographic Engine:** OpenQPEP by Calyx Labs Inc. (`Release Candidate 1.0.0`, `OpenQPEP/RC-1.0.0`)

---

## 1. Dual-Mode Email Transport Architecture

| Route | Recipients | Encryption / Security Mode | Wire Format |
| :--- | :--- | :--- | :--- |
| **Internal (`@calyxmail.org` → `@calyxmail.org`)** | Registered Calyx Mail users | **OpenQPEP `v1.0.0-rc` End-to-End Encrypted** (`QLX-4096 + QVS-256 + CC-512` default; supports all 10 post-quantum suites) | Client-side whitened binary Wire Format v4 packet (`\x89QPE\x04\x00`) encapsulating Subject, Body, and Attachments inside `CC-512`, wrapped in RFC 5322 MIME (`application/vnd.calyx.openqpep+armor` + `application/vnd.calyx.openqpep-sig+armor`). Zero plaintext stored on server. |
| **External Outbound (`@calyxmail.org` → Gmail, Yahoo, etc.)** | Any 3rd-party email provider | **Standard RFC 5322 + Opportunistic STARTTLS + DKIM RSA-SHA256 + SPF + DMARC** | Standard `text/plain` / `multipart/mixed` RFC 5322 email signed with `calyx2026._domainkey.calyxmail.org` and delivered via MX DNS resolution (or optional SMTP relay). |
| **External Inbound (Gmail, Yahoo, etc. → `@calyxmail.org`)** | Registered Calyx Mail users | **Standard RFC 5321 SMTP MX (Port 25 + STARTTLS)** | Parsed into structured inbox message + binary-safe attachments and stored in the user's SQLite WAL mailbox. |

---

## 2. Server Components & Port Map

| Component | Port(s) | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **SMTP MX Inbound** | `25` | RFC 5321 ESMTP + STARTTLS | Receives internet email from Gmail, Yahoo, Outlook, etc. for `*@calyxmail.org`. |
| **SMTP Submission** | `587` (STARTTLS), `465` (SMTPS) | RFC 5321 + AUTH PLAIN/LOGIN | Authenticated submission from standard mail clients. |
| **IMAP4rev1** | `143` (STARTTLS), `993` (IMAPS) | RFC 3501 IMAP4rev1 | Standard mailbox access (`LIST`, `SELECT`, `FETCH`, `STORE`, `SEARCH`, `EXPUNGE`). |
| **REST API & Web App** | `8448` (Primary), `8449` (HA Replica) | HTTPS via Cloudflare Tunnel / Nginx | Serves `https://mail.calyxlabsinc.org`, OpenQPEP `.qpkrf` Key Directory, 100 MB Streaming Attachments API, BlindSearchVault API, and JSON Mail API. |

---

## 3. Zero-Knowledge OpenQPEP E2EE Guarantees (Internal Mail)
1. **Private Key Isolation:** Private `.qpkrf` key rings are generated locally on-device under the mandatory `QPKD-Argon2id` (`kdf_version: 3`) passphrase gate (`>=12` chars, `>=2` digits, `>=4` special chars, `>=2` uppercase, `>=4` lowercase) and are **never transmitted** to `calyxmail.org`.
2. **Encrypted Metadata & Payload:** For internal `@calyxmail.org` emails, the subject line, message body, and attachments are serialized into an inner JSON envelope and sealed inside `CC-512` (Wire Format v4 `\x89QPE\x04\x00`) before leaving the client. The server only sees the placeholder subject `(OpenQPEP Encrypted Email)` and the whitened binary `.qpep` armor.
3. **Sender Self-Copy:** The client encrypts a separate copy to the sender's own public key (`sender_self_packet`) so the `Sent` folder also remains end-to-end encrypted at rest.
4. **100 MB Streaming Attachments, BlindSearchVault & Key Rotation:** Supports $O(1)$-RAM 64 KiB chunked streaming attachments with `AnonymousMultiRecipient` slots (`/api/v1/attachments/upload`), HMAC-`qSponge-512` blind index trapdoor search (`/api/v1/search/blind`), and one-click subkey rotation & `.qrev` revocation (`/api/v1/account/rotate-key`).

## All 10 OpenQPEP Post-Quantum Suites (`v1.0.0-rc`)

Every OpenQPEP suite uses the canonical naming standard `"Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"` paired with **CC-512 AEAD**, **RFC 9106 QPKD-Argon2id + qSponge-512 (`kdf_version: 3`)**, and **Frozen Wire Format v4 (`\x89QPE\x04\x00`) / Compact TLV v4.1 (`\x89QPE\x04\x01`)**.

| Canonical Suite Name | KEM + Signature | Mathematical Family | Hardware Classification | Primary Role |
| :--- | :--- | :--- | :--- | :--- |
| **Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)** | `QLX-4096` + `QVS-256` | Structured Module-LWE (`k=16`, 4,096-dim) + Hybrid X448 | **All Devices** | Default flagship security for mobile & desktop |
| **Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)** | `QLX-768` + `QVS-65` | Structured Module-LWE (`k=3`, 768-dim) + Hybrid X448 | **All Devices** | Lowest-latency mobile messaging & constrained links |
| **Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)** | `QLX-1024` + `QVS-87` | Structured Module-LWE (`k=4`, 1,024-dim) + Hybrid X448 | **All Devices** | Balanced NIST-Level-5-class lattice security |
| **Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)** | `QLX-2048` + `QVS-128` | Structured Module-LWE (`k=8`, 2,048-dim) + Hybrid X448 | **All Devices** | Elevated 2,048-dimensional lattice margin |
| **Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)** | `CIF-SQI-512` + `QHS-512` | 2D Supersingular Abelian Isogeny + Stateless Hash-Based Hypertree | **All Devices** | Beyond-LWE compact isogeny key exchange & hash signatures |
| **Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)** | `CRT-RSD512` + `QMQ-512` | Rank-Metric Syndrome Decoding + Multivariate Quadratic (`MQ`) | **All Devices** | Beyond-LWE rank-metric code & multivariate diversity |
| **Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)** | `QLX-16384` + `QVS-1024` | 4-Manifold Coupled Module-LWE (`k=64`, 16,384-dim) + `16×14` QVS | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Maximum structured-lattice dimension (~69 KB secret vectors) |
| **Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)** | `CGM-8192` + `QHS-512` | Classic McEliece-class Binary Goppa Code (`n=8192`) + Hash Hypertree | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Beyond-LWE conservative code-based encryption (large public matrix) |
| **Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)** | `CULC-2048` + `CGM-8192` | Unstructured Plain-LWE (`n×n` ring-free) + Binary Goppa Code | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Zero algebraic ring-structure defense against ring/ideal-lattice attacks |
| **Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)** | `CSP-Omega` + `QHS-512` | 5-Family Combiner (Plain-LWE + Goppa + 2D Isogeny + MQ + Hash + X448) | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Ultimate multi-assumption citadel; secure if any 1 of 5 families holds |
