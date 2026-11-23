# Calyx Encrypted Email (`Official Release 1.1.0`)

**Post-Quantum Encrypted Email powered by OpenQPEP (`Official Release 1.1.0` / `v1.1.0` / `OpenQPEP/1.1.0`) — by Calyx Labs Inc.**

Calyx Encrypted Email (`com.calyxlabs.mail`, `1.1.0` / `vc13`) provides sovereign `@calyxmail.org` email addresses with automatic **OpenQPEP Official Release 1.1.0** end-to-end encryption between `@calyxmail.org` users (Wire Format v5 `\x89QPE\x05\x00` / Compact Binary TLV v5.1 `\x89QPE\x05\x01`, CMT-4 Key-Committing `CC-512` AEAD, mandatory `QPKD-Argon2id` `kdf_version: 4`), 100 MB $O(1)$-RAM chunked Stream v5 (`\x89QPS\x05\x00`) attachments, `BlindSearchVault` zero-knowledge search, optional self-destructing email timers (`TTL`), an in-app Wire v5 & CMT-4 packet inspector, one-click key rotation & `.qrev` revocation, and full standard email compatibility with 3rd-party providers such as Gmail, Yahoo, and Outlook.

- **Web App:** `https://mail.calyxlabsinc.org`
- **Email Domain:** `@calyxmail.org`
- **Encryption Protocol:** OpenQPEP by Calyx Labs Inc. (`Official Release 1.1.0`, `v1.1.0`, `OpenQPEP/1.1.0`) — `https://github.com/CalyxLabsInc/OpenQPEP`
- **Publisher:** Calyx Labs Inc. (Tristen Martinez, Founder & Lead Architect)

## Downloads (`Official Release 1.1.0`)

| Platform | Package | Details |
| :--- | :--- | :--- |
| **Android** | `CalyxEncryptedEmail.apk` | Direct-install APK (`com.calyxlabs.mail`, `1.1.0` / `vc13`, Android 10–17), featuring the new unique Calyx Encrypted Email Quantum Shield-Envelope icon, signed with the Calyx Labs Inc. Release Key (v1 + v2). |
| **iOS** | `CalyxEncryptedEmail.mobileconfig` | Signed Apple Configuration Profile (DER PKCS#7/CMS by Calyx Labs Inc.) with the unique 384×384 Calyx Encrypted Email icon, installing a full-screen Home Screen app pointing to `https://mail.calyxlabsinc.org`. |
| **Desktop** | `desktop/` (`Tauri`) | Native Linux (`.AppImage`/`.deb`), macOS (`.dmg`), and Windows (`.msi`) desktop build powered by `protocol/rust/openqpep-core` (`v1.1.0`). |
| **Web** | `https://mail.calyxlabsinc.org` | Works directly in any modern desktop or mobile browser with zero installation required. |

## Key Features (`Official Release 1.1.0`)

- **Automatic Dual-Mode Transport:**
  - **`@calyxmail.org` → `@calyxmail.org`:** Encrypted client-side using **OpenQPEP Official Release 1.1.0 (`OpenQPEP/1.1.0`)** before transmission. Subject lines, message bodies, and attachments are sealed inside whitened binary `.qpep` packets (`\x89QPE\x05\x00` Wire Format v5 / `\x89QPE\x05\x01` Compact Binary TLV v5.1) with **CMT-4 Key-Committing `CC-512` AEAD** (`CC512-CMT4-COMMIT-v1.0.0`) and post-quantum signatures.
  - **Strict Zero Backwards Compatibility (`QPEPLegacyProtocolError`):** All pre-release Release Candidate (`-rc`, Wire v4 `\x89QPE\x04\x00`, `kdf_version: 3`), Production Candidate (`-pc`, Wire v3 `\x89QPE\x03\x00`, `kdf_version: 2`), and Beta (`-beta`, Wire v1/v2, `kdf_version: 1`) packets and key rings are strictly rejected.
  - **`@calyxmail.org` → 3rd-Party Providers (Gmail, Yahoo, Outlook, etc.):** Sent as standard RFC 5322 email with TLS and 2048-bit RSA DKIM signing (`calyxmail.org`) for universal deliverability.
- **Unique Quantum Shield-Envelope Brand Identity:** Dedicated Obsidian & Electric Neon Cyan-Blue Hexagonal Shield + Sealed Quantum Envelope application icon across Web, Android, Desktop, and iOS.
- **Self-Destructing Encrypted Emails (`TTL`):** Senders can set optional expiration timers (`1 Hour`, `24 Hours`, `7 Days`, `30 Days`, or `Never`) with automatic server-side expiration purge.
- **In-App Wire Format v5 & CMT-4 Packet Inspector (`/api/v1/crypto/inspect`):** Inspect and verify any `.qpep`, `.qpkrf`, `.qsig`, or `.qrev` block directly inside the client.
- **100 MB Multi-Recipient Streaming Attachments (Stream v5 `\x89QPS\x05\x00`):** $O(1)$-RAM 64 KiB chunked AEAD attachments (`/api/v1/attachments/upload`, `GET /api/v1/attachments/<id>`).
- **Encrypted Zero-Knowledge Search (`BlindSearchVault`):** Client-side `qSponge-512` blind index trapdoors (`POST /api/v1/search/blind`).
- **One-Click Key Rotation & `.qrev` Revocation:** Rotate to any of the 10 post-quantum suites and publish signed `.qrev` revocation certificates (`POST /api/v1/account/rotate-key`).

## All 10 OpenQPEP Post-Quantum Suites (`Official Release 1.1.0`)

Every OpenQPEP suite uses the canonical naming standard `"Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"` paired with **CMT-4 Key-Committing CC-512 AEAD**, **RFC 9106 QPKD-Argon2id + qSponge-512 (`kdf_version: 4`)**, and **Official Wire Format v5 (`\x89QPE\x05\x00`) / Compact TLV v5.1 (`\x89QPE\x05\x01`)**.

| Canonical Suite Name | KEM + Signature | Mathematical Family | Hardware Classification | Primary Role |
| :--- | :--- | :--- | :--- | :--- |
| **Calyx Lattice-Apex: QLX-4096 + QVS-256 (4,096-Dim Module-LWE — All Devices)** | `QLX-4096` + `QVS-256` | Structured Module-LWE (`k=16`, 4,096-dim) + Module-SIS `QVS-Ring` + Hybrid X448 | **All Devices** | Default flagship security for mobile & desktop |
| **Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)** | `QLX-768` + `QVS-65` | Structured Module-LWE (`k=3`, 768-dim) + Module-SIS `QVS-Ring` + Hybrid X448 | **All Devices** | Lowest-latency mobile messaging & constrained links |
| **Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)** | `QLX-1024` + `QVS-87` | Structured Module-LWE (`k=4`, 1,024-dim) + Module-SIS `QVS-Ring` + Hybrid X448 | **All Devices** | Balanced NIST-Level-5-class lattice security |
| **Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)** | `QLX-2048` + `QVS-128` | Structured Module-LWE (`k=8`, 2,048-dim) + Module-SIS `QVS-Ring` + Hybrid X448 | **All Devices** | Elevated 2,048-dimensional lattice margin |
| **Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)** | `CIF-SQI-512` + `QHS-512` | Commutative Supersingular Isogeny (`CSIDH-512`) + `BLISS-SeaSign` + Stateless Hash | **All Devices** | Beyond-LWE compact isogeny key exchange & class-group signatures |
| **Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (All-Devices Signature Default — All Devices)** | `CRT-RSD512` + `QMQ-512` | Ideal LRPC Rank-Metric Syndrome Decoding over $\mathbb{F}_{2^{29}}$ + Multivariate UOV | **All Devices** | Beyond-LWE rank-metric code & multivariate diversity |
| **Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)** | `QLX-16384` + `QVS-1024` | 4-Manifold Coupled Module-LWE (`k=64`, 16,384-dim) + `16×14` QVS | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Maximum structured-lattice dimension (~69 KB secret vectors) |
| **Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)** | `CGM-8192` + `QHS-512` | Classic McEliece Binary Goppa Code (Patterson decoding) + Multivariate UOV / Hash | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Beyond-LWE conservative code-based encryption |
| **Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)** | `CULC-2048` + `CGM-8192` | Unstructured Plain-LWE + NTRU-Prime + Binary Goppa Code | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Zero algebraic ring-structure defense against ideal-lattice attacks |
| **Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (High-Tier Signature Default — HIGH-TIER HARDWARE ONLY)** | `CSP-Omega` + `QHS-512` | 5-Family Combiner (Plain-LWE + Goppa + Isogeny + Rank-Metric + UOV + X448) | **HIGH-TIER HARDWARE ONLY (`>= 12 GB RAM`)** | Ultimate multi-assumption citadel; secure if any 1 of 5 families holds |
