# OpenQPEP vs. Legacy OpenPGP (`RFC 4880`) & Post-Quantum OpenPGP (`RFC 9980` v6) — Security Analysis

**Protocol:** **OpenQPEP by Calyx Labs Inc.** (`Production Candidate 1.0.0`)  
**Creator & Lead Architect:** **Tristen Martinez** ([Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/))  
**Public Key Registry:** [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org)  

---

## 1. Why Legacy OpenPGP (`RFC 4880`) and Early Post-Quantum OpenPGP (`RFC 9980`) Fall Short

Legacy OpenPGP (`RFC 4880`) was standardized in the 1990s around classical number-theoretic assumptions (RSA integer factorization and discrete logarithms over elliptic curves) and legacy packet framing. Even with the recent [IETF RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) (extending [RFC 9580](https://datatracker.ietf.org/doc/rfc9580/) v6 keys) and GnuPG's competing [LibrePGP v5](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/) fork, the OpenPGP ecosystem exhibits six systemic limitations:

1. **Quantum Breakability of Classical Keys ("Harvest Now, Decrypt Later")**:
   Shor's polynomial-time quantum algorithm and the 2026 [Jesse-Victor-Gharabaghi (JVG) Hybrid Quantum Number Theoretic Transform (QNTT) Algorithm](https://www.preprints.org/manuscript/202510.1649/v1) ([MDPI JVG Study](https://www.mdpi.com/2624-800x/6/2/71)) target RSA-2048/4096, DSA, ECDSA, and ECDH (`Curve25519` / `nistp256`).
2. **1,024-Dimension Lattice Ceiling & v4/v5/v6 Dialect Fragmentation in Post-Quantum OpenPGP (`RFC 9980`)**:
   As analyzed in [Post-Quantum OpenPGP: RFC 9980 Standard Explained](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/), [IETF RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) caps its maximum encryption lattice at **`ML-KEM-1024 + X448` (`1,024` dimensions, $k=4$)**, still permits `ML-KEM-768 + X25519` on legacy v4 subkeys, and is incompatible with GnuPG's LibrePGP v5 KDF context strings. By contrast, OpenQPEP's default **`Calyx Signature` (`Signature QLX-4096 + QVS-256`)** operates at **4,096 encryption dimensions** ($k=16$, 4× larger than `ML-KEM-1024` v6) and **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)** scales to **16,384 encryption dimensions** ($k=64$, 16× larger than `ML-KEM-1024` v6).
3. **Optional or Weak Passphrases At Rest**:
   Both legacy OpenPGP (`RFC 4880`) and Post-Quantum OpenPGP (`RFC 9580` / `RFC 9980`) permit generating and exporting private keys with empty passphrases or weak passwords without binding the passphrase policy into the mathematical key generation.
4. **Single-Layer Symmetric Payload Encryption**:
   Even modern OpenPGP v6 AEAD (`AES-OCB`/`AES-GCM`) encrypts the payload with a single symmetric cipher family. When [Anthropic's Claude Mythos Preview (July 2026)](https://www.anthropic.com/research/discovering-cryptographic-weaknesses) discovered an 800× "Möbius Bridge" speedup against 7-round AES-128 ([PostQuantum Report](https://postquantum.com/security-pqc/ai-cryptanalysis-hawk-aes/)), it highlighted the risk of relying on a single symmetric cipher primitive without an orthogonal second layer.
5. **256-Bit SHA-256 v6 Fingerprints Under Grover's Algorithm**:
   [RFC 9580](https://datatracker.ietf.org/doc/rfc9580/) v6 keys use 256-bit SHA-256 fingerprints and [RFC 9980](https://www.rfc-editor.org/info/rfc9980/) allows 256-bit signature hashes, leaving a 128-bit quantum preimage margin under Grover's $O(2^{n/2})$ algorithm.
6. **Detached Signature Stripping & Readable Packet Headers**:
   OpenPGP allows detached signatures that can be stripped from payloads and wraps predictable TLV packet headers directly in Base64.

---

## 2. Head-to-Head Comparison: Legacy OpenPGP vs. Post-Quantum OpenPGP (`RFC 9980` v6) vs. OpenQPEP (`Production Candidate 1.0.0`)

| Security Dimension | Legacy OpenPGP (`RFC 4880`) | Post-Quantum OpenPGP ([RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) v6 & [LibrePGP v5](https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/)) | **OpenQPEP by Calyx Labs Inc. (`Production Candidate 1.0.0`)** |
| :--- | :--- | :--- | :--- |
| **Encryption Lattice Tiers (`KEM`)** | Classical RSA-2048/4096 or X25519 (0 lattice dims) | `ML-KEM-768` ($768$-dim) or `ML-KEM-1024` ($1,024$-dim ceiling) | **5 Tiers:** `QLX-768` ($768$-dim), `QLX-1024` ($1,024$-dim), `QLX-2048` ($2,048$-dim), **`Calyx Signature QLX-4096` ($4,096$-dim Default)**, and **`Calyx Hyper-Tesseract QLX-16384` ($16,384$-dim Flagship Hardware)** + `HGC-448` |
| **Digital Signature Tiers** | Classical RSA / Ed25519 | `ML-DSA-65+Ed25519` or `ML-DSA-87+Ed448` ($8 \times 7$ ceiling) | **5 Conjunctive Tiers + `Ed448` + `Fault-Guard`:** `QVS-65` ($3 \times 2$), `QVS-87` ($4 \times 3$), `QVS-128` ($6 \times 5$), **`QVS-256` ($8 \times 7$ Default)**, and **`QVS-1024` ($16 \times 14$ Hyper-Tesseract)** |
| **Passphrase Enforcement** | Optional (allows empty passphrases) | Optional (inherits OpenPGP S2K) | **Mandatory Protocol-Enforced `QPKD-Argon` 64-Byte Witness** (`>=12` chars, `2+` digits, `4+` specials, `2+` upper, `4+` lower) |
| **Symmetric Payload Cipher** | Legacy CFB+MDC or single AEAD | Single-layer 128/256-bit AEAD | **Cascaded Dual-Stream 512-Bit `CC-512`** (`14-round AES-256-GCM` + `20-round ChaCha20-Poly1305`) across 165+ binary file formats |
| **Key Identifier & Hashing** | 64-bit Key ID / 160-bit SHA-1 Fingerprint | 256-bit SHA-256 v6 Fingerprint | **512-Bit `Key Hash`** (64-character hex `qSponge-512` / `SHA3-512` digest; zero `SHA-256`) |
| **Fault-Injection & Side-Channel Guard** | Implementation-dependent | No protocol-mandated verify-before-emit | **Mandatory Verify-Before-Emit `Fault-Guard`** in `QVSEngine.sign` + `qSponge-XOF` secret-key XOR masking |
| **Outer Wire Armor** | Base64 over predictable PGP packet headers | Base64 over OpenPGP TLV packets | **`\x89QPE\x01\x01` Binary Wire Frame + `qSponge-XOF` Stream Whitening + 256-Bit Wire MAC** |

---

## 3. 2026 Quantum & AI-Cryptanalysis Threat Immunity Matrix

1. **Jesse-Victor-Gharabaghi (JVG) Hybrid QNTT Factorization & Shor's Algorithm**:
   Whereas JVG ([Preprints.org 202510.1649](https://www.preprints.org/manuscript/202510.1649/v1)) and Shor's algorithm attack RSA composite moduli and abelian discrete logarithms via Quantum Number Theoretic Transform (`QNTT`) / `IQFT` period estimation, OpenQPEP anchors asymmetric security in Module-LWE (`QLX`) and Module-SIS (`QVS`) polynomial rings with no hidden abelian period, fused with 448-bit `HGC-448` (`X448`/`Ed448`) via `qSponge-512`.
2. **Quantum-Accelerated Lattice Sieving (Grover-Enhanced BKZ-$\beta$)**:
   Quantum walk and Grover-accelerated sieving ([PostQuantum Sieving Analysis](https://postquantum.com/quantum-research/quantum-sieving-breakthrough/)) reduce the SVP attack exponent from classical $2^{0.292\beta}$ toward quantum $2^{0.265\beta}$. Scaling the lattice rank to $k=16$ (`4,096` dimensions in **`Calyx Signature`**) pushes required BKZ block sizes to $\beta > 1,650$ ($>512$-bit quantum work factor), while scaling to $k=64$ (`16,384` dimensions across 4 coupled Tesseract manifolds in **`Calyx Hyper-Tesseract`**) pushes $\beta > 6,400$ ($>1,024$-bit quantum work factor).
3. **Quantum Algorithms for the Dihedral Coset Problem (DCP / Extrapolated DCP)**:
   Hardened against theoretical LWE-to-DCP reductions ([IACR ePrint 2026/1591](https://eprint.iacr.org/2026/1591); formally refuted by MIT and Google researchers in [PQprobe / ePrint 2026/1693](https://pqprobe.com/blog/dcp-claim-refuted)) via Fujisaki-Okamoto (`FO`) IND-CCA2 re-encryption verification (`CALYX-QLX-FO-G|`), lossy $(d_u=11, d_v=5)$ rounding compression, and constant-time implicit rejection (`CALYX-QLX-FO-REJECT|`).
4. **Anthropic Claude Mythos Preview (July 2026) HAWK-256 Algebraic Symmetry Flaw & 7-Round AES Shortcuts**:
   In July 2026, [Anthropic's Claude Mythos Preview](https://www.anthropic.com/research/discovering-cryptographic-weaknesses) halved the security of `HAWK-256` ($2^{64} \to 2^{38}$) by exploiting rotational/Galois symmetries in rank-2 NTRU lattices and accelerated 7-round AES-128 attacks by 800× via the Möbius Bridge. OpenQPEP avoids NTRU ring isomorphisms completely, using asymmetric Module-SIS matrices (`QVS-256` $8 \times 7$ and `QVS-1024` $16 \times 14$) with per-coordinate `qSponge-XOF` domain separation (`CALYX-QVS-MAT-A|`), while `Calyx-Cascade-512 (CC-512)` cascades **full 14-round AES-256-GCM** inside **full 20-round ChaCha20-Poly1305** across two orthogonal cipher families (SPN + ARX).
5. **Grover's Algorithm on Symmetric & Hash-Based Primitives**:
   Enforces 512-bit `qSponge-512` (`SHA3-512`) and `qSponge-XOF` (`SHAKE-256`) over a 1600-bit Keccak state (zero `SHA-256` usage) and 512-bit cascaded `CC-512` keys, preserving $\ge 256$ bits of post-quantum security under Grover's $O(2^{n/2})$ bound.
6. **Side-Channel & Fault Injection Attacks (`Fault-Guard`)**:
   Enforces **Verify-Before-Emit `Fault-Guard`** inside `QVSEngine.sign` (verifying every lattice signature against `pk` in memory before output), constant-time `hmac.compare_digest` checks, and `qSponge-XOF` secret-key XOR masking (`CALYX-QPEP-SK-MASK|`) at rest.
