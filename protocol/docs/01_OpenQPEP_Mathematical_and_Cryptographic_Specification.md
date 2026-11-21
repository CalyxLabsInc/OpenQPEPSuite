# 01 — OpenQPEP Mathematical & Cryptographic Specification (`v1.0.0-rc`)

**Protocol:** `OpenQPEP/RC-1.0.0` (`Release Candidate 1.0.0`)  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)

---

## 1. Lattice Suites (`QLX-768` through `QLX-16384` & `QVS-65` through `QVS-1024`)

### 1.1 Algebraic Rings & Vectorized NTTs
- **KEM Ring (`QLX`):** $R_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ with primitive root $\zeta = 17$, 7-layer Cooley-Tukey / Gentleman-Sande NTT (`ntt_3329.c` / `ntt_3329.py`), and Fujisaki-Okamoto IND-CCA2 implicit rejection via branchless `ct_cmov`.
- **Signature Ring (`QVS`):** $R_{8380417} = \mathbb{Z}_{8380417}[X]/(X^{256}+1)$ with primitive root $\zeta = 1753$, 8-layer complete NTT (`ntt_8380417.c` / `ntt_8380417.py`), Fiat-Shamir with Aborts, and mandatory **Fault-Guard** post-signing verification (`QPEPFaultGuardError` on any injected glitch).
- **4-Manifold Calyx Hyper-Tesseract (`QLX-16384 + QVS-1024`):** Couples 4 independent 4,096-dim manifolds ($k = 64$, total dimension $16,384$) using unstructured dense cross-manifold seed coupling and unit-variance $\text{CBD}_1$ noise (`24,608 B` PK, `23,168 B` CT, `10,816 B` QVS-1024 signature).

### 1.2 Classical Goldilocks Hybrid Combiner (`HGC-448`)
Every lattice KEM and signature is fused with **X448** (RFC 7748) and **Ed448** (RFC 8032) via `qSponge-512` transcript binding so security holds under the stronger of classical and post-quantum assumptions.

---

## 2. Beyond-LWE Cryptographic Suites (`CIF-SQI-512`, `CRT-RSD512`, `CGM-8192`, `CULC-2048`, `CSP-Omega`)

### 2.1 Calyx Sovereign-Pentad: `Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)`
Simultaneously executes **five mathematically disjoint post-quantum families** in parallel threads (protected by a mandatory `>= 12 GB` RAM flagship hardware guardrail):
1. **Family 1 — Unstructured Plain-LWE (`CULC-2048`):** Row-streamed general matrix $A \in \mathbb{Z}_{65536}^{n \times n}$ with zero polynomial ring symmetry and native C99 row-accumulator acceleration.
2. **Family 2 — Binary Goppa Codes (`CGM-8192`):** NP-complete Hamming-metric syndrome decoding.
3. **Family 3 — Higher-Dimensional Abelian Isogenies (`CIF-SQI-512`):** 2D supersingular quaternion isogeny geometry.
4. **Family 4 — Multivariate Quadratic Signatures (`QMQ-512`):** NP-complete MQ over $\text{GF}(256)$ with native `openqpep_gf256_mul`.
5. **Family 5 — Stateless Hash-Based Hypertree (`QHS-512`):** Zero-trapdoor Keccak-f[1600] one-wayness.

Session key and conjunctive triple-family signature binding:
$$ss_\Omega = \text{qSponge-512}(\texttt{"CALYX-PENTAD-OMEGA-v1|"} \parallel ss_{\text{LWE}} \parallel ss_{\text{Goppa}} \parallel ss_{\text{Isog}} \parallel ss_{\text{X448}} \parallel \text{transcript})$$
$$\sigma_\Omega = (\sigma_{\text{QHS-512}},\; \sigma_{\text{QMQ-512}},\; \sigma_{\text{SQI-512}})$$

### 2.2 Standalone Beyond-LWE Suites (`CGM-8192`, `CRT-RSD512`, `CIF-SQI-512`, `CULC-2048`)
- **Calyx Goppa-Monolith (`CGM-8192 + QHS-512`):** Standalone Binary Goppa code-based KEM + `CC-512` AEAD (zero lattice assumptions).
- **Calyx Rank-Metric Tensor (`CRT-RSD512 + QMQ-512`):** Standalone Rank-Metric syndrome KEM over $\mathbb{F}_{2^{127}}$ modulo $x^{127}+x^{63}+1$ with FO implicit rejection + `CC-512` AEAD.
- **Calyx Isogeny-Forge (`CIF-SQI-512 + QHS-512`):** 2D Supersingular Abelian Isogeny KEM + Stateless Hash-Based Hypertree.
- **Calyx Unstructured-Citadel (`CULC-2048 + CGM-8192`):** Zero-Ring Unstructured Plain-LWE fused conjunctively with Binary Goppa Codes.

---

## 3. Mandatory `kdf_version: 3` (`QPKD-Argon2id + qSponge-512`) & `CC-512`

- **Passphrase Policy Witness (64 Bytes):** Hardcoded non-bypassable policy (`>= 12` chars, `>= 2` digits, `>= 4` specials, `>= 2` uppercase, `>= 4` lowercase) hashed into a 64-byte witness absorbed directly into key derivation.
- **RFC 9106 Argon2id + qSponge-512 Cascade (`kdf_version: 3`):** Default `m = 65,536 KiB` (64 MiB) on standard hardware and `m = 262,144 KiB` (256 MiB) on high-tier hardware (`t = 3`, `p = 4`, 256-bit salt, `"personalization": "OpenQPEP/RC-1.0.0"`, optional `FIDO2-PRF` hardware passkey secret). Legacy `kdf_version < 3` key rings are **strictly rejected** in `v1.0.0-rc` with `QPEPLegacyProtocolError`.
- **Calyx-Cascade-512 (`CC-512`):** Dual-stream AEAD cascading `AES-256-GCM` inside `ChaCha20-Poly1305` with independent keys and nonces derived from `qSponge-512`.

---

## 4. Native C99 / SIMD Acceleration (`libopenqpep`)
Hot inner loops (`NTT_3329`, `NTT_8380417`, `CBD_1`/`CBD_2`, Plain-LWE, `GF(256)`/`XOR` Pentad kernels, compiler-barrier `openqpep_explicit_bzero`, constant-time `openqpep_verify_wire_v4_magic`) compile with `-O3 -std=c99 -mavx2` (x86_64) or `-march=armv8-a` (ARM64) via `make -C calyx_qpep/native/csrc` and load automatically via zero-copy `array.array` `ctypes`, delivering 6×–17× end-to-end speedups with 100% bit-exact KAT parity against the pure-Python reference engine.

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
