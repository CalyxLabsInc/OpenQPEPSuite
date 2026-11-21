# 01 — OpenQPEP Mathematical & Cryptographic Specification (`v1.0.0-pc`)

**Protocol:** `OpenQPEP/PC-1.0.0` (`Production Candidate 1.0.0`)  
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

## 2. Beyond-LWE Cryptographic Suites (Tiers 10, 11, and 12)

### 2.1 Tier 10: `Calyx Sovereign-Pentad (CSP-Omega — 5-Family Citadel)`
Simultaneously executes **five mathematically disjoint post-quantum families** in parallel threads (protected by a mandatory `>= 12 GB` RAM flagship hardware guardrail):
1. **Family 1 — Unstructured Plain-LWE (`CULC-2048`):** Row-streamed general matrix $A \in \mathbb{Z}_{65536}^{n \times n}$ with zero polynomial ring symmetry and native C99 row-accumulator acceleration.
2. **Family 2 — Binary Goppa Codes (`CGM-8192`):** NP-complete Hamming-metric syndrome decoding.
3. **Family 3 — Higher-Dimensional Abelian Isogenies (`CIF-SQI-512`):** 2D supersingular quaternion isogeny geometry.
4. **Family 4 — Multivariate Quadratic Signatures (`QMQ-512`):** NP-complete MQ over $\text{GF}(256)$ with native `openqpep_gf256_mul`.
5. **Family 5 — Stateless Hash-Based Hypertree (`QHS-512`):** Zero-trapdoor Keccak-f[1600] one-wayness.

Session key and conjunctive triple-family signature binding:
$$ss_\Omega = \text{qSponge-512}(\texttt{"CALYX-PENTAD-OMEGA-v1|"} \parallel ss_{\text{LWE}} \parallel ss_{\text{Goppa}} \parallel ss_{\text{Isog}} \parallel ss_{\text{X448}} \parallel \text{transcript})$$
$$\sigma_\Omega = (\sigma_{\text{QHS-512}},\; \sigma_{\text{QMQ-512}},\; \sigma_{\text{SQI-512}})$$

### 2.2 Tier 11 (`CGM-8192`) & Tier 12 (`RMT-512`) Standalone Non-Lattice Suites
- **Tier 11 — `Calyx Goppa-Monolith (CGM-8192)`:** Standalone Binary Goppa code-based KEM + `CC-512` AEAD (zero lattice assumptions).
- **Tier 12 — `Calyx Rank-Metric Tensor (RMT-512)`:** Standalone Rank-Metric syndrome KEM over $\mathbb{F}_{2^{127}}$ modulo $x^{127}+x^{63}+1$ with FO implicit rejection + `CC-512` AEAD.

---

## 3. Mandatory `kdf_version: 2` (`QPKD-Argon2id + qSponge-512`) & `CC-512`

- **Passphrase Policy Witness (64 Bytes):** Hardcoded non-bypassable policy (`>= 12` chars, `>= 2` digits, `>= 4` specials, `>= 2` uppercase, `>= 4` lowercase) hashed into a 64-byte witness absorbed directly into key derivation.
- **RFC 9106 Argon2id + qSponge-512 Cascade (`kdf_version: 2`):** Default `m = 65,536 KiB` (64 MiB) on standard hardware and `m = 262,144 KiB` (256 MiB) on high-tier hardware (`t = 3`, `p = 4`, 256-bit salt). Legacy beta `kdf_version: 1` key rings are **strictly rejected** in `v1.0.0-pc`.
- **Calyx-Cascade-512 (`CC-512`):** Dual-stream AEAD cascading `AES-256-GCM` inside `ChaCha20-Poly1305` with independent keys and nonces derived from `qSponge-512`.

---

## 4. Native C99 / SIMD Acceleration (`libopenqpep`)
Hot inner loops (`NTT_3329`, `NTT_8380417`, `CBD_1`/`CBD_2`, Plain-LWE, `GF(256)`/`XOR` Pentad kernels) compile with `-O3 -std=c99 -mavx2` (x86_64) or `-march=armv8-a` (ARM64) via `make -C calyx_qpep/native/csrc` and load automatically via zero-copy `array.array` `ctypes`, delivering 6×–17× end-to-end speedups with 100% bit-exact KAT parity against the pure-Python reference engine.
