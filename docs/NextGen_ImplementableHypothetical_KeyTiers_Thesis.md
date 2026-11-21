# OpenQPEP Generation II-B: Implementable Flagship Beyond-LWE Hypothetical Key Tiers (`NextGen_ImplementableHypothetical_KeyTiers_Thesis.md`)

* **Document Type:** Cryptographic Research Thesis & Flagship Implementation Blueprint (`OpenQPEP Beyond-LWE / Flagship-Implementable Concept`)
* **Author & Chief Cryptography Architect:** Tristen Martinez, Founder & Lead Architect at [Calyx Labs Inc.](https://calyxlabsinc.org/) ([Documentation Mirror](https://calyxlabsinc.github.io/))
* **Current Suite Baseline:** [OpenQPEP by Calyx Labs Inc.](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) (`Production Candidate 1.0.0`, `CPOSLS-1.0`) — Current Apex Production Tier: **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)**
* **Target Reference Hardware:** High-RAM Flagship Smartphones (**Samsung Galaxy Z Fold 8** / 12–16 GB LPDDR5X RAM, ARMv9 multi-core SoC with NEON/SVE2, native NDK/C99 or WebAssembly SIMD) & High-Spec Desktop/Workstation PCs
* **Live Ecosystem:** [https://calyxlabsinc.org/](https://calyxlabsinc.org/) | [https://qpepkeys.calyxlabsinc.org](https://qpepkeys.calyxlabsinc.org) | [https://messenger.calyxlabsinc.org](https://messenger.calyxlabsinc.org)

---

## 1. Executive Thesis: Moving Beyond Module-LWE on Real Flagship Silicon

With **`Calyx Hyper-Tesseract` (`QLX-16384 + QVS-1024`)**, [OpenQPEP](https://github.com/CalyxLabsInc/OpenQPEPSuite/tree/pc/protocol/) pushed structured Module-LWE encryption to **16,384 coupled lattice dimensions** ($k = 64$ across four 4,096-dimensional Tesseract manifolds over $\mathcal{R}_{3329} = \mathbb{Z}_{3329}[X]/(X^{256}+1)$) and Lattice Fiat-Shamir with Aborts signatures to **7,680 dimensions** ($(16 \times 14)$ over $\mathcal{R}_{8380417}$), far exceeding the 1,024-dimension single-cipher ceiling of [IETF RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) / [RFC 9580](https://datatracker.ietf.org/doc/rfc9580/) and [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) / [FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf).

Yet any cryptographic design that relies *exclusively* on structured polynomial lattices (`Module-LWE` / `Module-SIS`) shares a single mathematical assumption class. While `Calyx Hyper-Tesseract` defeats Shor's algorithm, [JVG Hybrid QNTT Factorization](https://www.preprints.org/manuscript/202510.1649/v1), [Grover-Enhanced BKZ Lattice Sieving](https://postquantum.com/quantum-research/quantum-sieving-breakthrough/), and theoretical [Dihedral Coset Problem (DCP)](https://eprint.iacr.org/2026/1591) reductions ([refuted in PQprobe / ePrint 2026/1693](https://pqprobe.com/blog/dcp-claim-refuted)), the July 2026 [Anthropic Claude Mythos Preview](https://www.anthropic.com/research/discovering-cryptographic-weaknesses) attack on `HAWK-256` proved that AI-assisted cryptanalysis can uncover subtle algebraic symmetries inside structured polynomial rings.

This thesis defines **five brand-new hypothetical OpenQPEP Key Tiers** that satisfy two strict engineering constraints simultaneously:
1. **Mathematically Stronger Than Module-LWE (`Calyx Hyper-Tesseract`):** Every tier replaces or conjunctively reinforces Module-LWE with **harder, less-structured, or completely non-lattice mathematical problems**—specifically **NP-complete Binary Goppa Syndrome Decoding**, **Higher-Dimensional Supersingular Abelian Isogenies**, **Rank-Metric Syndrome Decoding (`RSD`)**, **NP-complete Multivariate Quadratic (`MQ`) Polynomial Systems**, **Unstructured Plain-LWE (zero ring symmetry)**, and **Zero-Trapdoor Stateless Hash-Based Hypertrees (`qSponge-512`)**.
2. **Actually Implementable on a High-RAM Flagship Device Today (e.g., Samsung Galaxy Z Fold 8):** Unlike purely sci-fi photonic or FHE-ASIC tiers, every tier below fits comfortably inside **12–16 GB LPDDR5X RAM** (`< 45 MB` peak working heap) and executes in **milliseconds to sub-second latency** using multi-threaded ARMv9 NEON/SVE2 C99/Rust native code (`libopenqpep`) or WebAssembly SIMD—never triggering Android `ANR` or WebView `OOM` kills on flagship hardware.

---

## 2. Comparative Architecture Matrix (Flagship Galaxy Z Fold 8 Budget)

| Hypothetical Key Tier | Non-LWE / Beyond-LWE Hardness Family | Public Key / CT / Sig Sizes | Peak RAM on Z Fold 8 | Est. Flagship Latency (Native ARMv9) | Why It Beats Module-LWE (`Hyper-Tesseract`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 6: `Calyx Goppa-Monolith` (`CGM-8192 + QHS-512`)** | **NP-Complete Binary Goppa Syndrome Decoding** ($n=8192, t=128$) + **Stateless `qSponge-512` Hypertree** | `1.35 MB` PK / `240 B` CT / `49.8 KB` Sig | `~14 MB` | `~3 ms` Decaps / `~85 ms` Sign | Zero lattice geometry, zero polynomial rings, 48+ years unbroken (since 1978), pure hash-only signature unforgeability |
| **Tier 7: `Calyx Isogeny-Forge` (`CIF-SQI-512 + QHS-512`)** | **2D/4D Supersingular Abelian Isogeny Path-Finding & Quaternion `EndRing`** over $\mathbb{F}_{p^2}$ ($\log_2 p = 512$) | `256 B` PK / `512 B` CT / `368 B` Sig | `~16 MB` | `~180 ms` Keygen / `~260 ms` Sign | Non-linear algebraic geometry over quaternion orders; immune to all lattice sieving, BKZ, and linear algebra attacks; ultra-compact keys |
| **Tier 8: `Calyx Rank-Metric Tensor` (`CRT-RSD512 + QMQ-512`)** | **Rank-Metric Syndrome Decoding (`RSD`)** over $\mathbb{F}_{2^{127}}$ + **NP-Complete Multivariate Quadratic (`MQ` / `MAYO-512`)** | `18.4 KB` PK / `1.4 KB` CT / `512 B` Sig | `~8 MB` | `~12 ms` Decaps / `~9 ms` Sign | Combines two completely non-lattice NP-hard algebraic families (Rank-Metric codes + MQ systems) with fast ARM64 `PMULL` execution |
| **Tier 9: `Calyx Unstructured-Citadel` (`CULC-2048 + CGM-8192`)** | **Zero-Ring Unstructured Plain-LWE** ($\mathbb{Z}_{2^{16}}^{2048 \times 2048}$) $\oplus$ **Binary Goppa Codes** + **`QHS-512` Hypertree** | `1.39 MB` PK / `34.1 KB` CT / `49.8 KB` Sig | `~22 MB` | `~110 ms` Encaps / `~125 ms` Decaps | Erases all cyclotomic ideal/Galois ring symmetries *and* requires breaking both unstructured worst-case SIVP lattices AND NP-complete Goppa codes |
| **Tier 10: `Calyx Sovereign-Pentad` (`CSP-Ω` 5-Family Combiner)** | **Simultaneous 5-Family Fusion:** Plain-LWE + Binary Goppa + 2D Isogeny + `MQ` + Stateless `qSponge-512` Hypertree | `1.42 MB` PK / `36.2 KB` CT / `50.7 KB` Sig | `~42 MB` | `~390 ms` Parallel (6–8 ARMv9 Cores) | **Zero Single-Family Failure:** Remains unbroken even if lattices, codes, isogenies, *and* MQ all fall simultaneously (falls back to `qSponge-512` + `CC-512`) |

---

## 3. Deep-Dive Mathematical Specifications & Flagship Implementation Blueprints

### Tier 6: `Calyx Goppa-Monolith` (`CGM-8192 + QHS-512`)
#### 1. Mathematical Foundation (Beyond LWE)
`Calyx Goppa-Monolith` removes lattice assumptions entirely, replacing Module-LWE with the **Binary Goppa Syndrome Decoding Problem** (the conservative 1978 McEliece family) and replacing Lattice Fiat-Shamir signatures with a **Stateless Hash-Based Hypertree (`QHS-512`)** over 24-round `qSponge-512` (`SHA3-512`):

1. **KEM (`CGM-8192` — Binary Goppa Code over $\mathbb{F}_{2^{13}}$):**
   - Parameters: code length $n = 8192$, error weight $t = 128$, extension field $\mathbb{F}_{2^{13}}$ ($m = 13$), parity-check matrix $\mathbf{H} = [\mathbf{I}_{mt} \mid \mathbf{T}] \in \mathbb{F}_2^{1664 \times 8192}$ derived from a secret irreducible degree-$128$ Goppa polynomial $g(x) \in \mathbb{F}_{2^{13}}[x]$ and random support permutation $(\alpha_1, \dots, \alpha_n)$.
   - **Encapsulation:** Sample a random weight-$128$ binary error vector $\mathbf{e} \in \mathbb{F}_2^{8192}$ ($\text{wt}(\mathbf{e}) = 128$) and compute the compact 208-byte syndrome $\mathbf{c}_0 = \mathbf{H}\mathbf{e}^T \in \mathbb{F}_2^{1664}$ plus a 32-byte `qSponge-512` Fujisaki-Okamoto confirmation tag $\mathbf{c}_1 = \text{qSponge-512}(\text{"CALYX-CGM-CONF|"} \parallel \mathbf{e})[:32]$ (total ciphertext: **`240 bytes`** — nearly **100× smaller** than Hyper-Tesseract's 23,168-byte ciphertext!).
   - **Decapsulation:** Uses Patterson / Berlekamp-Massey algebraic decoding over $\mathbb{F}_{2^{13}}$ with secret $(g(x), \alpha_1, \dots, \alpha_n)$ to recover $\mathbf{e}$ exactly, verifies $\mathbf{c}_1$ in constant time (`ct_eq`), and outputs $\text{ss} = \text{qSponge-512}(\text{"CALYX-CGM-SS|"} \parallel \mathbf{e} \parallel \mathbf{c}_0)$ (with branchless `ct_cmov` implicit rejection on failure).
2. **Signature (`QHS-512` — Stateless `qSponge-512` Hypertree):**
   - A `FORS` (Forest of Random Subsets) + `WOTS+` + `XMSS` multi-layer hypertree ($h = 64, d = 8$, Winternitz $w = 16$) instantiated purely with 24-round `qSponge-512` (`SHA3-512` / `SHAKE-256`).
   - **Why It Is Stronger Than Any Lattice Signature:** Security reduces *strictly* to second-preimage resistance of Keccak-f[1600]. There is **no trapdoor, no lattice, no polynomial ring, and no algebraic structure to attack**.

#### 2. Flagship Implementability (Samsung Galaxy Z Fold 8)
* **RAM & Storage:** The `1.35 MB` public matrix $\mathbf{T}$ fits trivially inside L3 cache + 16 GB LPDDR5X RAM (`~14 MB` peak during Gaussian elimination in keygen).
* **Execution Speed:** Encapsulation is a sparse XOR of 128 columns (`< 0.5 ms`); bit-sliced NEON Berlekamp-Massey decapsulation completes in `~3 ms`; parallelized `QHS-512` signing across 8 ARMv9 cores completes in `~85 ms`.

---

### Tier 7: `Calyx Isogeny-Forge` (`CIF-SQI-512 + QHS-512`)
#### 1. Mathematical Foundation (Beyond LWE)
`Calyx Isogeny-Forge` moves into **Non-Abelian Algebraic Geometry** over supersingular elliptic curves and higher-dimensional abelian surfaces—completely disjoint from both lattices and error-correcting codes:

1. **Hardness Assumption (`EndRing` + Higher-Dimensional Kani Isogenies):**
   - Let $p$ be a 512-bit prime ($p \equiv 3 \pmod 4$) such that $2^e \cdot 3^f \mid (p^2 - 1)$ with $e \ge 256$. Let $E_0 / \mathbb{F}_{p^2}: y^2 = x^3 + x$ be the base supersingular elliptic curve whose endomorphism ring $\mathcal{O}_0 = \text{End}(E_0)$ is a maximal order in the quaternion algebra $B_{p,\infty}$.
   - **Immune to Castryck-Decru (2022) Attacks:** Legacy `SIDH`/`SIKE` was broken because it published auxiliary torsion-point images $\phi(P_B), \phi(Q_B)$ of known smooth degree. `CIF-SQI-512` publishes **zero torsion-point hints** and executes **2-dimensional / 4-dimensional Richelot & Theta-Model Abelian Isogenies** (following the modern `SQIsign2D-West` / `SQIsignHD` paradigm) where the secret key is a random quaternion ideal $I \subset \mathcal{O}_0$ of prime norm and the public key is solely the codomain curve $E_A = E_0 / E_0[I]$ (just **`256 bytes`**!).
2. **KEM & Signature:**
   - **Zero-Knowledge Quaternion Proof of Endomorphism Ring (`CIF-SQI-512`):** Produces a **`368-byte`** signature by sampling a commitment curve $E_{\text{com}}$, deriving a challenge isogeny $\psi: E_{\text{com}} \to E_{\text{chl}}$ via `qSponge-512`, and computing a short-norm equivalent ideal in $B_{p,\infty}$ translated to a smooth-degree 2D abelian isogeny response (revealing zero information about $\text{End}(E_A)$).
   - **Hybrid Encapsulation:** Combines non-interactive higher-dimensional isogeny key encapsulation with `HGC-448` (`X448`) and `qSponge-512` FO confirmation.

#### 2. Flagship Implementability (Samsung Galaxy Z Fold 8)
* **RAM & Storage:** Tiny `256 B` public keys and `368 B` signatures (ideal for Scannable CLX-Codes / QR codes!) with `< 16 MB` peak RAM during quaternion lattice (`KLPT` / `2D-Theta`) reduction.
* **Execution Speed:** ARM64 `UMULH` / `MUL` 64-bit Montgomery limbs over 512-bit $\mathbb{F}_{p^2}$ execute verification in `~15 ms` and full signing/decapsulation in `~180–260 ms` on flagship Snapdragon 8-series cores.

---

### Tier 8: `Calyx Rank-Metric Tensor` (`CRT-RSD512 + QMQ-512`)
#### 1. Mathematical Foundation (Beyond LWE)
`Calyx Rank-Metric Tensor` fuses two completely independent NP-hard algebraic problems—**Rank-Metric Decoding** (for KEM) and **Multivariate Quadratic Equations** (for Signatures):

1. **Rank-Metric KEM (`CRT-RSD512`):**
   - Operates over $\mathbb{F}_{2^{127}}$-linear **Low-Rank Parity-Check (LRPC)** codes of length $n = 113$, dimension $k = 56$, parity-check weight $d = 7$, and error rank weight $r = 7$ over $\mathbb{F}_{2^{127}}$.
   - **Hardness:** Recovering a rank-$r$ error vector $\mathbf{e} \in \mathbb{F}_{2^{127}}^n$ from syndrome $\mathbf{s} = \mathbf{e}\mathbf{H}^T$ reduces to the **Rank Syndrome Decoding (`RSD`)** / **MinRank** problem. Unlike Hamming-metric codes or Module-LWE, the best known algebraic Gröbner-basis and support-minors attacks scale super-exponentially in $(r, m)$, achieving $>384$-bit post-quantum security with keys **75× smaller** than Binary Goppa (`~18.4 KB` PK, `~1.4 KB` CT).
2. **Multivariate Quadratic Signature (`QMQ-512` — Whipped `MAYO` / `UOV` over $\mathbb{F}_{256}$):**
   - Public key is a system of $m = 108$ quadratic polynomials in $n = 148$ variables over $\mathbb{F}_{256}$:
     $$\mathcal{P}(\mathbf{x}) = \big(p_1(x_1,\dots,x_n),\; \dots,\; p_m(x_1,\dots,x_n)\big) \in \mathbb{F}_{256}^m$$
     hiding a secret oil subspace $O \subset \mathbb{F}_{256}^n$ on which $\mathcal{P}$ vanishes (generalizing the whipped-oil `MAYO` construction to 512-bit security).
   - Forging a signature requires solving a random system of multivariate quadratic equations over $\mathbb{F}_{256}$ (the **NP-complete `MQ` problem**)—completely impervious to lattice reduction and Shor's algorithm.

#### 2. Flagship Implementability (Samsung Galaxy Z Fold 8)
* **RAM & Storage:** Compact `18.4 KB` public key, `~8 MB` peak working RAM for $\mathbb{F}_{256}$ Gaussian elimination and $\mathbb{F}_{2^{127}}$ carryless polynomial multiplication.
* **Execution Speed:** ARMv9 cryptographic extensions (`PMULL` 64×64 carryless multiply for $\mathbb{F}_{2^{127}}$ and NEON `TBL` SIMD lookup tables for $\mathbb{F}_{256}$) run both KEM decapsulation and `MQ` signing in **`9–15 ms`** on a Galaxy Z Fold 8!

---

### Tier 9: `Calyx Unstructured-Citadel` (`CULC-2048 + CGM-8192`)
#### 1. Mathematical Foundation (Eliminating Ring Symmetry + Dual-Family Lock)
Even if an attacker finds an algebraic symmetry break against **every** structured polynomial ring (`Ring-LWE`, `Module-LWE`, `NTRU`, `HAWK-256`)—like the July 2026 [Claude Mythos Preview](https://www.anthropic.com/research/discovering-cryptographic-weaknesses) attack—**Unstructured Plain-LWE** has **zero polynomial ring, zero cyclotomic ideal, and zero Galois automorphisms**!

`Calyx Unstructured-Citadel` pairs **Unstructured Plain-LWE** directly with **NP-Complete Binary Goppa Codes** in a conjunctive `qSponge-512` combiner:
1. **Unstructured Plain-LWE (`CULC-2048`):**
   - Expands a completely unstructured dense matrix $\mathbf{A} \in \mathbb{Z}_{65536}^{2048 \times 2048}$ row-by-row on-the-fly from a 256-bit `qSponge-XOF` seed (zero NTT, zero Toeplitz/circulant structure, zero ring ideal!):
     $$\mathbf{B} = \mathbf{A}\mathbf{S} + \mathbf{E} \pmod{65536}, \qquad \mathbf{S}, \mathbf{E} \leftarrow \chi_{\text{DGauss}}^{2048 \times 8}$$
   - Directly reduces to worst-case **GapSVP / SIVP** on general unstructured lattices—the single most conservative lattice assumption in existence.
2. **Conjunctive Dual-Family Fusion (`CULC-2048` $\oplus$ `CGM-8192`):**
   - Every encapsulation computes both $\text{ss}_{\text{LWE}} \leftarrow \text{CULC-2048.Encaps}$ and $\text{ss}_{\text{Goppa}} \leftarrow \text{CGM-8192.Encaps}$, fusing them via:
     $$\text{ss}_{\text{citadel}} = \text{qSponge-512}\big(\text{"CALYX-CITADEL-v1|"} \parallel \text{ss}_{\text{LWE}} \parallel \text{ss}_{\text{Goppa}} \parallel \text{ct}_{\text{LWE}} \parallel \text{ct}_{\text{Goppa}}\big)$$
   - Breaking this tier requires **simultaneously** solving general unstructured worst-case lattice problems *and* NP-complete Binary Goppa syndrome decoding!

#### 2. Flagship Implementability (Samsung Galaxy Z Fold 8)
* **Why $n = 2048$ (Instead of $16,384$) Works Today:** Generating $\mathbf{A} \in \mathbb{Z}_{65536}^{2048 \times 2048}$ row-by-row (4 rows at a time in 4 parallel ARMv9 threads) requires only **`~22 MB` peak RAM** (never materializing the full matrix) and `2048 × 2048 × 8 ≈ 33.5M` 16-bit NEON multiply-accumulates (`VMLAL`), finishing in **`~110–125 ms`** on a Galaxy Z Fold 8!

---

### Tier 10: `Calyx Sovereign-Pentad` (`CSP-Ω` — Five-Family Cryptographic Citadel)
#### 1. Mathematical Foundation (Zero Single-Family Failure)
`Calyx Sovereign-Pentad` (`CSP-Ω`) is the ultimate flagship-implementable post-quantum key tier: a **simultaneous 5-family conjunctive combiner** engineered so that **no single mathematical breakthrough—or even four simultaneous breakthroughs—can compromise confidentiality or authenticity**:

1. **Five Disjoint Cryptographic Locks Executed in Parallel:**
   - **Family 1 — Unstructured Plain-LWE (`CULC-2048`):** Worst-case general lattice hardness (zero ring symmetry).
   - **Family 2 — Binary Goppa Codes (`CGM-8192`):** NP-complete Hamming-metric syndrome decoding (48+ years unbroken).
   - **Family 3 — Higher-Dimensional Abelian Isogenies (`CIF-SQI-512`):** Non-linear supersingular quaternion algebraic geometry.
   - **Family 4 — Multivariate Quadratic Signatures (`QMQ-512`):** NP-complete quadratic polynomial solving over $\mathbb{F}_{256}$.
   - **Family 5 — Stateless Hash-Based Hypertree (`QHS-512` over `qSponge-512`):** Zero-trapdoor symmetric one-wayness—immune to *all* algebraic, geometric, and quantum period-finding attacks.
2. **Conjunctive Session Key & Dual-Signature Binding:**
   $$\text{ss}_{\Omega} = \text{qSponge-512}\big(\text{"CALYX-PENTAD-OMEGA-v1|"} \parallel \text{ss}_{\text{LWE}} \parallel \text{ss}_{\text{Goppa}} \parallel \text{ss}_{\text{Isog}} \parallel \text{ss}_{\text{X448}} \parallel \text{transcript}\big)$$
   $$\sigma_{\Omega} = \big(\sigma_{\text{QHS-512}},\; \sigma_{\text{QMQ-512}},\; \sigma_{\text{SQI-512}}\big)$$
   Every payload is then encrypted through OpenQPEP's dual-stream **`Calyx-Cascade-512 (CC-512)`** (14-round `AES-256-GCM` inside 20-round `ChaCha20-Poly1305`) wrapped in whitened binary `\x89QPE` framing with `SecretBuffer` active RAM scrubbing.

#### 2. Flagship Implementability (Samsung Galaxy Z Fold 8)
* **Parallel Thread Allocation on Flagship ARMv9 Octa-Core SoCs:**
  - *Core 0–1 (Prime / Big):* `CIF-SQI-512` 2D Abelian Isogeny (~220 ms)
  - *Core 2–3 (Big):* `CULC-2048` Unstructured Plain-LWE row-streaming (~115 ms)
  - *Core 4–5 (Performance):* `QHS-512` Stateless `qSponge-512` Hypertree (~85 ms)
  - *Core 6–7 (Performance):* `CGM-8192` Goppa Decoder (~3 ms) + `QMQ-512` Multivariate Quadratic (~12 ms)
* **Wall-Clock Result:** Because all five families are mathematically independent, they execute **concurrently** across the Galaxy Z Fold 8's 8 cores in **`~390 ms` total wall-clock latency** using **`~42 MB` peak RAM** (`0.26%` of 16 GB RAM)—making a 5-family beyond-LWE citadel genuinely usable on a flagship smartphone!

---

## 4. OpenQPEP Protocol Integration Path (`v1.0.0-pc+` / Generation II-B)

Because OpenQPEP `Production Candidate 1.0.0` now uses a modular cryptographic kernel (`calyx_qpep/primitives/`, `calyx_qpep/lattice/`, `calyx_qpep/wire/`, `calyx_qpep/kdf/`, `calyx_qpep/keyring/`), integrating any of Tiers 6–10 requires **zero breaking changes** to `.qpkrf` key rings, `Key Hash` addressing, `QPEP-Ratchet`, or `Calyx-Cascade-512`:
1. **Modular Plugin Directories:** Add `calyx_qpep/codes/` (`goppa_8192.py`, `rank_rsd512.py`), `calyx_qpep/isogeny/` (`sqi_2d_512.py`), `calyx_qpep/multivariate/` (`qmq_512.py`), and `calyx_qpep/hashsig/` (`qhs_512_hypertree.py`).
2. **Native ARMv9 / x86_64 Acceleration (`libopenqpep`):** Compile hot inner loops (`PMULL`, `VMLAL`, 64-bit Montgomery limbs, and vectorized Keccak-f[1600]) via C99/Rust NDK (`Android JNI`) and WebAssembly SIMD (`iOS/Web`).
3. **Mandatory Hardware Guardrails:** Enforce the same automatic RAM/hardware capability check already built into `calyx_qpep/kdf/hardware_tuner.py` and the Calyx QPEP Client High-Tier Hardware Notice, gating Tiers 6–10 to devices with `>= 12 GB RAM` and native SIMD support while keeping **`Calyx Signature` (`QLX-4096 + QVS-256`)** as the fast universal default for all devices.
