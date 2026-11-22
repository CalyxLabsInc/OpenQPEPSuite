# OpenQPEP Core Protocol Roadmap: Release Candidate 1.0.0 (`v1.0.0-rc`) → Official Release 1.0.0 (`v1.0.0`) → Official Release 2.0.0 (`v2.0.0`)

**Organization:** Calyx Labs Inc. (Cleveland, Ohio)  
**Creator & Lead Architect:** Tristen Martinez  
**Repository:** https://github.com/CalyxLabsInc/OpenQPEP  
**License:** Calyx Public Open Source Specifications v1.0 License (`CPOSLS-1.0`)  
**Mission:** Establish OpenQPEP as the definitive, quantum-proof worldwide successor to OpenPGP (RFC 4880 / RFC 9580) with zero legacy cryptographic baggage, provable multi-assumption security, constant-time native performance, and universal interoperability.

---

## Executive Summary

OpenQPEP enters this roadmap at **Release Candidate 1.0.0 (`v1.0.0-rc`, Wire Format v4, `kdf_version: 3`)**. Before declaring **Official Release - Version 1.0.0 (`v1.0.0`)**—the permanent public starting point of the OpenQPEP worldwide ecosystem—every cryptographic primitive, stateful protocol, binary parser, native accelerator, CLI command, and cross-language binding underwent a ruthless, line-by-line adversarial cryptographic audit.

This roadmap documents:
1. **Part I (`v1.0.0-rc` → `v1.0.0` Official Release):** Every concrete vulnerability, shortcut, or specification gap uncovered during the pre-1.0.0 audit, and the exact cryptographic engineering milestones required to eliminate 100% of them prior to Official Release `v1.0.0`.
2. **Part II (`v1.0.0` Final Cutover — Zero Backwards Compatibility):** The clean-slate official release wire freeze (**Wire Format v5 `\x89QPE\x05\x00`**, **Compact TLV v5.1 `\x89QPE\x05\x01`**, **Stream v5 `\x89QPS\x05\x00`**, **Mandatory `kdf_version: 4`**) that strictly rejects **all** legacy Release Candidate (`-rc`), Production Candidate (`-pc`), and Beta (`-beta`) packets and key rings with `QPEPLegacyProtocolError`.
3. **Part III (`v1.1.0` → `v2.0.0` Official Release Evolution):** The multi-year public standards roadmap extending OpenQPEP into hardware security modules, formally verified assembly/Rust backends, federated transparency witnesses, and universal email/messaging/supply-chain adoption while maintaining clean forward-compatible governance.

---

## Part I — Pre-1.0.0 Cryptographic Perfection Milestones (`v1.0.0-rc` → `v1.0.0`)

### Milestone 1 (`v1.0.0-rc.2`): Complete Cryptographic Remediation of All Beyond-LWE Primitives & Ring Signatures

A worldwide PGP replacement cannot contain *any* placeholder trapdoor, public-mask shortcut, classical-only assumption in a post-quantum slot, or leaky privacy primitive. Every single non-lattice and privacy engine is upgraded to textbook, cryptanalytically genuine post-quantum constructions:

1. **Binary Goppa Code KEM (`CGM-8192` — `calyx_qpep/codes/goppa_8192.py`):**
   - *Audit Finding:* `v1.0.0-rc` masked `err_seed` using `pk || c0_syn` (both public values), permitting key recovery without `sk`.
   - *`v1.0.0` Perfection Fix:* Replace entirely with a **genuine Classic McEliece / Niederreiter Binary Goppa Code KEM** over $\mathbb{F}_{2^{10}}$ ($x^{10} + x^3 + 1$, $n = 1024$, irreducible degree-$t=32$ Goppa polynomial $g(x)$, secret support permutation $\alpha_0 \dots \alpha_{n-1}$, systematic parity-check public matrix $H_{\text{sys}} = [I_{320} \mid T]$) decoded strictly via **Patterson's Algebraic Decoding Algorithm** (syndrome polynomial $S(x)$, Frobenius square-root $\sqrt{S(x)^{-1}+x} \bmod g(x)$, Extended Euclidean key equation, and Chien search), wrapped in Fujisaki-Okamoto CCA2 confirmation and branchless `ct_cmov` implicit rejection.
2. **Rank-Metric Syndrome Decoding KEM (`CRT-RSD512` — `calyx_qpep/codes/rank_rsd512.py`):**
   - *Audit Finding:* `v1.0.0-rc` transmitted `r_val` in the clear and decapsulated without using `seed_sk`; residual legacy `CALYX-RMT-` domain strings remained.
   - *`v1.0.0` Perfection Fix:* Replace entirely with a **genuine FO-hardened LRPC (Low-Rank Parity-Check / ROLLO-I-class) Rank-Metric Syndrome Decoding KEM** over $\mathbb{F}_{2^{127}}[X]/(X^{47} + X^5 + 1)$ (prime extension degree $127$, zero subfield structure). Secret low-rank subspace $F = \langle f_1, \dots, f_4 \rangle$, secret polynomials $x, y \in F[X]$, public key $h = x \cdot y^{-1}$. Encapsulation samples a rank-4 error support $E$, canonically encodes its RREF basis, deterministically expands $(e_A, e_B) \in E[X]^2$, and outputs $c = e_A + h \cdot e_B$. Decapsulation multiplies $s = y \cdot c$, runs **Rank Support Recovery (RSR)** via Zassenhaus $\mathbb{F}_2$-subspace intersections $E' = \bigcap_{i=1}^4 f_i^{-1} \text{span}(s)$, performs full Fujisaki-Okamoto re-encryption verification `ct_eq(c, c')`, and uses branchless `ct_cmov` implicit rejection. Eliminate all legacy `RMT` strings (`CALYX-CRT-RSD512-*-v1.0.0|`).
3. **Multivariate Quadratic Signature (`QMQ-512` — `calyx_qpep/multivariate/qmq_512.py`):**
   - *Audit Finding:* `v1.0.0-rc` placed the unhidden central map seed directly in `pk` without transforming by the secret oil subspace $O$, allowing forgery from `pk`.
   - *`v1.0.0` Perfection Fix:* Replace entirely with **genuine Unbalanced Oil-and-Vinegar (UOV — NIST PQC Round 2 canonical construction)** over $\mathbb{F}_{256}$ ($v = 32$ vinegar variables, $m = 16$ oil variables, $n = 48$). Secret oil subspace $O \in \mathbb{F}_{256}^{v \times m}$ is **never** included in `pk`; keygen computes the public hidden block $P_3^{(k)} = \text{Upper}(O^T P_1^{(k)} O + O^T P_2^{(k)})$ so $P^{(k)}$ vanishes identically on $\mathcal{O} = \text{col}\binom{O}{I_m}$. Signing solves the linear oil system for random vinegars, embeds $s = (v_{\text{vec}} \oplus O x_o, x_o)$, and enforces **Verify-Before-Emit Fault-Guard** (`QPEPFaultGuardError`). Verification evaluates only public $(P_1, P_2, P_3)$.
4. **Supersingular Isogeny Engine (`CIF-SQI-512` — `calyx_qpep/isogeny/sqi_2d_512.py`):**
   - *Audit Finding:* `v1.0.0-rc` performed multiplicative exponentiation in $\mathbb{F}_{p^2}^\times$ (classical discrete logarithm vulnerable to Shor's algorithm).
   - *`v1.0.0` Perfection Fix:* Replace entirely with **genuine CSIDH-512 Supersingular Elliptic Curve Isogeny Class-Group Action** over the exact 511-bit supersingular prime $p = 4 \cdot (\prod_{i=1}^{73} \ell_i) \cdot 587 - 1$ ($p \equiv 3 \pmod 4$) using projective Montgomery-Edwards **Meyer-Reith odd-degree Vélu isogenies** with **zero torsion-point publication** (immune to Castryck-Decru SIDH attacks), mandatory supersingular curve validation on every untrusted curve $A$, implicit FO rejection on invalid curves, and **genuine multi-round CSIDH-512 SeaSign Fiat-Shamir with Aborts isogeny signatures**!
5. **Post-Quantum Linkable Ring Signatures (`QVS-Ring` — `calyx_qpep/privacy/ring_sig.py`):**
   - *Audit Finding:* `v1.0.0-rc` leaked `signer_index` during verification (`ct_eq(responses[i] ^ cur_c, commit_s)`) and permitted forgery without `signer_sk`.
   - *`v1.0.0` Perfection Fix:* Replace entirely with a **genuine Module-SIS Lattice AOS Ring Signature** over $R_{8380417} = \mathbb{Z}_{8380417}[X]/(X^{256}+1)$ using our C99-accelerated `NTT_8380417` engine, uniform decoy sampling in $(-\gamma_1 + \beta, \gamma_1 - \beta)$, rejection sampling (Fiat-Shamir with Aborts) at the true signer index so all $n$ responses are **statistically indistinguishable** (zero signer leakage), and domain-bound Module-SIS key images $I = H_{\text{domain}} s_\pi$ for linkability.

---

### Milestone 2 (`v1.0.0-rc.3`): CMT-4 Key-Committing `CC-512`, Self-Certifying Suite Binding & Unified Beyond-LWE Envelopes

1. **CMT-4 Key-Committing `CC-512` AEAD (`calyx_qpep/primitives/cc512_aead.py`):**
   - Upgrade `CC-512` from raw `AES-256-GCM` + `ChaCha20-Poly1305` (non-key-committing individually, susceptible to invisible salamanders multi-key collisions) to **provably CMT-4 Key-Committing Cascade AEAD**:
     - Derive independent `(k_aes, k_chacha, k_commit)` via `qSponge-XOF("CALYX-CC512-CMT4-KEYS-v1.0.0|" || key64 || nonce24, 96)`.
     - Append a 256-bit `qSponge-512` key+nonce+AAD+ciphertext commitment tag `cmt_tag`, verified in constant time **before** decrypting either AEAD cipher.
     - Actively zeroize all subkeys via `SecretBuffer`.
   - Route `protocol.py` `_cc512_encrypt`/`_cc512_decrypt` through the unified CMT-4 `cc512_aead` engine, and update `multi_recipient.py` dummy-slot sizes (`+32 B` commitment tag = `128 B` wrapped CEK) to preserve indistinguishable dummy slots.
2. **Cryptographic Suite & Beyond-LWE Key Binding (`calyx_qpep/protocol.py`):**
   - *Audit Finding:* `key_hash` and `cert_transcript` omitted `suite_id` and `beyond_lwe_public`, allowing theoretical suite-tag or Beyond-LWE key substitution on `.qpkrf` rings.
   - *`v1.0.0` Perfection Fix:* Bind `suite_id` and canonical `qSponge-512(beyond_lwe_public)` directly into both `key_hash` and the conjunctive `QVS + Ed448` self-certification transcript `cert_transcript`.
3. **Unified Authenticated Envelopes for ALL 10 Suites (`calyx_qpep/protocol.py`):**
   - Upgrade `encrypt_bytes` / `decrypt_packet` so Beyond-LWE `.qpkrf` key rings also embed the sender's Beyond-LWE attached signature, filename/extension/MIME detection, `plaintext_qsponge_512` integrity hash, compression with decompression-bomb protection, and full `meta_info` parity (`signature_verified`, `encrypting_key_hash`, `plaintext_qsponge_512`, `filename`, `mime_type`, `suite_id`).
4. **Deterministic Ed448 & Complete Secret Zeroization (`calyx_qpep/primitives/hgc448.py`, `protocol.py`):**
   - Replace `Ed448PrivateKey.generate()` with `Ed448PrivateKey.from_private_bytes(os.urandom(57))` (100% deterministic under KAT DRBG and uniform CSPRNG in production).
   - Wrap private keys, session keys, KDF keys, and unwrapped JSON byte buffers in `SecretBuffer` backed by C99 compiler-barrier `openqpep_explicit_bzero`.

---

### Milestone 3 (`v1.0.0-rc.4`): Hardening All Stateful, Privacy, Transparency & Distributed Sub-Protocols

1. **`QPEPRatchetSession` True Rotating PCS + Atomic State Commit (`calyx_qpep/ratchet/`):**
   - *Audit Findings:* (a) Peers never rotated their own ephemeral ratchet keypairs on PCS rekey; (b) `decrypt()` mutated `_root_key` and `_recv_ck` *before* verifying the CC-512 AEAD tag, allowing a forged packet with `epoch + 1` to permanently desynchronize/DoS the session.
   - *`v1.0.0` Perfection Fix:* (a) Advertise fresh sender ephemeral `(qlx_pk, hgc_pk)` in every `pq_rekey` header and rotate peer keys upon authenticated receipt; (b) compute candidate state in local buffers, verify `cc512_decrypt` first, and **atomically commit** state updates only after AEAD authentication succeeds.
2. **`QPEPAKEHandshake` Bidirectional Post-Quantum Mutual Authentication (`calyx_qpep/transport/ake_handshake.py`):**
   - *Audit Findings:* Initiator authentication relied solely on classical X448 (`ss_se_x`); static dummy witness `b"W"*64`; `recv()` did not verify deterministic `nonce24`.
   - *`v1.0.0` Perfection Fix:* Add responder-to-initiator static QLX encapsulation (`ct_se_qlx, ss_se_qlx`) so **both** initiator and responder are mutually post-quantum authenticated; bind both static public keys into transcript; verify deterministic `nonce24` in `recv()`; scrub keys via `SecretBuffer` + `destroy()`.
3. **`QPEPGroupSession` (`QPEP-MLS` — `calyx_qpep/group/mls_epoch.py`):**
   - Add per-`(epoch, sender)` sequence replay protection, fresh random member witnesses, and active `SecretBuffer` zeroization of superseded epoch secrets.
4. **`KeyTransparencyLog` (`QPEP-KT` — `calyx_qpep/directory_kt/merkle_log.py`):**
   - Upgrade Signed Tree Heads (STHs) from a hardcoded symmetric secret to **publicly verifiable Ed448 asymmetric signatures** (`verify_sth(sth, log_public_key_hex)`).
   - Implement **RFC 6962 / RFC 9162 Merkle Consistency Proofs** (`consistency_proof(first_size, second_size)` and `verify_consistency_proof(...)`) enabling mathematical split-view / append-only equivocation detection.
   - Enforce constant-time `ct_eq` digest checks.
5. **Privacy, Threshold, Mixnet, ZKP & Streaming Hardening:**
   - **`DeniableVault` (`privacy/deniable_vault.py`):** Eliminate plaintext 4-byte length leakage by encrypting/masking slot headers `(nonce24 || len4)` under slot-key-derived `qSponge-XOF` masks and using memory-hard `QPKD-Argon2id` key derivation (with optional fast test cost parameter) so the entire container is statistically indistinguishable from `os.urandom`.
   - **`ThresholdKEM` (`threshold/tkem.py`):** Upgrade `proactive_refresh` to genuine **Herzberg-Jarecki-Krawczyk-Yung zero-reconstruction proactive share refresh** (adding a random degree-$(t-1)$ polynomial $g(x)$ with $g(0)=0$ over $\text{GF}(256)$ directly to shares without ever reconstructing the secret!), plus genuine public-key threshold encapsulation.
   - **`SphinxPQRouter` (`mixnet/sphinx_pq.py`):** Pad onion layers to fixed outer length (preventing hop-count leakage), record replay tag only *after* AEAD authentication succeeds, and remove `RC100` / `b"W"*64` artifacts.
   - **`LatticeZKProof` (`zkp/lattice_sigma.py`):** Fix 4× periodic masking bug (`* 4`) with full 256-coefficient uniform `qSponge-XOF` sampling, canonical 12-bit encoding of `(a_hat, t_hat, w_hat)` in Fiat-Shamir hash (closing 4-bit upper malleability), and strict range validation `0 <= c < 3329` in `verify()`.
   - **`StreamingEncryptor`/`StreamingDecryptor` (`wire/streaming.py`):** Bump magic to Official Release **`STREAM_MAGIC = b"\x89QPS\x05\x00"`** (hard-rejecting legacy `\x89QPS\x02\x07` with `QPEPLegacyProtocolError`), hash the **full chunk ciphertext** into each Merkle leaf (not only trailing 32 bytes), and enforce strict max chunk-size bounds.

---

### Milestone 4 (`v1.0.0-rc.5`): Parser Defenses, C99 Thread-Safety & JNI Bugfix, Scriptable CLI, and 5-Language Parity

1. **Armor, TLV & Decompression-Bomb Hardening (`wire/armor.py`, `wire/framing.py`, `wire/compact_v51.py`, `protocol.py`):**
   - Strictly verify the `={crc}` armor checksum in constant time (`ct_eq`) — eliminating the silent skip in `wire/armor.py`.
   - Enforce `MAX_ARMOR_BYTES` (64 MiB), `MAX_DECOMPRESSED_BYTES` (128 MiB via `zlib.decompressobj().decompress(data, max_length + 1)`), strict header injection rejection (no `\r`/`\n`/`\x00`), and duplicate-tag / trailing-byte rejection in Compact TLV `decode_tlv`.
2. **Native C99 Hardening (`calyx_qpep/native/csrc/`):**
   - **Critical JNI Bugfix (`openqpep_jni.c`):** Fix `int16_t` vs `int32_t` ABI mismatch on `openqpep_ntt_3329` / `openqpep_inv_ntt_3329` that would overflow 512 bytes on Android JNI.
   - **Thread-Safety & Constant-Time Tables (`ntt_3329.c`, `ntt_8380417.c`):** Replace racy runtime `zetas_initialized` lazy init with **compile-time `static const` zeta tables**, add branchless conditional reductions, and enforce `-Wall -Wextra -Werror` clean compilation.
   - **Constant-Time C99 Primitives (`pentad_accel.c`):** Add `openqpep_verify_wire_v5_magic`, `openqpep_ct_eq`, `openqpep_ct_cmov`, and `openqpep_explicit_bzero`.
3. **PGP-Replacing Production CLI (`calyx_qpep/cli.py`):**
   - Enforce strict `0o700` directory and `0o600` file permissions on `~/.openqpep/keyring.json`.
   - Add full scriptable non-interactive subcommands alongside the interactive blue-text shell: `keygen`, `encrypt`, `decrypt`, `sign`, `verify`, `inspect`, `fingerprint`, `revoke`, `verify-vectors`, `check-passphrase`, and `audit`.
   - Fix Beyond-LWE display formatting and remove stale Wire v3 / `kdf_version: 3` / `v1.0.0-rc` strings.
4. **5-Language Conformance & Formal Models (`rust/`, `go/`, `native/wasm/`, `formal/`):**
   - Synchronize Rust (`openqpep-core` `1.0.0`, `wire_v5.rs`, `ntt.rs`, zero `unsafe`), Go (`go/openqpep/wire_v5.go`), WASM (`@calyxlabs/openqpep-wasm` `1.0.0`, `wasm_bridge.mjs`, `qpep_worker.js`), and formal verification models (`qpep_ake.pv`, `qpep_ratchet.spthy`, `qpep_mls.spthy`, `csp_omega_combiner.cry`) to 100% Official Release `v1.0.0` Wire v5/v5.1 parity.

---

## Part II — Official Release - Version 1.0.0 (`v1.0.0`): Clean-Slate Zero-Backwards-Compatibility Cutover

**Official Release - Version 1.0.0 (`v1.0.0`)** is the permanent public launch baseline of the OpenQPEP worldwide ecosystem. As the final cutover step before publishing `v1.0.0`:

| Protocol Layer | Legacy Pre-Release (Hard Rejected) | Official Release `v1.0.0` (Mandatory) |
| :--- | :--- | :--- |
| **Version / Protocol ID** | `*-beta`, `*-pc`, `1.0.0-rc` (`OpenQPEP/RC-1.0.0`) | **`1.0.0`** (`OpenQPEP/1.0.0`, `Official Release 1.0.0`, PEP 440 `1.0.0`) |
| **Canonical Wire Magic** | `\x89QPE\x01\x01`, `\x01\x09`, `\x02\x00`, `\x03\x00`, `\x04\x00` | **`\x89QPE\x05\x00` (`WIRE_MAGIC_V5`)** |
| **Compact TLV Magic** | `\x89QPE\x03\x01`, `\x89QPE\x04\x01` | **`\x89QPE\x05\x01` (`WIRE_MAGIC_V5_1`)** |
| **Streaming AEAD Magic** | `\x89QPS\x02\x07` | **`\x89QPS\x05\x00` (`STREAM_MAGIC_V5`)** |
| **Private Keyring KDF** | `kdf_version: 1, 2, 3` (`derive_qpkrf_keys_v1..v3`) | **Mandatory `kdf_version: 4`** (`derive_qpkrf_keys_v4`, RFC 9106 `QPKD-Argon2id + qSponge-512`, `"personalization": "OpenQPEP/1.0.0"`) |
| **AEAD Engine** | `CC-512` (AES-GCM + ChaCha20-Poly1305) | **CMT-4 Key-Committing `CC-512`** (+256-bit `qSponge-512` key/nonce/AAD/ct commitment) |
| **Domain Separation** | `*-v1.0.0-rc\|`, `*-v4\|`, `*-RC100\|`, `CALYX-RMT-*` | **Clean `*-v1.0.0\|` / `*-v5\|` / `*-v51\|` across every primitive** |
| **Legacy Compatibility** | N/A | **ZERO backwards compatibility** — every `-rc`, `-pc`, and `-beta` wire frame, stream, and key ring raises **`QPEPLegacyProtocolError`** immediately |
| **Golden KAT Vectors** | `vectors/*.json` (`v1.0.0-rc` / Wire v4) | **Regenerated 10/10 Deterministic Golden KATs** (`CALYX-OPENQPEP-KAT-DRBG-v1.0.0\|`, Wire v5 `895150450500`, verified bit-exact across C99 & pure Python) |

---

## Part III — Post-1.0.0 Public Ecosystem & Standards Evolution (`v1.1.0` → `v2.0.0`)

Once Official Release `v1.0.0` is frozen as the permanent Wire v5 public starting point, all `v1.x` releases preserve **strict Wire Format v5 (`\x89QPE\x05\x00` / `\x89QPE\x05\x01`) backwards compatibility** across the public ecosystem:

### `v1.1.0` — Hardware Security, Smartcards & Supply-Chain Signing
- **OpenQPEP Hardware Applet & PKCS#11 / PIV / OpenPGP-Card-Replacement Bridge:** Native USB-C / NFC smartcard & HSM signing/decapsulation keeping Master QVS + Ed448 keys non-exportable in hardware.
- **Git & Software Supply-Chain Signing (`git config gpg.format openqpep`):** Drop-in Git commit/tag signer (`openqpep-git`), OCI container artifact signing, and Sigstore/SLSA provenance bundles using Attached Signatures & `m`-of-`n` Multisig policies.
- **RFC-Grade Detached-Prohibited Audit Logs & Streaming CLI Pipes:** `openqpep encrypt --stream` / `openqpep decrypt --stream` piping gigabyte tarballs directly over `stdin`/`stdout` in $O(1)$ RAM.

### `v1.2.0` — Full Native C99/Rust/WASM Accelerators & SIMD Beyond-LWE
- **Full C99/AVX2/AVX-512/NEON Accelerators for Beyond-LWE:** Constant-time 512-bit Montgomery field arithmetic (`uint64_t[8]`) for sub-10 ms **CSIDH-512**, bit-sliced Patterson Goppa decoding, AVX2 carryless `PCLMULQDQ` $\mathbb{F}_{2^{127}}$ LRPC multiplication, and constant-time UOV `GF(256)` vectorization.
- **Published Crates, Wheels & NPM Packages:** Reproducible binary wheels (`calyx-openqpep` on PyPI), `openqpep-core` on crates.io, `go/openqpep` Go module tag, and `@calyxlabs/openqpep-wasm` on npm with signed SPDX-2.3 SBOMs.

### `v1.3.0` — Federated Key Transparency & Zero-Trust Directory Gossip
- **Multi-Witness Federated `QPEP-KT` Gossip Protocol:** Independent witness cosigning of Ed448/QVS Signed Tree Heads (STHs) and automated client consistency-proof verification across mirrors to eliminate single-operator trust.
- **DNSSEC / DANE & WKD-Successor Auto-Discovery (`_openqpep.<domain>`):** Zero-configuration verified `.qpkrf` discovery bound to `QPEP-KT` inclusion proofs.

### `v1.5.0` — Formal Cryptographic Verification & Third-Party Audit Readiness
- **Machine-Checked Constant-Time Assembly / Rust Kernels:** Formal constant-time & functional equivalence verification via Jasmin / Vale / HACL* / Kani / Verus for `NTT_3329`, `NTT_8380417`, `CC-512 CMT-4`, and `CSIDH-512`.
- **Full ProVerif & Tamarin Symbolic + CryptoVerif Computational Proofs:** Expanded machine-checked proof suites covering `QPEP-AKE` (bidirectional PQ-XX), `QPEP-Ratchet` (rotating PCS), `QPEP-MLS` (TreeKEM 256-member eviction), and `CSP-Omega` (5-family combiner).
- **Independent External Cryptographic Audit & Public Bug Bounty:** Publication of third-party audit reports and continuous OSS-Fuzz / Atheris / cargo-fuzz harnesses.

### `v2.0.0` — Next-Generation Global Cryptographic Standard
- **IETF / ISO Standardization Track Drafts:** Formal RFC-style specifications for OpenQPEP Wire Format, `.qpkrf` Key Rings, `CC-512 CMT-4`, `QPEP-Ratchet`, `QPEP-MLS`, and `QPEP-KT`.
- **Distributed Threshold Post-Quantum Signing (Threshold-QVS & Threshold-QHS):** True interactive $t$-of-$n$ lattice/hash threshold signatures without ever assembling a full signing key on any single host.
- **Zero-Knowledge Post-Quantum Credentials & Selective Disclosure:** Anonymous enterprise/government attribute credentials built on `LatticeZKProof` and `QVS-Ring`.
- **Hardware-Agnostic Hybrid Agility Governance:** Formal deprecation & algorithm-agility lifecycle framework guaranteeing smooth cryptographic transitions for decades without ever repeating OpenPGP's legacy-algorithm debt.
