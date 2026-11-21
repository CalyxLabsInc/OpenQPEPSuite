"""
QLX Module-LWE & 4-Manifold Coupled Hyper-Tesseract KEM Engine (Production Candidate 1.1.7).
Hardened with branchless ct_cmov Fujisaki-Okamoto implicit rejection and SecretBuffer scrubbing.
"""
import os
from typing import Tuple
from ..constants import QLX_TIERS
from ..exceptions import QPEPSuiteError
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.consttime import ct_eq, ct_cmov
from ..primitives.zeroize import SecretBuffer
from .ntt_3329 import ntt_3329, inv_ntt_3329, ntt_base_mul_3329, poly_add_3329, poly_sub_3329
from .poly_ring import (
    sample_ntt_3329,
    sample_cbd2_3329,
    sample_cbd1_3329,
    byte_encode_12,
    byte_decode_12,
    compress_poly,
    decompress_poly,
)
from .tesseract_coupling import derive_tesseract_manifold_seeds, derive_tesseract_mu_blocks

class QLXEngine:
    """
    Multi-tier Quantum Lattice Exchange (Module-LWE + 4-Manifold Coupled Hyper-Tesseract)
    Engine supporting QLX-768, QLX-1024, QLX-2048, QLX-4096 (Calyx Signature),
    and QLX-16384 (Calyx Hyper-Tesseract, 16,384 dimensions = 4 coupled 4,096-dim manifolds
    with unstructured dense cross-manifold seed coupling).
    """

    @staticmethod
    def _indcpa_enc(ek: bytes, msg32: bytes, coins: bytes, tier: str) -> bytes:
        spec = QLX_TIERS[tier]
        k, du, dv = spec["k"], spec["du"], spec["dv"]
        manifolds = spec.get("manifolds", 1)
        rho = ek[-32:]
        t_hat = [byte_decode_12(ek[384 * i : 384 * (i + 1)]) for i in range(k)]

        if manifolds == 1:
            a_hat = [[sample_ntt_3329(rho, i, j) for j in range(k)] for i in range(k)]
            r_vec = [ntt_3329(sample_cbd2_3329(coins, i)) for i in range(k)]
            e1_vec = [sample_cbd2_3329(coins, k + i) for i in range(k)]
            e2_poly = sample_cbd2_3329(coins, 2 * k)

            u_chunks = []
            for i in range(k):
                acc = [0] * 256
                for j in range(k):
                    acc = poly_add_3329(acc, ntt_base_mul_3329(a_hat[j][i], r_vec[j]))
                u_i = poly_add_3329(inv_ntt_3329(acc), e1_vec[i])
                u_chunks.append(compress_poly(u_i, du))

            v_acc = [0] * 256
            for j in range(k):
                v_acc = poly_add_3329(v_acc, ntt_base_mul_3329(t_hat[j], r_vec[j]))
            v_poly = poly_add_3329(inv_ntt_3329(v_acc), e2_poly)
            m_poly = decompress_poly(msg32, 1)
            v_poly = poly_add_3329(v_poly, m_poly)
            v_bytes = compress_poly(v_poly, dv)
            return b"".join(u_chunks) + v_bytes

        # 4-Manifold Coupled 16,384-Dimensional Calyx Hyper-Tesseract (QLX-16384, k=64, k_m=16)
        k_m = k // manifolds
        h_ek = qsponge_var(b"CALYX-QLX-H-EK|" + ek, 32)
        m_rhos = [
            qsponge_var(b"CALYX-TESSERACT-DENSE-MANIFOLD|" + rho + bytes([m]), 32)
            for m in range(manifolds)
        ]
        mu_blocks = [msg32] + [
            qsponge_var(b"CALYX-TESSERACT-MU|" + msg32 + h_ek + bytes([m]), 32)
            for m in range(1, manifolds)
        ]
        r_vec = [ntt_3329(sample_cbd1_3329(coins, i)) for i in range(k)]
        e1_vec = [sample_cbd1_3329(coins, k + i) for i in range(k)]
        e2_vec = [sample_cbd1_3329(coins, 2 * k + m) for m in range(manifolds)]

        u_chunks = []
        v_chunks = []
        for m in range(manifolds):
            a_m = [[sample_ntt_3329(m_rhos[m], i, j) for j in range(k_m)] for i in range(k_m)]
            base = m * k_m
            for i in range(k_m):
                acc = [0] * 256
                for j in range(k_m):
                    acc = poly_add_3329(acc, ntt_base_mul_3329(a_m[j][i], r_vec[base + j]))
                u_i = poly_add_3329(inv_ntt_3329(acc), e1_vec[base + i])
                u_chunks.append(compress_poly(u_i, du))
            v_acc = [0] * 256
            for j in range(k_m):
                v_acc = poly_add_3329(v_acc, ntt_base_mul_3329(t_hat[base + j], r_vec[base + j]))
            v_m = poly_add_3329(inv_ntt_3329(v_acc), e2_vec[m])
            v_m = poly_add_3329(v_m, decompress_poly(mu_blocks[m], 1))
            v_chunks.append(compress_poly(v_m, dv))
        return b"".join(u_chunks) + b"".join(v_chunks)

    @staticmethod
    def keygen(tier: str = "QLX-4096", policy_witness: bytes = b"") -> Tuple[bytes, bytes]:
        if len(policy_witness) != 64:
            raise ValueError("QLX key generation requires a 64-byte QPKD-Argon2id passphrase policy witness.")
        spec = QLX_TIERS.get(tier, QLX_TIERS["QLX-4096"])
        k = spec["k"]
        manifolds = spec.get("manifolds", 1)

        seed_d = os.urandom(32)
        seed_z = os.urandom(32)
        g_out = qsponge_512(b"CALYX-QLX-KEYGEN|" + tier.encode("ascii") + seed_d + policy_witness)
        rho, sigma = g_out[:32], g_out[32:]

        if manifolds == 1:
            a_hat = [[sample_ntt_3329(rho, i, j) for j in range(k)] for i in range(k)]
            s_hat = [ntt_3329(sample_cbd2_3329(sigma, i)) for i in range(k)]
            e_hat = [ntt_3329(sample_cbd2_3329(sigma, k + i)) for i in range(k)]
            t_hat = []
            for i in range(k):
                acc = [0] * 256
                for j in range(k):
                    acc = poly_add_3329(acc, ntt_base_mul_3329(a_hat[i][j], s_hat[j]))
                t_hat.append(poly_add_3329(acc, e_hat[i]))
        else:
            k_m = k // manifolds
            m_rhos = [
                qsponge_var(b"CALYX-TESSERACT-DENSE-MANIFOLD|" + rho + bytes([m]), 32)
                for m in range(manifolds)
            ]
            s_hat = [ntt_3329(sample_cbd1_3329(sigma, i)) for i in range(k)]
            e_hat = [ntt_3329(sample_cbd1_3329(sigma, k + i)) for i in range(k)]
            t_hat = []
            for m in range(manifolds):
                a_m = [[sample_ntt_3329(m_rhos[m], i, j) for j in range(k_m)] for i in range(k_m)]
                base = m * k_m
                for i in range(k_m):
                    acc = [0] * 256
                    for j in range(k_m):
                        acc = poly_add_3329(acc, ntt_base_mul_3329(a_m[i][j], s_hat[base + j]))
                    t_hat.append(poly_add_3329(acc, e_hat[base + i]))

        ek = b"".join(byte_encode_12(p) for p in t_hat) + rho
        s_bytes = b"".join(byte_encode_12(p) for p in s_hat)
        h_ek = qsponge_var(b"CALYX-QLX-H-EK|" + ek, 32)
        dk = s_bytes + ek + h_ek + seed_z
        return ek, dk

    @staticmethod
    def encaps(ek: bytes, tier: str = "QLX-4096") -> Tuple[bytes, bytes]:
        spec = QLX_TIERS.get(tier, QLX_TIERS["QLX-4096"])
        if len(ek) != spec["pk_bytes"]:
            raise QPEPSuiteError(f"Invalid {tier} public key length: {len(ek)}")

        msg32 = os.urandom(32)
        h_ek = qsponge_var(b"CALYX-QLX-H-EK|" + ek, 32)
        kr = qsponge_512(b"CALYX-QLX-FO-G|" + msg32 + h_ek)
        k_shared, r_coins = kr[:32], kr[32:]
        ct = QLXEngine._indcpa_enc(ek, msg32, r_coins, tier)
        return ct, k_shared

    @staticmethod
    def decaps(dk: bytes, ct: bytes, tier: str = "QLX-4096") -> bytes:
        spec = QLX_TIERS.get(tier, QLX_TIERS["QLX-4096"])
        k, du, dv = spec["k"], spec["du"], spec["dv"]
        manifolds = spec.get("manifolds", 1)
        pk_len, sk_len, ct_len = spec["pk_bytes"], spec["sk_bytes"], spec["ct_bytes"]
        if len(dk) != sk_len or len(ct) != ct_len:
            raise QPEPSuiteError(f"Invalid {tier} secret key or ciphertext length.")

        s_bytes_len = 384 * k
        with SecretBuffer(dk) as dk_buf:
            raw_dk = dk_buf.raw
            s_hat = [byte_decode_12(bytes(raw_dk[384 * i : 384 * (i + 1)])) for i in range(k)]
            ek = bytes(raw_dk[s_bytes_len : s_bytes_len + pk_len])
            h_ek = bytes(raw_dk[s_bytes_len + pk_len : s_bytes_len + pk_len + 32])
            seed_z = bytes(raw_dk[s_bytes_len + pk_len + 32 :])

        u_step = 32 * du
        v_step = 32 * dv
        u_vec = [decompress_poly(ct[i * u_step : (i + 1) * u_step], du) for i in range(k)]
        v_poly0 = decompress_poly(ct[k * u_step : k * u_step + v_step], dv)

        k_m = k // manifolds
        su_hat = [0] * 256
        for j in range(k_m):
            su_hat = poly_add_3329(su_hat, ntt_base_mul_3329(s_hat[j], ntt_3329(u_vec[j])))
        w_poly = poly_sub_3329(v_poly0, inv_ntt_3329(su_hat))
        m_prime = compress_poly(w_poly, 1)

        # Full Fujisaki-Okamoto CCA2 re-encryption check across all k polynomials & manifolds
        kr_prime = qsponge_512(b"CALYX-QLX-FO-G|" + m_prime + h_ek)
        k_candidate, r_prime = kr_prime[:32], kr_prime[32:]
        ct_prime = QLXEngine._indcpa_enc(ek, m_prime, r_prime, tier)

        # Branchless constant-time Fujisaki-Okamoto implicit-rejection multiplexing:
        # Both candidate and rejection keys are always computed and selected via ct_cmov.
        k_reject = qsponge_var(b"CALYX-QLX-FO-REJECT|" + seed_z + ct, 32)
        is_valid = ct_eq(ct, ct_prime)
        return ct_cmov(is_valid, k_candidate, k_reject)

