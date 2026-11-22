"""
QVS Lattice Fiat-Shamir with Aborts Signature Engine over Z_8380417[X]/(X^256+1) (Official Release 1.0.0).
Hardened with Verify-Before-Emit Fault-Guard (QPEPFaultGuardError) and SecretBuffer scrubbing.
"""
import os
from typing import Tuple

from ..constants import QVS_GAMMA1, QVS_GAMMA2, QVS_Q, QVS_TIERS
from ..exceptions import QPEPFaultGuardError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_var
from ..primitives.zeroize import SecretBuffer
from .ntt_8380417 import center_qvs, decompose_qvs, inv_ntt_qvs, ntt_qvs
from .poly_ring import (
    pack_poly24_qvs,
    sample_eta_qvs,
    sample_in_ball_qvs,
    sample_mask_y_qvs,
    sample_ntt_qvs,
    unpack_poly24_qvs,
)


class QVSEngine:
    """
    Multi-tier Quantum Vector Signature (Lattice Fiat-Shamir with Aborts) Engine
    supporting QVS-65, QVS-87, QVS-128, QVS-256, and QVS-1024 over R_Q = Z_8380417[X]/(X^256 + 1).
    """

    @staticmethod
    def keygen(tier: str = "QVS-256", policy_witness: bytes = b"") -> Tuple[bytes, bytes]:
        if len(policy_witness) != 64:
            raise ValueError("QVS key generation requires a 64-byte QPKD-Argon2id passphrase policy witness.")
        spec = QVS_TIERS.get(tier, QVS_TIERS["QVS-256"])
        k, l = spec["k"], spec["l"]

        seed_xi = os.urandom(32)
        with SecretBuffer(
            qsponge_var(b"CALYX-QVS-KEYGEN-v1.0.0|" + tier.encode("ascii") + seed_xi + policy_witness, 128)
        ) as exp_buf:
            expanded = exp_buf.as_bytes()
            rho, rho_prime, k_sign = expanded[:32], expanded[32:96], expanded[96:128]

            a_hat = [[sample_ntt_qvs(rho, i, j) for j in range(l)] for i in range(k)]
            s1 = [sample_eta_qvs(rho_prime, j) for j in range(l)]
            s2 = [sample_eta_qvs(rho_prime, l + i) for i in range(k)]
            s1_hat = [ntt_qvs(p) for p in s1]

            t_vec = []
            for i in range(k):
                acc = [0] * 256
                for j in range(l):
                    acc = [(acc[m] + a_hat[i][j][m] * s1_hat[j][m]) % QVS_Q for m in range(256)]
                t_i = [(inv_ntt_qvs(acc)[m] + s2[i][m]) % QVS_Q for m in range(256)]
                t_vec.append(t_i)

            t_bytes = b"".join(pack_poly24_qvs(p) for p in t_vec)
            pk = rho + t_bytes
            tr = qsponge_var(b"CALYX-QVS-TR-v1.0.0|" + pk, 64)

            s1_bytes = b"".join(bytes((center_qvs(c) + 2) & 0xFF for c in p) for p in s1)
            s2_bytes = b"".join(bytes((center_qvs(c) + 2) & 0xFF for c in p) for p in s2)
            sk = rho + k_sign + tr + s1_bytes + s2_bytes + t_bytes
            return pk, sk

    @staticmethod
    def sign(sk: bytes, pk: bytes, message: bytes, tier: str = "QVS-256") -> bytes:
        spec = QVS_TIERS.get(tier, QVS_TIERS["QVS-256"])
        k, l, tau, beta = spec["k"], spec["l"], spec["tau"], spec["beta"]
        if len(sk) != spec["sk_bytes"] or len(pk) != spec["pk_bytes"]:
            raise ValueError(f"Invalid {tier} key sizes.")

        with SecretBuffer(sk) as sk_buf:
            raw_sk = sk_buf.as_bytes()
            rho = raw_sk[:32]
            k_sign = raw_sk[32:64]
            tr = raw_sk[64:128]
            off = 128
            s1 = []
            for _ in range(l):
                chunk = raw_sk[off : off + 256]
                off += 256
                s1.append([((b - 2) % QVS_Q) for b in chunk])
            s2 = []
            for _ in range(k):
                chunk = raw_sk[off : off + 256]
                off += 256
                s2.append([((b - 2) % QVS_Q) for b in chunk])
            t_bytes = raw_sk[off:]

            if not ct_eq(pk, rho + t_bytes):
                raise ValueError(f"{tier} secret key does not match public key.")

            a_hat = [[sample_ntt_qvs(rho, i, j) for j in range(l)] for i in range(k)]
            s1_hat = [ntt_qvs(p) for p in s1]
            s2_hat = [ntt_qvs(p) for p in s2]

            mu = qsponge_var(b"CALYX-QVS-MU-v1.0.0|" + tr + message, 64)
            rho_double_prime = qsponge_var(b"CALYX-QVS-RNDS-v1.0.0|" + k_sign + mu, 64)

        nonce = 0
        while True:
            y_vec = [sample_mask_y_qvs(rho_double_prime, nonce + j) for j in range(l)]
            nonce += l
            y_hat = [ntt_qvs(p) for p in y_vec]

            w_vec = []
            w1_bytes = bytearray()
            for i in range(k):
                acc = [0] * 256
                for j in range(l):
                    acc = [(acc[m] + a_hat[i][j][m] * y_hat[j][m]) % QVS_Q for m in range(256)]
                w_i = inv_ntt_qvs(acc)
                w_vec.append(w_i)
                for coeff in w_i:
                    w1_c, _ = decompose_qvs(coeff)
                    w1_bytes.append(w1_c & 0xFF)

            c_tilde = qsponge_var(b"CALYX-QVS-CHALLENGE-v1.0.0|" + mu + bytes(w1_bytes), 64)
            c_poly = sample_in_ball_qvs(c_tilde, tau)
            c_hat = ntt_qvs(c_poly)

            z_vec = []
            reject = False
            for j in range(l):
                cs1 = inv_ntt_qvs([(c_hat[m] * s1_hat[j][m]) % QVS_Q for m in range(256)])
                z_j = [(y_vec[j][m] + cs1[m]) % QVS_Q for m in range(256)]
                for coeff in z_j:
                    if abs(center_qvs(coeff)) >= QVS_GAMMA1 - beta:
                        reject = True
                        break
                if reject:
                    break
                z_vec.append(z_j)
            if reject:
                continue

            w1_idx = 0
            for i in range(k):
                cs2 = inv_ntt_qvs([(c_hat[m] * s2_hat[i][m]) % QVS_Q for m in range(256)])
                for m in range(256):
                    diff = (w_vec[i][m] - cs2[m]) % QVS_Q
                    r1, r0 = decompose_qvs(diff)
                    if abs(r0) >= QVS_GAMMA2 - beta or r1 != w1_bytes[w1_idx]:
                        reject = True
                        break
                    w1_idx += 1
                if reject:
                    break
            if reject:
                continue

            z_packed = b"".join(pack_poly24_qvs(p) for p in z_vec)
            sig_out = c_tilde + z_packed
            if not QVSEngine.verify(pk, message, sig_out, tier=tier):
                raise QPEPFaultGuardError("QVS Fault-Injection Guard triggered: signature failed internal verification.")
            return sig_out

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes, tier: str = "QVS-256") -> bool:
        spec = QVS_TIERS.get(tier, QVS_TIERS["QVS-256"])
        k, l, tau, beta = spec["k"], spec["l"], spec["tau"], spec["beta"]
        if len(pk) != spec["pk_bytes"] or len(signature) != spec["sig_bytes"]:
            return False

        rho = pk[:32]
        t_vec = [unpack_poly24_qvs(pk[32 + 768 * i : 32 + 768 * (i + 1)]) for i in range(k)]
        c_tilde = signature[:64]
        z_vec = [unpack_poly24_qvs(signature[64 + 768 * j : 64 + 768 * (j + 1)]) for j in range(l)]

        for z_j in z_vec:
            for coeff in z_j:
                if abs(center_qvs(coeff)) >= QVS_GAMMA1 - beta:
                    return False

        a_hat = [[sample_ntt_qvs(rho, i, j) for j in range(l)] for i in range(k)]
        z_hat = [ntt_qvs(p) for p in z_vec]
        t_hat = [ntt_qvs(p) for p in t_vec]
        c_poly = sample_in_ball_qvs(c_tilde, tau)
        c_hat = ntt_qvs(c_poly)

        w1_prime_bytes = bytearray()
        for i in range(k):
            az_hat = [0] * 256
            for j in range(l):
                az_hat = [(az_hat[m] + a_hat[i][j][m] * z_hat[j][m]) % QVS_Q for m in range(256)]
            ct_hat = [(c_hat[m] * t_hat[i][m]) % QVS_Q for m in range(256)]
            w_prime_i = inv_ntt_qvs([(az_hat[m] - ct_hat[m]) % QVS_Q for m in range(256)])
            for coeff in w_prime_i:
                r1, _ = decompose_qvs(coeff)
                w1_prime_bytes.append(r1 & 0xFF)

        tr = qsponge_var(b"CALYX-QVS-TR-v1.0.0|" + pk, 64)
        mu = qsponge_var(b"CALYX-QVS-MU-v1.0.0|" + tr + message, 64)
        expected_c_tilde = qsponge_var(b"CALYX-QVS-CHALLENGE-v1.0.0|" + mu + bytes(w1_prime_bytes), 64)
        return ct_eq(c_tilde, expected_c_tilde)
