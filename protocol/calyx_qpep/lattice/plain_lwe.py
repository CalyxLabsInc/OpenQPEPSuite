"""
Family 1 of Calyx Sovereign-Pentad (CSP-Omega): Pure Unstructured Plain-LWE (CULC-2048 — Official Release 1.1.0).
Zero cyclotomic polynomial ring, zero NTT, zero Galois symmetry.
Row-streams unstructured matrix A in Z_{65536}^{n x n} from qSponge-XOF with Fujisaki-Okamoto
IND-CCA2 re-encryption verification and branchless ct_cmov implicit rejection.
"""
import os
import struct
from typing import List, Tuple

from ..native.loader import native_plain_lwe_keygen_row, native_plain_lwe_row_accum
from ..primitives.consttime import ct_cmov, ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

PLAIN_LWE_Q = 65536  # 2^16


def _sample_centered_noise(seed: bytes, count: int, domain: bytes) -> List[int]:
    raw = qsponge_var(domain + seed, count)
    out = []
    for b in raw:
        a = ((b >> 0) & 1) + ((b >> 1) & 1)
        c = ((b >> 2) & 1) + ((b >> 3) & 1)
        out.append((a - c) % PLAIN_LWE_Q)
    return out


def _expand_row(seed_a: bytes, row_idx: int, n: int) -> List[int]:
    raw = qsponge_var(b"CALYX-PLAIN-LWE-ROW-v1.0.0|" + seed_a + struct.pack(">I", row_idx), 2 * n)
    return list(struct.unpack(f"<{n}H", raw))


class PlainLWEEngine:
    """Unstructured Plain-LWE KEM (zero ring ideal / zero NTT structure)."""

    @staticmethod
    def keygen(n: int = 64, nbar: int = 8) -> Tuple[bytes, bytes]:
        seed_a = os.urandom(32)
        seed_s = os.urandom(32)
        seed_z = os.urandom(32)

        with SecretBuffer(seed_s) as ss_buf:
            s_flat = _sample_centered_noise(ss_buf.as_bytes(), n * nbar, b"CALYX-PLWE-S-v1.0.0|")
            e_flat = _sample_centered_noise(ss_buf.as_bytes(), n * nbar, b"CALYX-PLWE-E-v1.0.0|")

        b_flat = [0] * (n * nbar)
        for i in range(n):
            row = _expand_row(seed_a, i, n)
            e_row = e_flat[i * nbar : (i + 1) * nbar]
            native_row = native_plain_lwe_keygen_row(e_row, row, s_flat, n, nbar)
            if native_row is not None:
                b_flat[i * nbar : (i + 1) * nbar] = native_row
            else:
                for j in range(nbar):
                    acc = e_flat[i * nbar + j]
                    for k in range(n):
                        acc = (acc + row[k] * s_flat[k * nbar + j]) & 0xFFFF
                    b_flat[i * nbar + j] = acc

        pk = struct.pack("<HH", n, nbar) + seed_a + struct.pack(f"<{n * nbar}H", *b_flat)
        sk = struct.pack("<HH", n, nbar) + seed_z + pk + struct.pack(f"<{n * nbar}H", *s_flat)
        return pk, sk

    @staticmethod
    def _indcpa_enc(pk: bytes, msg16: bytes, coins: bytes) -> bytes:
        n, nbar = struct.unpack("<HH", pk[:4])
        seed_a = pk[4:36]
        b_flat = list(struct.unpack(f"<{n * nbar}H", pk[36:]))

        sp = _sample_centered_noise(coins, nbar * n, b"CALYX-PLWE-SP-v1.0.0|")
        ep = _sample_centered_noise(coins, nbar * n, b"CALYX-PLWE-EP-v1.0.0|")
        epp = _sample_centered_noise(coins, nbar * nbar, b"CALYX-PLWE-EPP-v1.0.0|")

        u_flat = list(ep)
        for k in range(n):
            row = _expand_row(seed_a, k, n)
            for i in range(nbar):
                s_ik = sp[i * n + k]
                base = i * n
                native_u = native_plain_lwe_row_accum(u_flat[base : base + n], row, s_ik)
                if native_u is not None:
                    u_flat[base : base + n] = native_u
                else:
                    for j in range(n):
                        u_flat[base + j] = (u_flat[base + j] + s_ik * row[j]) & 0xFFFF

        v_flat = [0] * (nbar * nbar)
        for i in range(nbar):
            for j in range(nbar):
                acc = epp[i * nbar + j]
                for k in range(n):
                    acc = (acc + sp[i * n + k] * b_flat[k * nbar + j]) & 0xFFFF
                bit_pos = (i * nbar + j) * 2
                byte_val = msg16[bit_pos // 8]
                two_bits = (byte_val >> (bit_pos % 8)) & 0x03
                v_flat[i * nbar + j] = (acc + (two_bits << 14)) & 0xFFFF

        return struct.pack(f"<{nbar * n}H", *u_flat) + struct.pack(f"<{nbar * nbar}H", *v_flat)

    @staticmethod
    def encaps(pk: bytes) -> Tuple[bytes, bytes]:
        msg16 = os.urandom(16)
        h_pk = qsponge_var(b"CALYX-PLWE-HPK-v1.0.0|" + pk, 32)
        kr = qsponge_512(b"CALYX-PLWE-FO-G-v1.0.0|" + msg16 + h_pk)
        ss, coins = kr[:32], kr[32:]
        ct = PlainLWEEngine._indcpa_enc(pk, msg16, coins)
        return ct, ss

    @staticmethod
    def decaps(sk: bytes, ct: bytes) -> bytes:
        with SecretBuffer(sk) as sk_buf:
            raw = sk_buf.as_bytes()
            n, nbar = struct.unpack("<HH", raw[:4])
            seed_z = raw[4:36]
            pk_len = 4 + 32 + 2 * n * nbar
            pk = raw[36 : 36 + pk_len]
            s_flat = list(struct.unpack(f"<{n * nbar}H", raw[36 + pk_len :]))

        u_len = 2 * nbar * n
        u_flat = list(struct.unpack(f"<{nbar * n}H", ct[:u_len]))
        v_flat = list(struct.unpack(f"<{nbar * nbar}H", ct[u_len:]))

        msg_bits = bytearray(16)
        for i in range(nbar):
            for j in range(nbar):
                us = 0
                for k in range(n):
                    us = (us + u_flat[i * n + k] * s_flat[k * nbar + j]) & 0xFFFF
                w = (v_flat[i * nbar + j] - us) & 0xFFFF
                two_bits = ((w + (1 << 13)) >> 14) & 0x03
                bit_pos = (i * nbar + j) * 2
                msg_bits[bit_pos // 8] |= (two_bits << (bit_pos % 8))

        m_prime = bytes(msg_bits)
        h_pk = qsponge_var(b"CALYX-PLWE-HPK-v1.0.0|" + pk, 32)
        kr_prime = qsponge_512(b"CALYX-PLWE-FO-G-v1.0.0|" + m_prime + h_pk)
        k_cand, r_prime = kr_prime[:32], kr_prime[32:]
        ct_prime = PlainLWEEngine._indcpa_enc(pk, m_prime, r_prime)
        k_reject = qsponge_var(b"CALYX-PLWE-FO-REJECT-v1.0.0|" + seed_z + ct, 32)
        return ct_cmov(ct_eq(ct, ct_prime), k_cand, k_reject)
