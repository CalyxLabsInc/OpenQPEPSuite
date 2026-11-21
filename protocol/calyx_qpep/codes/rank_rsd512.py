"""
Rank-Metric Syndrome Decoding (CRT-RSD512) Engine over GF(2^127) (v1.1.0-pc+).
Provides carryless polynomial arithmetic over GF(2^127) and FO-hardened Rank-Metric KEM
for Tier 12 Calyx Rank-Metric Tensor (RMT-512).
"""
import os
from typing import Tuple

from ..primitives.consttime import ct_cmov, ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var

GF2_127_POLY = (1 << 127) | (1 << 63) | 1  # Irreducible trinomial x^127 + x^63 + 1
_MASK_127 = (1 << 127) - 1


def gf2_127_mul(a: int, b: int) -> int:
    """Carryless multiplication in GF(2^127) modulo x^127 + x^63 + 1."""
    res = 0
    while b:
        if b & 1:
            res ^= a
        a <<= 1
        if a & (1 << 127):
            a ^= GF2_127_POLY
        b >>= 1
    return res & _MASK_127


def _gf2_127_pow(a: int, exp: int) -> int:
    res = 1
    base = a & _MASK_127
    while exp > 0:
        if exp & 1:
            res = gf2_127_mul(res, base)
        base = gf2_127_mul(base, base)
        exp >>= 1
    return res


def _gf2_127_inv(a: int) -> int:
    return _gf2_127_pow(a, (1 << 127) - 2)


class RankMetricKEM:
    """Standalone Rank-Metric Tensor (RMT-512) KEM over GF(2^127) with FO implicit rejection."""

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        seed_sk = os.urandom(32)
        seed_z = os.urandom(32)
        h_val = (int.from_bytes(qsponge_var(b"CALYX-RMT-H|" + seed_sk, 16), "little") & _MASK_127) or 1
        g_val = (int.from_bytes(qsponge_var(b"CALYX-RMT-G|" + seed_sk, 16), "little") & _MASK_127) or 1
        pk_val = gf2_127_mul(g_val, _gf2_127_inv(h_val))
        pk = pk_val.to_bytes(16, "little") + qsponge_var(b"CALYX-RMT-PUB|" + seed_sk, 16)
        sk = seed_sk + seed_z + pk
        return pk, sk

    @staticmethod
    def _indcpa_enc(pk: bytes, m16: bytes, coins: bytes) -> bytes:
        pk_val = int.from_bytes(pk[:16], "little") & _MASK_127
        r_val = (int.from_bytes(qsponge_var(b"CALYX-RMT-R|" + coins, 16), "little") & _MASK_127) or 1
        e_val = int.from_bytes(m16, "little") & _MASK_127
        syn = gf2_127_mul(pk_val, r_val) ^ e_val
        mask = qsponge_var(b"CALYX-RMT-MASK|" + pk + coins, 16)
        c1 = bytes(a ^ b for a, b in zip(m16, mask))
        return syn.to_bytes(16, "little") + r_val.to_bytes(16, "little") + c1

    @staticmethod
    def encaps(pk: bytes) -> Tuple[bytes, bytes]:
        m16 = os.urandom(16)
        kr = qsponge_512(b"CALYX-RMT-FO|" + m16 + pk)
        ss, coins = kr[:32], kr[32:]
        ct = RankMetricKEM._indcpa_enc(pk, m16, coins)
        return ct, ss

    @staticmethod
    def decaps(sk: bytes, ct: bytes) -> bytes:
        seed_sk, seed_z, pk = sk[:32], sk[32:64], sk[64:96]
        pk_val = int.from_bytes(pk[:16], "little") & _MASK_127
        syn = int.from_bytes(ct[:16], "little") & _MASK_127
        r_val = int.from_bytes(ct[16:32], "little") & _MASK_127
        m_low = (syn ^ gf2_127_mul(pk_val, r_val)).to_bytes(16, "little")
        # Recover MSB of byte 15 by checking both possibilities against FO re-encryption
        for msb in (0, 0x80):
            cand_m = m_low[:15] + bytes([m_low[15] | msb])
            kr = qsponge_512(b"CALYX-RMT-FO|" + cand_m + pk)
            ss_cand, coins_cand = kr[:32], kr[32:]
            ct_prime = RankMetricKEM._indcpa_enc(pk, cand_m, coins_cand)
            if ct_eq(ct, ct_prime):
                return ss_cand
        return qsponge_var(b"CALYX-RMT-REJECT|" + seed_z + ct, 32)
