# OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc)
"""
8-Layer Complete Number Theoretic Transform & HighBits/LowBits Decomposition over Z_8380417[X]/(X^256+1).
Automatically dispatches through libopenqpep (C99/AVX2/NEON) when available, with
bit-exact pure-Python fallback.
"""
from typing import List, Tuple
from ..constants import QVS_Q, QVS_ZETA, QVS_GAMMA2, QVS_ALPHA
from ..native.loader import native_inv_ntt_qvs, native_ntt_qvs

def _bitrev8(x: int) -> int:
    r = 0
    for _ in range(8):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


_ZETAS_QVS = [pow(QVS_ZETA, _bitrev8(i), QVS_Q) for i in range(256)]
_INV_256_QVS = pow(256, QVS_Q - 2, QVS_Q)


def ntt_qvs(poly: List[int]) -> List[int]:
    """Forward 8-layer complete NTT in Z_8380417[X]/(X^256 + 1)."""
    res = native_ntt_qvs(poly)
    if res is not None:
        return res
    p = list(poly)
    k = 0
    length = 128
    while length >= 1:
        for start in range(0, 256, 2 * length):
            k += 1
            zeta = _ZETAS_QVS[k]
            for j in range(start, start + length):
                t = (zeta * p[j + length]) % QVS_Q
                p[j + length] = (p[j] - t) % QVS_Q
                p[j] = (p[j] + t) % QVS_Q
        length >>= 1
    return p


def inv_ntt_qvs(poly_hat: List[int]) -> List[int]:
    """Inverse 8-layer complete NTT in Z_8380417[X]/(X^256 + 1)."""
    res = native_inv_ntt_qvs(poly_hat)
    if res is not None:
        return res
    p = list(poly_hat)
    k = 256
    length = 1
    while length < 256:
        for start in range(0, 256, 2 * length):
            k -= 1
            zeta = QVS_Q - _ZETAS_QVS[k]
            for j in range(start, start + length):
                t = p[j]
                p[j] = (t + p[j + length]) % QVS_Q
                p[j + length] = (zeta * (t - p[j + length])) % QVS_Q
        length <<= 1
    return [(x * _INV_256_QVS) % QVS_Q for x in p]


def center_qvs(x: int) -> int:
    x %= QVS_Q
    return x - QVS_Q if x > QVS_Q // 2 else x


def decompose_qvs(r: int) -> Tuple[int, int]:
    """Decomposes r mod Q into (r1, r0) such that r == r1 * (2*gamma2) + r0 (mod Q)."""
    r %= QVS_Q
    r0 = r % QVS_ALPHA
    if r0 > QVS_GAMMA2:
        r0 -= QVS_ALPHA
    if r - r0 == QVS_Q - 1:
        return 0, r0 - 1
    return (r - r0) // QVS_ALPHA, r0
