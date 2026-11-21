"""
Shamir Secret Sharing over GF(2^8) (AES Irreducible Polynomial x^8 + x^4 + x^3 + x + 1 = 0x11B).
Information-theoretic security: any t shares reconstruct the exact secret; t-1 shares reveal 0 bits.
"""
import os
from typing import List, Sequence, Tuple

GF256_POLY = 0x11B


def gf256_mul(a: int, b: int) -> int:
    """Finite-field multiplication in GF(256) modulo 0x11B."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def gf256_pow(a: int, exp: int) -> int:
    res = 1
    base = a
    while exp > 0:
        if exp & 1:
            res = gf256_mul(res, base)
        base = gf256_mul(base, base)
        exp >>= 1
    return res


def gf256_inv(a: int) -> int:
    """Multiplicative inverse in GF(256) via Fermat's Little Theorem (a^254)."""
    if a == 0:
        raise ZeroDivisionError("0 has no multiplicative inverse in GF(256).")
    return gf256_pow(a, 254)


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    y = 0
    for c in reversed(coeffs):
        y = gf256_mul(y, x) ^ c
    return y


def split_secret(secret: bytes, threshold: int, total_shares: int) -> List[Tuple[int, bytes]]:
    """
    Splits `secret` into `total_shares` (n) shares requiring `threshold` (t) shares to reconstruct.
    Constraints: 2 <= t <= n <= 255.
    """
    if not secret:
        raise ValueError("Secret must be non-empty.")
    if threshold < 2 or total_shares < threshold or total_shares > 255:
        raise ValueError("Shamir parameters must satisfy 2 <= threshold <= total_shares <= 255.")

    out = [bytearray(len(secret)) for _ in range(total_shares)]
    for byte_idx, s_byte in enumerate(secret):
        rand_coeffs = os.urandom(threshold - 1)
        coeffs = [s_byte] + list(rand_coeffs)
        for share_idx in range(total_shares):
            x = share_idx + 1
            out[share_idx][byte_idx] = _eval_poly(coeffs, x)

    return [(i + 1, bytes(out[i])) for i in range(total_shares)]


def reconstruct_secret(shares: Sequence[Tuple[int, bytes]]) -> bytes:
    """Reconstructs the secret via Lagrange interpolation at x = 0 over GF(256)."""
    if len(shares) < 2:
        raise ValueError("At least 2 shares are required for reconstruction.")
    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs) or any(x < 1 or x > 255 for x in xs):
        raise ValueError("Share indices x must be unique integers in 1..255.")
    secret_len = len(shares[0][1])
    if any(len(s[1]) != secret_len for s in shares):
        raise ValueError("All shares must have identical byte length.")

    # Precompute Lagrange basis coefficients lambda_i(0)
    lambdas: List[int] = []
    k = len(shares)
    for i in range(k):
        num = 1
        den = 1
        xi = xs[i]
        for j in range(k):
            if i == j:
                continue
            xj = xs[j]
            num = gf256_mul(num, xj)
            den = gf256_mul(den, xi ^ xj)
        lambdas.append(gf256_mul(num, gf256_inv(den)))

    recovered = bytearray(secret_len)
    for byte_idx in range(secret_len):
        val = 0
        for i in range(k):
            val ^= gf256_mul(shares[i][1][byte_idx], lambdas[i])
        recovered[byte_idx] = val
    return bytes(recovered)
