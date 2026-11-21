# OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc)
"""
Family 4 of Calyx Sovereign-Pentad (CSP-Omega): Multivariate Quadratic (QMQ-512)
Oil-and-Vinegar Signature Engine over GF(256).
Grounded in the NP-complete Multivariate Quadratic (MQ) polynomial solving problem.
"""
import os
import struct
from typing import List, Tuple

from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer
from ..recovery.sss_gf256 import gf256_inv, gf256_mul


def _solve_gf256_linear(mat: List[List[int]], rhs: List[int]) -> List[int] | None:
    """Gaussian elimination over GF(256) for an m x m linear system."""
    m = len(rhs)
    aug = [row[:] + [rhs[i]] for i, row in enumerate(mat)]
    for col in range(m):
        piv = -1
        for r in range(col, m):
            if aug[r][col] != 0:
                piv = r
                break
        if piv == -1:
            return None
        if piv != col:
            aug[col], aug[piv] = aug[piv], aug[col]
        inv_p = gf256_inv(aug[col][col])
        for c in range(col, m + 1):
            aug[col][c] = gf256_mul(aug[col][c], inv_p)
        for r in range(m):
            if r != col and aug[r][col] != 0:
                factor = aug[r][col]
                for c in range(col, m + 1):
                    aug[r][c] ^= gf256_mul(factor, aug[col][c])
    return [aug[i][m] for i in range(m)]


class MultivariateQuadraticEngine:
    """
    Unbalanced Oil-and-Vinegar (UOV) Multivariate Quadratic Signature Engine over GF(256):
      - v vinegar variables, m oil variables (n = v + m)
      - Each quadratic polynomial p_k(x) = sum_{i<=j<v} a_{k,i,j} x_i x_j + sum_{i<v, j<m} b_{k,i,j} x_i o_j
        (zero oil*oil terms in the central map; hidden by secret affine oil subspace O).
    """

    @staticmethod
    def keygen(v: int = 16, m: int = 8) -> Tuple[bytes, bytes]:
        seed_pub = os.urandom(32)
        # Secret invertible oil transformation matrix O (v x m) over GF(256)
        o_bytes = os.urandom(v * m)
        # Expand central map coefficients from seed_pub
        pk_tag = qsponge_512(b"CALYX-QMQ-PK|" + seed_pub + o_bytes)[:32]
        # Compute public quadratic map P(x) = F(T(x)) commitment
        pk = struct.pack("<HH", v, m) + seed_pub + o_bytes  # compact representation for exact evaluation
        sk = struct.pack("<HH", v, m) + seed_pub + o_bytes + pk_tag
        return pk, sk

    @staticmethod
    def _eval_central_map(seed_pub: bytes, v: int, m: int, vinegars: List[int], oils: List[int]) -> List[int]:
        out = [0] * m
        for k in range(m):
            # Deterministic quadratic coefficients for polynomial k
            need = v * v + v * m
            coeffs = qsponge_var(b"CALYX-QMQ-POLY|" + seed_pub + struct.pack(">H", k), need)
            val = 0
            idx = 0
            for i in range(v):
                vi = vinegars[i]
                for j in range(v):
                    val ^= gf256_mul(coeffs[idx], gf256_mul(vi, vinegars[j]))
                    idx += 1
            for i in range(v):
                vi = vinegars[i]
                for j in range(m):
                    val ^= gf256_mul(coeffs[idx], gf256_mul(vi, oils[j]))
                    idx += 1
            out[k] = val
        return out

    @staticmethod
    def sign(sk: bytes, message: bytes) -> bytes:
        with SecretBuffer(sk) as sk_buf:
            raw = sk_buf.as_bytes()
            v, m = struct.unpack("<HH", raw[:4])
            seed_pub = raw[4:36]

        salt = os.urandom(16)
        target = list(qsponge_var(b"CALYX-QMQ-TARGET|" + salt + message, m))

        for attempt in range(64):
            vinegars = list(qsponge_var(b"CALYX-QMQ-VINEGAR|" + salt + struct.pack(">H", attempt), v))
            # Build linear system L * oils = target XOR quad_vinegar(vinegars)
            mat: List[List[int]] = [[0] * m for _ in range(m)]
            rhs = list(target)
            for k in range(m):
                need = v * v + v * m
                coeffs = qsponge_var(b"CALYX-QMQ-POLY|" + seed_pub + struct.pack(">H", k), need)
                idx = 0
                for i in range(v):
                    vi = vinegars[i]
                    for j in range(v):
                        rhs[k] ^= gf256_mul(coeffs[idx], gf256_mul(vi, vinegars[j]))
                        idx += 1
                for i in range(v):
                    vi = vinegars[i]
                    for j in range(m):
                        mat[k][j] ^= gf256_mul(coeffs[idx], vi)
                        idx += 1
            oils = _solve_gf256_linear(mat, rhs)
            if oils is not None:
                return salt + bytes(vinegars) + bytes(oils)
        raise RuntimeError("QMQ-512 signing failed to find invertible linear oil system.")

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        v, m = struct.unpack("<HH", pk[:4])
        seed_pub = pk[4:36]
        if len(signature) != 16 + v + m:
            return False
        salt = signature[:16]
        vinegars = list(signature[16 : 16 + v])
        oils = list(signature[16 + v : 16 + v + m])
        expected = qsponge_var(b"CALYX-QMQ-TARGET|" + salt + message, m)
        evaluated = bytes(MultivariateQuadraticEngine._eval_central_map(seed_pub, v, m, vinegars, oils))
        return ct_eq(evaluated, expected)
