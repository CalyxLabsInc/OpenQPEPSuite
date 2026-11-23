"""
Family 4 of Calyx Sovereign-Pentad (CSP-Omega): Genuine Unbalanced Oil-and-Vinegar (UOV)
Multivariate Quadratic Signature Engine over GF(256) (QMQ-512 — Official Release 1.1.0).

Cryptographic Construction (NIST PQC Round 2 Canonical UOV Structure):
  - Field: GF(256) modulo AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B),
    with primitive generator g = 3 (x + 1) of exact multiplicative order 255.
  - Parameters: v = 32 vinegar variables, m = 16 oil variables (n = v + m = 48 variables).
  - Secret Key: Secret oil subspace matrix O in GF(256)^{v x m} derived from seed_sk (NEVER in pk!).
  - Public Key: seed_pk (expanding upper-triangular P_1^{(k)} in GF(256)^{v x v} and
    P_2^{(k)} in GF(256)^{v x m}) + computed hidden public upper-triangular block
      P_3^{(k)} = Upper(O^T P_1^{(k)} O + O^T P_2^{(k)})
    so every public quadratic form P^{(k)}(x) vanishes identically on the secret oil subspace O.
  - Signing: Samples salted target t in GF(256)^m, derives vinegar v_vec, solves the m x m linear
    oil system L * x_o = t XOR y over GF(256), emits s = (v_vec XOR O*x_o, x_o), and enforces
    mandatory Verify-Before-Emit Fault-Guard (QPEPFaultGuardError).
  - Verification: Evaluates P(s) using ONLY public (P_1, P_2, P_3) and verifies ct_eq(P(s), target).
"""
import os
import struct
from typing import List, Optional, Tuple

from ..exceptions import QPEPFaultGuardError, QPEPSuiteError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

QMQ_DEFAULT_V = 32
QMQ_DEFAULT_M = 16

# Precompute O(1) GF(256) multiplication & inversion tables using primitive generator g = 3 (x + 1) mod 0x11B
_GF256_EXP = [0] * 512
_GF256_LOG = [0] * 256
_g = 1
for _i in range(255):
    _GF256_EXP[_i] = _g
    _GF256_EXP[_i + 255] = _g
    _GF256_LOG[_g] = _i
    _g2 = (_g << 1) ^ (0x11B if (_g & 0x80) else 0)
    _g = _g ^ _g2  # multiply by (x + 1) = 3

_MUL256: List[List[int]] = [
    [0 if (a == 0 or b == 0) else _GF256_EXP[_GF256_LOG[a] + _GF256_LOG[b]] for b in range(256)]
    for a in range(256)
]
_INV256: List[int] = [0] + [_GF256_EXP[255 - _GF256_LOG[a]] for a in range(1, 256)]


def _expand_p1_p2(seed_pk: bytes, v: int, m: int) -> Tuple[List[List[List[int]]], List[List[List[int]]]]:
    """Deterministically expands public quadratic blocks P1 (upper-tri v x v) and P2 (v x m) for k = 0..m-1."""
    n_p1 = (v * (v + 1)) // 2
    n_p2 = v * m
    raw = qsponge_var(b"CALYX-QMQ-P1P2-v1.0.0|" + seed_pk + struct.pack("<HH", v, m), m * (n_p1 + n_p2))
    p1_all: List[List[List[int]]] = []
    p2_all: List[List[List[int]]] = []
    off = 0
    for _k in range(m):
        p1k = [[0] * v for _ in range(v)]
        for i in range(v):
            row = p1k[i]
            for j in range(i, v):
                row[j] = raw[off]
                off += 1
        p2k = [[0] * m for _ in range(v)]
        for i in range(v):
            row = p2k[i]
            for j in range(m):
                row[j] = raw[off]
                off += 1
        p1_all.append(p1k)
        p2_all.append(p2k)
    return p1_all, p2_all


def _expand_oil_matrix(seed_sk: bytes, v: int, m: int) -> List[List[int]]:
    raw = qsponge_var(b"CALYX-QMQ-OIL-v1.0.0|" + seed_sk + struct.pack("<HH", v, m), v * m)
    return [[raw[i * m + j] for j in range(m)] for i in range(v)]


def _pack_p3(p3_all: List[List[List[int]]], m: int) -> bytes:
    out = bytearray()
    for p3k in p3_all:
        for i in range(m):
            for j in range(i, m):
                out.append(p3k[i][j])
    return bytes(out)


def _unpack_p3(data: bytes, m: int) -> List[List[List[int]]]:
    p3_all: List[List[List[int]]] = []
    off = 0
    for _k in range(m):
        p3k = [[0] * m for _ in range(m)]
        for i in range(m):
            for j in range(i, m):
                p3k[i][j] = data[off]
                off += 1
        p3_all.append(p3k)
    return p3_all


def _solve_gf256_linear(mat: List[List[int]], rhs: List[int]) -> Optional[List[int]]:
    """Gaussian elimination over GF(256) for an m x m linear system."""
    m = len(rhs)
    aug = [mat[i][:] + [rhs[i]] for i in range(m)]
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
        mip = _MUL256[_INV256[aug[col][col]]]
        for c in range(col, m + 1):
            aug[col][c] = mip[aug[col][c]]
        for r in range(m):
            if r != col and aug[r][col] != 0:
                mf = _MUL256[aug[r][col]]
                for c in range(col, m + 1):
                    aug[r][c] ^= mf[aug[col][c]]
    return [aug[i][m] for i in range(m)]


def _eval_public_map(
    p1_all: List[List[List[int]]],
    p2_all: List[List[List[int]]],
    p3_all: List[List[List[int]]],
    v: int,
    m: int,
    sv: List[int],
    so: List[int],
) -> bytes:
    out = bytearray(m)
    for k in range(m):
        p1k, p2k, p3k = p1_all[k], p2_all[k], p3_all[k]
        val = 0
        for i in range(v):
            si = sv[i]
            if not si:
                continue
            msi = _MUL256[si]
            r1, r2 = p1k[i], p2k[i]
            for j in range(i, v):
                if r1[j] and sv[j]:
                    val ^= _MUL256[msi[r1[j]]][sv[j]]
            for j in range(m):
                if r2[j] and so[j]:
                    val ^= _MUL256[msi[r2[j]]][so[j]]
        for i in range(m):
            si = so[i]
            if not si:
                continue
            msi = _MUL256[si]
            r3 = p3k[i]
            for j in range(i, m):
                if r3[j] and so[j]:
                    val ^= _MUL256[msi[r3[j]]][so[j]]
        out[k] = val
    return bytes(out)


class MultivariateQuadraticEngine:
    """
    Genuine Unbalanced Oil-and-Vinegar (UOV) Multivariate Quadratic Signature Engine over GF(256).
    The secret oil subspace O is cryptographically hidden inside public P_3 and never emitted in pk.
    """

    @staticmethod
    def keygen(v: int = QMQ_DEFAULT_V, m: int = QMQ_DEFAULT_M) -> Tuple[bytes, bytes]:
        if v < 16 or m < 8 or v < 2 * m:
            raise QPEPSuiteError("UOV requires v >= 2*m and (v >= 16, m >= 8).")
        seed_pk = os.urandom(32)
        seed_sk = os.urandom(32)

        p1_all, p2_all = _expand_p1_p2(seed_pk, v, m)
        oil_o = _expand_oil_matrix(seed_sk, v, m)

        # Compute hidden public block P3^(k) = Upper(O^T * P1^(k) * O + O^T * P2^(k))
        p3_all: List[List[List[int]]] = []
        for k in range(m):
            p1k, p2k = p1_all[k], p2_all[k]
            tmp = [[p2k[i][j] for j in range(m)] for i in range(v)]
            for i in range(v):
                row1, ti = p1k[i], tmp[i]
                for r in range(i, v):
                    c = row1[r]
                    if c:
                        mc, orow = _MUL256[c], oil_o[r]
                        for j in range(m):
                            ti[j] ^= mc[orow[j]]
            mmat = [[0] * m for _ in range(m)]
            for a in range(m):
                ma = mmat[a]
                for i in range(v):
                    oia = oil_o[i][a]
                    if oia:
                        mo, ti = _MUL256[oia], tmp[i]
                        for b in range(m):
                            ma[b] ^= mo[ti[b]]
            p3k = [[0] * m for _ in range(m)]
            for a in range(m):
                p3k[a][a] = mmat[a][a]
                for b in range(a + 1, m):
                    p3k[a][b] = mmat[a][b] ^ mmat[b][a]
            p3_all.append(p3k)

        p3_bytes = _pack_p3(p3_all, m)
        pk = struct.pack("<HH", v, m) + seed_pk + p3_bytes
        pk_hash = qsponge_512(b"CALYX-QMQ-PKH-v1.0.0|" + pk)[:32]
        sk = struct.pack("<HH", v, m) + seed_pk + seed_sk + pk_hash + p3_bytes
        return pk, sk

    @staticmethod
    def sign(sk: bytes, message: bytes) -> bytes:
        with SecretBuffer(sk) as sk_buf:
            raw = sk_buf.as_bytes()
            v, m = struct.unpack("<HH", raw[:4])
            seed_pk = raw[4:36]
            seed_sk = raw[36:68]
            pk_hash = raw[68:100]
            p3_bytes = raw[100:]
            oil_o = _expand_oil_matrix(seed_sk, v, m)

        p1_all, p2_all = _expand_p1_p2(seed_pk, v, m)
        salt = os.urandom(16)
        target = list(qsponge_var(b"CALYX-QMQ-TARGET-v1.0.0|" + pk_hash + salt + message, m))

        for attempt in range(64):
            vin = list(qsponge_var(b"CALYX-QMQ-VINEGAR-v1.0.0|" + seed_sk + salt + struct.pack(">H", attempt), v))
            rhs = list(target)
            lin = [[0] * m for _ in range(m)]

            for k in range(m):
                p1k, p2k = p1_all[k], p2_all[k]
                yk = 0
                w = [0] * v
                for i in range(v):
                    vi = vin[i]
                    row1 = p1k[i]
                    for j in range(i, v):
                        c = row1[j]
                        if not c:
                            continue
                        vj = vin[j]
                        if vi and vj:
                            yk ^= _MUL256[_MUL256[vi][c]][vj]
                        if i != j:
                            if vi:
                                w[j] ^= _MUL256[vi][c]
                            if vj:
                                w[i] ^= _MUL256[vj][c]
                rhs[k] ^= yk
                lk = lin[k]
                for i in range(v):
                    wi = w[i]
                    if wi:
                        mwi, oi = _MUL256[wi], oil_o[i]
                        for j in range(m):
                            lk[j] ^= mwi[oi[j]]
                    vi = vin[i]
                    if vi:
                        mvi, p2i = _MUL256[vi], p2k[i]
                        for j in range(m):
                            lk[j] ^= mvi[p2i[j]]

            xo = _solve_gf256_linear(lin, rhs)
            if xo is not None:
                sv = list(vin)
                for i in range(v):
                    oi = oil_o[i]
                    for j in range(m):
                        sv[i] ^= _MUL256[oi[j]][xo[j]]
                sig_out = salt + bytes(sv) + bytes(xo)
                # Mandatory Verify-Before-Emit Fault-Guard
                pk_rebuilt = struct.pack("<HH", v, m) + seed_pk + p3_bytes
                if not MultivariateQuadraticEngine.verify(pk_rebuilt, message, sig_out):
                    raise QPEPFaultGuardError("QMQ-512 UOV Fault-Guard triggered: signature failed internal verification.")
                return sig_out

        raise RuntimeError("QMQ-512 UOV signing failed to find invertible linear oil system.")

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        if len(pk) < 36:
            return False
        v, m = struct.unpack("<HH", pk[:4])
        expected_p3_len = m * (m * (m + 1) // 2)
        if len(pk) != 36 + expected_p3_len or len(signature) != 16 + v + m:
            return False
        seed_pk = pk[4:36]
        p3_all = _unpack_p3(pk[36:], m)
        p1_all, p2_all = _expand_p1_p2(seed_pk, v, m)
        pk_hash = qsponge_512(b"CALYX-QMQ-PKH-v1.0.0|" + pk)[:32]

        salt = signature[:16]
        sv = list(signature[16 : 16 + v])
        so = list(signature[16 + v : 16 + v + m])
        expected = qsponge_var(b"CALYX-QMQ-TARGET-v1.0.0|" + pk_hash + salt + message, m)
        evaluated = _eval_public_map(p1_all, p2_all, p3_all, v, m, sv, so)
        return ct_eq(evaluated, expected)
