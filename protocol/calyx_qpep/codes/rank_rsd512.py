"""
Genuine Rank-Metric Syndrome Decoding (CRT-RSD512) LRPC KEM Engine over GF(2^127)[X]/(X^47 + X^5 + 1)
(Official Release 1.0.0 / v1.0.0).

Cryptographic Construction (ROLLO-I / LRPC Rank-Metric Code):
  - Base field: GF(2^127) modulo irreducible trinomial x^127 + x^63 + 1 (prime degree 127 — zero subfields).
  - Polynomial ring: R = GF(2^127)[X] / (X^47 + X^5 + 1).
  - Secret Key: Secret F_2-subspace F = <f_1, f_2, f_3, f_4> (rank d = 4), secret polynomials
    x, y in F[X] with y invertible in R, plus implicit-rejection seed_z.
  - Public Key: Uniform-looking polynomial h = x * y^-1 in R (752 bytes).
  - Encapsulation (FO IND-CCA2): Samples random rank-4 error support E, encodes its unique
    canonical RREF basis E_canon (64 bytes), deterministically derives (e_A, e_B) in E[X]^2
    via qSponge-XOF, and emits syndrome ciphertext c = e_A + h * e_B (752 bytes).
  - Decapsulation: Computes s = y * c in R, recovers E' = cap_{i=1}^4 f_i^-1 * span_{F_2}(s)
    via Rank Support Recovery (RSR) & Zassenhaus F_2-subspace intersection, re-encrypts
    c' = e_A' + h * e_B', verifies ct_eq(c, c'), and selects via branchless ct_cmov.
"""
import os
from typing import List, Optional, Tuple

from ..exceptions import QPEPSuiteError
from ..primitives.consttime import ct_cmov, ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

GF2_127_POLY = (1 << 127) | (1 << 63) | 1  # Irreducible trinomial x^127 + x^63 + 1
_MASK_127 = (1 << 127) - 1

LRPC_N = 47   # Irreducible trinomial X^47 + X^5 + 1 over F_2
LRPC_D = 4    # Secret parity-check rank weight
LRPC_R = 4    # Error support rank weight
LRPC_POLY_BYTES = LRPC_N * 16  # 752 bytes


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


def _gf2_127_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^127).")
    res = 1
    base = a & _MASK_127
    exp = (1 << 127) - 2
    while exp:
        if exp & 1:
            res = gf2_127_mul(res, base)
        base = gf2_127_mul(base, base)
        exp >>= 1
    return res


def _ring_mul(a: List[int], b: List[int]) -> List[int]:
    """Polynomial multiplication in GF(2^127)[X] / (X^47 + X^5 + 1)."""
    tmp = [0] * (2 * LRPC_N - 1)
    for i in range(LRPC_N):
        ai = a[i]
        if ai == 0:
            continue
        for j in range(LRPC_N):
            bj = b[j]
            if bj:
                tmp[i + j] ^= gf2_127_mul(ai, bj)
    for i in range(2 * LRPC_N - 2, LRPC_N - 1, -1):
        c = tmp[i]
        if c:
            tmp[i - LRPC_N] ^= c
            tmp[i - LRPC_N + 5] ^= c
    return tmp[:LRPC_N]


def _ring_inv(a: List[int]) -> Optional[List[int]]:
    """Multiplicative inverse in GF(2^127)[X] / (X^47 + X^5 + 1) via Extended GCD."""
    mod = [0] * (LRPC_N + 1)
    mod[0] = 1
    mod[5] = 1
    mod[LRPC_N] = 1

    def trim(p: List[int]) -> List[int]:
        while len(p) > 1 and p[-1] == 0:
            p.pop()
        return p

    r0, r1 = mod, trim(list(a))
    t0, t1 = [0], [1]
    while not (len(r1) == 1 and r1[0] == 0):
        ac = list(r0)
        d1 = len(r1) - 1
        inv_lc = _gf2_127_inv(r1[-1])
        q = [0] * max(1, len(ac) - d1)
        while len(ac) - 1 >= d1 and not (len(ac) == 1 and ac[0] == 0):
            c = gf2_127_mul(ac[-1], inv_lc)
            sh = len(ac) - 1 - d1
            q[sh] ^= c
            for i in range(d1 + 1):
                if r1[i]:
                    ac[sh + i] ^= gf2_127_mul(c, r1[i])
            trim(ac)
        trim(q)
        prod = [0] * (len(q) + len(t1) - 1)
        for i, qi in enumerate(q):
            if qi:
                for j, tj in enumerate(t1):
                    if tj:
                        prod[i + j] ^= gf2_127_mul(qi, tj)
        tn = [0] * max(len(t0), len(prod))
        for i, v in enumerate(t0):
            tn[i] ^= v
        for i, v in enumerate(prod):
            tn[i] ^= v
        trim(tn)
        r0, r1 = r1, ac
        t0, t1 = t1, tn

    if len(r0) != 1 or r0[0] == 0:
        return None
    inv_r0 = _gf2_127_inv(r0[0])
    out = [gf2_127_mul(c, inv_r0) for c in t0]
    out.extend([0] * (LRPC_N - len(out)))
    return out[:LRPC_N]


def _f2_rref(vecs: List[int]) -> List[int]:
    """Canonical Reduced Row Echelon Form (RREF) F_2-basis of elements in GF(2^127)."""
    basis: List[int] = []
    for v in vecs:
        for b in basis:
            hb = b.bit_length() - 1
            if (v >> hb) & 1:
                v ^= b
        if v:
            hb = v.bit_length() - 1
            for i in range(len(basis)):
                if (basis[i] >> hb) & 1:
                    basis[i] ^= v
            basis.append(v)
            basis.sort(reverse=True)
    return basis


def _f2_intersect(u_basis: List[int], v_basis: List[int]) -> List[int]:
    """Exact F_2-subspace intersection U cap V via Zassenhaus algorithm over 254-bit integers."""
    rows = [(u << 127) | u for u in u_basis] + [(v << 127) for v in v_basis]
    rref = _f2_rref(rows)
    return _f2_rref([r & _MASK_127 for r in rref if (r >> 127) == 0])


def _pack_poly(poly: List[int]) -> bytes:
    return b"".join((c & _MASK_127).to_bytes(16, "little") for c in poly)


def _unpack_poly(data: bytes) -> List[int]:
    return [int.from_bytes(data[16 * i : 16 * (i + 1)], "little") & _MASK_127 for i in range(LRPC_N)]


def _pack_basis(basis: List[int], expected_dim: int) -> bytes:
    padded = list(basis[:expected_dim]) + [0] * max(0, expected_dim - len(basis))
    return b"".join((b & _MASK_127).to_bytes(16, "little") for b in padded)


def _expand_error_pair(h_pk: bytes, e_basis: List[int]) -> Tuple[List[int], List[int]]:
    """Deterministically derives (e_A, e_B) in E[X]^2 from canonical RREF basis of E."""
    e_canon = _pack_basis(e_basis, LRPC_R)
    raw = qsponge_var(b"CALYX-CRT-RSD512-COINS-v1.0.0|" + h_pk + e_canon, 2 * LRPC_N)
    e_a = [0] * LRPC_N
    e_b = [0] * LRPC_N
    dim = len(e_basis)
    for i in range(LRPC_N):
        ma = raw[i]
        mb = raw[LRPC_N + i]
        va = 0
        vb = 0
        for bit in range(dim):
            if (ma >> bit) & 1:
                va ^= e_basis[bit]
            if (mb >> bit) & 1:
                vb ^= e_basis[bit]
        e_a[i] = va
        e_b[i] = vb
    return e_a, e_b


class RankMetricKEM:
    """
    Standalone Genuine Rank-Metric Tensor (CRT-RSD512) LRPC KEM over GF(2^127)[X]/(X^47+X^5+1)
    with Rank Support Recovery (RSR), Fujisaki-Okamoto re-encryption check, and branchless ct_cmov.
    """

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        seed_z = os.urandom(32)
        while True:
            # Sample secret rank-d F_2-subspace F
            f_raw = [int.from_bytes(os.urandom(16), "little") & _MASK_127 for _ in range(LRPC_D)]
            f_basis = _f2_rref(f_raw)
            if len(f_basis) != LRPC_D:
                continue

            # Sample secret polynomials x, y with coefficients in F
            rnd = os.urandom(2 * LRPC_N)
            x_poly = [0] * LRPC_N
            y_poly = [0] * LRPC_N
            for i in range(LRPC_N):
                mx, my = rnd[i], rnd[LRPC_N + i]
                vx, vy = 0, 0
                for bit in range(LRPC_D):
                    if (mx >> bit) & 1:
                        vx ^= f_basis[bit]
                    if (my >> bit) & 1:
                        vy ^= f_basis[bit]
                x_poly[i] = vx
                y_poly[i] = vy

            if len(_f2_rref(x_poly + y_poly)) != LRPC_D:
                continue
            y_inv = _ring_inv(y_poly)
            if y_inv is None:
                continue
            h_poly = _ring_mul(x_poly, y_inv)
            break

        h_bytes = _pack_poly(h_poly)
        h_pk = qsponge_512(b"CALYX-CRT-RSD512-HPK-v1.0.0|" + h_bytes)[:32]
        pk = h_bytes + h_pk
        sk = seed_z + _pack_basis(f_basis, LRPC_D) + _pack_poly(y_poly) + pk
        return pk, sk

    @staticmethod
    def encaps(pk: bytes) -> Tuple[bytes, bytes]:
        if len(pk) != LRPC_POLY_BYTES + 32:
            raise QPEPSuiteError(f"Invalid CRT-RSD512 public key length: {len(pk)}.")
        h_bytes, h_pk = pk[:LRPC_POLY_BYTES], pk[LRPC_POLY_BYTES:]
        if not ct_eq(h_pk, qsponge_512(b"CALYX-CRT-RSD512-HPK-v1.0.0|" + h_bytes)[:32]):
            raise QPEPSuiteError("CRT-RSD512 public key commitment check failed.")
        h_poly = _unpack_poly(h_bytes)

        while True:
            e_raw = [int.from_bytes(os.urandom(16), "little") & _MASK_127 for _ in range(LRPC_R)]
            e_basis = _f2_rref(e_raw)
            if len(e_basis) != LRPC_R:
                continue
            e_a, e_b = _expand_error_pair(h_pk, e_basis)
            if len(_f2_rref(e_a + e_b)) == LRPC_R:
                break

        he_b = _ring_mul(h_poly, e_b)
        c_poly = [e_a[i] ^ he_b[i] for i in range(LRPC_N)]
        ct = _pack_poly(c_poly)
        e_canon = _pack_basis(e_basis, LRPC_R)
        ss = qsponge_512(b"CALYX-CRT-RSD512-SS-v1.0.0|" + e_canon + ct + h_pk)[:32]
        return ct, ss

    @staticmethod
    def decaps(sk: bytes, ct: bytes) -> bytes:
        with SecretBuffer(sk) as sk_buf:
            raw = sk_buf.as_bytes()
            seed_z = raw[:32]
            f_bytes = raw[32 : 32 + 16 * LRPC_D]
            y_bytes = raw[32 + 16 * LRPC_D : 32 + 16 * LRPC_D + LRPC_POLY_BYTES]
            pk = raw[32 + 16 * LRPC_D + LRPC_POLY_BYTES :]
            f_basis = [int.from_bytes(f_bytes[16 * i : 16 * (i + 1)], "little") & _MASK_127 for i in range(LRPC_D)]
            y_poly = _unpack_poly(y_bytes)

        k_reject = qsponge_var(b"CALYX-CRT-RSD512-REJECT-v1.0.0|" + seed_z + ct, 32)
        if len(ct) != LRPC_POLY_BYTES:
            return k_reject

        h_bytes, h_pk = pk[:LRPC_POLY_BYTES], pk[LRPC_POLY_BYTES:]
        h_poly = _unpack_poly(h_bytes)
        c_poly = _unpack_poly(ct)

        # 1. Multiply syndrome by secret polynomial y: s = y*e_A + x*e_B in (E * F)[X]
        s_poly = _ring_mul(y_poly, c_poly)
        s_space = _f2_rref(s_poly)

        # 2. Rank Support Recovery (RSR): E' = cap_{i=1}^d f_i^-1 * S
        e_rec: Optional[List[int]] = None
        for fi in f_basis:
            if fi == 0:
                continue
            fi_inv = _gf2_127_inv(fi)
            shifted = _f2_rref([gf2_127_mul(sv, fi_inv) for sv in s_space])
            e_rec = shifted if e_rec is None else _f2_intersect(e_rec, shifted)

        # 3. Fujisaki-Okamoto full re-encryption check & branchless ct_cmov
        e_rec = e_rec or []
        e_canon = _pack_basis(e_rec, LRPC_R)
        valid_dim = (len(e_rec) == LRPC_R)
        if valid_dim:
            ea_p, eb_p = _expand_error_pair(h_pk, e_rec)
            heb_p = _ring_mul(h_poly, eb_p)
            ct_prime = _pack_poly([ea_p[i] ^ heb_p[i] for i in range(LRPC_N)])
        else:
            ct_prime = b"\x00" * LRPC_POLY_BYTES

        valid = valid_dim and ct_eq(ct, ct_prime)
        k_cand = qsponge_512(b"CALYX-CRT-RSD512-SS-v1.0.0|" + e_canon + ct + h_pk)[:32]
        return ct_cmov(valid, k_cand, k_reject)
