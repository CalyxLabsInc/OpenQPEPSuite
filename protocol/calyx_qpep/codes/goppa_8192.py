"""
Family 2 of Calyx Sovereign-Pentad (CSP-Omega): Genuine Classic McEliece / Niederreiter
Binary Goppa Code Syndrome-Decoding KEM (CGM-8192 — Official Release 1.0.0).

Cryptographic Construction:
  - Field: GF(2^10) modulo primitive polynomial x^10 + x^3 + 1 (0x409), n = 1024 bits.
  - Secret Key: Monic irreducible Goppa polynomial g(x) in GF(2^10)[x] of degree t = 32,
    secret support permutation alpha_0..alpha_1023 of GF(2^10), and implicit-rejection seed_z.
  - Public Key: Systematic binary parity-check matrix H_sys = [I_320 | T] over F_2
    derived via Gaussian elimination (RREF) of the Goppa parity-check matrix H_{i,j} = alpha_j^i / g(alpha_j).
  - Encapsulation: Samples fixed-weight binary error vector e (wt(e) = 32), computes
    syndrome c0 = H_sys * e^T (40 bytes) and FO confirmation tag c1 (32 bytes).
  - Decapsulation: Recovers exact error vector e via Patterson's Algebraic Decoding Algorithm
    (syndrome polynomial S(x), Frobenius square-root sqrt(S(x)^-1 + x) mod g(x),
    Extended Euclidean key equation, and Chien search), verifies wt(e) == 32, re-encodes
    syndrome H_sys * e^T == c0, verifies c1, and multiplexes via branchless ct_cmov.
"""
import os
import struct
from typing import List, Optional, Tuple

from ..exceptions import QPEPSuiteError
from ..primitives.consttime import ct_cmov, ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

GOPPA_M = 10
GOPPA_N = 1024
GOPPA_T = 32
GOPPA_MT = GOPPA_M * GOPPA_T        # 320 syndrome bits = 40 bytes
GOPPA_K = GOPPA_N - GOPPA_MT        # 704 systematic columns = 88 bytes/row
GOPPA_GF_MOD = (1 << 10) | (1 << 3) | 1  # x^10 + x^3 + 1 (primitive)
GOPPA_GF_SIZE = 1 << GOPPA_M

# Precomputed O(1) GF(2^10) arithmetic tables (exp, log, Frobenius square root)
_GF_EXP = [0] * (2 * GOPPA_GF_SIZE)
_GF_LOG = [0] * GOPPA_GF_SIZE
_x = 1
for _i in range(GOPPA_GF_SIZE - 1):
    _GF_EXP[_i] = _x
    _GF_EXP[_i + GOPPA_GF_SIZE - 1] = _x
    _GF_LOG[_x] = _i
    _x <<= 1
    if _x & GOPPA_GF_SIZE:
        _x ^= GOPPA_GF_MOD

_GF_SQRT = [0] * GOPPA_GF_SIZE
for _a in range(1, GOPPA_GF_SIZE):
    _GF_SQRT[_GF_EXP[(2 * _GF_LOG[_a]) % (GOPPA_GF_SIZE - 1)]] = _a


def _gmul(a: int, b: int) -> int:
    return 0 if (a == 0 or b == 0) else _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _ginv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^10).")
    return _GF_EXP[(GOPPA_GF_SIZE - 1) - _GF_LOG[a]]


def _ptrim(p: List[int]) -> List[int]:
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def _padd(a: List[int], b: List[int]) -> List[int]:
    res = [0] * max(len(a), len(b))
    for i, v in enumerate(a):
        res[i] ^= v
    for i, v in enumerate(b):
        res[i] ^= v
    return _ptrim(res)


def _pmul(a: List[int], b: List[int]) -> List[int]:
    res = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            la = _GF_LOG[ai]
            for j, bj in enumerate(b):
                if bj:
                    res[i + j] ^= _GF_EXP[la + _GF_LOG[bj]]
    return _ptrim(res)


def _pdivmod(a: List[int], m: List[int]) -> Tuple[List[int], List[int]]:
    ac = list(a)
    dm = len(m) - 1
    inv_lc = _ginv(m[-1])
    q = [0] * max(1, len(ac) - dm)
    while len(ac) - 1 >= dm and not (len(ac) == 1 and ac[0] == 0):
        c = _gmul(ac[-1], inv_lc)
        sh = len(ac) - 1 - dm
        q[sh] ^= c
        lc = _GF_LOG[c]
        for i in range(dm + 1):
            if m[i]:
                ac[sh + i] ^= _GF_EXP[lc + _GF_LOG[m[i]]]
        _ptrim(ac)
    return _ptrim(q), ac


def _pmod(a: List[int], m: List[int]) -> List[int]:
    return _pdivmod(a, m)[1]


def _pgcd(a: List[int], b: List[int]) -> List[int]:
    while not (len(b) == 1 and b[0] == 0):
        a, b = b, _pmod(a, b)
    return a


def _pinv(a: List[int], m: List[int]) -> Optional[List[int]]:
    r0, r1 = list(m), _pmod(a, m)
    t0, t1 = [0], [1]
    while not (len(r1) == 1 and r1[0] == 0):
        q, r2 = _pdivmod(r0, r1)
        r0, r1 = r1, r2
        t0, t1 = t1, _padd(t0, _pmul(q, t1))
    if len(r0) != 1 or r0[0] == 0:
        return None
    inv_r0 = _ginv(r0[0])
    return [_gmul(c, inv_r0) for c in t0]


def _peval(p: List[int], a: int) -> int:
    acc = 0
    for c in reversed(p):
        acc = _gmul(acc, a) ^ c
    return acc


def _is_irreducible_gf2m(g: List[int], degree: int) -> bool:
    """Fast Rabin irreducibility test over GF(2^10) checking x^(q^k) - x for k = 1..degree//2."""
    xp = [0, 1]
    for _k in range(1, degree // 2 + 1):
        for _ in range(GOPPA_M):
            xp = _pmod(_pmul(xp, xp), g)
        if len(_pgcd(_padd(xp, [0, 1]), g)) > 1:
            return False
    return True


def _sample_irreducible_goppa(t: int) -> List[int]:
    """Samples a random monic irreducible Goppa polynomial of degree t over GF(2^10)."""
    while True:
        raw = os.urandom(2 * t)
        g = [(struct.unpack("<H", raw[2 * i : 2 * i + 2])[0] & (GOPPA_GF_SIZE - 1)) for i in range(t)] + [1]
        if g[0] == 0:
            g[0] = 1
        if _is_irreducible_gf2m(g, t):
            return g


def _compute_syndrome(t_rows: List[int], err_mask: int, mt: int) -> int:
    """Computes binary syndrome s = [I_mt | T] * e^T over F_2."""
    e_left = err_mask & ((1 << mt) - 1)
    e_right = err_mask >> mt
    syn = 0
    for r in range(mt):
        if ((e_left >> r) & 1) ^ ((t_rows[r] & e_right).bit_count() & 1):
            syn |= (1 << r)
    return syn


def _unpack_t_rows(t_bytes: bytes, mt: int, k_bytes: int) -> List[int]:
    return [
        int.from_bytes(t_bytes[r * k_bytes : (r + 1) * k_bytes], "little")
        for r in range(mt)
    ]


class BinaryGoppaKEM:
    """
    Genuine Classic McEliece / Niederreiter Binary Goppa Code Syndrome-Decoding KEM (CGM-8192).
    Uses systematic parity-check matrix H_sys = [I_320 | T] over F_2, Patterson algebraic decoding
    over GF(2^10)[x], Fujisaki-Okamoto confirmation tag c1, and branchless ct_cmov implicit rejection.
    """

    @staticmethod
    def keygen(n_bits: int = GOPPA_N, r_bits: int = GOPPA_MT, weight: int = GOPPA_T) -> Tuple[bytes, bytes]:
        if n_bits != GOPPA_N or r_bits != GOPPA_MT or weight != GOPPA_T:
            raise QPEPSuiteError(
                f"CGM-8192 Official Release 1.0.0 requires canonical Goppa parameters (n={GOPPA_N}, mt={GOPPA_MT}, t={GOPPA_T})."
            )
        seed_z = os.urandom(32)
        g = _sample_irreducible_goppa(weight)
        mt = r_bits
        k_bits = n_bits - mt
        k_bytes = k_bits // 8

        # Sample random support permutation alpha_0..alpha_{n-1} until left mt x mt block is invertible
        while True:
            support = list(range(n_bits))
            rnd = os.urandom(2 * n_bits)
            for i in range(n_bits - 1, 0, -1):
                j = struct.unpack("<H", rnd[2 * i : 2 * i + 2])[0] % (i + 1)
                support[i], support[j] = support[j], support[i]

            rows = [0] * mt
            g_inv = [_ginv(_peval(g, a)) for a in support]
            for col in range(n_bits):
                a = support[col]
                val = g_inv[col]
                bit = 1 << col
                for i in range(weight):
                    base = i * GOPPA_M
                    v = val
                    for b in range(GOPPA_M):
                        if (v >> b) & 1:
                            rows[base + b] |= bit
                    val = _gmul(val, a)

            invertible = True
            for col in range(mt):
                bit = 1 << col
                piv = -1
                for r in range(col, mt):
                    if rows[r] & bit:
                        piv = r
                        break
                if piv == -1:
                    invertible = False
                    break
                if piv != col:
                    rows[col], rows[piv] = rows[piv], rows[col]
                piv_row = rows[col]
                for r in range(mt):
                    if r != col and (rows[r] & bit):
                        rows[r] ^= piv_row
            if invertible:
                break

        t_bytes = b"".join((r >> mt).to_bytes(k_bytes, "little") for r in rows)
        pk_body = struct.pack("<HHH", n_bits, mt, weight) + t_bytes
        h_pk = qsponge_512(b"CALYX-CGM-HPK-v1.0.0|" + pk_body)[:32]
        pk = pk_body + h_pk

        g_bytes = struct.pack(f"<{weight + 1}H", *g)
        sup_bytes = struct.pack(f"<{n_bits}H", *support)
        sk = struct.pack("<HHH", n_bits, mt, weight) + seed_z + g_bytes + sup_bytes + pk
        return pk, sk

    @staticmethod
    def encaps(pk: bytes) -> Tuple[bytes, bytes]:
        expected_pk_len = 6 + (GOPPA_MT * (GOPPA_K // 8)) + 32
        if len(pk) != expected_pk_len:
            raise QPEPSuiteError(f"Invalid CGM-8192 public key length: {len(pk)} (expected {expected_pk_len}).")
        n_bits, mt, weight = struct.unpack("<HHH", pk[:6])
        if n_bits != GOPPA_N or mt != GOPPA_MT or weight != GOPPA_T:
            raise QPEPSuiteError("Corrupted CGM-8192 public key parameters.")

        k_bytes = (n_bits - mt) // 8
        t_rows = _unpack_t_rows(pk[6:-32], mt, k_bytes)
        h_pk = pk[-32:]
        if not ct_eq(h_pk, qsponge_512(b"CALYX-CGM-HPK-v1.0.0|" + pk[:-32])[:32]):
            raise QPEPSuiteError("CGM-8192 public key commitment check failed.")

        # Sample uniform random error vector e of exact Hamming weight t = 32
        positions: List[int] = []
        used = set()
        while len(positions) < weight:
            raw = os.urandom(2 * (weight - len(positions) + 4))
            for i in range(0, len(raw), 2):
                pos = struct.unpack("<H", raw[i : i + 2])[0] & (n_bits - 1)
                if pos not in used:
                    used.add(pos)
                    positions.append(pos)
                    if len(positions) == weight:
                        break
        err_mask = 0
        for pos in positions:
            err_mask |= (1 << pos)
        err_bytes = err_mask.to_bytes(n_bits // 8, "little")

        syn_int = _compute_syndrome(t_rows, err_mask, mt)
        c0_syn = syn_int.to_bytes(mt // 8, "little")
        c1_conf = qsponge_512(b"CALYX-CGM-CONF-v1.0.0|" + err_bytes + c0_syn + h_pk)[:32]
        ct = c0_syn + c1_conf
        ss = qsponge_512(b"CALYX-CGM-SS-v1.0.0|" + err_bytes + ct + h_pk)[:32]
        return ct, ss

    @staticmethod
    def decaps(sk: bytes, ct: bytes) -> bytes:
        with SecretBuffer(sk) as sk_buf:
            raw = sk_buf.as_bytes()
            n_bits, mt, weight = struct.unpack("<HHH", raw[:6])
            seed_z = raw[6:38]
            off = 38
            g = list(struct.unpack(f"<{weight + 1}H", raw[off : off + 2 * (weight + 1)]))
            off += 2 * (weight + 1)
            support = list(struct.unpack(f"<{n_bits}H", raw[off : off + 2 * n_bits]))
            off += 2 * n_bits
            pk = raw[off:]

        syn_bytes_len = mt // 8
        k_reject = qsponge_var(b"CALYX-CGM-REJECT-v1.0.0|" + seed_z + ct, 32)
        if len(ct) != syn_bytes_len + 32:
            return k_reject

        c0_syn = ct[:syn_bytes_len]
        c1_conf = ct[syn_bytes_len : syn_bytes_len + 32]
        syn_int = int.from_bytes(c0_syn, "little")
        k_bytes = (n_bits - mt) // 8
        t_rows = _unpack_t_rows(pk[6:-32], mt, k_bytes)
        h_pk = pk[-32:]

        # Patterson Algebraic Decoding over GF(2^10)[x]
        # 1. Syndrome polynomial S(x) = sum_{j<mt, syn_j=1} (x + alpha_j)^-1 mod g(x)
        s_poly = [0] * weight
        for j in range(mt):
            if not ((syn_int >> j) & 1):
                continue
            a = support[j]
            ga_inv = _ginv(_peval(g, a))
            q_cur = g[weight]
            s_poly[weight - 1] ^= _gmul(q_cur, ga_inv)
            for idx in range(weight - 2, -1, -1):
                q_cur = g[idx + 1] ^ _gmul(q_cur, a)
                s_poly[idx] ^= _gmul(q_cur, ga_inv)
        s_poly = _ptrim(s_poly)

        sigma: List[int] = [1]
        decoded_ok = False
        if not (len(s_poly) == 1 and s_poly[0] == 0):
            s_inv = _pinv(s_poly, g)
            if s_inv is not None:
                t_poly = _padd(s_inv, [0, 1])
                if len(t_poly) == 1 and t_poly[0] == 0:
                    sigma = [0, 1]
                    decoded_ok = True
                else:
                    g0 = [_GF_SQRT[g[i]] for i in range(0, len(g), 2)]
                    g1 = [_GF_SQRT[g[i]] for i in range(1, len(g), 2)]
                    g1_inv = _pinv(g1, g)
                    if g1_inv is not None:
                        sqrt_x = _pmod(_pmul(g0, g1_inv), g)
                        t_even = [_GF_SQRT[t_poly[i]] for i in range(0, len(t_poly), 2)]
                        t_odd = [_GF_SQRT[t_poly[i]] for i in range(1, len(t_poly), 2)]
                        r_poly = _pmod(_padd(t_even, _pmul(t_odd, sqrt_x)), g)
                        r0, r1 = list(g), r_poly
                        b0, b1 = [0], [1]
                        while len(r1) - 1 > weight // 2:
                            q, r2 = _pdivmod(r0, r1)
                            r0, r1 = r1, r2
                            b0, b1 = b1, _padd(b0, _pmul(q, b1))
                        sigma = _padd(_pmul(r1, r1), [0] + _pmul(b1, b1))
                        decoded_ok = True

        # 2. Constant-iteration Chien search across all n_bits support positions
        err_mask = 0
        found_wt = 0
        for j in range(n_bits):
            is_root = 1 if (_peval(sigma, support[j]) == 0) else 0
            err_mask |= (is_root << j)
            found_wt += is_root

        err_bytes = err_mask.to_bytes(n_bits // 8, "little")
        exp_syn = _compute_syndrome(t_rows, err_mask, mt).to_bytes(syn_bytes_len, "little")
        exp_conf = qsponge_512(b"CALYX-CGM-CONF-v1.0.0|" + err_bytes + exp_syn + h_pk)[:32]

        valid = (
            decoded_ok
            and (found_wt == weight)
            and ct_eq(c0_syn, exp_syn)
            and ct_eq(c1_conf, exp_conf)
        )
        k_cand = qsponge_512(b"CALYX-CGM-SS-v1.0.0|" + err_bytes + ct + h_pk)[:32]
        return ct_cmov(valid, k_cand, k_reject)
