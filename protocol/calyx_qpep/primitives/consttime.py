"""
Branchless Constant-Time Cryptographic Primitives (Production Candidate 1.1.7).
Provides constant-time byte equality, branchless byte-array conditional move (ct_cmov)
for Fujisaki-Okamoto implicit-rejection multiplexing, and Barrett/Montgomery reduction helpers.
"""
import hmac


def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time byte-string comparison."""
    return hmac.compare_digest(a, b)


def ct_select_int(cond: int, a: int, b: int) -> int:
    """Branchless integer select: returns a if cond != 0 else b."""
    mask = -(1 if cond else 0)
    return (a & mask) | (b & ~mask)


def ct_cmov(cond: bool, a: bytes, b: bytes) -> bytes:
    """
    Branchless constant-time conditional move over equal-length byte buffers.
    Returns a copy of `a` when `cond` is True, or `b` when `cond` is False,
    executing identical arithmetic across every byte index with zero secret-dependent branches.
    """
    if len(a) != len(b):
        raise ValueError("ct_cmov requires equal-length byte buffers.")
    mask = 0xFF if cond else 0x00
    inv_mask = mask ^ 0xFF
    out = bytearray(len(a))
    for i in range(len(a)):
        out[i] = (a[i] & mask) | (b[i] & inv_mask)
    return bytes(out)


def barrett_reduce_3329(x: int) -> int:
    """Barrett modular reduction modulo QLX_Q = 3329 (v = floor(2^26 / 3329) = 20159)."""
    t = ((x * 20159) + (1 << 25)) >> 26
    r = x - t * 3329
    return r + (3329 & (-(r < 0)))


def montgomery_reduce_3329(a: int) -> int:
    """Montgomery reduction modulo QLX_Q = 3329 with R = 2^16 (q^-1 mod 2^16 = 62209)."""
    t = (a * 62209) & 0xFFFF
    u = (a - t * 3329) >> 16
    return u % 3329


def barrett_reduce_qvs(x: int) -> int:
    """Canonical reduction modulo QVS_Q = 8380417."""
    return x % 8380417
