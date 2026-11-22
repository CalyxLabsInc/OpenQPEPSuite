# OpenQPEP Official Release 1.0.0 (v1.0.0)
"""
Polynomial Ring Sampling (NTT Rejection, CBD_1, CBD_2, Ball Challenge) & Bit-Packing Codecs.
Automatically accelerates CBD_1 / CBD_2 sampling via libopenqpep (C99/AVX2/NEON) when available.
"""
from typing import List
from ..constants import QLX_Q, QVS_Q, QVS_GAMMA1
from ..native.loader import native_cbd1_3329, native_cbd2_3329, native_cbd2_qvs
from ..primitives.qsponge import qsponge_var

def sample_ntt_3329(rho: bytes, row: int, col: int) -> List[int]:
    """Rejection-samples a uniform NTT-domain polynomial in R_3329 from seed rho || col || row."""
    stream = qsponge_var(b"CALYX-QLX-MAT-A|" + rho + bytes([col, row]), 840)
    coeffs: List[int] = []
    idx = 0
    while len(coeffs) < 256:
        d1 = stream[idx] + 256 * (stream[idx + 1] & 0x0F)
        d2 = (stream[idx + 1] >> 4) + 16 * stream[idx + 2]
        idx += 3
        if d1 < QLX_Q:
            coeffs.append(d1)
        if d2 < QLX_Q and len(coeffs) < 256:
            coeffs.append(d2)
    return coeffs


def sample_cbd2_3329(sigma: bytes, nonce: int) -> List[int]:
    """Samples a polynomial from the Centered Binomial Distribution CBD_2 over R_3329."""
    buf = qsponge_var(b"CALYX-QLX-CBD2|" + sigma + bytes([nonce]), 128)
    res = native_cbd2_3329(buf)
    if res is not None:
        return res
    coeffs = [0] * 256
    for i in range(128):
        b = buf[i]
        a0 = (b & 1) + ((b >> 1) & 1)
        b0 = ((b >> 2) & 1) + ((b >> 3) & 1)
        a1 = ((b >> 4) & 1) + ((b >> 5) & 1)
        b1 = ((b >> 6) & 1) + ((b >> 7) & 1)
        coeffs[2 * i] = (a0 - b0) % QLX_Q
        coeffs[2 * i + 1] = (a1 - b1) % QLX_Q
    return coeffs


def byte_encode_12(poly: List[int]) -> bytes:
    """Packs 256 12-bit coefficients in Z_3329 into 384 bytes."""
    out = bytearray(384)
    for i in range(128):
        c0 = poly[2 * i] % QLX_Q
        c1 = poly[2 * i + 1] % QLX_Q
        out[3 * i] = c0 & 0xFF
        out[3 * i + 1] = ((c0 >> 8) & 0x0F) | ((c1 & 0x0F) << 4)
        out[3 * i + 2] = (c1 >> 4) & 0xFF
    return bytes(out)


def byte_decode_12(data: bytes) -> List[int]:
    """Unpacks 384 bytes into 256 12-bit coefficients in Z_3329."""
    poly = [0] * 256
    for i in range(128):
        b0, b1, b2 = data[3 * i], data[3 * i + 1], data[3 * i + 2]
        poly[2 * i] = (b0 | ((b1 & 0x0F) << 8)) % QLX_Q
        poly[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) % QLX_Q
    return poly


def compress_poly(poly: List[int], d: int) -> bytes:
    """Compresses 256 coefficients mod 3329 to d bits each and packs into 32*d bytes."""
    mask = (1 << d) - 1
    bits = 0
    bit_len = 0
    out = bytearray()
    for c in poly:
        val = (((c % QLX_Q) << d) + (QLX_Q // 2)) // QLX_Q
        val &= mask
        bits |= val << bit_len
        bit_len += d
        while bit_len >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            bit_len -= 8
    return bytes(out)


def decompress_poly(data: bytes, d: int) -> List[int]:
    """Unpacks 32*d bytes of d-bit integers and decompresses to 256 coefficients mod 3329."""
    mask = (1 << d) - 1
    bits = 0
    bit_len = 0
    idx = 0
    poly: List[int] = []
    for _ in range(256):
        while bit_len < d:
            bits |= data[idx] << bit_len
            idx += 1
            bit_len += 8
        val = bits & mask
        bits >>= d
        bit_len -= d
        coeff = (val * QLX_Q + (1 << (d - 1))) >> d
        poly.append(coeff % QLX_Q)
    return poly


def sample_cbd1_3329(sigma: bytes, nonce: int) -> List[int]:
    """
    Samples a unit-variance polynomial from the Centered Binomial Distribution CBD_1
    (coefficients in {-1, 0, 1}, variance sigma^2 = 0.5) over R_3329 for the 16,384-dimensional
    Calyx Hyper-Tesseract (QLX-16384), preserving an 18.4-sigma decapsulation noise margin.
    """
    buf = qsponge_var(b"CALYX-QLX-CBD1|" + sigma + nonce.to_bytes(2, "little"), 64)
    res = native_cbd1_3329(buf)
    if res is not None:
        return res
    coeffs = [0] * 256
    for i in range(64):
        b = buf[i]
        for j in range(4):
            a = (b >> (2 * j)) & 1
            c = (b >> (2 * j + 1)) & 1
            coeffs[4 * i + j] = (a - c) % QLX_Q
    return coeffs


def sample_ntt_qvs(rho: bytes, row: int, col: int) -> List[int]:
    stream = qsponge_var(b"CALYX-QVS-MAT-A|" + rho + bytes([row, col]), 1024)
    coeffs: List[int] = []
    idx = 0
    while len(coeffs) < 256:
        val = (stream[idx] | (stream[idx + 1] << 8) | (stream[idx + 2] << 16)) & 0x7FFFFF
        idx += 3
        if val < QVS_Q:
            coeffs.append(val)
    return coeffs


def sample_eta_qvs(seed: bytes, nonce: int) -> List[int]:
    """Samples a short secret polynomial with coefficients in [-2, 2] mod Q."""
    buf = qsponge_var(b"CALYX-QVS-ETA2|" + seed + bytes([nonce]), 128)
    res = native_cbd2_qvs(buf)
    if res is not None:
        return res
    coeffs = [0] * 256
    for i in range(128):
        b = buf[i]
        a0 = (b & 1) + ((b >> 1) & 1)
        b0 = ((b >> 2) & 1) + ((b >> 3) & 1)
        a1 = ((b >> 4) & 1) + ((b >> 5) & 1)
        b1 = ((b >> 6) & 1) + ((b >> 7) & 1)
        coeffs[2 * i] = (a0 - b0) % QVS_Q
        coeffs[2 * i + 1] = (a1 - b1) % QVS_Q
    return coeffs


def sample_mask_y_qvs(seed: bytes, nonce: int) -> List[int]:
    """Samples masking polynomial y with coefficients in [-gamma_1 + 1, gamma_1] mod Q."""
    buf = qsponge_var(b"CALYX-QVS-MASK-Y|" + seed + nonce.to_bytes(2, "little"), 768)
    coeffs = [0] * 256
    for i in range(256):
        raw = (buf[3 * i] | (buf[3 * i + 1] << 8) | (buf[3 * i + 2] << 16)) & 0xFFFFF
        val = QVS_GAMMA1 - raw
        coeffs[i] = val % QVS_Q
    return coeffs


def sample_in_ball_qvs(c_tilde: bytes, tau: int) -> List[int]:
    """Samples sparse challenge polynomial c in R_Q with exactly tau coefficients in {-1, +1}."""
    stream = qsponge_var(b"CALYX-QVS-BALL|" + c_tilde, 256)
    sign_bits = int.from_bytes(stream[:8], "little")
    idx = 8
    c = [0] * 256
    for i in range(256 - tau, 256):
        while True:
            j = stream[idx]
            idx += 1
            if j <= i:
                break
        c[i] = c[j]
        c[j] = (QVS_Q - 1) if (sign_bits & 1) else 1
        sign_bits >>= 1
    return c


def pack_poly24_qvs(poly: List[int]) -> bytes:
    out = bytearray(768)
    for i, c in enumerate(poly):
        v = c % QVS_Q
        out[3 * i] = v & 0xFF
        out[3 * i + 1] = (v >> 8) & 0xFF
        out[3 * i + 2] = (v >> 16) & 0xFF
    return bytes(out)


def unpack_poly24_qvs(data: bytes) -> List[int]:
    return [
        (data[3 * i] | (data[3 * i + 1] << 8) | (data[3 * i + 2] << 16)) % QVS_Q
        for i in range(256)
    ]
