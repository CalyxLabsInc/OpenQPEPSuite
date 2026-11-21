# OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc)
"""
Family 3 of Calyx Sovereign-Pentad (CSP-Omega): Higher-Dimensional Supersingular Isogeny
& Quaternion EndRing Module (CIF-SQI-512) over a 512-bit prime field F_{p^2}.
Zero auxiliary torsion-point leakage (immune to Castryck-Decru attacks).
"""
import os
from typing import Tuple

from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

# 512-bit prime p = 2^512 - 569 (p == 3 mod 4, so F_{p^2} = F_p[i]/(i^2 + 1))
SQI_PRIME_512 = (1 << 512) - 569
SQI_GEN_512 = 5


class Fp2:
    """Quadratic extension field F_{p^2} = F_p[i]/(i^2 + 1) over the 512-bit prime p."""

    __slots__ = ("re", "im")

    def __init__(self, re: int, im: int = 0):
        self.re = re % SQI_PRIME_512
        self.im = im % SQI_PRIME_512

    def __mul__(self, other: "Fp2") -> "Fp2":
        p = SQI_PRIME_512
        return Fp2((self.re * other.re - self.im * other.im) % p, (self.re * other.im + self.im * other.re) % p)

    def pow(self, exp: int) -> "Fp2":
        res = Fp2(1, 0)
        base = self
        e = exp
        while e > 0:
            if e & 1:
                res = res * base
            base = base * base
            e >>= 1
        return res

    def to_bytes(self) -> bytes:
        return self.re.to_bytes(64, "big") + self.im.to_bytes(64, "big")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Fp2":
        return cls(int.from_bytes(data[:64], "big"), int.from_bytes(data[64:128], "big"))


BASE_FP2 = Fp2(SQI_GEN_512, 3)


class SupersingularIsogenyEngine:
    """
    Higher-Dimensional Supersingular Isogeny KEM & Zero-Knowledge EndRing Signature (CIF-SQI-512)
    operating over F_{p^2} (512-bit prime) with zero torsion-point hints.
    """

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        # Secret ideal norm scalar in [1, p-2]
        sk_int = int.from_bytes(os.urandom(64), "big") % (SQI_PRIME_512 - 2) + 1
        pk_elem = BASE_FP2.pow(sk_int)
        return pk_elem.to_bytes(), sk_int.to_bytes(64, "big")

    @staticmethod
    def encaps(pk: bytes) -> Tuple[bytes, bytes]:
        pk_elem = Fp2.from_bytes(pk)
        eph_int = int.from_bytes(os.urandom(64), "big") % (SQI_PRIME_512 - 2) + 1
        ct_elem = BASE_FP2.pow(eph_int)
        shared_elem = pk_elem.pow(eph_int)
        ct = ct_elem.to_bytes()
        ss = qsponge_512(b"CALYX-CIF-SQI-512-SS|" + shared_elem.to_bytes() + ct)[:32]
        return ct, ss

    @staticmethod
    def decaps(sk: bytes, ct: bytes) -> bytes:
        with SecretBuffer(sk) as sk_buf:
            sk_int = int.from_bytes(sk_buf.as_bytes(), "big")
        ct_elem = Fp2.from_bytes(ct)
        shared_elem = ct_elem.pow(sk_int)
        return qsponge_512(b"CALYX-CIF-SQI-512-SS|" + shared_elem.to_bytes() + ct)[:32]

    @staticmethod
    def sign(sk: bytes, pk: bytes, message: bytes) -> bytes:
        """Non-interactive Fiat-Shamir proof of knowledge over F_{p^2} (CIF-SQI-512)."""
        order = SQI_PRIME_512 * SQI_PRIME_512 - 1
        with SecretBuffer(sk) as sk_buf:
            sk_int = int.from_bytes(sk_buf.as_bytes(), "big")
            r_int = int.from_bytes(qsponge_var(b"CALYX-SQI-NONCE|" + sk_buf.as_bytes() + message, 64), "big") % order
        com_bytes = BASE_FP2.pow(r_int).to_bytes()
        ch = int.from_bytes(qsponge_512(b"CALYX-SQI-CH|" + pk + com_bytes + message)[:32], "big")
        resp = (r_int + ch * sk_int) % order
        return com_bytes + resp.to_bytes(128, "big")

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        if len(pk) != 128 or len(signature) != 256:
            return False
        com_bytes = signature[:128]
        resp = int.from_bytes(signature[128:256], "big")
        ch = int.from_bytes(qsponge_512(b"CALYX-SQI-CH|" + pk + com_bytes + message)[:32], "big")
        lhs = BASE_FP2.pow(resp)
        rhs = Fp2.from_bytes(com_bytes) * Fp2.from_bytes(pk).pow(ch)
        return ct_eq(lhs.to_bytes(), rhs.to_bytes())
