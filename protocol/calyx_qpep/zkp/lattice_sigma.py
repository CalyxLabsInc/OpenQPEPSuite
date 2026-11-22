"""
Fiat-Shamir Non-Interactive Zero-Knowledge Sigma Protocol over Z_3329[X]/(X^256 + 1)
(LatticeZKProof — Official Release 1.0.0).

Official Release 1.0.0 Hardening:
  - Samples 256 independent uniform masking coefficients in Z_3329 via rejection sampling
    from qSponge-XOF (eliminating the legacy 4x periodic masking vector).
  - Canonical 12-bit byte encoding of ALL three polynomials (a_hat, t_hat, w_hat) inside the
    Fiat-Shamir transcript hash (eliminating 4-bit upper-coefficient malleability).
  - Strict coefficient range verification (0 <= c < 3329) and constant-time equality in verify().
"""
import os
from typing import Dict, List

from ..constants import QLX_Q
from ..lattice.ntt_3329 import ntt_3329, ntt_base_mul_3329
from ..lattice.poly_ring import byte_encode_12
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var


def _sample_uniform_poly_3329(seed: bytes) -> List[int]:
    """Uniform rejection sampling of 256 independent coefficients in Z_3329."""
    stream = qsponge_var(b"CALYX-ZK-MASK-v1.0.0|" + seed, 840)
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


def _zk_challenge(a_hat: List[int], t_hat: List[int], w_hat: List[int], context: bytes) -> int:
    digest = qsponge_512(
        b"CALYX-ZK-CH-v1.0.0|"
        + context
        + byte_encode_12(a_hat)
        + byte_encode_12(t_hat)
        + byte_encode_12(w_hat)
    )
    return (int.from_bytes(digest[:4], "little") % (QLX_Q - 1)) + 1


class LatticeZKProof:
    @staticmethod
    def prove(a_hat: List[int], s_hat: List[int], t_hat: List[int], context: bytes) -> Dict[str, object]:
        r_raw = _sample_uniform_poly_3329(os.urandom(32))
        r_hat = ntt_3329(r_raw)
        w_hat = ntt_base_mul_3329(a_hat, r_hat)
        c_scalar = _zk_challenge(a_hat, t_hat, w_hat, context)
        z_hat = [(r_hat[i] + c_scalar * s_hat[i]) % QLX_Q for i in range(256)]
        return {"w_hat": w_hat, "z_hat": z_hat, "c_scalar": c_scalar}

    @staticmethod
    def verify(a_hat: List[int], t_hat: List[int], context: bytes, proof: Dict[str, object]) -> bool:
        try:
            w_hat = proof["w_hat"]
            z_hat = proof["z_hat"]
            if not (isinstance(w_hat, list) and isinstance(z_hat, list) and len(w_hat) == 256 and len(z_hat) == 256):
                return False
            if any(not (isinstance(x, int) and 0 <= x < QLX_Q) for x in w_hat):
                return False
            if any(not (isinstance(x, int) and 0 <= x < QLX_Q) for x in z_hat):
                return False
            c_scalar = _zk_challenge(a_hat, t_hat, w_hat, context)
            if c_scalar != proof.get("c_scalar"):
                return False
            lhs = ntt_base_mul_3329(a_hat, z_hat)
            rhs = [(w_hat[i] + c_scalar * t_hat[i]) % QLX_Q for i in range(256)]
            return ct_eq(byte_encode_12(lhs), byte_encode_12(rhs))
        except Exception:
            return False
