# OpenQPEP Production Candidate 1.1.4 (v1.1.4-pc)
"""
Fiat-Shamir non-interactive zero-knowledge sigma protocol proving knowledge of a secret
preimage over Z_3329[X]/(X^256+1) without revealing the secret vector.
"""
import os
from typing import Dict, List

from ..constants import QLX_Q
from ..lattice.ntt_3329 import ntt_3329, ntt_base_mul_3329, poly_add_3329
from ..primitives.qsponge import qsponge_512


class LatticeZKProof:
    @staticmethod
    def prove(a_hat: List[int], s_hat: List[int], t_hat: List[int], context: bytes) -> Dict[str, object]:
        r_raw = [b % QLX_Q for b in qsponge_512(b"CALYX-ZK-R|" + os.urandom(32)) * 4][:256]
        r_hat = ntt_3329(r_raw)
        w_hat = ntt_base_mul_3329(a_hat, r_hat)
        c_bytes = qsponge_512(b"CALYX-ZK-CH|" + context + bytes(x & 0xFF for x in t_hat) + bytes(x & 0xFF for x in w_hat))
        c_scalar = (int.from_bytes(c_bytes[:2], "little") % (QLX_Q - 1)) + 1
        z_hat = [(r_hat[i] + c_scalar * s_hat[i]) % QLX_Q for i in range(256)]
        return {"w_hat": w_hat, "z_hat": z_hat, "c_scalar": c_scalar}

    @staticmethod
    def verify(a_hat: List[int], t_hat: List[int], context: bytes, proof: Dict[str, object]) -> bool:
        w_hat = proof["w_hat"]
        z_hat = proof["z_hat"]
        c_bytes = qsponge_512(b"CALYX-ZK-CH|" + context + bytes(x & 0xFF for x in t_hat) + bytes(x & 0xFF for x in w_hat))
        c_scalar = (int.from_bytes(c_bytes[:2], "little") % (QLX_Q - 1)) + 1
        if c_scalar != proof["c_scalar"]:
            return False
        lhs = ntt_base_mul_3329(a_hat, z_hat)
        rhs = [(w_hat[i] + c_scalar * t_hat[i]) % QLX_Q for i in range(256)]
        return lhs == rhs
