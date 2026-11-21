# OpenQPEP Production Candidate 1.1.7 (v1.1.7-pc)
"""
Sequential non-parallelizable qSponge-512 hash-chain time-lock puzzle for embargoed disclosures
and dead-man's-switch capsules resistant to parallel quantum speedup.
"""
import base64
import os
from typing import Any, Dict

from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512


class TimeLockCapsule:
    @staticmethod
    def _eval_chain(seed: bytes, steps: int) -> bytes:
        cur = seed
        for _ in range(steps):
            cur = qsponge_512(b"CALYX-VDF|" + cur)
        return cur

    @staticmethod
    def seal(plaintext: bytes, steps: int = 2000) -> Dict[str, Any]:
        seed = os.urandom(32)
        key64 = TimeLockCapsule._eval_chain(seed, steps)
        nonce24 = os.urandom(24)
        ct = cc512_encrypt(key64, nonce24, plaintext, f"TIMELOCK:{steps}".encode("utf-8"))
        return {
            "scheme": "QPEP-TimeLock-VDF-v1",
            "steps": steps,
            "seed_b64": base64.b64encode(seed).decode("ascii"),
            "nonce24_b64": base64.b64encode(nonce24).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }

    @staticmethod
    def unlock(capsule: Dict[str, Any]) -> bytes:
        steps = int(capsule["steps"])
        seed = base64.b64decode(capsule["seed_b64"])
        key64 = TimeLockCapsule._eval_chain(seed, steps)
        return cc512_decrypt(key64, base64.b64decode(capsule["nonce24_b64"]), base64.b64decode(capsule["ct_b64"]), f"TIMELOCK:{steps}".encode("utf-8"))
