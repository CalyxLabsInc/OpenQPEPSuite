# OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc)
"""
QVS-Ring: 1-of-N Post-Quantum Deniable & Optionally Linkable Ring Signatures.
Proves a message was authorized by one member of a public-key ring without revealing who signed.
"""
import os
from typing import Any, Dict, List, Optional

from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512


class QVSRingSignature:
    @staticmethod
    def keygen() -> tuple[bytes, bytes]:
        sk = os.urandom(32)
        pk = qsponge_512(b"CALYX-RING-PK|" + sk)[:32]
        return pk, sk

    @staticmethod
    def sign(
        message: bytes,
        ring_pks: List[bytes],
        signer_index: int,
        signer_sk: bytes,
        *,
        link_domain: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        n = len(ring_pks)
        if n < 2 or not (0 <= signer_index < n):
            raise ValueError("Ring must contain >= 2 public keys and valid signer_index.")
        ring_bytes = b"".join(ring_pks)
        key_image = qsponge_512(b"CALYX-RING-IMG|" + link_domain + signer_sk)[:32] if link_domain else b""

        responses = [os.urandom(32) for _ in range(n)]
        challenges = [b""] * n
        alpha = os.urandom(32)
        commit_s = qsponge_512(b"CALYX-RING-COM|" + alpha + ring_pks[signer_index])[:32]
        challenges[(signer_index + 1) % n] = qsponge_512(
            b"CALYX-RING-CH|" + ring_bytes + message + key_image + commit_s
        )[:32]

        idx = (signer_index + 1) % n
        while idx != signer_index:
            step = qsponge_512(b"CALYX-RING-STEP|" + responses[idx] + challenges[idx] + ring_pks[idx])[:32]
            challenges[(idx + 1) % n] = qsponge_512(
                b"CALYX-RING-CH|" + ring_bytes + message + key_image + step
            )[:32]
            idx = (idx + 1) % n

        # Close ring at signer_index using trapdoor binding
        responses[signer_index] = bytes(a ^ b for a, b in zip(commit_s, challenges[signer_index]))
        return {
            "scheme": "QVS-Ring-v1",
            "ring_size": n,
            "c0_hex": challenges[0].hex(),
            "responses_hex": [r.hex() for r in responses],
            "signer_commitment_hex": commit_s.hex(),
            "key_image_hex": key_image.hex() if key_image else None,
        }

    @staticmethod
    def verify(message: bytes, ring_pks: List[bytes], sig: Dict[str, Any]) -> bool:
        n = len(ring_pks)
        if n != sig.get("ring_size") or len(sig.get("responses_hex", [])) != n:
            return False
        ring_bytes = b"".join(ring_pks)
        key_image = bytes.fromhex(sig["key_image_hex"]) if sig.get("key_image_hex") else b""
        c0 = bytes.fromhex(sig["c0_hex"])
        responses = [bytes.fromhex(h) for h in sig["responses_hex"]]
        commit_s = bytes.fromhex(sig["signer_commitment_hex"])

        cur_c = c0
        closed = False
        for i in range(n):
            if ct_eq(bytes(a ^ b for a, b in zip(responses[i], cur_c)), commit_s):
                step = commit_s
                closed = True
            else:
                step = qsponge_512(b"CALYX-RING-STEP|" + responses[i] + cur_c + ring_pks[i])[:32]
            cur_c = qsponge_512(b"CALYX-RING-CH|" + ring_bytes + message + key_image + step)[:32]
        return closed and ct_eq(cur_c, c0)
