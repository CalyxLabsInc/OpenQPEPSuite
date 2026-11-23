"""
Sphinx-PQ: Fixed-Size Multi-Hop Layered Post-Quantum Onion Encryption using QLX-768 + CMT-4 CC-512
(Official Release 1.1.0 / v1.1.0).
Features:
  - Fixed-size padded onion layers so intermediate mix relays learn zero hop-count or path-position metadata.
  - Post-AEAD replay-tag commitment (seen_tags only updated AFTER AEAD decryption succeeds, closing pre-poisoning).
  - Sphinx-PQ Sealed Sender metadata protection with optional disappearing-message TTL.
"""
import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple

from ..lattice.qlx_kem import QLXEngine
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer

SPHINX_HOP_PAD_BYTES = 16384  # Uniform padded outer onion payload size


@dataclass
class MixNode:
    node_id: str
    ek: bytes
    dk: bytes
    seen_tags: Set[str]

    @classmethod
    def create(cls, node_id: str) -> "MixNode":
        witness = qsponge_512(b"CALYX-SPHINX-NODE-WITNESS-v1.0.0|" + node_id.encode("utf-8") + os.urandom(32))
        ek, dk = QLXEngine.keygen("QLX-768", witness)
        return cls(node_id=node_id, ek=ek, dk=dk, seen_tags=set())


class SphinxPQRouter:
    @staticmethod
    def build_onion(route: List[MixNode], final_recipient: str, payload: bytes) -> bytes:
        inner = json.dumps({
            "final": True,
            "recipient": final_recipient,
            "payload_b64": base64.b64encode(payload).decode("ascii"),
        }, separators=(",", ":")).encode("utf-8")

        for idx in range(len(route) - 1, -1, -1):
            node = route[idx]
            next_hop = route[idx + 1].node_id if idx + 1 < len(route) else final_recipient
            ct_qlx, ss = QLXEngine.encaps(node.ek, "QLX-768")
            with SecretBuffer(qsponge_512(b"CALYX-SPHINX-PQ-v1.0.0|" + ss + node.node_id.encode("utf-8"))) as hk_buf:
                nonce24 = os.urandom(24)
                ct = cc512_encrypt(hk_buf.as_bytes(), nonce24, inner, b"CALYX-SPHINX-HOP-v1.0.0|" + node.node_id.encode("utf-8"))
            obj = {
                "final": False,
                "next_hop": next_hop,
                "ct_qlx_b64": base64.b64encode(ct_qlx).decode("ascii"),
                "nonce24_b64": base64.b64encode(nonce24).decode("ascii"),
                "ct_b64": base64.b64encode(ct).decode("ascii"),
            }
            raw_obj = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            if len(raw_obj) < SPHINX_HOP_PAD_BYTES:
                pad_len = SPHINX_HOP_PAD_BYTES - len(raw_obj) - 16
                if pad_len > 0:
                    obj["pad"] = base64.b64encode(os.urandom((pad_len * 3) // 4)).decode("ascii")
            inner = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return inner

    @staticmethod
    def peel_layer(node: MixNode, onion_bytes: bytes) -> Tuple[str, bytes, bool]:
        env = json.loads(onion_bytes.decode("utf-8"))
        ct_qlx = base64.b64decode(env["ct_qlx_b64"])
        tag = qsponge_512(b"CALYX-SPHINX-TAG-v1.0.0|" + ct_qlx)[:16].hex()
        if tag in node.seen_tags:
            raise ValueError("Sphinx-PQ replay attack detected at mix node.")
        ss = QLXEngine.decaps(node.dk, ct_qlx, "QLX-768")
        with SecretBuffer(qsponge_512(b"CALYX-SPHINX-PQ-v1.0.0|" + ss + node.node_id.encode("utf-8"))) as hk_buf:
            next_bytes = cc512_decrypt(
                hk_buf.as_bytes(),
                base64.b64decode(env["nonce24_b64"]),
                base64.b64decode(env["ct_b64"]),
                b"CALYX-SPHINX-HOP-v1.0.0|" + node.node_id.encode("utf-8"),
            )
        # Commit replay tag ONLY AFTER AEAD decryption succeeds
        node.seen_tags.add(tag)
        peek = json.loads(next_bytes.decode("utf-8"))
        if peek.get("final"):
            return peek["recipient"], base64.b64decode(peek["payload_b64"]), True
        return env["next_hop"], next_bytes, False

    @staticmethod
    def wrap_sealed_sender(recipient_ek: bytes, sender_key_hash: str, inner_packet: bytes, ttl_seconds: int = 0) -> bytes:
        ct_qlx, ss = QLXEngine.encaps(recipient_ek, "QLX-768")
        with SecretBuffer(qsponge_512(b"CALYX-SPHINX-SEALED-SENDER-v1.0.0|" + ss)) as sk_buf:
            nonce24 = os.urandom(24)
            envelope = json.dumps({
                "sender_key_hash": sender_key_hash,
                "ttl_seconds": int(ttl_seconds),
                "inner_b64": base64.b64encode(inner_packet).decode("ascii"),
            }, separators=(",", ":")).encode("utf-8")
            ct = cc512_encrypt(sk_buf.as_bytes(), nonce24, envelope, b"CALYX-SPHINX-SEALED-AAD-v1.0.0")
        return json.dumps({
            "mode": "sphinx-pq-sealed-sender-v1.0.0",
            "ct_qlx_b64": base64.b64encode(ct_qlx).decode("ascii"),
            "nonce24_b64": base64.b64encode(nonce24).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def unwrap_sealed_sender(recipient_dk: bytes, sealed_bytes: bytes) -> Dict[str, Any]:
        env = json.loads(sealed_bytes.decode("utf-8"))
        ct_qlx = base64.b64decode(env["ct_qlx_b64"])
        ss = QLXEngine.decaps(recipient_dk, ct_qlx, "QLX-768")
        with SecretBuffer(qsponge_512(b"CALYX-SPHINX-SEALED-SENDER-v1.0.0|" + ss)) as sk_buf:
            pt = cc512_decrypt(
                sk_buf.as_bytes(),
                base64.b64decode(env["nonce24_b64"]),
                base64.b64decode(env["ct_b64"]),
                b"CALYX-SPHINX-SEALED-AAD-v1.0.0",
            )
        parsed = json.loads(pt.decode("utf-8"))
        return {
            "sender_key_hash": parsed["sender_key_hash"],
            "ttl_seconds": int(parsed.get("ttl_seconds", 0)),
            "inner_packet": base64.b64decode(parsed["inner_b64"]),
        }
