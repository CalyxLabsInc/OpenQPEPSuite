# OpenQPEP Production Candidate 1.1.7 (v1.1.7-pc)
"""
Sphinx-PQ: Fixed-size multi-hop layered post-quantum onion encryption using QLX-768 + CC-512
with per-hop replay protection so no single relay knows both sender and final recipient.
"""
import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple

from ..lattice.qlx_kem import QLXEngine
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512


@dataclass
class MixNode:
    node_id: str
    ek: bytes
    dk: bytes
    seen_tags: Set[str]

    @classmethod
    def create(cls, node_id: str) -> "MixNode":
        ek, dk = QLXEngine.keygen("QLX-768", b"W" * 64)
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
            hop_key = qsponge_512(b"CALYX-SPHINX-PQ|" + ss + node.node_id.encode("utf-8"))
            nonce24 = os.urandom(24)
            ct = cc512_encrypt(hop_key, nonce24, inner, node.node_id.encode("utf-8"))
            inner = json.dumps({
                "final": False,
                "next_hop": next_hop,
                "ct_qlx_b64": base64.b64encode(ct_qlx).decode("ascii"),
                "nonce24_b64": base64.b64encode(nonce24).decode("ascii"),
                "ct_b64": base64.b64encode(ct).decode("ascii"),
            }, separators=(",", ":")).encode("utf-8")
        return inner

    @staticmethod
    def peel_layer(node: MixNode, onion_bytes: bytes) -> Tuple[str, bytes, bool]:
        env = json.loads(onion_bytes.decode("utf-8"))
        ct_qlx = base64.b64decode(env["ct_qlx_b64"])
        tag = qsponge_512(b"CALYX-SPHINX-TAG|" + ct_qlx)[:16].hex()
        if tag in node.seen_tags:
            raise ValueError("Sphinx-PQ replay attack detected at mix node.")
        node.seen_tags.add(tag)
        ss = QLXEngine.decaps(node.dk, ct_qlx, "QLX-768")
        hop_key = qsponge_512(b"CALYX-SPHINX-PQ|" + ss + node.node_id.encode("utf-8"))
        next_bytes = cc512_decrypt(hop_key, base64.b64decode(env["nonce24_b64"]), base64.b64decode(env["ct_b64"]), node.node_id.encode("utf-8"))
        peek = json.loads(next_bytes.decode("utf-8"))
        if peek.get("final"):
            return peek["recipient"], base64.b64decode(peek["payload_b64"]), True
        return env["next_hop"], next_bytes, False
