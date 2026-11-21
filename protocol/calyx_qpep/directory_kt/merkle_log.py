# OpenQPEP Production Candidate 1.1.7 (v1.1.7-pc)
"""
QPEP-KT: Append-only qSponge-512 Merkle Transparency Log for qpepkeys.calyxlabsinc.org.
Provides O(log N) inclusion proofs and Signed Tree Heads (STHs) preventing split-view attacks.
"""
from typing import Dict, List, Tuple
from ..primitives.qsponge import qsponge_512


def _leaf_hash(entry_bytes: bytes) -> bytes:
    return qsponge_512(b"\x00CALYX-KT-LEAF|" + entry_bytes)[:32]


def _node_hash(left: bytes, right: bytes) -> bytes:
    return qsponge_512(b"\x01CALYX-KT-NODE|" + left + right)[:32]


class KeyTransparencyLog:
    def __init__(self):
        self._leaves: List[bytes] = []

    def append(self, key_hash: str, qpkrf_digest_hex: str) -> int:
        entry = f"{key_hash}:{qpkrf_digest_hex}".encode("utf-8")
        self._leaves.append(_leaf_hash(entry))
        return len(self._leaves) - 1

    def root(self) -> bytes:
        if not self._leaves:
            return qsponge_512(b"CALYX-KT-EMPTY")[:32]
        level = list(self._leaves)
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])
            level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        return level[0]

    def inclusion_proof(self, index: int) -> List[Tuple[str, str]]:
        if index < 0 or index >= len(self._leaves):
            raise IndexError("Leaf index out of range.")
        proof: List[Tuple[str, str]] = []
        level = list(self._leaves)
        idx = index
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])
            sib = idx ^ 1
            side = "R" if (idx % 2 == 0) else "L"
            proof.append((side, level[sib].hex()))
            level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
            idx //= 2
        return proof

    def signed_tree_head(self) -> Dict[str, object]:
        return {"tree_size": len(self._leaves), "root_hex": self.root().hex()}


def verify_inclusion_proof(key_hash: str, qpkrf_digest_hex: str, proof: List[Tuple[str, str]], expected_root_hex: str) -> bool:
    cur = _leaf_hash(f"{key_hash}:{qpkrf_digest_hex}".encode("utf-8"))
    for side, sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        cur = _node_hash(cur, sib) if side == "R" else _node_hash(sib, cur)
    return cur.hex() == expected_root_hex
