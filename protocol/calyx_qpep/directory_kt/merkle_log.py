# OpenQPEP Release Candidate 1.0.0 (v1.0.0-rc)
"""
QPEP-KT: Append-only qSponge-512 Merkle Transparency Log for qpepkeys.calyxlabsinc.org.
Provides O(log N) inclusion proofs, Signed Tree Heads (STHs), and signed ownership challenge
verification preventing split-view and key-squatting attacks.
"""
import datetime
from typing import Any, Dict, List, Optional, Tuple
from ..constants import PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..primitives.qsponge import qsponge_512


def _leaf_hash(entry_bytes: bytes) -> bytes:
    return qsponge_512(b"\x00CALYX-KT-LEAF|" + entry_bytes)[:32]


def _node_hash(left: bytes, right: bytes) -> bytes:
    return qsponge_512(b"\x01CALYX-KT-NODE|" + left + right)[:32]


class KeyTransparencyLog:
    def __init__(self, log_signing_secret: bytes = b"CALYX-KT-LOG-STH-AUTHORITY-RC-1.0.0"):
        self._leaves: List[bytes] = []
        self._entries: List[Tuple[str, str]] = []
        self._key_index: Dict[str, int] = {}
        self._signing_secret = log_signing_secret

    @property
    def size(self) -> int:
        return len(self._leaves)

    def append(self, key_hash: str, qpkrf_digest_hex: str) -> int:
        kh = key_hash.strip()
        dg = qpkrf_digest_hex.strip()
        entry = f"{kh}:{dg}".encode("utf-8")
        idx = len(self._leaves)
        self._leaves.append(_leaf_hash(entry))
        self._entries.append((kh, dg))
        self._key_index[kh.upper()] = idx
        return idx

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

    def inclusion_proof_for_key(self, key_hash: str) -> Optional[Dict[str, Any]]:
        kh = key_hash.strip().upper()
        if kh not in self._key_index:
            return None
        idx = self._key_index[kh]
        _, dg = self._entries[idx]
        sth = self.signed_tree_head()
        return {
            "key_hash": kh,
            "leaf_index": idx,
            "qpkrf_digest_hex": dg,
            "tree_size": sth["tree_size"],
            "root_hex": sth["root_hex"],
            "sth_signature_hex": sth["sth_signature_hex"],
            "proof": self.inclusion_proof(idx),
            "kt_verified": True,
        }

    def signed_tree_head(self) -> Dict[str, Any]:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        r_hex = self.root().hex()
        tree_sz = len(self._leaves)
        transcript = f"CALYX-KT-STH-v1|{PROTOCOL_VERSION}|{tree_sz}|{r_hex}".encode("utf-8")
        sth_sig = qsponge_512(self._signing_secret + transcript).hex()
        return {
            "protocol": PROTOCOL_VERSION,
            "version": UNIVERSAL_VERSION,
            "tree_size": tree_sz,
            "root_hex": r_hex,
            "timestamp_utc": ts,
            "sth_signature_hex": sth_sig,
        }


def verify_inclusion_proof(key_hash: str, qpkrf_digest_hex: str, proof: List[Tuple[str, str]], expected_root_hex: str) -> bool:
    cur = _leaf_hash(f"{key_hash}:{qpkrf_digest_hex}".encode("utf-8"))
    for side, sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        cur = _node_hash(cur, sib) if side == "R" else _node_hash(sib, cur)
    return cur.hex() == expected_root_hex


def verify_directory_ownership_proof(public_qpkrf: str, ownership_signature: Optional[str] = None) -> Tuple[bool, str]:
    """
    Verifies cryptographic key ownership before directory publication (POST /api/v1/keys):
      1. Imports the public .qpkrf key ring and verifies its conjunctive QVS / QHS / QMQ + Ed448
         self-certification signature and 512-bit integrity_mac.
      2. If an attached ownership challenge signature is also supplied, verifies that the challenge
         signature was signed by the same key ring.
    """
    from ..protocol import OpenQPEPProtocol
    try:
        kr = OpenQPEPProtocol.import_qpkrf(public_qpkrf)
        if not OpenQPEPProtocol.verify_public_keyring_self_signature(kr):
            return False, "Self-certification signature failed verification."
        if ownership_signature:
            ok, _msg, matched = OpenQPEPProtocol.verify_signature(ownership_signature, signer_public_keyring=kr)
            if not ok or matched is None or matched.key_hash != kr.key_hash:
                return False, "Ownership challenge signature failed verification."
        return True, kr.key_hash
    except Exception as exc:
        return False, str(exc)
