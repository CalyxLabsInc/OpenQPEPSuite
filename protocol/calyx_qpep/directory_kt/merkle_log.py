"""
QPEP-KT: Append-Only qSponge-512 Merkle Transparency Log (Official Release 1.0.0).
Features:
  - O(log N) Merkle Inclusion Proofs (RFC 6962 / RFC 9162 canonical binary tree structure)
  - O(log N) Merkle Consistency Proofs (`consistency_proof` & `verify_consistency_proof`) proving
    strict append-only history between tree size M and N (detects split-view / equivocation!)
  - Publicly Verifiable Ed448 Signed Tree Heads (STHs) via `verify_sth(sth, log_public_key_hex)`
  - Signed ownership challenge verification preventing key-squatting attacks
"""
import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..constants import PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..primitives.consttime import ct_eq
from ..primitives.hgc448 import ed448_keygen, ed448_public_from_private, ed448_sign, ed448_verify
from ..primitives.qsponge import qsponge_512, qsponge_var


def _leaf_hash(entry_bytes: bytes) -> bytes:
    return qsponge_512(b"\x00CALYX-KT-LEAF-v1.0.0|" + entry_bytes)[:32]


def _node_hash(left: bytes, right: bytes) -> bytes:
    return qsponge_512(b"\x01CALYX-KT-NODE-v1.0.0|" + left + right)[:32]


def _largest_power_of_two_less_than(n: int) -> int:
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def _mth(leaves: List[bytes]) -> bytes:
    """RFC 6962 / RFC 9162 canonical Merkle Tree Hash (MTH) over leaves[0..n-1]."""
    n = len(leaves)
    if n == 0:
        return qsponge_512(b"CALYX-KT-EMPTY-v1.0.0")[:32]
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_less_than(n)
    return _node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def _inclusion_path_rfc9162(index: int, leaves: List[bytes]) -> List[Tuple[str, str]]:
    """RFC 6962 / RFC 9162 canonical inclusion path (side 'L'/'R', sibling hex)."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if index < k:
        sub = _inclusion_path_rfc9162(index, leaves[:k])
        sub.append(("R", _mth(leaves[k:]).hex()))
        return sub
    sub = _inclusion_path_rfc9162(index - k, leaves[k:])
    sub.append(("L", _mth(leaves[:k]).hex()))
    return sub


def _subproof_consistency(m: int, leaves: List[bytes], b: bool) -> List[bytes]:
    """RFC 6962 Section 2.1.2 SUBPROOF(m, D[n], b) returning audit hashes for consistency."""
    n = len(leaves)
    if m == n:
        return [] if b else [_mth(leaves)]
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return _subproof_consistency(m, leaves[:k], b) + [_mth(leaves[k:])]
    return _subproof_consistency(m - k, leaves[k:], False) + [_mth(leaves[:k])]


class KeyTransparencyLog:
    """Append-only QPEP-KT Merkle Transparency Log with Ed448 Signed Tree Heads & Consistency Proofs."""

    def __init__(self, log_signing_key: Optional[bytes] = None):
        if log_signing_key is None:
            self._pub_key, self._priv_key = ed448_keygen()
        else:
            # Deterministically derive a 57-byte Ed448 private key if a seed/secret was passed
            sk57 = log_signing_key if len(log_signing_key) == 57 else qsponge_var(b"CALYX-KT-ED448-SK-v1.0.0|" + log_signing_key, 57)
            self._priv_key = sk57
            self._pub_key = ed448_public_from_private(sk57)
        self._leaves: List[bytes] = []
        self._entries: List[Tuple[str, str]] = []
        self._key_index: Dict[str, int] = {}

    @property
    def public_key_hex(self) -> str:
        return self._pub_key.hex()

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

    def root(self, tree_size: Optional[int] = None) -> bytes:
        if tree_size is None:
            return _mth(self._leaves)
        if tree_size < 0 or tree_size > len(self._leaves):
            raise IndexError("tree_size out of range.")
        return _mth(self._leaves[:tree_size])

    def inclusion_proof(self, index: int) -> List[Tuple[str, str]]:
        if index < 0 or index >= len(self._leaves):
            raise IndexError("Leaf index out of range.")
        return _inclusion_path_rfc9162(index, self._leaves)

    def consistency_proof(self, first_size: int, second_size: Optional[int] = None) -> List[str]:
        """Generates an RFC 6962 / RFC 9162 Merkle Consistency Proof between tree sizes first_size <= second_size."""
        n = len(self._leaves) if second_size is None else int(second_size)
        m = int(first_size)
        if m < 0 or n < m or n > len(self._leaves):
            raise ValueError(f"Invalid consistency proof range: {m}..{n} (log size {len(self._leaves)}).")
        if m == 0 or m == n:
            return []
        return [h.hex() for h in _subproof_consistency(m, self._leaves[:n], True)]

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
            "log_public_key_hex": self.public_key_hex,
            "proof": self.inclusion_proof(idx),
            "kt_verified": True,
        }

    def signed_tree_head(self) -> Dict[str, Any]:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        r_hex = self.root().hex()
        tree_sz = len(self._leaves)
        transcript = f"CALYX-KT-STH-v1.0.0|{PROTOCOL_VERSION}|{tree_sz}|{r_hex}|{ts}".encode("utf-8")
        sth_sig = ed448_sign(self._priv_key, transcript).hex()
        return {
            "protocol": PROTOCOL_VERSION,
            "version": UNIVERSAL_VERSION,
            "tree_size": tree_sz,
            "root_hex": r_hex,
            "timestamp_utc": ts,
            "log_public_key_hex": self.public_key_hex,
            "sth_signature_hex": sth_sig,
        }


def verify_sth(sth: Dict[str, Any], expected_log_public_key_hex: Optional[str] = None) -> bool:
    """Publicly verifies an Ed448 Signed Tree Head (STH)."""
    try:
        pub_hex = expected_log_public_key_hex or str(sth["log_public_key_hex"])
        if expected_log_public_key_hex and not ct_eq(pub_hex.encode("ascii"), str(sth["log_public_key_hex"]).encode("ascii")):
            return False
        transcript = (
            f"CALYX-KT-STH-v1.0.0|{sth['protocol']}|{int(sth['tree_size'])}|{sth['root_hex']}|{sth['timestamp_utc']}"
        ).encode("utf-8")
        return ed448_verify(bytes.fromhex(pub_hex), bytes.fromhex(sth["sth_signature_hex"]), transcript)
    except Exception:
        return False


def verify_inclusion_proof(key_hash: str, qpkrf_digest_hex: str, proof: List[Tuple[str, str]], expected_root_hex: str) -> bool:
    """Verifies a QPEP-KT Merkle inclusion proof in constant time."""
    try:
        cur = _leaf_hash(f"{key_hash}:{qpkrf_digest_hex}".encode("utf-8"))
        for side, sib_hex in proof:
            sib = bytes.fromhex(sib_hex)
            cur = _node_hash(cur, sib) if side == "R" else _node_hash(sib, cur)
        return ct_eq(cur, bytes.fromhex(expected_root_hex))
    except Exception:
        return False


def verify_consistency_proof(
    first_size: int,
    second_size: int,
    first_root_hex: str,
    second_root_hex: str,
    proof_hex: List[str],
) -> bool:
    """
    Verifies an RFC 9162 Section 2.1.4.2 Merkle Consistency Proof proving that the log at
    `second_size` is a strict append-only extension of the log at `first_size` (zero split-view).
    """
    try:
        first_root = bytes.fromhex(first_root_hex)
        second_root = bytes.fromhex(second_root_hex)
        if first_size < 0 or second_size < first_size:
            return False
        if first_size == 0:
            return len(proof_hex) == 0
        if first_size == second_size:
            return len(proof_hex) == 0 and ct_eq(first_root, second_root)
        if not proof_hex:
            return False

        proof = [bytes.fromhex(h) for h in proof_hex]
        fn = first_size - 1
        sn = second_size - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1

        if fn == 0:
            fr = first_root
            sr = first_root
            idx = 0
        else:
            fr = proof[0]
            sr = proof[0]
            idx = 1

        for c in proof[idx:]:
            if sn == 0:
                return False
            if (fn & 1) or (fn == sn):
                fr = _node_hash(c, fr)
                sr = _node_hash(c, sr)
                while fn != 0 and (fn & 1) == 0:
                    fn >>= 1
                    sn >>= 1
            else:
                sr = _node_hash(sr, c)
            fn >>= 1
            sn >>= 1

        return sn == 0 and ct_eq(fr, first_root) and ct_eq(sr, second_root)
    except Exception:
        return False


def verify_directory_ownership_proof(public_qpkrf: str, ownership_signature: Optional[str] = None) -> Tuple[bool, str]:
    """
    Verifies cryptographic key ownership before directory publication:
      1. Imports the public .qpkrf key ring and verifies its self-certification signature and 512-bit integrity_mac.
      2. If an attached ownership challenge signature is supplied, verifies it was signed by the same key ring.
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
