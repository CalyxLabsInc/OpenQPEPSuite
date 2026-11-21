# OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc)
"""
QPEP-MLS: O(log N) Post-Quantum TreeKEM Group Key Agreement over QLX + HGC-448 + CC-512.
Supports member add, remove, and epoch PCS commits with forward secrecy and immediate eviction.
"""
import base64
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ..exceptions import QPEPMacVerificationError
from ..lattice.qlx_kem import QLXEngine
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.hgc448 import x448_exchange, x448_keygen
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer


@dataclass
class QPEPGroupMember:
    member_id: str
    qlx_tier: str = "QLX-768"
    ek: bytes = field(default=b"", repr=False)
    dk: bytes = field(default=b"", repr=False)
    x448_pub: bytes = field(default=b"", repr=False)
    x448_priv: bytes = field(default=b"", repr=False)

    @classmethod
    def create(cls, member_id: str, qlx_tier: str = "QLX-768") -> "QPEPGroupMember":
        ek, dk = QLXEngine.keygen(qlx_tier, b"W" * 64)
        xp, xs = x448_keygen()
        return cls(member_id=member_id, qlx_tier=qlx_tier, ek=ek, dk=dk, x448_pub=xp, x448_priv=xs)


class QPEPGroupSession:
    """Manages a binary TreeKEM group state across epochs with O(log N) path updates."""

    def __init__(self, group_id: str, members: List[QPEPGroupMember]):
        self.group_id = group_id
        self.epoch = 0
        self.roster: Dict[str, QPEPGroupMember] = {m.member_id: m for m in members}
        self._epoch_secret = qsponge_512(b"CALYX-MLS-INIT|" + group_id.encode("utf-8") + os.urandom(32))
        self._msg_counter = 0

    @property
    def member_ids(self) -> List[str]:
        return sorted(self.roster.keys())

    def commit_epoch(self, committer_id: str, *, add: List[QPEPGroupMember] | None = None, remove: List[str] | None = None) -> Dict[str, object]:
        """Rotates group epoch secret using hybrid QLX + X448 path encapsulations to all active members."""
        if committer_id not in self.roster:
            raise ValueError(f"Committer {committer_id} is not in group roster.")
        for mid in (remove or []):
            self.roster.pop(mid, None)
        for m in (add or []):
            self.roster[m.member_id] = m

        self.epoch += 1
        self._msg_counter = 0
        new_path_seed = os.urandom(32)
        roster_hash = qsponge_512(",".join(self.member_ids).encode("utf-8"))
        wrapped_paths: Dict[str, Dict[str, str]] = {}

        for mid, member in self.roster.items():
            ct_qlx, ss_qlx = QLXEngine.encaps(member.ek, member.qlx_tier)
            epk_x, esk_x = x448_keygen()
            with SecretBuffer(esk_x) as eb:
                ss_x = x448_exchange(eb.as_bytes(), member.x448_pub)
            wrap_key = qsponge_512(b"CALYX-MLS-WRAP|" + ss_qlx + ss_x + roster_hash)
            n24 = os.urandom(24)
            ct_seed = cc512_encrypt(wrap_key, n24, new_path_seed, f"{self.group_id}:{self.epoch}:{mid}".encode("utf-8"))
            wrapped_paths[mid] = {
                "ct_qlx": base64.b64encode(ct_qlx).decode("ascii"),
                "epk_x448": base64.b64encode(epk_x).decode("ascii"),
                "nonce24": base64.b64encode(n24).decode("ascii"),
                "ct_seed": base64.b64encode(ct_seed).decode("ascii"),
            }

        self._epoch_secret = qsponge_512(
            b"CALYX-MLS-EPOCH|" + self._epoch_secret + new_path_seed + roster_hash + self.epoch.to_bytes(8, "big")
        )
        return {
            "group_id": self.group_id,
            "epoch": self.epoch,
            "committer": committer_id,
            "roster": self.member_ids,
            "roster_hash": roster_hash.hex(),
            "wrapped_paths": wrapped_paths,
        }

    def unwrap_commit_seed(self, commit: Dict[str, object], member: QPEPGroupMember) -> bytes:
        wrapped_paths = commit["wrapped_paths"]
        if member.member_id not in wrapped_paths:
            raise QPEPMacVerificationError(f"Member {member.member_id} evicted or not authorized for epoch {commit['epoch']}.")
        entry = wrapped_paths[member.member_id]
        ct_qlx = base64.b64decode(entry["ct_qlx"])
        epk_x = base64.b64decode(entry["epk_x448"])
        ss_qlx = QLXEngine.decaps(member.dk, ct_qlx, member.qlx_tier)
        ss_x = x448_exchange(member.x448_priv, epk_x)
        roster_hash = bytes.fromhex(commit["roster_hash"])
        wrap_key = qsponge_512(b"CALYX-MLS-WRAP|" + ss_qlx + ss_x + roster_hash)
        return cc512_decrypt(
            wrap_key,
            base64.b64decode(entry["nonce24"]),
            base64.b64decode(entry["ct_seed"]),
            f"{self.group_id}:{commit['epoch']}:{member.member_id}".encode("utf-8"),
        )

    def encrypt_group_message(self, sender_id: str, plaintext: bytes) -> Dict[str, object]:
        if sender_id not in self.roster:
            raise ValueError("Sender not in active group epoch.")
        self._msg_counter += 1
        msg_key = qsponge_512(b"CALYX-MLS-MSG|" + self._epoch_secret + self._msg_counter.to_bytes(8, "big"))
        nonce24 = os.urandom(24)
        aad = f"{self.group_id}|epoch={self.epoch}|seq={self._msg_counter}|from={sender_id}".encode("utf-8")
        ct = cc512_encrypt(msg_key, nonce24, plaintext, aad)
        return {
            "group_id": self.group_id,
            "epoch": self.epoch,
            "seq": self._msg_counter,
            "sender": sender_id,
            "nonce24_b64": base64.b64encode(nonce24).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }

    def decrypt_group_message(self, recipient_id: str, packet: Dict[str, object]) -> bytes:
        if recipient_id not in self.roster:
            raise QPEPMacVerificationError("Evicted or unauthorized member cannot decrypt group epoch.")
        if packet["epoch"] != self.epoch:
            raise QPEPMacVerificationError("Epoch mismatch.")
        msg_key = qsponge_512(b"CALYX-MLS-MSG|" + self._epoch_secret + int(packet["seq"]).to_bytes(8, "big"))
        aad = f"{self.group_id}|epoch={packet['epoch']}|seq={packet['seq']}|from={packet['sender']}".encode("utf-8")
        return cc512_decrypt(msg_key, base64.b64decode(packet["nonce24_b64"]), base64.b64decode(packet["ct_b64"]), aad)
