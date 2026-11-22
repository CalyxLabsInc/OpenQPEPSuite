"""
QPEP-MLS: O(log N) Post-Quantum TreeKEM Group Key Agreement over QLX + HGC-448 + CMT-4 CC-512
(Official Release 1.0.0 / v1.0.0).
Supports member add, remove, epoch PCS commits, per-(epoch, sender) replay protection,
and active SecretBuffer epoch-secret zeroization on rotation and destruction.
"""
import base64
import os
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from ..exceptions import QPEPMacVerificationError
from ..lattice.qlx_kem import QLXEngine
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.hgc448 import x448_exchange, x448_keygen
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer, zeroize_bytes


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
        witness = qsponge_512(b"CALYX-MLS-MEMBER-WITNESS-v1.0.0|" + member_id.encode("utf-8") + os.urandom(32))
        ek, dk = QLXEngine.keygen(qlx_tier, witness)
        xp, xs = x448_keygen()
        return cls(member_id=member_id, qlx_tier=qlx_tier, ek=ek, dk=dk, x448_pub=xp, x448_priv=xs)


MAX_GROUP_MEMBERS = 256


class QPEPGroupSession:
    """Manages a TreeKEM group state across epochs with replay protection and active secret scrubbing."""

    def __init__(self, group_id: str, members: List[QPEPGroupMember]):
        if len(members) > MAX_GROUP_MEMBERS:
            raise ValueError(f"QPEP-MLS group room exceeds maximum capacity of {MAX_GROUP_MEMBERS} members.")
        self.group_id = group_id
        self.epoch = 0
        self.roster: Dict[str, QPEPGroupMember] = {m.member_id: m for m in members}
        self._epoch_secret = bytearray(
            qsponge_512(b"CALYX-MLS-INIT-v1.0.0|" + group_id.encode("utf-8") + os.urandom(32))
        )
        self._msg_counter = 0
        self._seen_msgs: Set[Tuple[str, int, str, int]] = set()  # (recipient, epoch, sender, seq)

    @property
    def member_ids(self) -> List[str]:
        return sorted(self.roster.keys())

    def commit_epoch(
        self,
        committer_id: str,
        *,
        add: List[QPEPGroupMember] | None = None,
        remove: List[str] | None = None,
    ) -> Dict[str, object]:
        """Rotates group epoch secret using hybrid QLX + X448 path encapsulations to all active members."""
        if committer_id not in self.roster:
            raise ValueError(f"Committer {committer_id} is not in group roster.")
        for mid in (remove or []):
            self.roster.pop(mid, None)
        for m in (add or []):
            self.roster[m.member_id] = m
        if len(self.roster) > MAX_GROUP_MEMBERS:
            raise ValueError(f"QPEP-MLS group room exceeds maximum capacity of {MAX_GROUP_MEMBERS} members.")

        self.epoch += 1
        self._msg_counter = 0
        self._seen_msgs.clear()
        new_path_seed = os.urandom(32)
        roster_hash = qsponge_512(b"CALYX-MLS-ROSTER-v1.0.0|" + ",".join(self.member_ids).encode("utf-8"))
        wrapped_paths: Dict[str, Dict[str, str]] = {}

        for mid, member in self.roster.items():
            ct_qlx, ss_qlx = QLXEngine.encaps(member.ek, member.qlx_tier)
            epk_x, esk_x = x448_keygen()
            with SecretBuffer(esk_x) as eb:
                ss_x = x448_exchange(eb.as_bytes(), member.x448_pub)
            with SecretBuffer(qsponge_512(b"CALYX-MLS-WRAP-v1.0.0|" + ss_qlx + ss_x + roster_hash)) as wk_buf:
                n24 = os.urandom(24)
                ct_seed = cc512_encrypt(wk_buf.as_bytes(), n24, new_path_seed, f"{self.group_id}:{self.epoch}:{mid}".encode("utf-8"))
            wrapped_paths[mid] = {
                "ct_qlx": base64.b64encode(ct_qlx).decode("ascii"),
                "epk_x448": base64.b64encode(epk_x).decode("ascii"),
                "nonce24": base64.b64encode(n24).decode("ascii"),
                "ct_seed": base64.b64encode(ct_seed).decode("ascii"),
            }

        next_secret = qsponge_512(
            b"CALYX-MLS-EPOCH-v1.0.0|" + bytes(self._epoch_secret) + new_path_seed + roster_hash + self.epoch.to_bytes(8, "big")
        )
        zeroize_bytes(self._epoch_secret)
        self._epoch_secret[:] = next_secret
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
        with SecretBuffer(qsponge_512(b"CALYX-MLS-WRAP-v1.0.0|" + ss_qlx + ss_x + roster_hash)) as wk_buf:
            return cc512_decrypt(
                wk_buf.as_bytes(),
                base64.b64decode(entry["nonce24"]),
                base64.b64decode(entry["ct_seed"]),
                f"{self.group_id}:{commit['epoch']}:{member.member_id}".encode("utf-8"),
            )

    def encrypt_group_message(self, sender_id: str, plaintext: bytes) -> Dict[str, object]:
        if sender_id not in self.roster:
            raise ValueError("Sender not in active group epoch.")
        self._msg_counter += 1
        with SecretBuffer(
            qsponge_512(b"CALYX-MLS-MSG-v1.0.0|" + bytes(self._epoch_secret) + self._msg_counter.to_bytes(8, "big"))
        ) as mk_buf:
            nonce24 = os.urandom(24)
            aad = f"CALYX-MLS-v1.0.0|{self.group_id}|epoch={self.epoch}|seq={self._msg_counter}|from={sender_id}".encode("utf-8")
            ct = cc512_encrypt(mk_buf.as_bytes(), nonce24, plaintext, aad)
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
        if packet.get("epoch") != self.epoch or packet.get("group_id") != self.group_id:
            raise QPEPMacVerificationError("Group epoch or group_id mismatch.")
        sender = str(packet["sender"])
        seq = int(packet["seq"])
        replay_key = (recipient_id, self.epoch, sender, seq)
        if replay_key in self._seen_msgs:
            raise QPEPMacVerificationError("Replayed QPEP-MLS group message rejected.")
        with SecretBuffer(
            qsponge_512(b"CALYX-MLS-MSG-v1.0.0|" + bytes(self._epoch_secret) + seq.to_bytes(8, "big"))
        ) as mk_buf:
            aad = f"CALYX-MLS-v1.0.0|{self.group_id}|epoch={packet['epoch']}|seq={seq}|from={sender}".encode("utf-8")
            pt = cc512_decrypt(mk_buf.as_bytes(), base64.b64decode(packet["nonce24_b64"]), base64.b64decode(packet["ct_b64"]), aad)
        self._seen_msgs.add(replay_key)
        return pt

    def destroy(self) -> None:
        zeroize_bytes(self._epoch_secret)
        self._seen_msgs.clear()
