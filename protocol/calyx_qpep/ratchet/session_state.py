"""
QPEP-Ratchet Stateful Session Machine (Official Release 1.0.0).
Implements:
  - Per-message symmetric CMT-4 CC-512 ratcheting (Forward Secrecy)
  - Periodic hybrid QLX + HGC-448 asymmetric re-encapsulation WITH ephemeral key rotation (true PCS)
  - Atomic state commitment: decrypt() verifies the CMT-4 CC-512 AEAD tag BEFORE mutating
    _root_key, _recv_ck, recv_epoch, recv_count, peer ephemeral keys, or _skipped_keys
    (eliminating forged-epoch DoS / state desynchronization attacks!)
  - Bounded out-of-order skipped-key cache (MAX_SKIP = 256) with TTL expiration RAM scrubbing
"""
import base64
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from ..constants import PACKET_TYPE_RATCHET, PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..exceptions import QPEPMacVerificationError, QPEPWireFormatError
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_var
from ..primitives.zeroize import SecretBuffer, zeroize_bytes
from ..wire.armor import armor_unwrap, armor_wrap
from .kdf_chain import kdf_chain_step, kdf_root_step
from .pq_rekey import (
    generate_ephemeral_ratchet_keypair,
    perform_pq_rekey_decaps,
    perform_pq_rekey_encaps,
)

RATCHET_ARMOR_LABEL = "CALYX QPEP RATCHET MESSAGE"
MAX_SKIP = 256
DEFAULT_REKEY_MESSAGES = 16
DEFAULT_REKEY_SECONDS = 3600
DEFAULT_SKIPPED_TTL_SECONDS = 86400


class QPEPRatchetSession:
    """
    Stateful Post-Quantum Double Ratchet session supporting Forward Secrecy (FS),
    true rotating-ephemeral Post-Compromise Security (PCS), atomic AEAD-before-commit state
    transitions, and out-of-order message delivery.
    """

    def __init__(
        self,
        *,
        role: str,
        root_key: bytes,
        send_chain_key: bytes,
        recv_chain_key: bytes,
        my_ephemeral: Dict[str, bytes],
        peer_qlx_pk: bytes,
        peer_hgc_pk: bytes,
        qlx_tier: str = "QLX-4096",
        rekey_interval_messages: int = DEFAULT_REKEY_MESSAGES,
        rekey_interval_seconds: int = DEFAULT_REKEY_SECONDS,
        skipped_key_ttl_seconds: int = DEFAULT_SKIPPED_TTL_SECONDS,
    ):
        self.role = role
        self.qlx_tier = qlx_tier
        self._root_key = bytearray(root_key)
        self._send_ck = bytearray(send_chain_key)
        self._recv_ck = bytearray(recv_chain_key)
        self._my_qlx_pk = bytes(my_ephemeral["qlx_pk"])
        self._my_qlx_sk = bytearray(my_ephemeral["qlx_sk"])
        self._my_hgc_pk = bytes(my_ephemeral["hgc_pk"])
        self._my_hgc_sk = bytearray(my_ephemeral["hgc_sk"])
        # Retain previous ephemeral secret until peer acknowledges rotation on incoming rekey
        self._prev_qlx_sk: Optional[bytearray] = None
        self._prev_hgc_sk: Optional[bytearray] = None
        self._peer_qlx_pk = bytes(peer_qlx_pk)
        self._peer_hgc_pk = bytes(peer_hgc_pk)

        self.send_epoch = 0
        self.recv_epoch = 0
        self.send_count = 0
        self.recv_count = 0
        self.prev_send_count = 0

        self.rekey_interval_messages = max(1, int(rekey_interval_messages))
        self.rekey_interval_seconds = max(1, int(rekey_interval_seconds))
        self.skipped_key_ttl_seconds = max(1, int(skipped_key_ttl_seconds))
        self.last_rekey_ts = time.time()

        self._skipped_keys: Dict[Tuple[int, int], Tuple[bytearray, bytes, float]] = {}
        self._destroyed = False

    @classmethod
    def create_pair(
        cls,
        shared_master_secret: bytes,
        qlx_tier: str = "QLX-4096",
        rekey_interval_messages: int = DEFAULT_REKEY_MESSAGES,
        rekey_interval_seconds: int = DEFAULT_REKEY_SECONDS,
        skipped_key_ttl_seconds: int = DEFAULT_SKIPPED_TTL_SECONDS,
    ) -> Tuple["QPEPRatchetSession", "QPEPRatchetSession"]:
        rk = qsponge_var(b"CALYX-RATCHET-INIT-RK-v1.0.0|" + shared_master_secret, 32)
        ck_a2b = qsponge_var(b"CALYX-RATCHET-INIT-A2B-v1.0.0|" + shared_master_secret, 32)
        ck_b2a = qsponge_var(b"CALYX-RATCHET-INIT-B2A-v1.0.0|" + shared_master_secret, 32)

        eph_a = generate_ephemeral_ratchet_keypair(qlx_tier)
        eph_b = generate_ephemeral_ratchet_keypair(qlx_tier)

        alice = cls(
            role="initiator",
            root_key=rk,
            send_chain_key=ck_a2b,
            recv_chain_key=ck_b2a,
            my_ephemeral=eph_a,
            peer_qlx_pk=eph_b["qlx_pk"],
            peer_hgc_pk=eph_b["hgc_pk"],
            qlx_tier=qlx_tier,
            rekey_interval_messages=rekey_interval_messages,
            rekey_interval_seconds=rekey_interval_seconds,
            skipped_key_ttl_seconds=skipped_key_ttl_seconds,
        )
        bob = cls(
            role="responder",
            root_key=rk,
            send_chain_key=ck_b2a,
            recv_chain_key=ck_a2b,
            my_ephemeral=eph_b,
            peer_qlx_pk=eph_a["qlx_pk"],
            peer_hgc_pk=eph_a["hgc_pk"],
            qlx_tier=qlx_tier,
            rekey_interval_messages=rekey_interval_messages,
            rekey_interval_seconds=rekey_interval_seconds,
            skipped_key_ttl_seconds=skipped_key_ttl_seconds,
        )
        return alice, bob

    def _ensure_active(self) -> None:
        if self._destroyed:
            raise RuntimeError("QPEPRatchetSession has been destroyed and zeroized.")

    def purge_expired_skipped_keys(self, now_ts: Optional[float] = None) -> int:
        now = time.time() if now_ts is None else now_ts
        expired = [k for k, (_, _, ts) in self._skipped_keys.items() if (now - ts) >= self.skipped_key_ttl_seconds]
        for k in expired:
            mk_buf, _, _ = self._skipped_keys.pop(k)
            zeroize_bytes(mk_buf)
        return len(expired)

    def _compute_skipped_steps(
        self, start_ck: bytes, epoch: int, start_num: int, target_num: int
    ) -> Tuple[bytes, List[Tuple[Tuple[int, int], bytearray, bytes, float]]]:
        """Purely computes skipped keys without mutating session state until AEAD verifies."""
        if target_num - start_num > MAX_SKIP:
            raise QPEPWireFormatError(f"Ratchet skip count exceeds MAX_SKIP ({MAX_SKIP}).")
        now = time.time()
        ck = start_ck
        cnt = start_num
        staged: List[Tuple[Tuple[int, int], bytearray, bytes, float]] = []
        while cnt < target_num:
            next_ck, mk64, n24 = kdf_chain_step(ck)
            staged.append(((epoch, cnt), bytearray(mk64), n24, now))
            ck = next_ck
            cnt += 1
        return ck, staged

    def _commit_staged_skipped(self, staged: List[Tuple[Tuple[int, int], bytearray, bytes, float]]) -> None:
        for key, mk_buf, n24, ts in staged:
            if len(self._skipped_keys) >= MAX_SKIP:
                oldest_key = min(self._skipped_keys.items(), key=lambda item: item[1][2])[0]
                old_buf, _, _ = self._skipped_keys.pop(oldest_key)
                zeroize_bytes(old_buf)
            self._skipped_keys[key] = (mk_buf, n24, ts)

    def encrypt(self, plaintext: bytes, force_pq_rekey: bool = False) -> str:
        """
        Encrypts `plaintext` under the next one-way CMT-4 CC-512 ratchet message key.
        On PCS rekey, rotates local ephemeral ratchet keypair and advertises the new public keys
        inside the authenticated header so the peer heals to fresh keys on its next rekey.
        """
        self._ensure_active()
        now = time.time()
        rekey_hdr: Optional[Dict[str, str]] = None

        need_rekey = (
            force_pq_rekey
            or (self.send_count > 0 and self.send_count >= self.rekey_interval_messages)
            or (now - self.last_rekey_ts >= self.rekey_interval_seconds)
        )
        if need_rekey:
            fresh_eph = generate_ephemeral_ratchet_keypair(self.qlx_tier)
            rekey_hdr, hybrid_ss = perform_pq_rekey_encaps(
                self._peer_qlx_pk,
                self._peer_hgc_pk,
                qlx_tier=self.qlx_tier,
                advertised_qlx_pk=fresh_eph["qlx_pk"],
                advertised_hgc_pk=fresh_eph["hgc_pk"],
            )
            # Rotate local ephemeral keypair (keep previous until next incoming rekey for in-flight safety)
            if self._prev_qlx_sk is not None:
                zeroize_bytes(self._prev_qlx_sk)
            if self._prev_hgc_sk is not None:
                zeroize_bytes(self._prev_hgc_sk)
            self._prev_qlx_sk = bytearray(self._my_qlx_sk)
            self._prev_hgc_sk = bytearray(self._my_hgc_sk)
            zeroize_bytes(self._my_qlx_sk)
            zeroize_bytes(self._my_hgc_sk)
            self._my_qlx_pk = fresh_eph["qlx_pk"]
            self._my_qlx_sk = bytearray(fresh_eph["qlx_sk"])
            self._my_hgc_pk = fresh_eph["hgc_pk"]
            self._my_hgc_sk = bytearray(fresh_eph["hgc_sk"])

            new_rk, new_send_ck = kdf_root_step(bytes(self._root_key), hybrid_ss)
            zeroize_bytes(self._root_key)
            zeroize_bytes(self._send_ck)
            self._root_key[:] = new_rk
            self._send_ck[:] = new_send_ck
            self.prev_send_count = self.send_count
            self.send_epoch += 1
            self.send_count = 0
            self.last_rekey_ts = now

        next_ck, msg_key64, nonce24 = kdf_chain_step(bytes(self._send_ck))
        zeroize_bytes(self._send_ck)
        self._send_ck[:] = next_ck
        msg_num = self.send_count
        self.send_count += 1

        header = {
            "type": "openqpep-ratchet-msg",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "epoch": self.send_epoch,
            "msg_num": msg_num,
            "prev_chain_len": self.prev_send_count,
            "pq_rekey": rekey_hdr,
        }
        aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with SecretBuffer(msg_key64) as mk_buf:
            ct = cc512_encrypt(mk_buf.as_bytes(), nonce24, plaintext, aad)

        packet_obj = {
            "header": header,
            "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
        }
        return armor_wrap(
            RATCHET_ARMOR_LABEL,
            json.dumps(packet_obj, separators=(",", ":")).encode("utf-8"),
            packet_type=PACKET_TYPE_RATCHET,
        )

    def decrypt(self, armored_packet: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Decrypts an incoming QPEP-Ratchet packet with ATOMIC state transition:
        AEAD verification succeeds BEFORE any root/chain/epoch/peer-key state is committed.
        """
        self._ensure_active()
        self.purge_expired_skipped_keys()

        raw_json, _ = armor_unwrap(armored_packet, RATCHET_ARMOR_LABEL)
        packet_obj = json.loads(raw_json.decode("utf-8"))
        header = packet_obj.get("header") or {}
        if header.get("type") != "openqpep-ratchet-msg":
            raise QPEPWireFormatError("Not a valid OpenQPEP Ratchet message.")

        epoch = int(header["epoch"])
        msg_num = int(header["msg_num"])
        prev_len = int(header.get("prev_chain_len", 0))
        ct = base64.b64decode(packet_obj["ciphertext_b64"])
        aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # 1. Check out-of-order skipped-key cache first (non-destructive peek until AEAD passes)
        cache_key = (epoch, msg_num)
        if cache_key in self._skipped_keys:
            mk_buf, n24, _ = self._skipped_keys[cache_key]
            pt = cc512_decrypt(bytes(mk_buf), n24, ct, aad)
            popped_buf, _, _ = self._skipped_keys.pop(cache_key)
            zeroize_bytes(popped_buf)
            return pt, {"epoch": epoch, "msg_num": msg_num, "from_skipped_cache": True, "pcs_rekey": False}

        # 2. Stage candidate state (NO mutation until AEAD decrypt passes!)
        staged_skipped: List[Tuple[Tuple[int, int], bytearray, bytes, float]] = []
        cand_rk = bytes(self._root_key)
        cand_recv_ck = bytes(self._recv_ck)
        cand_recv_epoch = self.recv_epoch
        cand_recv_count = self.recv_count
        pcs_rekeyed = False
        new_peer_qlx_pk: Optional[bytes] = None
        new_peer_hgc_pk: Optional[bytes] = None

        if epoch > self.recv_epoch:
            rekey_hdr = header.get("pq_rekey")
            if not rekey_hdr:
                raise QPEPWireFormatError("Ratchet epoch advanced without a hybrid QLX+HGC-448 PCS rekey header.")
            if prev_len > self.recv_count:
                _, prev_staged = self._compute_skipped_steps(cand_recv_ck, self.recv_epoch, self.recv_count, prev_len)
                staged_skipped.extend(prev_staged)

            # Try current ephemeral secret key first; fallback to previous if in-flight crossover occurred
            key_candidates = [(bytes(self._my_qlx_sk), bytes(self._my_hgc_sk))]
            if self._prev_qlx_sk is not None and self._prev_hgc_sk is not None:
                key_candidates.append((bytes(self._prev_qlx_sk), bytes(self._prev_hgc_sk)))

            decrypted_pt: Optional[bytes] = None
            final_next_ck: bytes = b""
            final_staged = list(staged_skipped)
            for qlx_sk_c, hgc_sk_c in key_candidates:
                try:
                    hybrid_ss = perform_pq_rekey_decaps(qlx_sk_c, hgc_sk_c, rekey_hdr, qlx_tier=self.qlx_tier)
                    rk_try, ck_try = kdf_root_step(cand_rk, hybrid_ss)
                    ck_try, cur_staged = self._compute_skipped_steps(ck_try, epoch, 0, msg_num)
                    next_ck_try, msg_key64, nonce24 = kdf_chain_step(ck_try)
                    with SecretBuffer(msg_key64) as mk_buf:
                        decrypted_pt = cc512_decrypt(mk_buf.as_bytes(), nonce24, ct, aad)
                    cand_rk = rk_try
                    final_next_ck = next_ck_try
                    final_staged = staged_skipped + cur_staged
                    break
                except Exception:
                    continue

            if decrypted_pt is None:
                for _, mb, _, _ in staged_skipped:
                    zeroize_bytes(mb)
                raise QPEPMacVerificationError("QPEP-Ratchet PCS epoch AEAD verification failed; session state preserved.")

            if "new_peer_qlx_pk_b64" in rekey_hdr and "new_peer_hgc_pk_b64" in rekey_hdr:
                new_peer_qlx_pk = base64.b64decode(rekey_hdr["new_peer_qlx_pk_b64"])
                new_peer_hgc_pk = base64.b64decode(rekey_hdr["new_peer_hgc_pk_b64"])

            # Atomic commit AFTER AEAD authentication passed
            zeroize_bytes(self._root_key)
            zeroize_bytes(self._recv_ck)
            self._root_key[:] = cand_rk
            self._recv_ck[:] = final_next_ck
            self.recv_epoch = epoch
            self.recv_count = msg_num + 1
            self._commit_staged_skipped(final_staged)
            if new_peer_qlx_pk is not None and new_peer_hgc_pk is not None:
                self._peer_qlx_pk = new_peer_qlx_pk
                self._peer_hgc_pk = new_peer_hgc_pk
            return decrypted_pt, {"epoch": epoch, "msg_num": msg_num, "from_skipped_cache": False, "pcs_rekey": True}

        if epoch < self.recv_epoch:
            raise QPEPMacVerificationError("Message from expired ratchet epoch not found in skipped-key cache.")

        if msg_num < self.recv_count:
            raise QPEPMacVerificationError("Duplicate or replayed ratchet message index.")
        if msg_num > self.recv_count:
            cand_recv_ck, staged_skipped = self._compute_skipped_steps(cand_recv_ck, epoch, self.recv_count, msg_num)

        next_ck, msg_key64, nonce24 = kdf_chain_step(cand_recv_ck)
        try:
            with SecretBuffer(msg_key64) as mk_buf:
                pt = cc512_decrypt(mk_buf.as_bytes(), nonce24, ct, aad)
        except Exception:
            for _, mb, _, _ in staged_skipped:
                zeroize_bytes(mb)
            raise

        # Atomic commit AFTER AEAD authentication passed
        zeroize_bytes(self._recv_ck)
        self._recv_ck[:] = next_ck
        self.recv_count = msg_num + 1
        self._commit_staged_skipped(staged_skipped)
        return pt, {"epoch": epoch, "msg_num": msg_num, "from_skipped_cache": False, "pcs_rekey": pcs_rekeyed}

    def destroy(self) -> None:
        """Actively zeroizes all session keys, ephemeral private keys, and skipped keys in RAM."""
        if not self._destroyed:
            zeroize_bytes(self._root_key)
            zeroize_bytes(self._send_ck)
            zeroize_bytes(self._recv_ck)
            zeroize_bytes(self._my_qlx_sk)
            zeroize_bytes(self._my_hgc_sk)
            if self._prev_qlx_sk is not None:
                zeroize_bytes(self._prev_qlx_sk)
            if self._prev_hgc_sk is not None:
                zeroize_bytes(self._prev_hgc_sk)
            for mk_buf, _, _ in self._skipped_keys.values():
                zeroize_bytes(mk_buf)
            self._skipped_keys.clear()
            self._destroyed = True
