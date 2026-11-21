"""
QPEP-Ratchet Stateful Session Machine (Production Candidate 1.1.4).
Implements:
  - Per-message symmetric CC-512 ratcheting (Forward Secrecy)
  - Periodic hybrid QLX + HGC-448 asymmetric re-encapsulation every M messages or T seconds (PCS)
  - Bounded out-of-order skipped-key cache (MAX_SKIP = 256) with TTL expiration RAM scrubbing
"""
import base64
import json
import time
from typing import Any, Dict, Optional, Tuple

from ..constants import PROTOCOL_VERSION, UNIVERSAL_VERSION
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
    Post-Compromise Security (PCS), and out-of-order message delivery.
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

        # Bounded skipped-key cache: (epoch, msg_num) -> (msg_key_bytearray, nonce24_bytes, created_ts)
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
        """
        Bootstraps a synchronized (initiator, responder) QPEP-Ratchet session pair from
        an initial shared secret (e.g. from an initial QLX + HGC-448 handshake).
        """
        rk = qsponge_var(b"CALYX-RATCHET-INIT-RK|" + shared_master_secret, 32)
        ck_a2b = qsponge_var(b"CALYX-RATCHET-INIT-A2B|" + shared_master_secret, 32)
        ck_b2a = qsponge_var(b"CALYX-RATCHET-INIT-B2A|" + shared_master_secret, 32)

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
        """Zeroizes via ctypes.memset and evicts any skipped message keys past TTL."""
        now = time.time() if now_ts is None else now_ts
        expired = [k for k, (_, _, ts) in self._skipped_keys.items() if (now - ts) >= self.skipped_key_ttl_seconds]
        for k in expired:
            mk_buf, _, _ = self._skipped_keys.pop(k)
            zeroize_bytes(mk_buf)
        return len(expired)

    def _skip_recv_keys_until(self, target_num: int) -> None:
        if target_num - self.recv_count > MAX_SKIP:
            raise QPEPWireFormatError(f"Ratchet skip count exceeds MAX_SKIP ({MAX_SKIP}).")
        now = time.time()
        while self.recv_count < target_num:
            if len(self._skipped_keys) >= MAX_SKIP:
                # Evict and zeroize oldest skipped key to maintain strict MAX_SKIP memory bound
                oldest_key = min(self._skipped_keys.items(), key=lambda item: item[1][2])[0]
                old_buf, _, _ = self._skipped_keys.pop(oldest_key)
                zeroize_bytes(old_buf)
            next_ck, mk64, n24 = kdf_chain_step(bytes(self._recv_ck))
            zeroize_bytes(self._recv_ck)
            self._recv_ck[:] = next_ck
            self._skipped_keys[(self.recv_epoch, self.recv_count)] = (bytearray(mk64), n24, now)
            self.recv_count += 1

    def encrypt(self, plaintext: bytes, force_pq_rekey: bool = False) -> str:
        """
        Encrypts `plaintext` under the next one-way CC-512 ratchet message key.
        Automatically performs a fresh hybrid QLX + HGC-448 PCS re-encapsulation when
        send_count >= rekey_interval_messages or elapsed time >= rekey_interval_seconds.
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
            rekey_hdr, hybrid_ss = perform_pq_rekey_encaps(
                self._peer_qlx_pk, self._peer_hgc_pk, qlx_tier=self.qlx_tier
            )
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
        return armor_wrap(RATCHET_ARMOR_LABEL, json.dumps(packet_obj, separators=(",", ":")).encode("utf-8"))

    def decrypt(self, armored_packet: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Decrypts an incoming QPEP-Ratchet packet, handling out-of-order skipped keys and
        periodic hybrid QLX + HGC-448 PCS rekey epochs transparently.
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

        # 1. Check out-of-order skipped-key cache first
        cache_key = (epoch, msg_num)
        if cache_key in self._skipped_keys:
            mk_buf, n24, _ = self._skipped_keys.pop(cache_key)
            try:
                pt = cc512_decrypt(bytes(mk_buf), n24, ct, aad)
            finally:
                zeroize_bytes(mk_buf)
            return pt, {"epoch": epoch, "msg_num": msg_num, "from_skipped_cache": True, "pcs_rekey": False}

        # 2. Handle incoming PCS QLX + HGC-448 rekey epoch advancement
        pcs_rekeyed = False
        if epoch > self.recv_epoch:
            rekey_hdr = header.get("pq_rekey")
            if not rekey_hdr:
                raise QPEPWireFormatError("Ratchet epoch advanced without a hybrid QLX+HGC-448 PCS rekey header.")
            # Save any still-unreceived messages from the previous epoch into the skipped-key cache
            if prev_len > self.recv_count:
                self._skip_recv_keys_until(prev_len)
            hybrid_ss = perform_pq_rekey_decaps(
                bytes(self._my_qlx_sk), bytes(self._my_hgc_sk), rekey_hdr, qlx_tier=self.qlx_tier
            )
            new_rk, new_recv_ck = kdf_root_step(bytes(self._root_key), hybrid_ss)
            zeroize_bytes(self._root_key)
            zeroize_bytes(self._recv_ck)
            self._root_key[:] = new_rk
            self._recv_ck[:] = new_recv_ck
            self.recv_epoch = epoch
            self.recv_count = 0
            pcs_rekeyed = True
        elif epoch < self.recv_epoch:
            raise QPEPMacVerificationError("Message from expired ratchet epoch not found in skipped-key cache.")

        # 3. Advance receiving chain to msg_num (caching any skipped intermediate keys)
        if msg_num < self.recv_count:
            raise QPEPMacVerificationError("Duplicate or replayed ratchet message index.")
        if msg_num > self.recv_count:
            self._skip_recv_keys_until(msg_num)

        next_ck, msg_key64, nonce24 = kdf_chain_step(bytes(self._recv_ck))
        zeroize_bytes(self._recv_ck)
        self._recv_ck[:] = next_ck
        self.recv_count += 1

        with SecretBuffer(msg_key64) as mk_buf:
            pt = cc512_decrypt(mk_buf.as_bytes(), nonce24, ct, aad)
        return pt, {"epoch": epoch, "msg_num": msg_num, "from_skipped_cache": False, "pcs_rekey": pcs_rekeyed}

    def destroy(self) -> None:
        """Actively zeroizes all session keys, ephemeral private keys, and skipped keys in RAM."""
        if not self._destroyed:
            zeroize_bytes(self._root_key)
            zeroize_bytes(self._send_ck)
            zeroize_bytes(self._recv_ck)
            zeroize_bytes(self._my_qlx_sk)
            zeroize_bytes(self._my_hgc_sk)
            for mk_buf, _, _ in self._skipped_keys.values():
                zeroize_bytes(mk_buf)
            self._skipped_keys.clear()
            self._destroyed = True
