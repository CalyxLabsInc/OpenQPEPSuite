# OpenQPEP Production Candidate 1.1.7 (v1.1.7-pc)
"""
Conflict-free LWW-Element-Map CRDT with per-operation CC-512 encryption for zero-knowledge
multi-device synchronization of contact keyrings, subkeys, and messenger state.
"""
import base64
import json
import os
from typing import Any, Dict, Tuple

from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt


class EncryptedLWWMapCRDT:
    def __init__(self, device_id: str, sync_key64: bytes):
        self.device_id = device_id
        self._key = sync_key64
        self._clock = 0
        self._state: Dict[str, Tuple[int, str, Any]] = {}

    def set(self, key: str, value: Any) -> Dict[str, str]:
        self._clock += 1
        op = {"k": key, "v": value, "ts": self._clock, "dev": self.device_id}
        self._apply_local(op)
        nonce24 = os.urandom(24)
        ct = cc512_encrypt(self._key, nonce24, json.dumps(op, separators=(",", ":")).encode("utf-8"), b"CRDT-OP")
        return {"nonce24_b64": base64.b64encode(nonce24).decode("ascii"), "ct_b64": base64.b64encode(ct).decode("ascii")}

    def merge_encrypted_op(self, enc_op: Dict[str, str]) -> None:
        raw = cc512_decrypt(self._key, base64.b64decode(enc_op["nonce24_b64"]), base64.b64decode(enc_op["ct_b64"]), b"CRDT-OP")
        op = json.loads(raw.decode("utf-8"))
        self._clock = max(self._clock, int(op["ts"]))
        self._apply_local(op)

    def _apply_local(self, op: Dict[str, Any]) -> None:
        k, ts, dev = op["k"], int(op["ts"]), op["dev"]
        cur = self._state.get(k)
        if cur is None or (ts, dev) > (cur[0], cur[1]):
            self._state[k] = (ts, dev, op["v"])

    def snapshot(self) -> Dict[str, Any]:
        return {k: v[2] for k, v in self._state.items()}
