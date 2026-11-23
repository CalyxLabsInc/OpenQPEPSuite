# OpenQPEP Official Release 1.1.0 (v1.1.0)
"""
Rateless Luby-Transform (LT) QR Fountain Codec for transferring 24–69 KB PQ keys/packets
over air-gapped cameras with automatic drop resilience and qSponge-512 integrity check.
"""
import base64
import hmac
import json
import random
from typing import Dict, List, Optional, Set, Tuple

from ..primitives.qsponge import qsponge_512


class QRFountainEncoder:
    def __init__(self, payload: bytes, block_size: int = 256):
        self.payload = payload
        self.total_len = len(payload)
        self.block_size = block_size
        self.digest = qsponge_512(payload)[:16].hex()
        padded = payload + b"\x00" * ((block_size - (len(payload) % block_size)) % block_size)
        self.blocks = [padded[i : i + block_size] for i in range(0, len(padded), block_size)] or [b"\x00" * block_size]
        self.k = len(self.blocks)

    def next_frame(self, seq: int) -> str:
        if seq < self.k:
            indices = [seq]
        else:
            rng = random.Random(seq ^ 0x51504550)  # non-cryptographic deterministic Luby-Transform fountain schedule
            deg = min(self.k, rng.randint(1, min(3, self.k)))
            indices = sorted(rng.sample(range(self.k), deg))
        xored = bytearray(self.block_size)
        for idx in indices:
            blk = self.blocks[idx]
            for i in range(self.block_size):
                xored[i] ^= blk[i]
        return json.dumps({
            "v": "qpep-qr-fountain-1",
            "k": self.k,
            "n": self.total_len,
            "bs": self.block_size,
            "d": self.digest,
            "idx": indices,
            "b": base64.b64encode(bytes(xored)).decode("ascii"),
        }, separators=(",", ":"))


class QRFountainDecoder:
    def __init__(self):
        self.k: Optional[int] = None
        self.total_len: int = 0
        self.digest: str = ""
        self.solved: Dict[int, bytes] = {}
        self.pending: List[Tuple[Set[int], bytearray]] = []

    def feed_frame(self, frame_str: str) -> Optional[bytes]:
        obj = json.loads(frame_str)
        k = int(obj["k"])
        total_len = int(obj["n"])
        digest = str(obj["d"])
        if k <= 0 or k > 65536 or total_len < 0 or total_len > 16 * 1024 * 1024:
            raise ValueError("QR Fountain frame parameters out of safe bounds.")
        if self.k is None:
            self.k = k
            self.total_len = total_len
            self.digest = digest
        elif self.k != k or self.total_len != total_len or not hmac.compare_digest(self.digest, digest):
            raise ValueError("QR Fountain frame stream metadata mismatch.")
        indices = set(int(i) for i in obj["idx"])
        if not indices or any(i < 0 or i >= self.k for i in indices):
            raise ValueError("QR Fountain frame contains out-of-range block index.")
        data = bytearray(base64.b64decode(obj["b"]))

        # Peel already-solved blocks
        for idx in list(indices):
            if idx in self.solved:
                blk = self.solved[idx]
                if len(blk) != len(data):
                    raise ValueError("QR Fountain block length mismatch.")
                for i in range(len(data)):
                    data[i] ^= blk[i]
                indices.remove(idx)

        if len(indices) == 1:
            only = next(iter(indices))
            self.solved[only] = bytes(data)
            self._propagate()
        elif len(indices) > 1:
            self.pending.append((indices, data))

        if self.k is not None and len(self.solved) == self.k:
            raw = b"".join(self.solved[i] for i in range(self.k))[: self.total_len]
            if not hmac.compare_digest(qsponge_512(raw)[:16].hex(), self.digest):
                raise ValueError("QR Fountain integrity digest mismatch.")
            return raw
        return None

    def _propagate(self) -> None:
        changed = True
        while changed:
            changed = False
            remaining = []
            for indices, data in self.pending:
                for idx in list(indices):
                    if idx in self.solved:
                        blk = self.solved[idx]
                        for i in range(len(data)):
                            data[i] ^= blk[i]
                        indices.remove(idx)
                if len(indices) == 1:
                    only = next(iter(indices))
                    self.solved[only] = bytes(data)
                    changed = True
                elif len(indices) > 1:
                    remaining.append((indices, data))
            self.pending = remaining
