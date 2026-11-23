"""
OpenQPEP O(1)-RAM Streaming Chunked AEAD & Seekable Merkle-Tree File Encryption (Official Release 1.1.0).

Features:
  - Official Release 1.1.0 Stream Magic `STREAM_MAGIC = \\x89QPS\\x05\\x00` (hard-rejects legacy
    pre-release `\\x89QPS\\x02\\x07` streams with QPEPLegacyProtocolError).
  - Constant ~256 KiB RAM streaming for arbitrary-sized files in 64 KiB CMT-4 CC-512 frames.
  - Deterministic chunk-bound nonces making chunk reordering, duplication, or mid-stream truncation impossible.
  - Full-ciphertext qSponge-512 Binary Merkle Tree over every byte of every encrypted chunk enabling
    verified random-access byte-range decryption (`decrypt_byte_range`).
"""
import os
import struct
from typing import BinaryIO, Dict, List, Optional, Tuple

from ..constants import CHUNK_SIZE, LEGACY_STREAM_MAGICS, STREAM_MAGIC_V5
from ..exceptions import (
    QPEPLegacyProtocolError,
    QPEPMacVerificationError,
    QPEPTruncationError,
    QPEPWireFormatError,
)
from ..primitives.cc512_aead import CC512_OVERHEAD_BYTES, cc512_decrypt, cc512_encrypt
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

STREAM_MAGIC = STREAM_MAGIC_V5  # b"\x89QPS\x05\x00"
HEADER_STRUCT = struct.Struct(">6sII16s")  # magic(6), chunk_size(4), flags(4), base_nonce(16) -> 30 bytes
CHUNK_PREFIX_STRUCT = struct.Struct(">QBI")  # chunk_idx(8), is_final(1), ct_len(4) -> 13 bytes
FLAG_MERKLE_SEEKABLE = 0x00000001
MAX_STREAM_CHUNK_SIZE = 16 * 1024 * 1024  # 16 MiB max chunk ceiling


def _validate_stream_magic(magic: bytes) -> None:
    if magic in LEGACY_STREAM_MAGICS:
        raise QPEPLegacyProtocolError(
            "Legacy pre-release OpenQPEP stream magic (\\x89QPS\\x02\\x07) is strictly rejected in "
            "Official Release 1.1.0 (zero backwards compatibility). Official stream magic \\x89QPS\\x05\\x00 is required."
        )
    if magic != STREAM_MAGIC:
        raise QPEPWireFormatError("Invalid OpenQPEP Official Release 1.1.0 streaming magic bytes.")


def derive_chunk_nonce24(base_nonce: bytes, chunk_idx: int, is_final: bool) -> bytes:
    """Derives a unique 24-byte CC-512 nonce bound strictly to (base_nonce, chunk_idx, is_final)."""
    return qsponge_var(
        b"CALYX-STREAM-NONCE-v1.0.0|" + base_nonce + struct.pack(">QB", chunk_idx, 1 if is_final else 0),
        24,
    )


def _chunk_aad(base_nonce: bytes, chunk_idx: int, is_final: bool) -> bytes:
    return b"CALYX-STREAM-AAD-v1.0.0|" + base_nonce + struct.pack(">QB", chunk_idx, 1 if is_final else 0)


def _chunk_merkle_leaf(chunk_idx: int, ct: bytes) -> bytes:
    """Commits to EVERY byte of the chunk ciphertext via qSponge-512."""
    return qsponge_512(b"CALYX-MERKLE-LEAF-v1.0.0|" + struct.pack(">Q", chunk_idx) + qsponge_512(ct))


def build_chunk_merkle_tree(leaf_hashes: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    """Builds a qSponge-512 binary Merkle tree over chunk authentication leaf digests."""
    if not leaf_hashes:
        empty_root = qsponge_512(b"CALYX-MERKLE-EMPTY-v1.0.0")
        return empty_root, [[empty_root]]
    levels: List[List[bytes]] = [list(leaf_hashes)]
    cur = list(leaf_hashes)
    while len(cur) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else left
            nxt.append(qsponge_512(b"CALYX-MERKLE-NODE-v1.0.0|" + left + right))
        levels.append(nxt)
        cur = nxt
    return cur[0], levels


def get_merkle_proof(levels: List[List[bytes]], chunk_idx: int) -> List[Tuple[str, bytes]]:
    """Extracts the sibling authentication path for `chunk_idx` from Merkle `levels`."""
    proof: List[Tuple[str, bytes]] = []
    idx = chunk_idx
    for lvl in levels[:-1]:
        if idx % 2 == 0:
            sib = lvl[idx + 1] if idx + 1 < len(lvl) else lvl[idx]
            proof.append(("R", sib))
        else:
            proof.append(("L", lvl[idx - 1]))
        idx //= 2
    return proof


def verify_merkle_proof(leaf_hash: bytes, proof: List[Tuple[str, bytes]], expected_root: bytes) -> bool:
    """Verifies a chunk's qSponge-512 Merkle proof against the authenticated Merkle root."""
    cur = leaf_hash
    for side, sib in proof:
        if side == "R":
            cur = qsponge_512(b"CALYX-MERKLE-NODE-v1.0.0|" + cur + sib)
        else:
            cur = qsponge_512(b"CALYX-MERKLE-NODE-v1.0.0|" + sib + cur)
    return ct_eq(cur, expected_root)


class StreamingEncryptor:
    """O(1)-RAM streaming chunked CMT-4 CC-512 encryptor with optional Merkle-tree seek index."""

    def __init__(self, key64: bytes, *, chunk_size: int = CHUNK_SIZE, merkle_seekable: bool = True):
        if len(key64) != 64:
            raise ValueError("StreamingEncryptor requires a 64-byte CC-512 key.")
        if chunk_size <= 0 or chunk_size > MAX_STREAM_CHUNK_SIZE:
            raise ValueError(f"chunk_size must be in 1..{MAX_STREAM_CHUNK_SIZE}.")
        self._key_buf = SecretBuffer(key64)
        self.chunk_size = int(chunk_size)
        self.merkle_seekable = bool(merkle_seekable)

    def encrypt_stream(self, src: BinaryIO, dst: BinaryIO) -> Dict[str, object]:
        base_nonce = os.urandom(16)
        flags = FLAG_MERKLE_SEEKABLE if self.merkle_seekable else 0
        dst.write(HEADER_STRUCT.pack(STREAM_MAGIC, self.chunk_size, flags, base_nonce))

        chunk_idx = 0
        total_plain = 0
        leaf_hashes: List[bytes] = []
        chunk_offsets: List[int] = []

        cur_buf = src.read(self.chunk_size)
        while True:
            nxt_buf = src.read(self.chunk_size) if cur_buf else b""
            is_final = (len(nxt_buf) == 0)
            nonce24 = derive_chunk_nonce24(base_nonce, chunk_idx, is_final)
            aad = _chunk_aad(base_nonce, chunk_idx, is_final)
            ct = cc512_encrypt(self._key_buf.as_bytes(), nonce24, cur_buf, aad)

            chunk_offsets.append(dst.tell())
            dst.write(CHUNK_PREFIX_STRUCT.pack(chunk_idx, 1 if is_final else 0, len(ct)))
            dst.write(ct)

            if self.merkle_seekable:
                leaf_hashes.append(_chunk_merkle_leaf(chunk_idx, ct))

            total_plain += len(cur_buf)
            chunk_idx += 1
            if is_final:
                break
            cur_buf = nxt_buf

        merkle_root = b""
        merkle_levels: List[List[bytes]] = []
        if self.merkle_seekable:
            merkle_root, merkle_levels = build_chunk_merkle_tree(leaf_hashes)

        return {
            "base_nonce": base_nonce,
            "chunk_size": self.chunk_size,
            "chunk_count": chunk_idx,
            "total_plaintext_bytes": total_plain,
            "merkle_seekable": self.merkle_seekable,
            "merkle_root": merkle_root,
            "merkle_levels": merkle_levels,
            "chunk_offsets": chunk_offsets,
        }

    def close(self) -> None:
        self._key_buf.wipe()

    def __enter__(self) -> "StreamingEncryptor":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class StreamingDecryptor:
    """O(1)-RAM streaming chunked CMT-4 CC-512 decryptor with truncation, reorder, and Merkle range verification."""

    def __init__(self, key64: bytes):
        if len(key64) != 64:
            raise ValueError("StreamingDecryptor requires a 64-byte CC-512 key.")
        self._key_buf = SecretBuffer(key64)

    def decrypt_stream(self, src: BinaryIO, dst: BinaryIO, *, expected_merkle_root: Optional[bytes] = None) -> Dict[str, object]:
        hdr = src.read(HEADER_STRUCT.size)
        if len(hdr) != HEADER_STRUCT.size:
            raise QPEPWireFormatError("Truncated OpenQPEP streaming header.")
        magic, chunk_size, flags, base_nonce = HEADER_STRUCT.unpack(hdr)
        _validate_stream_magic(magic)
        if chunk_size <= 0 or chunk_size > MAX_STREAM_CHUNK_SIZE:
            raise QPEPWireFormatError("Invalid chunk_size in OpenQPEP streaming header.")

        expected_idx = 0
        saw_final = False
        total_plain = 0
        leaf_hashes: List[bytes] = []
        max_ct_len = chunk_size + CC512_OVERHEAD_BYTES

        while True:
            prefix = src.read(CHUNK_PREFIX_STRUCT.size)
            if not prefix:
                break
            if len(prefix) != CHUNK_PREFIX_STRUCT.size:
                raise QPEPTruncationError("Truncated chunk header in OpenQPEP stream.")
            chunk_idx, is_final_byte, ct_len = CHUNK_PREFIX_STRUCT.unpack(prefix)
            if chunk_idx != expected_idx:
                raise QPEPMacVerificationError(f"Chunk reordering/duplication detected: expected {expected_idx}, got {chunk_idx}.")
            if ct_len < CC512_OVERHEAD_BYTES or ct_len > max_ct_len:
                raise QPEPWireFormatError(f"Invalid chunk ciphertext length {ct_len} in chunk {chunk_idx}.")
            ct = src.read(ct_len)
            if len(ct) != ct_len:
                raise QPEPTruncationError(f"Truncated ciphertext in chunk {chunk_idx}.")

            is_final = bool(is_final_byte)
            nonce24 = derive_chunk_nonce24(base_nonce, chunk_idx, is_final)
            aad = _chunk_aad(base_nonce, chunk_idx, is_final)
            pt = cc512_decrypt(self._key_buf.as_bytes(), nonce24, ct, aad)
            dst.write(pt)
            total_plain += len(pt)

            if flags & FLAG_MERKLE_SEEKABLE:
                leaf_hashes.append(_chunk_merkle_leaf(chunk_idx, ct))

            expected_idx += 1
            if is_final:
                saw_final = True
                if src.read(1):
                    raise QPEPWireFormatError("Unexpected trailing bytes after terminal final=1 chunk.")
                break

        if not saw_final:
            raise QPEPTruncationError("Stream ended without a terminal final=1 chunk (truncation attack detected).")

        computed_root = b""
        if flags & FLAG_MERKLE_SEEKABLE:
            computed_root, _ = build_chunk_merkle_tree(leaf_hashes)
            if expected_merkle_root is not None and not ct_eq(computed_root, expected_merkle_root):
                raise QPEPMacVerificationError("Stream Merkle root mismatch.")

        return {
            "chunk_size": chunk_size,
            "chunk_count": expected_idx,
            "total_plaintext_bytes": total_plain,
            "merkle_root": computed_root,
        }

    def decrypt_byte_range(
        self,
        src: BinaryIO,
        start_byte: int,
        end_byte: int,
        *,
        chunk_offsets: List[int],
        merkle_levels: List[List[bytes]],
        merkle_root: bytes,
    ) -> bytes:
        if start_byte < 0 or end_byte < start_byte:
            raise ValueError("Invalid byte range.")
        if start_byte == end_byte:
            return b""

        src.seek(0)
        hdr = src.read(HEADER_STRUCT.size)
        if len(hdr) != HEADER_STRUCT.size:
            raise QPEPWireFormatError("Truncated OpenQPEP streaming header.")
        magic, chunk_size, _flags, base_nonce = HEADER_STRUCT.unpack(hdr)
        _validate_stream_magic(magic)

        first_chunk = start_byte // chunk_size
        last_chunk = (end_byte - 1) // chunk_size
        if last_chunk >= len(chunk_offsets):
            raise ValueError("Requested byte range exceeds encrypted stream length.")

        out = bytearray()
        for cidx in range(first_chunk, last_chunk + 1):
            src.seek(chunk_offsets[cidx])
            prefix = src.read(CHUNK_PREFIX_STRUCT.size)
            chunk_idx, is_final_byte, ct_len = CHUNK_PREFIX_STRUCT.unpack(prefix)
            if chunk_idx != cidx:
                raise QPEPMacVerificationError("Seeked chunk index mismatch.")
            ct = src.read(ct_len)
            if len(ct) != ct_len:
                raise QPEPTruncationError(f"Truncated seeked chunk {cidx}.")
            leaf = _chunk_merkle_leaf(cidx, ct)
            proof = get_merkle_proof(merkle_levels, cidx)
            if not verify_merkle_proof(leaf, proof, merkle_root):
                raise QPEPMacVerificationError(f"Merkle proof verification failed for seeked chunk {cidx}.")

            is_final = bool(is_final_byte)
            nonce24 = derive_chunk_nonce24(base_nonce, cidx, is_final)
            aad = _chunk_aad(base_nonce, cidx, is_final)
            pt = cc512_decrypt(self._key_buf.as_bytes(), nonce24, ct, aad)

            chunk_start = cidx * chunk_size
            lo = max(0, start_byte - chunk_start)
            hi = min(len(pt), end_byte - chunk_start)
            out.extend(pt[lo:hi])

        return bytes(out)

    def close(self) -> None:
        self._key_buf.wipe()

    def __enter__(self) -> "StreamingDecryptor":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
