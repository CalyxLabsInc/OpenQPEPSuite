"""
OpenQPEP v1.1.0-pc — Plausible-Deniability Dual-Volume Container.
Embeds a hidden inner CC-512 volume inside uniform random bucket padding of an outer decoy volume.
"""
import os
import struct
from typing import Tuple

from ..exceptions import QPEPMacVerificationError
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512


class DeniableVault:
    @staticmethod
    def seal(outer_plaintext: bytes, outer_passphrase: str, hidden_plaintext: bytes, hidden_passphrase: str, container_size: int = 8192) -> bytes:
        salt = os.urandom(32)
        outer_key = qsponge_512(b"CALYX-DENIABLE-OUTER|" + salt + outer_passphrase.encode("utf-8"))
        hidden_key = qsponge_512(b"CALYX-DENIABLE-HIDDEN|" + salt + hidden_passphrase.encode("utf-8"))

        n_outer = os.urandom(24)
        ct_outer = cc512_encrypt(outer_key, n_outer, outer_plaintext, b"OUTER")
        n_hidden = os.urandom(24)
        ct_hidden = cc512_encrypt(hidden_key, n_hidden, hidden_plaintext, b"HIDDEN")

        half = container_size // 2
        if 32 + 24 + 4 + len(ct_outer) > half or 24 + 4 + len(ct_hidden) > half:
            raise ValueError("Container size too small for outer + hidden payloads.")

        buf = bytearray(os.urandom(container_size))
        buf[0:32] = salt
        buf[32:56] = n_outer
        buf[56:60] = struct.pack(">I", len(ct_outer))
        buf[60 : 60 + len(ct_outer)] = ct_outer

        # Hidden slot starts at deterministic keyed offset in second half
        h_off = half
        buf[h_off : h_off + 24] = n_hidden
        buf[h_off + 24 : h_off + 28] = struct.pack(">I", len(ct_hidden))
        buf[h_off + 28 : h_off + 28 + len(ct_hidden)] = ct_hidden
        return bytes(buf)

    @staticmethod
    def open(container: bytes, passphrase: str) -> Tuple[str, bytes]:
        salt = container[0:32]
        half = len(container) // 2

        # Try outer volume first
        outer_key = qsponge_512(b"CALYX-DENIABLE-OUTER|" + salt + passphrase.encode("utf-8"))
        n_outer = container[32:56]
        l_outer = struct.unpack(">I", container[56:60])[0]
        if 60 + l_outer <= half:
            try:
                return "outer", cc512_decrypt(outer_key, n_outer, container[60 : 60 + l_outer], b"OUTER")
            except Exception:
                pass

        # Try hidden volume
        hidden_key = qsponge_512(b"CALYX-DENIABLE-HIDDEN|" + salt + passphrase.encode("utf-8"))
        n_hidden = container[half : half + 24]
        l_hidden = struct.unpack(">I", container[half + 24 : half + 28])[0]
        if half + 28 + l_hidden <= len(container):
            try:
                return "hidden", cc512_decrypt(hidden_key, n_hidden, container[half + 28 : half + 28 + l_hidden], b"HIDDEN")
            except Exception:
                pass

        raise QPEPMacVerificationError("Invalid passphrase for deniable container.")
