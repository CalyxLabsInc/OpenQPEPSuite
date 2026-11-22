"""
OpenQPEP Official Release 1.0.0 — Plausible-Deniability Dual-Volume Container (DeniableVault).
Embeds a hidden inner CMT-4 CC-512 volume inside uniform random bucket padding of an outer decoy volume.

Official Release 1.0.0 Cryptographic Hardening:
  - Eliminates plaintext 4-byte length leakage: both outer and hidden slot headers (nonce24 || len4)
    are XOR-masked under independent key-derived qSponge-XOF streams so EVERY byte from offset 32
    to container_size is statistically indistinguishable from os.urandom() without the passphrase.
  - Uses memory-hard RFC 9106 Argon2id + qSponge-512 key derivation for offline brute-force defense.
"""
import os
import struct
from typing import Tuple

from ..exceptions import QPEPMacVerificationError
from ..kdf.argon2id_cascade import _memory_hard_argon2id_raw
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer


def _derive_slot_keys(salt: bytes, passphrase: str, role: bytes, m_kib: int = 16384, t_cost: int = 2) -> Tuple[bytes, bytes]:
    """Derives (cc512_key_64, header_mask_28) using memory-hard RFC 9106 Argon2id + qSponge-512."""
    with SecretBuffer(b"CALYX-DENIABLE-v1.0.0|" + role + b"|" + passphrase.encode("utf-8")) as ikm:
        root, _ = _memory_hard_argon2id_raw(
            ikm.as_bytes(),
            salt,
            m_kib=m_kib,
            t_cost=t_cost,
            p_lanes=2,
            out_len=64,
        )
    with SecretBuffer(root) as rb:
        enc_key = qsponge_512(b"CALYX-DENIABLE-KEY-v1.0.0|" + role + rb.as_bytes() + salt)
        hdr_mask = qsponge_var(b"CALYX-DENIABLE-HDRMASK-v1.0.0|" + role + rb.as_bytes() + salt, 28)
    return enc_key, hdr_mask


class DeniableVault:
    @staticmethod
    def seal(
        outer_plaintext: bytes,
        outer_passphrase: str,
        hidden_plaintext: bytes,
        hidden_passphrase: str,
        container_size: int = 8192,
        *,
        kdf_m_kib: int = 16384,
        kdf_t_cost: int = 2,
    ) -> bytes:
        salt = os.urandom(32)
        outer_key, outer_mask = _derive_slot_keys(salt, outer_passphrase, b"OUTER", m_kib=kdf_m_kib, t_cost=kdf_t_cost)
        hidden_key, hidden_mask = _derive_slot_keys(salt, hidden_passphrase, b"HIDDEN", m_kib=kdf_m_kib, t_cost=kdf_t_cost)

        n_outer = os.urandom(24)
        n_hidden = os.urandom(24)
        with SecretBuffer(outer_key) as ok_b, SecretBuffer(hidden_key) as hk_b:
            ct_outer = cc512_encrypt(ok_b.as_bytes(), n_outer, outer_plaintext, b"CALYX-DENIABLE-OUTER-v1.0.0|" + salt)
            ct_hidden = cc512_encrypt(hk_b.as_bytes(), n_hidden, hidden_plaintext, b"CALYX-DENIABLE-HIDDEN-v1.0.0|" + salt)

        half = container_size // 2
        if 32 + 28 + len(ct_outer) > half or 28 + len(ct_hidden) > (container_size - half):
            raise ValueError("Container size too small for outer + hidden payloads.")

        buf = bytearray(os.urandom(container_size))
        buf[0:32] = salt

        # Mask (nonce24 || len4) so zero cleartext integers exist anywhere in the container
        outer_hdr = n_outer + struct.pack(">I", len(ct_outer))
        buf[32:60] = bytes(a ^ b for a, b in zip(outer_hdr, outer_mask))
        buf[60 : 60 + len(ct_outer)] = ct_outer

        hidden_hdr = n_hidden + struct.pack(">I", len(ct_hidden))
        buf[half : half + 28] = bytes(a ^ b for a, b in zip(hidden_hdr, hidden_mask))
        buf[half + 28 : half + 28 + len(ct_hidden)] = ct_hidden
        return bytes(buf)

    @staticmethod
    def open(container: bytes, passphrase: str, *, kdf_m_kib: int = 16384, kdf_t_cost: int = 2) -> Tuple[str, bytes]:
        if len(container) < 128:
            raise QPEPMacVerificationError("Invalid or truncated deniable container.")
        salt = container[0:32]
        half = len(container) // 2

        outer_key, outer_mask = _derive_slot_keys(salt, passphrase, b"OUTER", m_kib=kdf_m_kib, t_cost=kdf_t_cost)
        outer_hdr = bytes(a ^ b for a, b in zip(container[32:60], outer_mask))
        n_outer = outer_hdr[:24]
        l_outer = struct.unpack(">I", outer_hdr[24:28])[0]
        if 64 <= l_outer and 60 + l_outer <= half:
            try:
                with SecretBuffer(outer_key) as ok_b:
                    return "outer", cc512_decrypt(ok_b.as_bytes(), n_outer, container[60 : 60 + l_outer], b"CALYX-DENIABLE-OUTER-v1.0.0|" + salt)
            except (ValueError, KeyError, RuntimeError):
                pass

        hidden_key, hidden_mask = _derive_slot_keys(salt, passphrase, b"HIDDEN", m_kib=kdf_m_kib, t_cost=kdf_t_cost)
        hidden_hdr = bytes(a ^ b for a, b in zip(container[half : half + 28], hidden_mask))
        n_hidden = hidden_hdr[:24]
        l_hidden = struct.unpack(">I", hidden_hdr[24:28])[0]
        if 64 <= l_hidden and half + 28 + l_hidden <= len(container):
            try:
                with SecretBuffer(hidden_key) as hk_b:
                    return "hidden", cc512_decrypt(hk_b.as_bytes(), n_hidden, container[half + 28 : half + 28 + l_hidden], b"CALYX-DENIABLE-HIDDEN-v1.0.0|" + salt)
            except (ValueError, KeyError, RuntimeError):
                pass

        raise QPEPMacVerificationError("Invalid passphrase for deniable container.")
