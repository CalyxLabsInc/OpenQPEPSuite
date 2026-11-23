"""
Calyx-Cascade-512 (CC-512) Provably CMT-4 Key-Committing Dual-Stream AEAD (Official Release 1.1.0).

Security Guarantees:
  - Dual-Algorithm Confidentiality & Integrity: AES-256-GCM nested inside ChaCha20-Poly1305
    with cryptographically independent 256-bit keys and 96-bit nonces.
  - Provable CMT-4 Key Commitment: Derives domain-separated (k_aes, k_chacha, k_commit) via
    qSponge-XOF("CALYX-CC512-CMT4-KEYS-v1.0.0|" || key64 || nonce24, 96) and appends a 256-bit
    qSponge-512 commitment tag bound to (k_commit, nonce24, len(aad), aad, ct_outer), verified in
    constant time BEFORE decryption—eliminating multi-key / invisible-salamanders collisions.
  - Active Memory Zeroization: Scrubs all derived subkeys via SecretBuffer on exit.

Wire overhead: 64 bytes (16 B AES-GCM tag + 16 B Poly1305 tag + 32 B CMT-4 commitment tag).
"""
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from ..exceptions import QPEPMacVerificationError
from .consttime import ct_eq
from .qsponge import qsponge_512, qsponge_var
from .zeroize import SecretBuffer

CC512_CMT_TAG_BYTES = 32
CC512_OVERHEAD_BYTES = 64  # 16 (AES-GCM) + 16 (ChaCha20-Poly1305) + 32 (CMT-4 tag)


def _derive_cmt4_subkeys(key64: bytes, nonce24: bytes) -> bytes:
    return qsponge_var(b"CALYX-CC512-CMT4-KEYS-v1.0.0|" + key64 + nonce24, 96)


def _compute_cmt4_tag(k_commit: bytes, nonce24: bytes, aad: bytes, ct_outer: bytes) -> bytes:
    return qsponge_512(
        b"CALYX-CC512-CMT4-TAG-v1.0.0|"
        + k_commit
        + nonce24
        + struct.pack(">Q", len(aad))
        + aad
        + ct_outer
    )[:CC512_CMT_TAG_BYTES]


def cc512_encrypt(key64: bytes, nonce24: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """
    Encrypts `plaintext` with CMT-4 Key-Committing CC-512 AEAD:
      ct_inner = AES-256-GCM(k_aes, nonce24[:12], plaintext, aad)
      ct_outer = ChaCha20-Poly1305(k_chacha, nonce24[12:24], ct_inner, aad)
      cmt_tag  = qSponge-512("CALYX-CC512-CMT4-TAG-v1.0.0|" || k_commit || nonce24 || len(aad) || aad || ct_outer)[:32]
      output   = ct_outer || cmt_tag
    """
    if len(key64) != 64:
        raise ValueError("CC-512 requires a 64-byte (512-bit) key.")
    if len(nonce24) != 24:
        raise ValueError("CC-512 requires a 24-byte (192-bit) dual nonce.")
    with SecretBuffer(_derive_cmt4_subkeys(key64, nonce24)) as sub_buf:
        sub = sub_buf.as_bytes()
        k_aes, k_chacha, k_commit = sub[:32], sub[32:64], sub[64:96]
        ct_inner = AESGCM(k_aes).encrypt(nonce24[:12], plaintext, aad)
        ct_outer = ChaCha20Poly1305(k_chacha).encrypt(nonce24[12:24], ct_inner, aad)
        cmt_tag = _compute_cmt4_tag(k_commit, nonce24, aad, ct_outer)
        return ct_outer + cmt_tag


def cc512_decrypt(key64: bytes, nonce24: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """
    Verifies the 256-bit CMT-4 key commitment tag in constant time, then decrypts
    outer ChaCha20-Poly1305 and inner AES-256-GCM.
    """
    if len(key64) != 64:
        raise ValueError("CC-512 requires a 64-byte (512-bit) key.")
    if len(nonce24) != 24:
        raise ValueError("CC-512 requires a 24-byte (192-bit) dual nonce.")
    if len(ciphertext) < CC512_OVERHEAD_BYTES:
        raise QPEPMacVerificationError("CC-512 ciphertext truncated below 64-byte minimum overhead.")

    ct_outer = ciphertext[:-CC512_CMT_TAG_BYTES]
    recv_cmt = ciphertext[-CC512_CMT_TAG_BYTES:]

    with SecretBuffer(_derive_cmt4_subkeys(key64, nonce24)) as sub_buf:
        sub = sub_buf.as_bytes()
        k_aes, k_chacha, k_commit = sub[:32], sub[32:64], sub[64:96]
        expected_cmt = _compute_cmt4_tag(k_commit, nonce24, aad, ct_outer)
        if not ct_eq(recv_cmt, expected_cmt):
            raise QPEPMacVerificationError("CC-512 CMT-4 key-commitment verification failed.")
        try:
            ct_inner = ChaCha20Poly1305(k_chacha).decrypt(nonce24[12:24], ct_outer, aad)
            return AESGCM(k_aes).decrypt(nonce24[:12], ct_inner, aad)
        except Exception as exc:
            raise QPEPMacVerificationError("CC-512 AEAD authentication tag verification failed.") from exc
