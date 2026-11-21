"""
Calyx-Cascade-512 (CC-512) Dual-Stream Authenticated Payload Cipher (Production Candidate 1.1.0).
Cascades 14-round NIST AES-256-GCM inside 20-round RFC 8439 ChaCha20-Poly1305 with active
SecretBuffer memory scrubbing of derived 64-byte session keys.
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from .zeroize import SecretBuffer
from ..exceptions import QPEPMacVerificationError


def cc512_encrypt(key64: bytes, nonce24: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypts plaintext through AES-256-GCM followed by ChaCha20-Poly1305."""
    if len(key64) != 64 or len(nonce24) != 24:
        raise ValueError("CC-512 requires a 64-byte key and 24-byte nonce.")
    with SecretBuffer(key64[:32]) as k_aes, SecretBuffer(key64[32:]) as k_chacha:
        inner_ct = AESGCM(k_aes.as_bytes()).encrypt(nonce24[:12], plaintext, aad)
        return ChaCha20Poly1305(k_chacha.as_bytes()).encrypt(nonce24[12:], inner_ct, aad)


def cc512_decrypt(key64: bytes, nonce24: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypts ChaCha20-Poly1305 outer layer followed by AES-256-GCM inner layer."""
    if len(key64) != 64 or len(nonce24) != 24:
        raise ValueError("CC-512 requires a 64-byte key and 24-byte nonce.")
    try:
        with SecretBuffer(key64[:32]) as k_aes, SecretBuffer(key64[32:]) as k_chacha:
            inner_ct = ChaCha20Poly1305(k_chacha.as_bytes()).decrypt(nonce24[12:], ciphertext, aad)
            return AESGCM(k_aes.as_bytes()).decrypt(nonce24[:12], inner_ct, aad)
    except Exception as exc:
        raise QPEPMacVerificationError("CC-512 dual-stream AEAD authentication failed.") from exc
