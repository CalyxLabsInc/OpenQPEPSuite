"""
HGC-448 (448-bit Goldilocks X448 Diffie-Hellman & Ed448 Edwards Signatures) Hybrid Combiner
(Official Release 1.0.0 / v1.0.0).
Uses os.urandom(56)/os.urandom(57) so keygen is CSPRNG-secure in production and 100% deterministic
under KAT DRBG, with SecretBuffer RAM scrubbing on every private-key operation.
"""
import os
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from .zeroize import SecretBuffer


def x448_keygen() -> Tuple[bytes, bytes]:
    with SecretBuffer(os.urandom(56)) as seed_buf:
        priv = X448PrivateKey.from_private_bytes(seed_buf.as_bytes())
        pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return pub_bytes, priv_bytes


def x448_exchange(priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    with SecretBuffer(priv_bytes) as sb:
        priv = X448PrivateKey.from_private_bytes(sb.as_bytes())
        peer_pub = X448PublicKey.from_public_bytes(peer_pub_bytes)
        shared = priv.exchange(peer_pub)
        # RFC 7748 Section 6.2: reject all-zero low-order shared secret
        if not any(shared):
            raise ValueError("X448 low-order contributor point rejected (all-zero shared secret).")
        return shared


def ed448_keygen() -> Tuple[bytes, bytes]:
    with SecretBuffer(os.urandom(57)) as seed_buf:
        priv = Ed448PrivateKey.from_private_bytes(seed_buf.as_bytes())
        pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return pub_bytes, priv_bytes


def ed448_public_from_private(priv_bytes: bytes) -> bytes:
    with SecretBuffer(priv_bytes) as sb:
        priv = Ed448PrivateKey.from_private_bytes(sb.as_bytes())
        return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed448_sign(priv_bytes: bytes, data: bytes) -> bytes:
    with SecretBuffer(priv_bytes) as sb:
        return Ed448PrivateKey.from_private_bytes(sb.as_bytes()).sign(data)


def ed448_verify(pub_bytes: bytes, signature: bytes, data: bytes) -> bool:
    try:
        if len(pub_bytes) != 57 or len(signature) != 114:
            return False
        Ed448PublicKey.from_public_bytes(pub_bytes).verify(signature, data)
        return True
    except Exception:
        return False
