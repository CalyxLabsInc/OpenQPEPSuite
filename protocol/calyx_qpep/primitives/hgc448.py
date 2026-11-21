import os
# OpenQPEP Release Candidate 1.0.0 (v1.0.0-rc)
"""
HGC-448 (448-bit Goldilocks X448 Diffie-Hellman & Ed448 Edwards Signatures) Hybrid Combiner.
"""
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from .zeroize import SecretBuffer


def x448_keygen() -> Tuple[bytes, bytes]:
    priv = X448PrivateKey.from_private_bytes(os.urandom(56))
    pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return pub_bytes, priv_bytes


def x448_exchange(priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    with SecretBuffer(priv_bytes) as sb:
        priv = X448PrivateKey.from_private_bytes(sb.as_bytes())
        peer_pub = X448PublicKey.from_public_bytes(peer_pub_bytes)
        return priv.exchange(peer_pub)


def ed448_keygen() -> Tuple[bytes, bytes]:
    priv = Ed448PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return pub_bytes, priv_bytes


def ed448_sign(priv_bytes: bytes, data: bytes) -> bytes:
    with SecretBuffer(priv_bytes) as sb:
        return Ed448PrivateKey.from_private_bytes(sb.as_bytes()).sign(data)


def ed448_verify(pub_bytes: bytes, signature: bytes, data: bytes) -> bool:
    try:
        Ed448PublicKey.from_public_bytes(pub_bytes).verify(signature, data)
        return True
    except Exception:
        return False
