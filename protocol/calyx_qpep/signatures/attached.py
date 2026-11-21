"""
OpenQPEP Self-Contained Attached Signatures & Canonical Payload Digest Helpers (Production Candidate 1.0.0).
"""
from typing import Sequence, Tuple

from ..primitives.qsponge import qsponge_512
from ..protocol import OpenQPEPProtocol, QPEPKeyRing


def canonical_payload_digest(payload: bytes) -> bytes:
    """Computes the canonical domain-separated 512-bit qSponge-512 digest of a payload."""
    return qsponge_512(b"CALYX-QPEP-CANONICAL-PAYLOAD-v1.0.0-pc|" + payload)


def sign_attached_text(message: str, signer_keyring: QPEPKeyRing, passphrase: str) -> str:
    return OpenQPEPProtocol.sign_text(message, signer_keyring, passphrase)


def verify_attached_text(armored_sig: str, keyring_pool: Sequence[QPEPKeyRing]) -> Tuple[bool, str, QPEPKeyRing | None]:
    return OpenQPEPProtocol.verify_text_signature(armored_sig, keyring_pool=list(keyring_pool))
