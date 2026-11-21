# OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc)
"""Canonical QPEPKeyRing model re-export under calyx_qpep.keyring."""
from ..protocol import QPEPKeyRing, _compute_keyring_integrity_mac

__all__ = ["QPEPKeyRing", "_compute_keyring_integrity_mac"]
