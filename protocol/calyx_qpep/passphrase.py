"""
Backward-compatible re-export facade for QPKD-Argon2id Passphrase Policy (Release Candidate 1.0.0).
Canonical implementation now lives in calyx_qpep.kdf.passphrase_policy.
"""
from .kdf.passphrase_policy import (
    MIN_LENGTH,
    MIN_DIGITS,
    MIN_SPECIALS,
    MIN_UPPERCASE,
    MIN_LOWERCASE,
    QPEPPassphrasePolicyError,
    PassphraseValidationResult,
    analyze_passphrase,
    enforce_passphrase_policy,
)

__all__ = [
    "MIN_LENGTH",
    "MIN_DIGITS",
    "MIN_SPECIALS",
    "MIN_UPPERCASE",
    "MIN_LOWERCASE",
    "QPEPPassphrasePolicyError",
    "PassphraseValidationResult",
    "analyze_passphrase",
    "enforce_passphrase_policy",
]
