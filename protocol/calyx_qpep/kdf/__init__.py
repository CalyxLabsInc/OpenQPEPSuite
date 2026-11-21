"""OpenQPEP Memory-Hard QPKD-Argon2id Key Derivation & Hardware Auto-Tuner (Production Candidate 1.1.0)."""
from .passphrase_policy import (
    MIN_LENGTH, MIN_DIGITS, MIN_SPECIALS, MIN_UPPERCASE, MIN_LOWERCASE,
    QPEPPassphrasePolicyError, PassphraseValidationResult,
    analyze_passphrase, enforce_passphrase_policy,
)
from .hardware_tuner import KDFHardwareProfile, detect_system_ram_mib, select_kdf_profile, benchmark_kdf
from .argon2id_cascade import (
    get_active_kdf_backend,
    derive_qpkrf_keys_v2,
)

__all__ = [
    "MIN_LENGTH", "MIN_DIGITS", "MIN_SPECIALS", "MIN_UPPERCASE", "MIN_LOWERCASE",
    "QPEPPassphrasePolicyError", "PassphraseValidationResult",
    "analyze_passphrase", "enforce_passphrase_policy",
    "KDFHardwareProfile", "detect_system_ram_mib", "select_kdf_profile", "benchmark_kdf",
    "get_active_kdf_backend", "derive_qpkrf_keys_v1", "derive_qpkrf_keys_v2",
]
