# OpenQPEP Official Release 1.1.0 (v1.1.0)
"""Calyx Sovereign-Pentad (CSP-Omega — Five-Family Beyond-LWE Cryptographic Citadel)."""
from .sovereign_pentad import (
    PENTAD_SUITE_NAME,
    PENTAD_MIN_RAM_MIB,
    PENTAD_ENC_LABEL,
    PENTAD_SIG_LABEL,
    check_flagship_hardware_guardrail,
    CalyxSovereignPentad,
)

__all__ = [
    "PENTAD_SUITE_NAME",
    "PENTAD_MIN_RAM_MIB",
    "PENTAD_ENC_LABEL",
    "PENTAD_SIG_LABEL",
    "check_flagship_hardware_guardrail",
    "CalyxSovereignPentad",
]
