"""
OpenQPEP by Calyx Labs Inc. — Production Candidate 1.0.0 (Modular Cryptographic Kernel)
Clean backward-compatible facade over calyx_qpep.primitives.*, calyx_qpep.lattice.*, and protocol.
"""
from .constants import (
    PROJECT_NAME,
    APP_NAME,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    PROTOCOL_VERSION,
    DEFAULT_SUITE,
    QPKRF_EXTENSION,
    CALYX_HYPER_TESSERACT_HARDWARE_WARNING,
)
from .exceptions import (
    OpenQPEPError,
    QPEPPassphrasePolicyError,
    QPEPMacVerificationError,
    QPEPFaultGuardError,
    QPEPWireFormatError,
    QPEPTruncationError,
    QPEPKeyRingError,
    QPEPSuiteError,
)
from .primitives import ct_eq, ct_cmov, SecretBuffer, zeroize_bytes, qsponge_512, qsponge_var
from .passphrase import PassphraseValidationResult, analyze_passphrase, enforce_passphrase_policy
from .protocol import (
    CalyxQPEPProtocol,
    OpenQPEPProtocol,
    QPEPKeyRing,
    SUPPORTED_FILE_EXTENSIONS,
    QUANTUM_IMMUNITY_MATRIX,
    detect_file_extension_and_mime,
)

__version__ = UNIVERSAL_VERSION
__all__ = [
    "PROJECT_NAME",
    "APP_NAME",
    "UNIVERSAL_VERSION",
    "UNIVERSAL_VERSION_LABEL",
    "PROTOCOL_VERSION",
    "DEFAULT_SUITE",
    "QPKRF_EXTENSION",
    "CALYX_HYPER_TESSERACT_HARDWARE_WARNING",
    "OpenQPEPError",
    "QPEPPassphrasePolicyError",
    "QPEPMacVerificationError",
    "QPEPFaultGuardError",
    "QPEPWireFormatError",
    "QPEPTruncationError",
    "QPEPKeyRingError",
    "QPEPSuiteError",
    "ct_eq",
    "ct_cmov",
    "SecretBuffer",
    "zeroize_bytes",
    "qsponge_512",
    "qsponge_var",
    "PassphraseValidationResult",
    "analyze_passphrase",
    "enforce_passphrase_policy",
    "CalyxQPEPProtocol",
    "OpenQPEPProtocol",
    "QPEPKeyRing",
    "SUPPORTED_FILE_EXTENSIONS",
    "QUANTUM_IMMUNITY_MATRIX",
    "detect_file_extension_and_mime",
    "__version__",
]

from .native.loader import is_native_available, native_backend_info, set_native_enabled
