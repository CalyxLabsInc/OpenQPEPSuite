"""
OpenQPEP by Calyx Labs Inc. — Official Release 1.1.0 (v1.1.0, Modular Cryptographic Kernel)
Clean official API facade over calyx_qpep.primitives.*, calyx_qpep.lattice.*, compat_server, and protocol.
"""
from .compat_server import SlidingWindowRateLimiter
from .constants import (
    APP_NAME,
    CALYX_HYPER_TESSERACT_HARDWARE_WARNING,
    DEFAULT_SUITE,
    MANDATORY_KDF_VERSION,
    PROJECT_NAME,
    PROTOCOL_VERSION,
    QPKRF_EXTENSION,
    STREAM_MAGIC_V5,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    WIRE_MAGIC_V5,
    WIRE_MAGIC_V5_1,
)
from .exceptions import (
    OpenQPEPError,
    QPEPFaultGuardError,
    QPEPKeyRingError,
    QPEPLegacyProtocolError,
    QPEPMacVerificationError,
    QPEPPassphrasePolicyError,
    QPEPSuiteError,
    QPEPTruncationError,
    QPEPWireFormatError,
)
from .native.loader import is_native_available, native_backend_info, set_native_enabled
from .passphrase import PassphraseValidationResult, analyze_passphrase, enforce_passphrase_policy
from .primitives import SecretBuffer, ct_cmov, ct_eq, qsponge_512, qsponge_var, zeroize_bytes
from .protocol import (
    QUANTUM_IMMUNITY_MATRIX,
    SUPPORTED_FILE_EXTENSIONS,
    CalyxQPEPProtocol,
    OpenQPEPProtocol,
    QPEPKeyRing,
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
    "MANDATORY_KDF_VERSION",
    "CALYX_HYPER_TESSERACT_HARDWARE_WARNING",
    "WIRE_MAGIC_V5",
    "WIRE_MAGIC_V5_1",
    "STREAM_MAGIC_V5",
    "OpenQPEPError",
    "QPEPPassphrasePolicyError",
    "QPEPMacVerificationError",
    "QPEPFaultGuardError",
    "QPEPWireFormatError",
    "QPEPLegacyProtocolError",
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
    "is_native_available",
    "native_backend_info",
    "set_native_enabled",
    "SlidingWindowRateLimiter",
    "__version__",
]
