"""
OpenQPEP Typed Cryptographic Exception Hierarchy (Official Release 1.0.0 / v1.0.0).
All custom exceptions inherit from OpenQPEPError(ValueError) for clean error handling.
"""


class OpenQPEPError(ValueError):
    """Base exception for all OpenQPEP protocol, cryptographic, and wire errors."""


class QPEPPassphrasePolicyError(OpenQPEPError):
    """Raised when a passphrase fails the mandatory QPKD-Argon2id complexity policy."""


class QPEPMacVerificationError(OpenQPEPError):
    """Raised when a 512-bit integrity_mac, 256-bit wire MAC, CMT-4 commitment, or AEAD tag fails verification."""


class QPEPFaultGuardError(OpenQPEPError):
    """Raised when Verify-Before-Emit Fault-Guard detects a corrupted signature before emission."""


class QPEPWireFormatError(OpenQPEPError):
    """Raised when an armored block, .qpkrf key ring, or binary \\x89QPE wire frame is malformed."""


class QPEPLegacyProtocolError(QPEPWireFormatError):
    """Raised when any legacy pre-release (-rc, -pc, or -beta) wire frame, stream, or kdf_version < 4 key ring is hard-rejected in Official Release 1.0.0."""


class QPEPTruncationError(OpenQPEPError):
    """Raised when a multi-frame CC-512 stream is truncated or missing its terminal final=1 flag."""


class QPEPKeyRingError(OpenQPEPError):
    """Raised on missing private key material, key hash mismatch, or invalid key ring state."""


class QPEPSuiteError(OpenQPEPError):
    """Raised when an unsupported suite identifier, hardware guardrail violation, or mismatched key/ciphertext size occurs."""
