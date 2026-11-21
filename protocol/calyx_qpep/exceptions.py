"""
OpenQPEP Typed Cryptographic Exception Hierarchy (Release Candidate 1.0.0 / v1.0.0-rc).
All custom exceptions inherit from OpenQPEPError(ValueError) to maintain
100% backward compatibility with existing callers catching ValueError.
"""


class OpenQPEPError(ValueError):
    """Base exception for all OpenQPEP protocol, cryptographic, and wire errors."""


class QPEPPassphrasePolicyError(OpenQPEPError):
    """Raised when a passphrase fails the mandatory QPKD-Argon2id complexity policy."""


class QPEPMacVerificationError(OpenQPEPError):
    """Raised when a 512-bit integrity_mac, 256-bit wire MAC, or AEAD tag fails verification."""


class QPEPFaultGuardError(OpenQPEPError):
    """Raised when Verify-Before-Emit Fault-Guard detects a corrupted lattice signature."""


class QPEPWireFormatError(OpenQPEPError):
    """Raised when an armored block, .qpkrf key ring, or binary \x89QPE wire frame is malformed."""


class QPEPLegacyProtocolError(QPEPWireFormatError):
    """Raised when a legacy Production Candidate (-pc, Wire v3/v3.1, kdf_version < 3) or beta packet/keyring is hard-rejected in Release Candidate v1.0.0 (v1.0.0-rc)."""


class QPEPTruncationError(OpenQPEPError):
    """Raised when a multi-frame CC-512 stream is truncated or missing its terminal final=1 flag."""


class QPEPKeyRingError(OpenQPEPError):
    """Raised on missing private key material, key hash mismatch, or invalid key ring state."""


class QPEPSuiteError(OpenQPEPError):
    """Raised when an unsupported QLX/QVS suite identifier or mismatched key/ciphertext size is used."""
