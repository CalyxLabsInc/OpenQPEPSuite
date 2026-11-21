"""OpenQPEP Key Lifecycle: .qpkrf Codec, Rotatable Subkeys, & .qrev Revocation (Release Candidate 1.0.0)."""
from .qpkrf_model import QPEPKeyRing
from .qpkrf_codec import export_qpkrf, import_qpkrf
from .subkeys import VALID_SUBKEY_ROLES, QPEPSubkey, issue_subkey, verify_subkey
from .revocation import (
    REVOCATION_ARMOR_LABEL,
    REVOCATION_REASONS,
    create_revocation_certificate,
    verify_revocation_certificate,
)

__all__ = [
    "QPEPKeyRing", "export_qpkrf", "import_qpkrf",
    "VALID_SUBKEY_ROLES", "QPEPSubkey", "issue_subkey", "verify_subkey",
    "REVOCATION_ARMOR_LABEL", "REVOCATION_REASONS",
    "create_revocation_certificate", "verify_revocation_certificate",
]
