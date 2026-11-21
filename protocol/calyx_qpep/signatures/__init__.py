"""OpenQPEP Attached Signatures, m-of-n Threshold Cosigning & Timestamp Proofs (Production Candidate 1.1.7)."""
from .attached import canonical_payload_digest, sign_attached_text, verify_attached_text
from .multisig import MULTISIG_ARMOR_LABEL, create_multisig_policy, cosign_payload, verify_multisig_bundle
from .timestamp_proof import TIMESTAMP_ARMOR_LABEL, create_timestamp_proof, verify_timestamp_proof

__all__ = [
    "canonical_payload_digest", "sign_attached_text", "verify_attached_text",
    "MULTISIG_ARMOR_LABEL", "create_multisig_policy", "cosign_payload", "verify_multisig_bundle",
    "TIMESTAMP_ARMOR_LABEL", "create_timestamp_proof", "verify_timestamp_proof",
]
