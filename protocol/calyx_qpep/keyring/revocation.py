"""
OpenQPEP Self-Authenticating .qrev Key Revocation Certificates (Production Candidate 1.0.0).
Supports offline revocation certificates signed conjunctively by the Master QVS + Ed448
identity key with standardized reason codes: KEY_COMPROMISED, KEY_SUPERSEDED, KEY_RETIRED.
"""
import base64
import datetime
import json
from typing import Any, Dict, Optional, Tuple

from ..constants import PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..exceptions import QPEPKeyRingError, QPEPWireFormatError
from ..lattice.qvs_dsa import QVSEngine
from ..primitives.hgc448 import ed448_sign, ed448_verify
from ..primitives.qsponge import qsponge_512
from ..protocol import OpenQPEPProtocol, QPEPKeyRing
from ..wire.armor import armor_unwrap, armor_wrap

REVOCATION_ARMOR_LABEL = "CALYX QPEP REVOCATION CERTIFICATE"
REVOCATION_REASONS = ("KEY_COMPROMISED", "KEY_SUPERSEDED", "KEY_RETIRED")


def _revocation_transcript(body: Dict[str, Any]) -> bytes:
    return qsponge_512(
        b"CALYX-QPEP-REVOCATION-v1.0.0-pc|"
        + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def create_revocation_certificate(
    master_keyring: QPEPKeyRing,
    master_passphrase: str,
    *,
    reason: str = "KEY_COMPROMISED",
    comment: str = "",
    target_subkey_id: Optional[str] = None,
) -> str:
    """
    Generates an offline, self-authenticating .qrev Revocation Certificate signed
    conjunctively by the Master QVS + Ed448 key.
    """
    if reason not in REVOCATION_REASONS:
        raise QPEPKeyRingError(f"Invalid revocation reason '{reason}'. Must be one of {REVOCATION_REASONS}.")

    master_priv = OpenQPEPProtocol.unlock_private_keys(master_keyring, master_passphrase)
    revoked_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    body = {
        "type": "openqpep-revocation-certificate",
        "version": UNIVERSAL_VERSION,
        "protocol": PROTOCOL_VERSION,
        "key_hash": master_keyring.key_hash,
        "target_subkey_id": target_subkey_id,
        "reason": reason,
        "comment": comment,
        "revoked_at_utc": revoked_at,
    }
    transcript = _revocation_transcript(body)
    master_qvs_pk = base64.b64decode(master_keyring.public_bundle["qvs_public_b64"])
    sig_qvs = QVSEngine.sign(master_priv["qvs_private"], master_qvs_pk, transcript, tier=master_keyring.qvs_tier)
    sig_ed448 = ed448_sign(master_priv["hgc_sig_private"], transcript)

    cert = {
        "body": body,
        "master_qvs_sig_b64": base64.b64encode(sig_qvs).decode("ascii"),
        "master_ed448_sig_b64": base64.b64encode(sig_ed448).decode("ascii"),
    }
    return armor_wrap(REVOCATION_ARMOR_LABEL, json.dumps(cert, separators=(",", ":")).encode("utf-8"))


def verify_revocation_certificate(
    armored_qrev: str,
    master_public_keyring: QPEPKeyRing,
) -> Tuple[bool, Dict[str, Any]]:
    """Verifies a .qrev Revocation Certificate against the Master public key ring."""
    raw_json, _ = armor_unwrap(armored_qrev, REVOCATION_ARMOR_LABEL)
    cert = json.loads(raw_json.decode("utf-8"))
    body = cert.get("body") or {}
    if body.get("type") != "openqpep-revocation-certificate":
        raise QPEPWireFormatError("Not a valid OpenQPEP .qrev revocation certificate.")
    if body.get("key_hash") != master_public_keyring.key_hash:
        return False, {"error": "Revocation certificate key_hash does not match Master public key."}
    if body.get("reason") not in REVOCATION_REASONS:
        return False, {"error": "Unknown revocation reason code."}

    transcript = _revocation_transcript(body)
    master_qvs_pk = base64.b64decode(master_public_keyring.public_bundle["qvs_public_b64"])
    master_ed_pk = base64.b64decode(master_public_keyring.public_bundle["hgc_sig_public_b64"])
    sig_qvs = base64.b64decode(cert["master_qvs_sig_b64"])
    sig_ed = base64.b64decode(cert["master_ed448_sig_b64"])

    ok_qvs = QVSEngine.verify(master_qvs_pk, transcript, sig_qvs, tier=master_public_keyring.qvs_tier)
    ok_ed = ed448_verify(master_ed_pk, sig_ed, transcript)
    if not (ok_qvs and ok_ed):
        return False, {"error": "Conjunctive QVS + Ed448 revocation signature verification failed."}
    return True, body
