"""
OpenQPEP m-of-n Threshold Multi-Party Cosigning Bundles (Official Release 1.1.0 / Wire v5).
Requires m-of-n independent conjunctive QVS + Ed448 signatures bound to the same canonical
qSponge-512 payload digest and multisig policy.
"""
import base64
import datetime
import json
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..constants import PACKET_TYPE_MULTISIG, PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..exceptions import QPEPKeyRingError, QPEPWireFormatError
from ..lattice.qvs_dsa import QVSEngine
from ..primitives.consttime import ct_eq
from ..primitives.hgc448 import ed448_sign, ed448_verify
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer
from ..protocol import OpenQPEPProtocol, QPEPKeyRing
from ..wire.armor import armor_unwrap, armor_wrap
from .attached import canonical_payload_digest

MULTISIG_ARMOR_LABEL = "CALYX QPEP MULTISIG BUNDLE"


def create_multisig_policy(
    threshold: int,
    authorized_signers: Sequence[QPEPKeyRing],
    *,
    policy_name: str = "OpenQPEP Threshold Cosigning Policy",
) -> Dict[str, Any]:
    hashes = sorted({kr.key_hash for kr in authorized_signers})
    n = len(hashes)
    if threshold < 1 or threshold > n:
        raise QPEPKeyRingError(f"Invalid multisig threshold {threshold}-of-{n}.")
    policy_core = {
        "policy_name": policy_name,
        "threshold": int(threshold),
        "total_signers": n,
        "authorized_key_hashes": hashes,
    }
    policy_id = qsponge_512(
        b"CALYX-QPEP-MULTISIG-POLICY-v1.0.0|"
        + json.dumps(policy_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hex()[:32].upper()
    policy_core["policy_id"] = policy_id
    return policy_core


def _multisig_transcript(policy_id: str, threshold: int, payload_digest_hex: str) -> bytes:
    return qsponge_512(
        f"CALYX-QPEP-MULTISIG-SIGN-v1.0.0|{policy_id}|{threshold}|{payload_digest_hex}".encode("ascii")
    )


def cosign_payload(
    payload: bytes,
    signer_keyring: QPEPKeyRing,
    passphrase: str,
    policy: Dict[str, Any],
    *,
    existing_bundle: Optional[str] = None,
) -> str:
    if signer_keyring.key_hash not in policy["authorized_key_hashes"]:
        raise QPEPKeyRingError("Signer key_hash is not authorized under this multisig policy.")

    digest_hex = canonical_payload_digest(payload).hex()
    if existing_bundle is not None:
        raw_j, _ = armor_unwrap(existing_bundle, MULTISIG_ARMOR_LABEL)
        bundle = json.loads(raw_j.decode("utf-8"))
        if bundle.get("type") != "openqpep-multisig-bundle":
            raise QPEPWireFormatError("Existing armor is not a valid OpenQPEP multisig bundle.")
        if not ct_eq(bundle["payload_digest_sha3_512"].encode("ascii"), digest_hex.encode("ascii")):
            raise QPEPWireFormatError("Payload digest does not match existing multisig bundle.")
        if bundle["policy"]["policy_id"] != policy["policy_id"]:
            raise QPEPWireFormatError("Multisig policy_id mismatch.")
        if any(s["signer_key_hash"] == signer_keyring.key_hash for s in bundle["signatures"]):
            raise QPEPKeyRingError(f"Signer {signer_keyring.key_hash[:12]} has already cosigned this bundle.")
    else:
        bundle = {
            "type": "openqpep-multisig-bundle",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "policy": policy,
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_digest_sha3_512": digest_hex,
            "signatures": [],
        }

    priv = OpenQPEPProtocol.unlock_private_keys(signer_keyring, passphrase)
    transcript = _multisig_transcript(policy["policy_id"], int(policy["threshold"]), digest_hex)
    qvs_pk = base64.b64decode(signer_keyring.public_bundle["qvs_public_b64"])
    with SecretBuffer(priv["qvs_private"]) as qbuf, SecretBuffer(priv["hgc_sig_private"]) as ebuf:
        sig_qvs = QVSEngine.sign(qbuf.as_bytes(), qvs_pk, transcript, tier=signer_keyring.qvs_tier)
        sig_ed = ed448_sign(ebuf.as_bytes(), transcript)

    bundle["signatures"].append({
        "signer_key_hash": signer_keyring.key_hash,
        "signer_name": signer_keyring.name,
        "qvs_tier": signer_keyring.qvs_tier,
        "signed_at_utc": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "qvs_sig_b64": base64.b64encode(sig_qvs).decode("ascii"),
        "ed448_sig_b64": base64.b64encode(sig_ed).decode("ascii"),
    })
    return armor_wrap(
        MULTISIG_ARMOR_LABEL,
        json.dumps(bundle, separators=(",", ":")).encode("utf-8"),
        packet_type=PACKET_TYPE_MULTISIG,
    )


def verify_multisig_bundle(
    armored_bundle: str,
    authorized_public_keyrings: Sequence[QPEPKeyRing],
    *,
    expected_payload: Optional[bytes] = None,
) -> Tuple[bool, Dict[str, Any]]:
    raw_j, _ = armor_unwrap(armored_bundle, MULTISIG_ARMOR_LABEL)
    bundle = json.loads(raw_j.decode("utf-8"))
    if bundle.get("type") != "openqpep-multisig-bundle":
        raise QPEPWireFormatError("Not a valid OpenQPEP multisig bundle.")

    payload = base64.b64decode(bundle["payload_b64"])
    actual_digest = canonical_payload_digest(payload).hex()
    if not ct_eq(actual_digest.encode("ascii"), str(bundle["payload_digest_sha3_512"]).encode("ascii")):
        return False, {"error": "Payload digest mismatch inside multisig bundle."}
    if expected_payload is not None and not ct_eq(payload, expected_payload):
        return False, {"error": "Embedded payload does not match expected_payload."}

    policy = bundle["policy"]
    threshold = int(policy["threshold"])
    allowed_set = set(policy["authorized_key_hashes"])
    kr_map = {kr.key_hash: kr for kr in authorized_public_keyrings}
    transcript = _multisig_transcript(policy["policy_id"], threshold, actual_digest)

    verified_signers: List[str] = []
    seen = set()
    for entry in bundle.get("signatures", []):
        kh = entry.get("signer_key_hash", "")
        if kh in seen or kh not in allowed_set or kh not in kr_map:
            continue
        kr = kr_map[kh]
        qvs_pk = base64.b64decode(kr.public_bundle["qvs_public_b64"])
        ed_pk = base64.b64decode(kr.public_bundle["hgc_sig_public_b64"])
        ok_qvs = QVSEngine.verify(qvs_pk, transcript, base64.b64decode(entry["qvs_sig_b64"]), tier=kr.qvs_tier)
        ok_ed = ed448_verify(ed_pk, base64.b64decode(entry["ed448_sig_b64"]), transcript)
        if ok_qvs and ok_ed:
            seen.add(kh)
            verified_signers.append(kh)

    passed = len(verified_signers) >= threshold
    return passed, {
        "policy_id": policy["policy_id"],
        "threshold": threshold,
        "total_authorized": len(allowed_set),
        "valid_signature_count": len(verified_signers),
        "verified_signer_hashes": verified_signers,
        "payload": payload,
    }
