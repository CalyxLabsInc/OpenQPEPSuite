"""
OpenQPEP Cryptographic Timestamp Bindings (Production Candidate 1.1.4).
Binds a signed payload's qSponge-512 digest to a UTC timestamp, a public hash-chain anchor,
and/or a Timestamp Authority (TSA) conjunctive QVS + Ed448 attestation—proving a document
existed prior to a specific UTC instant even after operational signing keys rotate or expire.
"""
import base64
import datetime
import json
from typing import Any, Dict, Optional, Tuple

from ..constants import PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..exceptions import QPEPWireFormatError
from ..lattice.qvs_dsa import QVSEngine
from ..primitives.consttime import ct_eq
from ..primitives.hgc448 import ed448_sign, ed448_verify
from ..primitives.qsponge import qsponge_512
from ..protocol import OpenQPEPProtocol, QPEPKeyRing
from ..wire.armor import armor_unwrap, armor_wrap
from .attached import canonical_payload_digest

TIMESTAMP_ARMOR_LABEL = "CALYX QPEP TIMESTAMP PROOF"


def _compute_anchor_commitment(
    payload_digest_hex: str,
    utc_timestamp: str,
    anchor_chain_id: str,
    anchor_block_height: int,
    anchor_prev_hash_hex: str,
) -> str:
    body = f"CALYX-QPEP-TSA-ANCHOR-v1.1.4-pc|{anchor_chain_id}|{anchor_block_height}|{anchor_prev_hash_hex}|{payload_digest_hex}|{utc_timestamp}"
    return qsponge_512(body.encode("utf-8")).hex()


def create_timestamp_proof(
    payload: bytes,
    *,
    tsa_keyring: Optional[QPEPKeyRing] = None,
    tsa_passphrase: Optional[str] = None,
    anchor_chain_id: str = "calyx-public-hashchain-v1",
    anchor_block_height: int = 1,
    anchor_prev_hash_hex: str = "0" * 64,
    utc_timestamp: Optional[str] = None,
) -> str:
    """
    Creates an armored OpenQPEP Cryptographic Timestamp Proof binding `payload`'s
    qSponge-512 digest to a UTC instant, hash-chain anchor, and optional TSA QVS+Ed448 signature.
    """
    ts = utc_timestamp or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    digest_hex = canonical_payload_digest(payload).hex()
    anchor_commit = _compute_anchor_commitment(
        digest_hex, ts, anchor_chain_id, int(anchor_block_height), anchor_prev_hash_hex
    )

    proof_obj: Dict[str, Any] = {
        "type": "openqpep-timestamp-proof",
        "version": UNIVERSAL_VERSION,
        "protocol": PROTOCOL_VERSION,
        "payload_digest_sha3_512": digest_hex,
        "utc_timestamp": ts,
        "anchor": {
            "chain_id": anchor_chain_id,
            "block_height": int(anchor_block_height),
            "prev_hash_hex": anchor_prev_hash_hex,
            "anchor_commitment_sha3_512": anchor_commit,
        },
        "tsa_attestation": None,
    }

    if tsa_keyring is not None and tsa_passphrase is not None:
        priv = OpenQPEPProtocol.unlock_private_keys(tsa_keyring, tsa_passphrase)
        transcript = qsponge_512(b"CALYX-TSA-SIGN|" + anchor_commit.encode("ascii"))
        qvs_pk = base64.b64decode(tsa_keyring.public_bundle["qvs_public_b64"])
        sig_qvs = QVSEngine.sign(priv["qvs_private"], qvs_pk, transcript, tier=tsa_keyring.qvs_tier)
        sig_ed = ed448_sign(priv["hgc_sig_private"], transcript)
        proof_obj["tsa_attestation"] = {
            "tsa_key_hash": tsa_keyring.key_hash,
            "tsa_name": tsa_keyring.name,
            "qvs_tier": tsa_keyring.qvs_tier,
            "qvs_sig_b64": base64.b64encode(sig_qvs).decode("ascii"),
            "ed448_sig_b64": base64.b64encode(sig_ed).decode("ascii"),
        }

    return armor_wrap(TIMESTAMP_ARMOR_LABEL, json.dumps(proof_obj, separators=(",", ":")).encode("utf-8"))


def verify_timestamp_proof(
    armored_proof: str,
    payload: bytes,
    *,
    tsa_public_keyring: Optional[QPEPKeyRing] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Verifies a cryptographic timestamp proof against `payload` and optional TSA public key ring."""
    raw_j, _ = armor_unwrap(armored_proof, TIMESTAMP_ARMOR_LABEL)
    obj = json.loads(raw_j.decode("utf-8"))
    if obj.get("type") != "openqpep-timestamp-proof":
        raise QPEPWireFormatError("Not a valid OpenQPEP timestamp proof.")

    actual_digest = canonical_payload_digest(payload).hex()
    if not ct_eq(actual_digest.encode("ascii"), str(obj["payload_digest_sha3_512"]).encode("ascii")):
        return False, {"error": "Payload digest does not match timestamp proof."}

    anc = obj["anchor"]
    expected_commit = _compute_anchor_commitment(
        actual_digest,
        obj["utc_timestamp"],
        anc["chain_id"],
        int(anc["block_height"]),
        anc["prev_hash_hex"],
    )
    if not ct_eq(expected_commit.encode("ascii"), str(anc["anchor_commitment_sha3_512"]).encode("ascii")):
        return False, {"error": "Hash-chain anchor commitment mismatch."}

    tsa_verified = False
    att = obj.get("tsa_attestation")
    if tsa_public_keyring is not None:
        if not att or att.get("tsa_key_hash") != tsa_public_keyring.key_hash:
            return False, {"error": "TSA attestation missing or key_hash mismatch."}
        transcript = qsponge_512(b"CALYX-TSA-SIGN|" + expected_commit.encode("ascii"))
        qvs_pk = base64.b64decode(tsa_public_keyring.public_bundle["qvs_public_b64"])
        ed_pk = base64.b64decode(tsa_public_keyring.public_bundle["hgc_sig_public_b64"])
        ok_qvs = QVSEngine.verify(qvs_pk, transcript, base64.b64decode(att["qvs_sig_b64"]), tier=tsa_public_keyring.qvs_tier)
        ok_ed = ed448_verify(ed_pk, base64.b64decode(att["ed448_sig_b64"]), transcript)
        if not (ok_qvs and ok_ed):
            return False, {"error": "TSA conjunctive QVS + Ed448 signature verification failed."}
        tsa_verified = True

    return True, {
        "utc_timestamp": obj["utc_timestamp"],
        "chain_id": anc["chain_id"],
        "block_height": int(anc["block_height"]),
        "anchor_commitment": expected_commit,
        "tsa_verified": tsa_verified,
    }
