"""
OpenQPEP Verifiable .qshare Shamir Recovery Shard Codec (Production Candidate 1.0.0).
Wraps GF(256) Shamir shares in whitened \x89QPE armor authenticated with per-shard
qSponge-512 commitment MACs and a master secret commitment digest to detect any
corrupted, mismatched, or tampered recovery shard.
"""
import base64
import json
import os
from typing import Any, Dict, List, Sequence, Tuple

from ..constants import PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..exceptions import QPEPMacVerificationError, QPEPWireFormatError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer
from ..wire.armor import armor_unwrap, armor_wrap
from .sss_gf256 import reconstruct_secret, split_secret

QSHARE_ARMOR_LABEL = "CALYX QPEP RECOVERY SHARD"


def _compute_share_commitment(group_id: str, share_index: int, share_bytes: bytes, secret_commit: str) -> str:
    return qsponge_512(
        b"CALYX-QSHARE-COMMIT-v1.0.0-pc|"
        + group_id.encode("ascii")
        + bytes([share_index])
        + share_bytes
        + secret_commit.encode("ascii")
    ).hex()


def create_recovery_shards(
    secret: bytes,
    *,
    threshold: int = 3,
    total_shares: int = 5,
    key_hash: str = "",
) -> List[str]:
    """
    Splits `secret` into `total_shares` verifiable .qshare armored recovery shards
    requiring any `threshold` shards to reconstruct.
    """
    group_id = qsponge_512(b"CALYX-QSHARE-GROUP|" + os.urandom(32)).hex()[:24].upper()
    with SecretBuffer(secret) as sec_buf:
        secret_commit = qsponge_512(b"CALYX-QSHARE-SECRET-COMMIT|" + group_id.encode("ascii") + sec_buf.as_bytes()).hex()
        raw_shares = split_secret(sec_buf.as_bytes(), threshold=threshold, total_shares=total_shares)

    shards: List[str] = []
    for idx, sbytes in raw_shares:
        share_mac = _compute_share_commitment(group_id, idx, sbytes, secret_commit)
        obj = {
            "type": "openqpep-recovery-shard",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "group_id": group_id,
            "key_hash": key_hash,
            "threshold": threshold,
            "total_shares": total_shares,
            "share_index": idx,
            "share_b64": base64.b64encode(sbytes).decode("ascii"),
            "secret_commitment_sha3_512": secret_commit,
            "share_commitment_mac": share_mac,
        }
        shards.append(armor_wrap(QSHARE_ARMOR_LABEL, json.dumps(obj, separators=(",", ":")).encode("utf-8")))
    return shards


def recover_secret_from_shards(armored_shards: Sequence[str]) -> Tuple[bytes, Dict[str, Any]]:
    """
    Verifies every shard's qSponge-512 commitment MAC, checks threshold & group consistency,
    reconstructs the secret over GF(256), and verifies the final secret commitment digest.
    """
    if not armored_shards:
        raise QPEPWireFormatError("No .qshare recovery shards provided.")

    parsed: List[Dict[str, Any]] = []
    for raw in armored_shards:
        payload, _ = armor_unwrap(raw, QSHARE_ARMOR_LABEL)
        obj = json.loads(payload.decode("utf-8"))
        if obj.get("type") != "openqpep-recovery-shard":
            raise QPEPWireFormatError("Invalid .qshare recovery shard structure.")
        sbytes = base64.b64decode(obj["share_b64"])
        expected_mac = _compute_share_commitment(
            obj["group_id"], int(obj["share_index"]), sbytes, obj["secret_commitment_sha3_512"]
        )
        if not ct_eq(expected_mac.encode("ascii"), str(obj["share_commitment_mac"]).encode("ascii")):
            raise QPEPMacVerificationError(f"Shard #{obj['share_index']} failed qSponge-512 commitment MAC check.")
        obj["_share_bytes"] = sbytes
        parsed.append(obj)

    group_id = parsed[0]["group_id"]
    threshold = int(parsed[0]["threshold"])
    secret_commit = parsed[0]["secret_commitment_sha3_512"]

    if any(p["group_id"] != group_id or p["secret_commitment_sha3_512"] != secret_commit for p in parsed):
        raise QPEPMacVerificationError("Recovery shards belong to different key-recovery groups.")
    if len(parsed) < threshold:
        raise QPEPWireFormatError(f"Need at least {threshold} shards to reconstruct (got {len(parsed)}).")

    selected = [(int(p["share_index"]), p["_share_bytes"]) for p in parsed[:threshold]]
    recovered = reconstruct_secret(selected)

    actual_commit = qsponge_512(b"CALYX-QSHARE-SECRET-COMMIT|" + group_id.encode("ascii") + recovered).hex()
    if not ct_eq(actual_commit.encode("ascii"), secret_commit.encode("ascii")):
        raise QPEPMacVerificationError("Reconstructed secret failed final qSponge-512 commitment verification.")

    return recovered, {
        "group_id": group_id,
        "threshold": threshold,
        "total_shares": int(parsed[0]["total_shares"]),
        "shards_used": len(selected),
        "key_hash": parsed[0].get("key_hash", ""),
    }
