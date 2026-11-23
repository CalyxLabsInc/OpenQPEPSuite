"""
OpenQPEP Master Identity Key + Rotatable Operational Subkeys (Official Release 1.1.0 / kdf_version: 4).
Separates a user's long-lived Master Identity Key (64-character Key Hash) from short-lived
operational Encryption Subkeys (QLX + X448) and Signing Subkeys (QVS + Ed448) with explicit
UTC expiration timestamps and conjunctive Master QVS + Ed448 certification.
"""
import base64
import datetime
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..constants import MANDATORY_KDF_VERSION, PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..exceptions import QPEPKeyRingError
from ..kdf.argon2id_cascade import derive_qpkrf_keys_v4
from ..lattice.qlx_kem import QLXEngine
from ..lattice.qvs_dsa import QVSEngine
from ..primitives.cc512_aead import cc512_encrypt
from ..primitives.hgc448 import ed448_keygen, ed448_sign, ed448_verify, x448_keygen
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer
from ..protocol import OpenQPEPProtocol, QPEPKeyRing

VALID_SUBKEY_ROLES = ("encryption", "signing")


@dataclass
class QPEPSubkey:
    subkey_id: str
    role: str
    master_key_hash: str
    qlx_tier: str
    qvs_tier: str
    created_at_utc: str
    expires_at_utc: str
    public_bundle: Dict[str, str]
    encrypted_private_bundle: Optional[Dict[str, Any]]
    master_qvs_sig_b64: str
    master_ed448_sig_b64: str

    def to_dict(self, include_private: bool = False) -> Dict[str, Any]:
        return {
            "type": "openqpep-subkey",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "subkey_id": self.subkey_id,
            "role": self.role,
            "master_key_hash": self.master_key_hash,
            "qlx_tier": self.qlx_tier,
            "qvs_tier": self.qvs_tier,
            "created_at_utc": self.created_at_utc,
            "expires_at_utc": self.expires_at_utc,
            "public_bundle": self.public_bundle,
            "encrypted_private_bundle": self.encrypted_private_bundle if include_private else None,
            "master_qvs_sig_b64": self.master_qvs_sig_b64,
            "master_ed448_sig_b64": self.master_ed448_sig_b64,
        }


def _subkey_cert_transcript(
    master_key_hash: str,
    subkey_id: str,
    role: str,
    qlx_tier: str,
    qvs_tier: str,
    created_at_utc: str,
    expires_at_utc: str,
    public_bundle: Dict[str, str],
) -> bytes:
    payload = {
        "domain": "CALYX-QPEP-SUBKEY-CERT-v1.0.0",
        "master_key_hash": master_key_hash,
        "subkey_id": subkey_id,
        "role": role,
        "qlx_tier": qlx_tier,
        "qvs_tier": qvs_tier,
        "created_at_utc": created_at_utc,
        "expires_at_utc": expires_at_utc,
        "public_bundle": public_bundle,
    }
    return qsponge_512(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def issue_subkey(
    master_keyring: QPEPKeyRing,
    master_passphrase: str,
    *,
    role: str = "encryption",
    validity_days: int = 90,
    qlx_tier: Optional[str] = None,
) -> QPEPSubkey:
    if role not in VALID_SUBKEY_ROLES:
        raise QPEPKeyRingError(f"Invalid subkey role: {role}. Must be one of {VALID_SUBKEY_ROLES}.")
    if validity_days <= 0:
        raise QPEPKeyRingError("validity_days must be a positive integer.")

    tier_qlx = qlx_tier or master_keyring.qlx_tier
    tier_qvs = master_keyring.qvs_tier
    master_priv = OpenQPEPProtocol.unlock_private_keys(master_keyring, master_passphrase)

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    expires = now + datetime.timedelta(days=validity_days)
    created_iso = now.isoformat()
    expires_iso = expires.isoformat()
    sub_witness = qsponge_512(b"CALYX-SUBKEY-WITNESS-v1.0.0|" + os.urandom(32))

    if role == "encryption":
        qlx_pk, qlx_sk = QLXEngine.keygen(tier_qlx, sub_witness)
        hgc_pk, hgc_sk = x448_keygen()
        public_bundle = {
            "qlx_public_b64": base64.b64encode(qlx_pk).decode("ascii"),
            "hgc_448_public_b64": base64.b64encode(hgc_pk).decode("ascii"),
        }
        priv_raw = json.dumps({
            "qlx_private_b64": base64.b64encode(qlx_sk).decode("ascii"),
            "hgc_448_private_b64": base64.b64encode(hgc_sk).decode("ascii"),
        }, separators=(",", ":")).encode("utf-8")
    else:
        qvs_pk, qvs_sk = QVSEngine.keygen(tier_qvs, sub_witness)
        ed_pk, ed_sk = ed448_keygen()
        public_bundle = {
            "qvs_public_b64": base64.b64encode(qvs_pk).decode("ascii"),
            "hgc_sig_public_b64": base64.b64encode(ed_pk).decode("ascii"),
        }
        priv_raw = json.dumps({
            "qvs_private_b64": base64.b64encode(qvs_sk).decode("ascii"),
            "hgc_sig_private_b64": base64.b64encode(ed_sk).decode("ascii"),
        }, separators=(",", ":")).encode("utf-8")

    subkey_id = qsponge_512(
        b"CALYX-SUBKEY-ID-v1.0.0|" + master_keyring.key_hash.encode("ascii") + json.dumps(public_bundle, sort_keys=True).encode("utf-8")
    ).hex()[:32].upper()

    transcript = _subkey_cert_transcript(
        master_keyring.key_hash, subkey_id, role, tier_qlx, tier_qvs, created_iso, expires_iso, public_bundle
    )
    master_qvs_pk = base64.b64decode(master_keyring.public_bundle["qvs_public_b64"])
    sig_qvs = QVSEngine.sign(master_priv["qvs_private"], master_qvs_pk, transcript, tier=master_keyring.qvs_tier)
    sig_ed448 = ed448_sign(master_priv["hgc_sig_private"], transcript)

    kdf_salt = os.urandom(32)
    k1, k2, _kmac, kdf_params = derive_qpkrf_keys_v4(master_passphrase, kdf_salt, qlx_tier=tier_qlx)
    nonce24 = os.urandom(24)
    aad = f"CALYX-SUBKEY-PRIV-v1.0.0|{master_keyring.key_hash}|{subkey_id}".encode("utf-8")
    with SecretBuffer(k1 + k2) as kbuf, SecretBuffer(priv_raw) as pbuf:
        ct_priv = cc512_encrypt(kbuf.as_bytes(), nonce24, pbuf.as_bytes(), aad)

    enc_priv = {
        "kdf_version": MANDATORY_KDF_VERSION,
        "kdf_salt_b64": base64.b64encode(kdf_salt).decode("ascii"),
        "kdf_params": kdf_params,
        "nonce24_b64": base64.b64encode(nonce24).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ct_priv).decode("ascii"),
    }

    return QPEPSubkey(
        subkey_id=subkey_id,
        role=role,
        master_key_hash=master_keyring.key_hash,
        qlx_tier=tier_qlx,
        qvs_tier=tier_qvs,
        created_at_utc=created_iso,
        expires_at_utc=expires_iso,
        public_bundle=public_bundle,
        encrypted_private_bundle=enc_priv,
        master_qvs_sig_b64=base64.b64encode(sig_qvs).decode("ascii"),
        master_ed448_sig_b64=base64.b64encode(sig_ed448).decode("ascii"),
    )


def verify_subkey(
    subkey: QPEPSubkey,
    master_public_keyring: QPEPKeyRing,
    *,
    now_utc: Optional[datetime.datetime] = None,
) -> Tuple[bool, str]:
    if subkey.master_key_hash != master_public_keyring.key_hash:
        return False, "Subkey master_key_hash does not match Master Identity Key."

    now = now_utc or datetime.datetime.now(datetime.timezone.utc)
    expires = datetime.datetime.fromisoformat(subkey.expires_at_utc)
    if now >= expires:
        return False, f"Subkey {subkey.subkey_id} expired at {subkey.expires_at_utc}."

    transcript = _subkey_cert_transcript(
        subkey.master_key_hash,
        subkey.subkey_id,
        subkey.role,
        subkey.qlx_tier,
        subkey.qvs_tier,
        subkey.created_at_utc,
        subkey.expires_at_utc,
        subkey.public_bundle,
    )
    master_qvs_pk = base64.b64decode(master_public_keyring.public_bundle["qvs_public_b64"])
    master_ed_pk = base64.b64decode(master_public_keyring.public_bundle["hgc_sig_public_b64"])
    sig_qvs = base64.b64decode(subkey.master_qvs_sig_b64)
    sig_ed = base64.b64decode(subkey.master_ed448_sig_b64)

    if not QVSEngine.verify(master_qvs_pk, transcript, sig_qvs, tier=master_public_keyring.qvs_tier):
        return False, "Master QVS lattice signature verification failed."
    if not ed448_verify(master_ed_pk, sig_ed, transcript):
        return False, "Master Ed448 signature verification failed."
    return True, f"Verified active {subkey.role} subkey {subkey.subkey_id} (expires {subkey.expires_at_utc})."
