"""
Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)
OpenQPEP Official Release 1.1.0 (v1.1.0) — Calyx Labs Inc. (CPOSLS-1.0).

Combines genuine CSIDH-512 Supersingular Isogeny KEM (CIF-SQI-512) with Stateless Hash-Based
Hypertree signatures (QHS-512) and CMT-4 Key-Committing CC-512 over Official Wire Format v5 (\\x89QPE\\x05\\x00).
"""
import base64
import json
import os
from typing import Dict, Tuple

from ..constants import PACKET_TYPE_SIGNATURE, PACKET_TYPE_SINGLE, PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..hashsig.qhs_512_hypertree import QHS512HypertreeEngine
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer
from ..wire.armor import armor_unwrap, armor_wrap
from .sqi_2d_512 import SupersingularIsogenyEngine

CIF_ENC_LABEL = "CALYX QPEP ISOGENY-FORGE PACKET"
CIF_SIG_LABEL = "CALYX QPEP ISOGENY-FORGE SIGNATURE"


class CalyxIsogenyForgeSuite:
    SUITE_ID = "CIF-SQI-512"
    SUITE_NAME = "Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)"
    HIGH_TIER_ONLY = False

    @staticmethod
    def keygen() -> Tuple[Dict[str, str], Dict[str, str]]:
        iso_pk, iso_sk = SupersingularIsogenyEngine.keygen()
        qhs_pk, qhs_sk = QHS512HypertreeEngine.keygen()
        b64 = lambda b: base64.b64encode(b).decode("ascii")
        pub = {
            "suite_id": CalyxIsogenyForgeSuite.SUITE_ID,
            "suite": CalyxIsogenyForgeSuite.SUITE_NAME,
            "version": UNIVERSAL_VERSION,
            "isogeny_pk_b64": b64(iso_pk),
            "qhs_pk_b64": b64(qhs_pk),
        }
        pub["key_hash"] = qsponge_512(
            b"CALYX-CIF-SQI512-KH-v1.0.0|" + json.dumps(pub, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hex()[:64].upper()
        priv = {
            "key_hash": pub["key_hash"],
            "isogeny_sk_b64": b64(iso_sk),
            "qhs_sk_b64": b64(qhs_sk),
        }
        return pub, priv

    @staticmethod
    def encrypt(plaintext: bytes, recipient_pub: Dict[str, str]) -> str:
        ct_iso, ss = SupersingularIsogenyEngine.encaps(base64.b64decode(recipient_pub["isogeny_pk_b64"]))
        with SecretBuffer(qsponge_512(b"CALYX-CIF-SQI512-CC512-v1.0.0|" + ss + ct_iso)) as key_buf:
            n24 = os.urandom(24)
            ct = cc512_encrypt(key_buf.as_bytes(), n24, plaintext, b"CALYX-CIF-SQI-512-v1.0.0")
        pkt = {
            "type": "openqpep-isogeny-forge-packet",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "suite": CalyxIsogenyForgeSuite.SUITE_NAME,
            "ct_iso_b64": base64.b64encode(ct_iso).decode("ascii"),
            "nonce24_b64": base64.b64encode(n24).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }
        return armor_wrap(CIF_ENC_LABEL, json.dumps(pkt, separators=(",", ":")).encode("utf-8"), packet_type=PACKET_TYPE_SINGLE)

    @staticmethod
    def decrypt(armored: str, recipient_priv: Dict[str, str]) -> bytes:
        raw, _ = armor_unwrap(armored, CIF_ENC_LABEL)
        pkt = json.loads(raw.decode("utf-8"))
        ct_iso = base64.b64decode(pkt["ct_iso_b64"])
        ss = SupersingularIsogenyEngine.decaps(base64.b64decode(recipient_priv["isogeny_sk_b64"]), ct_iso)
        with SecretBuffer(qsponge_512(b"CALYX-CIF-SQI512-CC512-v1.0.0|" + ss + ct_iso)) as key_buf:
            return cc512_decrypt(
                key_buf.as_bytes(),
                base64.b64decode(pkt["nonce24_b64"]),
                base64.b64decode(pkt["ct_b64"]),
                b"CALYX-CIF-SQI-512-v1.0.0",
            )

    @staticmethod
    def sign(message: bytes, signer_priv: Dict[str, str]) -> str:
        sig_qhs = QHS512HypertreeEngine.sign(base64.b64decode(signer_priv["qhs_sk_b64"]), message)
        bundle = {
            "type": "openqpep-isogeny-forge-signature",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "suite": CalyxIsogenyForgeSuite.SUITE_NAME,
            "message_b64": base64.b64encode(message).decode("ascii"),
            "sig_qhs_b64": base64.b64encode(sig_qhs).decode("ascii"),
        }
        return armor_wrap(CIF_SIG_LABEL, json.dumps(bundle, separators=(",", ":")).encode("utf-8"), packet_type=PACKET_TYPE_SIGNATURE)

    @staticmethod
    def verify(armored_sig: str, signer_pub: Dict[str, str]) -> Tuple[bool, bytes]:
        try:
            raw, _ = armor_unwrap(armored_sig, CIF_SIG_LABEL)
            bundle = json.loads(raw.decode("utf-8"))
            msg = base64.b64decode(bundle["message_b64"])
            ok = QHS512HypertreeEngine.verify(
                base64.b64decode(signer_pub["qhs_pk_b64"]),
                msg,
                base64.b64decode(bundle["sig_qhs_b64"]),
            )
            return bool(ok), (msg if ok else b"")
        except Exception:
            return False, b""
