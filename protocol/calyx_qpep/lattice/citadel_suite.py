# OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc)
"""
Tier 9: Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)
OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc) — Calyx Labs Inc. (CPOSLS-1.0).

Fuses Zero-Ring Unstructured Plain-LWE (CULC-2048) with NP-Complete Binary Goppa Codes (CGM-8192),
Stateless qSponge-512 Hypertree signatures (QHS-512), and CC-512 over Frozen Wire Format v3.
Enforces the >= 12 GB RAM flagship hardware guardrail.
"""
import base64
import concurrent.futures
import json
import os
from typing import Dict, Tuple

from ..codes.goppa_8192 import BinaryGoppaKEM
from ..constants import PACKET_TYPE_SINGLE, PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..exceptions import QPEPSuiteError
from ..hashsig.qhs_512_hypertree import QHS512HypertreeEngine
from ..kdf.hardware_tuner import detect_system_ram_mib
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512
from ..wire.armor import armor_unwrap, armor_wrap
from .plain_lwe import PlainLWEEngine

CITADEL_ENC_LABEL = "CALYX QPEP UNSTRUCTURED-CITADEL PACKET"
CITADEL_SIG_LABEL = "CALYX QPEP UNSTRUCTURED-CITADEL SIGNATURE"
CITADEL_MIN_RAM_MIB = 12288


class CalyxUnstructuredCitadelSuite:
    SUITE_ID = "CULC-2048"
    SUITE_NAME = "Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)"
    HIGH_TIER_ONLY = True

    @staticmethod
    def keygen(*, allow_low_ram_override: bool = False) -> Tuple[Dict[str, str], Dict[str, str]]:
        ram_mib = detect_system_ram_mib()
        if ram_mib < CITADEL_MIN_RAM_MIB and not allow_low_ram_override:
            raise QPEPSuiteError(
                f"Calyx Unstructured-Citadel (CULC-2048 + CGM-8192) requires >= 12 GB RAM flagship hardware "
                f"(detected {ram_mib} MiB)."
            )
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            f_lwe = ex.submit(PlainLWEEngine.keygen)
            f_gop = ex.submit(BinaryGoppaKEM.keygen)
            f_qhs = ex.submit(QHS512HypertreeEngine.keygen)
            lwe_pk, lwe_sk = f_lwe.result()
            gop_pk, gop_sk = f_gop.result()
            qhs_pk, qhs_sk = f_qhs.result()

        b64 = lambda b: base64.b64encode(b).decode("ascii")
        pub = {
            "suite_id": CalyxUnstructuredCitadelSuite.SUITE_ID,
            "suite": CalyxUnstructuredCitadelSuite.SUITE_NAME,
            "version": UNIVERSAL_VERSION,
            "plain_lwe_pk_b64": b64(lwe_pk),
            "goppa_pk_b64": b64(gop_pk),
            "qhs_pk_b64": b64(qhs_pk),
        }
        pub["key_hash"] = qsponge_512(
            b"CALYX-CULC2048-KH|" + json.dumps(pub, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hex()[:64].upper()
        priv = {
            "key_hash": pub["key_hash"],
            "plain_lwe_sk_b64": b64(lwe_sk),
            "goppa_sk_b64": b64(gop_sk),
            "qhs_sk_b64": b64(qhs_sk),
        }
        return pub, priv

    @staticmethod
    def encrypt(plaintext: bytes, recipient_pub: Dict[str, str]) -> str:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_lwe = ex.submit(PlainLWEEngine.encaps, base64.b64decode(recipient_pub["plain_lwe_pk_b64"]))
            f_gop = ex.submit(BinaryGoppaKEM.encaps, base64.b64decode(recipient_pub["goppa_pk_b64"]))
            ct_lwe, ss_lwe = f_lwe.result()
            ct_gop, ss_gop = f_gop.result()

        transcript = qsponge_512(ct_lwe + ct_gop)
        key64 = qsponge_512(b"CALYX-CULC2048-CC512|" + ss_lwe + ss_gop + transcript)
        n24 = os.urandom(24)
        ct = cc512_encrypt(key64, n24, plaintext, b"CULC-2048+CGM-8192")
        pkt = {
            "type": "openqpep-unstructured-citadel-packet",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "suite": CalyxUnstructuredCitadelSuite.SUITE_NAME,
            "ct_lwe_b64": base64.b64encode(ct_lwe).decode("ascii"),
            "ct_goppa_b64": base64.b64encode(ct_gop).decode("ascii"),
            "nonce24_b64": base64.b64encode(n24).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }
        return armor_wrap(CITADEL_ENC_LABEL, json.dumps(pkt, separators=(",", ":")).encode("utf-8"), packet_type=PACKET_TYPE_SINGLE)

    @staticmethod
    def decrypt(armored: str, recipient_priv: Dict[str, str]) -> bytes:
        raw, _ = armor_unwrap(armored, CITADEL_ENC_LABEL)
        pkt = json.loads(raw.decode("utf-8"))
        ct_lwe = base64.b64decode(pkt["ct_lwe_b64"])
        ct_gop = base64.b64decode(pkt["ct_goppa_b64"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_lwe = ex.submit(PlainLWEEngine.decaps, base64.b64decode(recipient_priv["plain_lwe_sk_b64"]), ct_lwe)
            f_gop = ex.submit(BinaryGoppaKEM.decaps, base64.b64decode(recipient_priv["goppa_sk_b64"]), ct_gop)
            ss_lwe = f_lwe.result()
            ss_gop = f_gop.result()
        transcript = qsponge_512(ct_lwe + ct_gop)
        key64 = qsponge_512(b"CALYX-CULC2048-CC512|" + ss_lwe + ss_gop + transcript)
        return cc512_decrypt(key64, base64.b64decode(pkt["nonce24_b64"]), base64.b64decode(pkt["ct_b64"]), b"CULC-2048+CGM-8192")

    @staticmethod
    def sign(message: bytes, signer_priv: Dict[str, str]) -> str:
        sig_qhs = QHS512HypertreeEngine.sign(base64.b64decode(signer_priv["qhs_sk_b64"]), message)
        bundle = {
            "type": "openqpep-unstructured-citadel-signature",
            "version": UNIVERSAL_VERSION,
            "suite": CalyxUnstructuredCitadelSuite.SUITE_NAME,
            "message_b64": base64.b64encode(message).decode("ascii"),
            "sig_qhs_b64": base64.b64encode(sig_qhs).decode("ascii"),
        }
        return armor_wrap(CITADEL_SIG_LABEL, json.dumps(bundle, separators=(",", ":")).encode("utf-8"))

    @staticmethod
    def verify(armored_sig: str, signer_pub: Dict[str, str]) -> Tuple[bool, bytes]:
        raw, _ = armor_unwrap(armored_sig, CITADEL_SIG_LABEL)
        bundle = json.loads(raw.decode("utf-8"))
        msg = base64.b64decode(bundle["message_b64"])
        ok = QHS512HypertreeEngine.verify(
            base64.b64decode(signer_pub["qhs_pk_b64"]),
            msg,
            base64.b64decode(bundle["sig_qhs_b64"]),
        )
        return bool(ok), msg
