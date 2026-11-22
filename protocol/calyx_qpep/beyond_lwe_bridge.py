"""
OpenQPEP Official Release 1.0.0 (v1.0.0) Beyond-LWE Native .qpkrf Persistence & Dispatch Bridge.
Provides unified Wire Format v5 keygen, encrypt, decrypt, sign, and verify dispatch for all 5 Beyond-LWE suites:
  - CIF-SQI-512  (Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512)
  - CRT-RSD512   (Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512)
  - CGM-8192     (Calyx Goppa-Monolith: CGM-8192 + QHS-512)
  - CULC-2048    (Calyx Unstructured-Citadel: CULC-2048 + CGM-8192)
  - CSP-Omega    (Calyx Sovereign-Pentad: CSP-Omega + QHS-512)
"""
import base64
import json
from typing import Any, Dict, Tuple

from .constants import PACKET_TYPE_SIGNATURE, PROTOCOL_VERSION, UNIVERSAL_VERSION
from .wire.armor import armor_unwrap, armor_wrap

BEYOND_LWE_SUITES = ("CIF-SQI-512", "CRT-RSD512", "CGM-8192", "CULC-2048", "CSP-Omega")
CRT_SIG_LABEL = "CALYX QPEP RANK-METRIC SIGNATURE"
CGM_SIG_LABEL = "CALYX QPEP GOPPA-MONOLITH SIGNATURE"


def _engines():
    from .codes.goppa_suite import CalyxGoppaMonolithSuite
    from .codes.rank_suite import CalyxRankMetricSuite
    from .hashsig.qhs_512_hypertree import QHS512HypertreeEngine
    from .isogeny.isogeny_suite import CalyxIsogenyForgeSuite
    from .lattice.citadel_suite import CalyxUnstructuredCitadelSuite
    from .multivariate.qmq_512 import MultivariateQuadraticEngine
    from .pentad import CalyxSovereignPentad
    return (
        CalyxGoppaMonolithSuite, CalyxRankMetricSuite, QHS512HypertreeEngine,
        CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, MultivariateQuadraticEngine,
        CalyxSovereignPentad,
    )


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def generate_beyond_lwe_material(suite_id: str, allow_low_ram_override: bool = True) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generates JSON-serializable (public_dict, private_dict) for any of the 5 Beyond-LWE suites."""
    CalyxGoppaMonolithSuite, CalyxRankMetricSuite, QHS512HypertreeEngine, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, MultivariateQuadraticEngine, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        pub, priv = CalyxIsogenyForgeSuite.keygen()
        return {"suite_id": suite_id, "pub": pub}, {"suite_id": suite_id, "priv": priv}
    if suite_id == "CRT-RSD512":
        kem_pk, kem_sk = CalyxRankMetricSuite.keygen()
        sig_pk, sig_sk = MultivariateQuadraticEngine.keygen()
        return (
            {"suite_id": suite_id, "kem_pk_b64": _b64e(kem_pk), "sig_pk_b64": _b64e(sig_pk)},
            {"suite_id": suite_id, "kem_sk_b64": _b64e(kem_sk), "sig_sk_b64": _b64e(sig_sk)},
        )
    if suite_id == "CGM-8192":
        kem_pk, kem_sk = CalyxGoppaMonolithSuite.keygen()
        sig_pk, sig_sk = QHS512HypertreeEngine.keygen()
        return (
            {"suite_id": suite_id, "kem_pk_b64": _b64e(kem_pk), "sig_pk_b64": _b64e(sig_pk)},
            {"suite_id": suite_id, "kem_sk_b64": _b64e(kem_sk), "sig_sk_b64": _b64e(sig_sk)},
        )
    if suite_id == "CULC-2048":
        pub, priv = CalyxUnstructuredCitadelSuite.keygen(allow_low_ram_override=allow_low_ram_override)
        return {"suite_id": suite_id, "pub": pub}, {"suite_id": suite_id, "priv": priv}
    if suite_id == "CSP-Omega":
        pub, priv = CalyxSovereignPentad.keygen(allow_low_ram_override=allow_low_ram_override)
        return {"suite_id": suite_id, "pub": pub}, {"suite_id": suite_id, "priv": priv}
    raise ValueError(f"Unsupported Beyond-LWE suite: {suite_id}")


def encrypt_beyond_lwe(suite_id: str, plaintext: bytes, blwe_pub: Dict[str, Any]) -> str:
    CalyxGoppaMonolithSuite, CalyxRankMetricSuite, _QHS, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, _QMQ, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        return CalyxIsogenyForgeSuite.encrypt(plaintext, blwe_pub["pub"])
    if suite_id == "CRT-RSD512":
        return CalyxRankMetricSuite.encrypt(plaintext, _b64d(blwe_pub["kem_pk_b64"]))
    if suite_id == "CGM-8192":
        return CalyxGoppaMonolithSuite.encrypt(plaintext, _b64d(blwe_pub["kem_pk_b64"]))
    if suite_id == "CULC-2048":
        return CalyxUnstructuredCitadelSuite.encrypt(plaintext, blwe_pub["pub"])
    if suite_id == "CSP-Omega":
        return CalyxSovereignPentad.encrypt(plaintext, blwe_pub["pub"])
    raise ValueError(f"Unsupported Beyond-LWE suite: {suite_id}")


def decrypt_beyond_lwe(suite_id: str, armored: str, blwe_priv: Dict[str, Any]) -> bytes:
    CalyxGoppaMonolithSuite, CalyxRankMetricSuite, _QHS, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, _QMQ, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        return CalyxIsogenyForgeSuite.decrypt(armored, blwe_priv["priv"])
    if suite_id == "CRT-RSD512":
        return CalyxRankMetricSuite.decrypt(armored, _b64d(blwe_priv["kem_sk_b64"]))
    if suite_id == "CGM-8192":
        return CalyxGoppaMonolithSuite.decrypt(armored, _b64d(blwe_priv["kem_sk_b64"]))
    if suite_id == "CULC-2048":
        return CalyxUnstructuredCitadelSuite.decrypt(armored, blwe_priv["priv"])
    if suite_id == "CSP-Omega":
        return CalyxSovereignPentad.decrypt(armored, blwe_priv["priv"])
    raise ValueError(f"Unsupported Beyond-LWE suite: {suite_id}")


def sign_beyond_lwe(suite_id: str, message: bytes, blwe_pub: Dict[str, Any], blwe_priv: Dict[str, Any]) -> str:
    _CGM, _CRT, QHS512HypertreeEngine, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, MultivariateQuadraticEngine, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        return CalyxIsogenyForgeSuite.sign(message, blwe_priv["priv"])
    if suite_id == "CRT-RSD512":
        sig = MultivariateQuadraticEngine.sign(_b64d(blwe_priv["sig_sk_b64"]), message)
        bundle = {
            "type": "openqpep-rank-metric-signature",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "suite_id": "CRT-RSD512",
            "message_b64": _b64e(message),
            "sig_qmq_b64": _b64e(sig),
        }
        return armor_wrap(CRT_SIG_LABEL, json.dumps(bundle, separators=(",", ":")).encode("utf-8"), packet_type=PACKET_TYPE_SIGNATURE)
    if suite_id == "CGM-8192":
        sig = QHS512HypertreeEngine.sign(_b64d(blwe_priv["sig_sk_b64"]), message)
        bundle = {
            "type": "openqpep-goppa-monolith-signature",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "suite_id": "CGM-8192",
            "message_b64": _b64e(message),
            "sig_qhs_b64": _b64e(sig),
        }
        return armor_wrap(CGM_SIG_LABEL, json.dumps(bundle, separators=(",", ":")).encode("utf-8"), packet_type=PACKET_TYPE_SIGNATURE)
    if suite_id == "CULC-2048":
        return CalyxUnstructuredCitadelSuite.sign(message, blwe_priv["priv"])
    if suite_id == "CSP-Omega":
        return CalyxSovereignPentad.sign(message, blwe_pub["pub"], blwe_priv["priv"])
    raise ValueError(f"Unsupported Beyond-LWE suite: {suite_id}")


def verify_beyond_lwe(suite_id: str, armored_sig: str, blwe_pub: Dict[str, Any]) -> Tuple[bool, bytes]:
    _CGM, _CRT, QHS512HypertreeEngine, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, MultivariateQuadraticEngine, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        return CalyxIsogenyForgeSuite.verify(armored_sig, blwe_pub["pub"])
    if suite_id == "CRT-RSD512":
        try:
            raw, _ = armor_unwrap(armored_sig, CRT_SIG_LABEL)
            bundle = json.loads(raw.decode("utf-8"))
            if bundle.get("suite_id") != "CRT-RSD512":
                return False, b""
            msg = _b64d(bundle["message_b64"])
            ok = MultivariateQuadraticEngine.verify(_b64d(blwe_pub["sig_pk_b64"]), msg, _b64d(bundle["sig_qmq_b64"]))
            return bool(ok), (msg if ok else b"")
        except Exception:
            return False, b""
    if suite_id == "CGM-8192":
        try:
            raw, _ = armor_unwrap(armored_sig, CGM_SIG_LABEL)
            bundle = json.loads(raw.decode("utf-8"))
            if bundle.get("suite_id") != "CGM-8192":
                return False, b""
            msg = _b64d(bundle["message_b64"])
            ok = QHS512HypertreeEngine.verify(_b64d(blwe_pub["sig_pk_b64"]), msg, _b64d(bundle["sig_qhs_b64"]))
            return bool(ok), (msg if ok else b"")
        except Exception:
            return False, b""
    if suite_id == "CULC-2048":
        return CalyxUnstructuredCitadelSuite.verify(armored_sig, blwe_pub["pub"])
    if suite_id == "CSP-Omega":
        return CalyxSovereignPentad.verify(armored_sig, blwe_pub["pub"])
    raise ValueError(f"Unsupported Beyond-LWE suite: {suite_id}")
