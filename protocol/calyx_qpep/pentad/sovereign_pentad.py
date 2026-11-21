"""
Calyx Sovereign-Pentad (CSP-Omega — Five-Family Cryptographic Citadel) (Release Candidate 1.0.0).

Simultaneously fuses FIVE mathematically disjoint post-quantum families in parallel threads:
  Family 1 — Unstructured Plain-LWE (CULC-2048): zero ring symmetry, worst-case general lattice
             (native C99/AVX2 accelerated inner loops in v1.0.0-rc via libopenqpep)
  Family 2 — Binary Goppa Codes (CGM-8192): NP-complete Hamming-metric syndrome decoding
  Family 3 — Higher-Dimensional Abelian Isogenies (CIF-SQI-512): supersingular quaternion geometry
  Family 4 — Multivariate Quadratic Signatures (QMQ-512): NP-complete MQ over GF(256)
  Family 5 — Stateless Hash-Based Hypertree (QHS-512): zero-trapdoor Keccak-f[1600] one-wayness

Release Candidate 1.0.0 Updates:
  - Frozen Wire Format v3 (\\x89QPE\\x03\\x00, packet_type=0x06 PACKET_TYPE_PENTAD) with full
    read compatibility for legacy v1.0.0-rc–v1.0.0-rc Sovereign-Pentad packets.
  - Native C99/AVX2 acceleration for Family 1 Unstructured Plain-LWE row-streamed operations.
  - Mandatory >= 12 GB RAM flagship hardware guardrail (Samsung Galaxy Z Fold 8 / high-spec PCs).
"""
import base64
import concurrent.futures
import json
import os
from typing import Any, Dict, Tuple

from ..codes.goppa_8192 import BinaryGoppaKEM
from ..constants import PACKET_TYPE_PENTAD, PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..exceptions import QPEPMacVerificationError, QPEPSuiteError
from ..hashsig.qhs_512_hypertree import QHS512HypertreeEngine
from ..isogeny.sqi_2d_512 import SupersingularIsogenyEngine
from ..kdf.hardware_tuner import detect_system_ram_mib
from ..lattice.plain_lwe import PlainLWEEngine
from ..multivariate.qmq_512 import MultivariateQuadraticEngine
from ..native.loader import is_native_available
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.hgc448 import x448_exchange, x448_keygen
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer
from ..wire.armor import armor_unwrap, armor_wrap

PENTAD_SUITE_NAME = "Calyx Sovereign-Pentad: CSP-Omega (5-Family Citadel)"
PENTAD_MIN_RAM_MIB = 12288  # 12 GB flagship hardware guardrail
PENTAD_ENC_LABEL = "CALYX QPEP SOVEREIGN-PENTAD PACKET"
PENTAD_SIG_LABEL = "CALYX QPEP SOVEREIGN-PENTAD SIGNATURE"


def check_flagship_hardware_guardrail(*, override_ram_mib: int = 0, allow_override: bool = False) -> Dict[str, Any]:
    """
    Enforces the >= 12 GB RAM flagship hardware guardrail for Calyx Sovereign-Pentad (CSP-Omega).
    Raises QPEPSuiteError on low-RAM devices unless `allow_override=True` is explicitly set.
    """
    ram_mib = override_ram_mib if override_ram_mib > 0 else detect_system_ram_mib()
    meets = ram_mib >= PENTAD_MIN_RAM_MIB
    if not meets and not allow_override:
        raise QPEPSuiteError(
            f"Calyx Sovereign-Pentad (CSP-Omega) requires >= 12 GB RAM flagship hardware "
            f"(detected {ram_mib} MiB). Use Calyx Signature (QLX-4096 + QVS-256) on standard devices."
        )
    return {
        "suite": PENTAD_SUITE_NAME,
        "detected_ram_mib": ram_mib,
        "required_ram_mib": PENTAD_MIN_RAM_MIB,
        "flagship_qualified": meets,
        "wire_format": "v4",
        "native_acceleration": is_native_available(),
    }


class CalyxSovereignPentad:
    """Simultaneous 5-Family Beyond-LWE Post-Quantum Combiner (CSP-Omega, Wire Format v3)."""

    @staticmethod
    def keygen(*, allow_low_ram_override: bool = False) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Generates all 5 disjoint cryptographic key pairs concurrently across threads."""
        check_flagship_hardware_guardrail(allow_override=allow_low_ram_override)
        with concurrent.futures.ThreadPoolExecutor(max_workers=(1 if os.environ.get('OPENQPEP_DETERMINISTIC_KAT') == '1' else 5)) as ex:
            f_lwe = ex.submit(PlainLWEEngine.keygen)
            f_goppa = ex.submit(BinaryGoppaKEM.keygen)
            f_isog = ex.submit(SupersingularIsogenyEngine.keygen)
            f_qmq = ex.submit(MultivariateQuadraticEngine.keygen)
            f_qhs = ex.submit(QHS512HypertreeEngine.keygen)
            f_x448 = ex.submit(x448_keygen)

            lwe_pk, lwe_sk = f_lwe.result()
            gop_pk, gop_sk = f_goppa.result()
            iso_pk, iso_sk = f_isog.result()
            qmq_pk, qmq_sk = f_qmq.result()
            qhs_pk, qhs_sk = f_qhs.result()
            x448_pk, x448_sk = f_x448.result()

        b64 = lambda b: base64.b64encode(b).decode("ascii")
        pub = {
            "suite": PENTAD_SUITE_NAME,
            "version": UNIVERSAL_VERSION,
            "wire_format": "v3",
            "plain_lwe_pk_b64": b64(lwe_pk),
            "goppa_pk_b64": b64(gop_pk),
            "isogeny_pk_b64": b64(iso_pk),
            "qmq_pk_b64": b64(qmq_pk),
            "qhs_pk_b64": b64(qhs_pk),
            "x448_pk_b64": b64(x448_pk),
        }
        pub["key_hash"] = qsponge_512(
            b"CALYX-PENTAD-KEYHASH|" + json.dumps(pub, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hex()[:64].upper()
        priv = {
            "key_hash": pub["key_hash"],
            "plain_lwe_sk_b64": b64(lwe_sk),
            "goppa_sk_b64": b64(gop_sk),
            "isogeny_sk_b64": b64(iso_sk),
            "qmq_sk_b64": b64(qmq_sk),
            "qhs_sk_b64": b64(qhs_sk),
            "x448_sk_b64": b64(x448_sk),
        }
        return pub, priv

    @staticmethod
    def encrypt(plaintext: bytes, recipient_pub: Dict[str, str]) -> str:
        """Concurrently encapsulates across Plain-LWE + Binary Goppa + 2D Isogeny + X448, fused into CC-512."""
        b64d = base64.b64decode
        with concurrent.futures.ThreadPoolExecutor(max_workers=(1 if os.environ.get('OPENQPEP_DETERMINISTIC_KAT') == '1' else 4)) as ex:
            f_lwe = ex.submit(PlainLWEEngine.encaps, b64d(recipient_pub["plain_lwe_pk_b64"]))
            f_gop = ex.submit(BinaryGoppaKEM.encaps, b64d(recipient_pub["goppa_pk_b64"]))
            f_iso = ex.submit(SupersingularIsogenyEngine.encaps, b64d(recipient_pub["isogeny_pk_b64"]))
            f_x448 = ex.submit(x448_keygen)

            ct_lwe, ss_lwe = f_lwe.result()
            ct_gop, ss_gop = f_gop.result()
            ct_iso, ss_iso = f_iso.result()
            epk_x448, esk_x448 = f_x448.result()
            with SecretBuffer(esk_x448) as esk_buf:
                ss_x448 = x448_exchange(esk_buf.as_bytes(), b64d(recipient_pub["x448_pk_b64"]))

        transcript = qsponge_512(ct_lwe + ct_gop + ct_iso + epk_x448)
        with SecretBuffer(
            qsponge_512(b"CALYX-PENTAD-OMEGA-v1|" + ss_lwe + ss_gop + ss_iso + ss_x448 + transcript)
        ) as ss_omega_buf:
            nonce24 = os.urandom(24)
            aad = b"CALYX-PENTAD-CC512-v1|" + transcript[:32]
            ct_payload = cc512_encrypt(ss_omega_buf.as_bytes(), nonce24, plaintext, aad)

        b64e = lambda b: base64.b64encode(b).decode("ascii")
        pkt = {
            "type": "openqpep-sovereign-pentad-packet",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "wire_format": "v3",
            "suite": PENTAD_SUITE_NAME,
            "ct_plain_lwe_b64": b64e(ct_lwe),
            "ct_goppa_b64": b64e(ct_gop),
            "ct_isogeny_b64": b64e(ct_iso),
            "epk_x448_b64": b64e(epk_x448),
            "nonce24_b64": b64e(nonce24),
            "ciphertext_b64": b64e(ct_payload),
        }
        return armor_wrap(
            PENTAD_ENC_LABEL,
            json.dumps(pkt, separators=(",", ":")).encode("utf-8"),
            packet_type=PACKET_TYPE_PENTAD,
        )

    @staticmethod
    def decrypt(armored_packet: str, recipient_priv: Dict[str, str]) -> bytes:
        """Concurrently decapsulates all 4 KEM locks, reconstructs ss_Omega, and decrypts CC-512."""
        raw_json, _ = armor_unwrap(armored_packet, PENTAD_ENC_LABEL)
        pkt = json.loads(raw_json.decode("utf-8"))
        b64d = base64.b64decode
        ct_lwe = b64d(pkt["ct_plain_lwe_b64"])
        ct_gop = b64d(pkt["ct_goppa_b64"])
        ct_iso = b64d(pkt["ct_isogeny_b64"])
        epk_x448 = b64d(pkt["epk_x448_b64"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=(1 if os.environ.get('OPENQPEP_DETERMINISTIC_KAT') == '1' else 4)) as ex:
            f_lwe = ex.submit(PlainLWEEngine.decaps, b64d(recipient_priv["plain_lwe_sk_b64"]), ct_lwe)
            f_gop = ex.submit(BinaryGoppaKEM.decaps, b64d(recipient_priv["goppa_sk_b64"]), ct_gop)
            f_iso = ex.submit(SupersingularIsogenyEngine.decaps, b64d(recipient_priv["isogeny_sk_b64"]), ct_iso)
            ss_x448 = x448_exchange(b64d(recipient_priv["x448_sk_b64"]), epk_x448)

            ss_lwe = f_lwe.result()
            ss_gop = f_gop.result()
            ss_iso = f_iso.result()

        transcript = qsponge_512(ct_lwe + ct_gop + ct_iso + epk_x448)
        with SecretBuffer(
            qsponge_512(b"CALYX-PENTAD-OMEGA-v1|" + ss_lwe + ss_gop + ss_iso + ss_x448 + transcript)
        ) as ss_omega_buf:
            aad = b"CALYX-PENTAD-CC512-v1|" + transcript[:32]
            return cc512_decrypt(ss_omega_buf.as_bytes(), b64d(pkt["nonce24_b64"]), b64d(pkt["ciphertext_b64"]), aad)

    @staticmethod
    def sign(message: bytes, signer_pub: Dict[str, str], signer_priv: Dict[str, str]) -> str:
        """Produces conjunctive triple-family signature sigma_Omega = (sigma_QHS-512, sigma_QMQ-512, sigma_SQI-512)."""
        b64d = base64.b64decode
        with concurrent.futures.ThreadPoolExecutor(max_workers=(1 if os.environ.get('OPENQPEP_DETERMINISTIC_KAT') == '1' else 3)) as ex:
            f_qhs = ex.submit(QHS512HypertreeEngine.sign, b64d(signer_priv["qhs_sk_b64"]), message)
            f_qmq = ex.submit(MultivariateQuadraticEngine.sign, b64d(signer_priv["qmq_sk_b64"]), message)
            f_sqi = ex.submit(
                SupersingularIsogenyEngine.sign,
                b64d(signer_priv["isogeny_sk_b64"]),
                b64d(signer_pub["isogeny_pk_b64"]),
                message,
            )
            sig_qhs = f_qhs.result()
            sig_qmq = f_qmq.result()
            sig_sqi = f_sqi.result()

        b64e = lambda b: base64.b64encode(b).decode("ascii")
        bundle = {
            "type": "openqpep-sovereign-pentad-signature",
            "version": UNIVERSAL_VERSION,
            "wire_format": "v3",
            "suite": PENTAD_SUITE_NAME,
            "message_b64": b64e(message),
            "sigma_qhs_512_b64": b64e(sig_qhs),
            "sigma_qmq_512_b64": b64e(sig_qmq),
            "sigma_sqi_512_b64": b64e(sig_sqi),
        }
        return armor_wrap(
            PENTAD_SIG_LABEL,
            json.dumps(bundle, separators=(",", ":")).encode("utf-8"),
            packet_type=PACKET_TYPE_PENTAD,
        )

    @staticmethod
    def verify(armored_signature: str, signer_pub: Dict[str, str]) -> Tuple[bool, bytes]:
        """Verifies ALL THREE disjoint signature families (QHS-512 AND QMQ-512 AND SQI-512)."""
        raw_json, _ = armor_unwrap(armored_signature, PENTAD_SIG_LABEL)
        bundle = json.loads(raw_json.decode("utf-8"))
        b64d = base64.b64decode
        message = b64d(bundle["message_b64"])

        ok_qhs = QHS512HypertreeEngine.verify(b64d(signer_pub["qhs_pk_b64"]), message, b64d(bundle["sigma_qhs_512_b64"]))
        ok_qmq = MultivariateQuadraticEngine.verify(b64d(signer_pub["qmq_pk_b64"]), message, b64d(bundle["sigma_qmq_512_b64"]))
        ok_sqi = SupersingularIsogenyEngine.verify(b64d(signer_pub["isogeny_pk_b64"]), message, b64d(bundle["sigma_sqi_512_b64"]))
        return bool(ok_qhs and ok_qmq and ok_sqi), message
