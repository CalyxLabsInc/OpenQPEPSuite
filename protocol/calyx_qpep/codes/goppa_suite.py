"""OpenQPEP Official Release 1.0.0 — Standalone Calyx Goppa-Monolith (CGM-8192) Non-Lattice Suite."""
import base64
import json
import os
from typing import Tuple

from ..constants import PACKET_TYPE_SINGLE, PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer
from ..wire.armor import armor_unwrap, armor_wrap
from .goppa_8192 import BinaryGoppaKEM

CGM_LABEL = "CALYX QPEP GOPPA-MONOLITH PACKET"


class CalyxGoppaMonolithSuite:
    SUITE_NAME = "Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)"

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        return BinaryGoppaKEM.keygen()

    @staticmethod
    def encrypt(plaintext: bytes, recipient_pk: bytes) -> str:
        ct_kem, ss = BinaryGoppaKEM.encaps(recipient_pk)
        with SecretBuffer(qsponge_512(b"CALYX-CGM8192-CC512-v1.0.0|" + ss + ct_kem)) as key_buf:
            n24 = os.urandom(24)
            ct = cc512_encrypt(key_buf.as_bytes(), n24, plaintext, b"CALYX-CGM-8192-v1.0.0")
        pkt = {
            "type": "openqpep-goppa-monolith-packet",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "suite": CalyxGoppaMonolithSuite.SUITE_NAME,
            "ct_kem_b64": base64.b64encode(ct_kem).decode("ascii"),
            "nonce24_b64": base64.b64encode(n24).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }
        return armor_wrap(CGM_LABEL, json.dumps(pkt, separators=(",", ":")).encode("utf-8"), packet_type=PACKET_TYPE_SINGLE)

    @staticmethod
    def decrypt(armored: str, recipient_sk: bytes) -> bytes:
        raw, _ = armor_unwrap(armored, CGM_LABEL)
        pkt = json.loads(raw.decode("utf-8"))
        ct_kem = base64.b64decode(pkt["ct_kem_b64"])
        ss = BinaryGoppaKEM.decaps(recipient_sk, ct_kem)
        with SecretBuffer(qsponge_512(b"CALYX-CGM8192-CC512-v1.0.0|" + ss + ct_kem)) as key_buf:
            return cc512_decrypt(
                key_buf.as_bytes(),
                base64.b64decode(pkt["nonce24_b64"]),
                base64.b64decode(pkt["ct_b64"]),
                b"CALYX-CGM-8192-v1.0.0",
            )
