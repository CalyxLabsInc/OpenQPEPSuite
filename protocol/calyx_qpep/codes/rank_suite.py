"""OpenQPEP Official Release 1.0.0 — Standalone Calyx Rank-Metric Tensor (CRT-RSD512) Non-Lattice Suite."""
import base64
import json
import os
from typing import Tuple

from ..constants import PACKET_TYPE_SINGLE, PROTOCOL_VERSION, UNIVERSAL_VERSION
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer
from ..wire.armor import armor_unwrap, armor_wrap
from .rank_rsd512 import RankMetricKEM

CRT_LABEL = "CALYX QPEP RANK-METRIC PACKET"


class CalyxRankMetricSuite:
    SUITE_NAME = "Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)"

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        return RankMetricKEM.keygen()

    @staticmethod
    def encrypt(plaintext: bytes, recipient_pk: bytes) -> str:
        ct_kem, ss = RankMetricKEM.encaps(recipient_pk)
        with SecretBuffer(qsponge_512(b"CALYX-CRT-RSD512-CC512-v1.0.0|" + ss + ct_kem)) as key_buf:
            n24 = os.urandom(24)
            ct = cc512_encrypt(key_buf.as_bytes(), n24, plaintext, b"CALYX-CRT-RSD512-v1.0.0")
        pkt = {
            "type": "openqpep-rank-metric-packet",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "suite": CalyxRankMetricSuite.SUITE_NAME,
            "ct_kem_b64": base64.b64encode(ct_kem).decode("ascii"),
            "nonce24_b64": base64.b64encode(n24).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }
        return armor_wrap(CRT_LABEL, json.dumps(pkt, separators=(",", ":")).encode("utf-8"), packet_type=PACKET_TYPE_SINGLE)

    @staticmethod
    def decrypt(armored: str, recipient_sk: bytes) -> bytes:
        raw, _ = armor_unwrap(armored, CRT_LABEL)
        pkt = json.loads(raw.decode("utf-8"))
        ct_kem = base64.b64decode(pkt["ct_kem_b64"])
        ss = RankMetricKEM.decaps(recipient_sk, ct_kem)
        with SecretBuffer(qsponge_512(b"CALYX-CRT-RSD512-CC512-v1.0.0|" + ss + ct_kem)) as key_buf:
            return cc512_decrypt(
                key_buf.as_bytes(),
                base64.b64decode(pkt["nonce24_b64"]),
                base64.b64decode(pkt["ct_b64"]),
                b"CALYX-CRT-RSD512-v1.0.0",
            )
