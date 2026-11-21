"""OpenQPEP v1.1.0-pc — Standalone Tier 12: Calyx Rank-Metric Tensor (RMT-512) Non-Lattice Suite."""
import base64
import json
import os
from typing import Tuple

from .rank_rsd512 import RankMetricKEM
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512
from ..wire.armor import armor_unwrap, armor_wrap

RMT_LABEL = "CALYX QPEP RANK-METRIC PACKET"


class CalyxRankMetricSuite:
    SUITE_NAME = "Calyx Rank-Metric Tensor: RMT-512 (Rank-Syndrome Code-Based)"

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        return RankMetricKEM.keygen()

    @staticmethod
    def encrypt(plaintext: bytes, recipient_pk: bytes) -> str:
        ct_kem, ss = RankMetricKEM.encaps(recipient_pk)
        key64 = qsponge_512(b"CALYX-RMT512-CC512|" + ss + ct_kem)
        n24 = os.urandom(24)
        ct = cc512_encrypt(key64, n24, plaintext, b"RMT-512")
        pkt = {
            "suite": CalyxRankMetricSuite.SUITE_NAME,
            "ct_kem_b64": base64.b64encode(ct_kem).decode("ascii"),
            "nonce24_b64": base64.b64encode(n24).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }
        return armor_wrap(RMT_LABEL, json.dumps(pkt, separators=(",", ":")).encode("utf-8"))

    @staticmethod
    def decrypt(armored: str, recipient_sk: bytes) -> bytes:
        raw, _ = armor_unwrap(armored, RMT_LABEL)
        pkt = json.loads(raw.decode("utf-8"))
        ct_kem = base64.b64decode(pkt["ct_kem_b64"])
        ss = RankMetricKEM.decaps(recipient_sk, ct_kem)
        key64 = qsponge_512(b"CALYX-RMT512-CC512|" + ss + ct_kem)
        return cc512_decrypt(key64, base64.b64decode(pkt["nonce24_b64"]), base64.b64decode(pkt["ct_b64"]), b"RMT-512")
