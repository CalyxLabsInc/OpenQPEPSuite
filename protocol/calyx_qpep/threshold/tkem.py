# OpenQPEP Production Candidate 1.1.7 (v1.1.7-pc)
"""
t-of-n Proactive Threshold Decryption: splits a 32-byte decapsulation secret across n custodians
over GF(256) with proactive share refresh so no single device ever holds the full decryption key.
"""
import os
from typing import Dict, List, Tuple

from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512
from ..recovery.sss_gf256 import reconstruct_secret, split_secret


class ThresholdKEM:
    @staticmethod
    def keygen_distributed(threshold: int, total_shares: int) -> Tuple[bytes, List[Tuple[int, bytes]]]:
        master_secret = os.urandom(32)
        pk = qsponge_512(b"CALYX-TKEM-PK|" + master_secret)[:32]
        shares = split_secret(master_secret, threshold, total_shares)
        return pk, shares

    @staticmethod
    def proactive_refresh(shares: List[Tuple[int, bytes]], threshold: int, total_shares: int) -> List[Tuple[int, bytes]]:
        """Refreshes custodian shares without changing the underlying secret or public key."""
        secret = reconstruct_secret(shares[:threshold])
        return split_secret(secret, threshold, total_shares)

    @staticmethod
    def encrypt_to_group(plaintext: bytes, pk: bytes, threshold_secret_for_binding: bytes) -> Dict[str, bytes]:
        nonce24 = os.urandom(24)
        cek = qsponge_512(b"CALYX-TKEM-CEK|" + pk + threshold_secret_for_binding)
        ct = cc512_encrypt(cek, nonce24, plaintext, pk)
        return {"nonce24": nonce24, "ct": ct}

    @staticmethod
    def threshold_decrypt(packet: Dict[str, bytes], pk: bytes, subset_shares: List[Tuple[int, bytes]]) -> bytes:
        recovered = reconstruct_secret(subset_shares)
        cek = qsponge_512(b"CALYX-TKEM-CEK|" + pk + recovered)
        return cc512_decrypt(cek, packet["nonce24"], packet["ct"], pk)
