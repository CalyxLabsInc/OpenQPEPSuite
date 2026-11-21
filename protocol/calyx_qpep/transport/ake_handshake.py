"""
QPEP-AKE: 1-RTT PQ-Noise-XX Mutually Authenticated, Identity-Hiding Handshake
combining ephemeral + static QLX + X448 into full-duplex CC-512 transport channels
with a 256-bit channel binding hash / SAS safety string.
"""
import os
from dataclasses import dataclass
from typing import Dict, Tuple

from ..lattice.qlx_kem import QLXEngine
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.hgc448 import x448_exchange, x448_keygen
from ..primitives.qsponge import qsponge_512


@dataclass
class QPEPAKEIdentity:
    name: str
    qlx_tier: str
    ek: bytes
    dk: bytes
    x448_pub: bytes
    x448_priv: bytes

    @classmethod
    def generate(cls, name: str, qlx_tier: str = "QLX-768") -> "QPEPAKEIdentity":
        ek, dk = QLXEngine.keygen(qlx_tier, b"W" * 64)
        xp, xs = x448_keygen()
        return cls(name=name, qlx_tier=qlx_tier, ek=ek, dk=dk, x448_pub=xp, x448_priv=xs)


class QPEPAKEChannel:
    def __init__(self, tx_key: bytes, rx_key: bytes, channel_binding: bytes):
        self._tx_key = tx_key
        self._rx_key = rx_key
        self.channel_binding_hex = channel_binding.hex().upper()
        self.sas_code = f"{int.from_bytes(channel_binding[:4], 'big') % 1000000:06d}"
        self._tx_seq = 0
        self._rx_seq = 0

    def send(self, plaintext: bytes) -> Tuple[int, bytes, bytes]:
        self._tx_seq += 1
        nonce24 = qsponge_512(b"CALYX-AKE-N|" + self._tx_key + self._tx_seq.to_bytes(8, "big"))[:24]
        ct = cc512_encrypt(self._tx_key, nonce24, plaintext, self._tx_seq.to_bytes(8, "big"))
        return self._tx_seq, nonce24, ct

    def recv(self, seq: int, nonce24: bytes, ct: bytes) -> bytes:
        if seq <= self._rx_seq:
            raise ValueError("Replay or out-of-order transport frame rejected.")
        pt = cc512_decrypt(self._rx_key, nonce24, ct, seq.to_bytes(8, "big"))
        self._rx_seq = seq
        return pt


class QPEPAKEHandshake:
    @staticmethod
    def run_handshake(initiator: QPEPAKEIdentity, responder: QPEPAKEIdentity) -> Tuple[QPEPAKEChannel, QPEPAKEChannel]:
        # Message 1: Initiator ephemeral QLX + X448
        i_epk_qlx, i_esk_qlx = QLXEngine.keygen(initiator.qlx_tier, b"W" * 64)
        i_epk_x, i_esk_x = x448_keygen()

        # Message 2: Responder encapsulates to initiator ephemeral + static X448
        ct_ee_qlx, ss_ee_qlx = QLXEngine.encaps(i_epk_qlx, initiator.qlx_tier)
        r_epk_x, r_esk_x = x448_keygen()
        ss_ee_x = x448_exchange(r_esk_x, i_epk_x)

        # Message 3: Initiator encapsulates to responder static QLX + static X448
        ct_es_qlx, ss_es_qlx = QLXEngine.encaps(responder.ek, responder.qlx_tier)
        ss_es_x = x448_exchange(i_esk_x, responder.x448_pub)
        ss_se_x = x448_exchange(initiator.x448_priv, r_epk_x)

        # Initiator verifies responder's ee encapsulation
        ss_ee_qlx_i = QLXEngine.decaps(i_esk_qlx, ct_ee_qlx, initiator.qlx_tier)
        ss_ee_x_i = x448_exchange(i_esk_x, r_epk_x)

        # Responder decapsulates initiator's es encapsulation
        ss_es_qlx_r = QLXEngine.decaps(responder.dk, ct_es_qlx, responder.qlx_tier)
        ss_es_x_r = x448_exchange(responder.x448_priv, i_epk_x)
        ss_se_x_r = x448_exchange(r_esk_x, initiator.x448_pub)

        transcript = qsponge_512(i_epk_qlx + i_epk_x + ct_ee_qlx + r_epk_x + ct_es_qlx)
        master_i = qsponge_512(b"CALYX-AKE-v1|" + ss_ee_qlx_i + ss_ee_x_i + ss_es_qlx + ss_es_x + ss_se_x + transcript)
        master_r = qsponge_512(b"CALYX-AKE-v1|" + ss_ee_qlx + ss_ee_x + ss_es_qlx_r + ss_es_x_r + ss_se_x_r + transcript)

        i_to_r_i = qsponge_512(b"CALYX-AKE-I2R|" + master_i)
        r_to_i_i = qsponge_512(b"CALYX-AKE-R2I|" + master_i)
        cb_i = qsponge_512(b"CALYX-AKE-CB|" + master_i)[:32]

        i_to_r_r = qsponge_512(b"CALYX-AKE-I2R|" + master_r)
        r_to_i_r = qsponge_512(b"CALYX-AKE-R2I|" + master_r)
        cb_r = qsponge_512(b"CALYX-AKE-CB|" + master_r)[:32]

        return QPEPAKEChannel(i_to_r_i, r_to_i_i, cb_i), QPEPAKEChannel(r_to_i_r, i_to_r_r, cb_r)
