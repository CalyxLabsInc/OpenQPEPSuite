"""
QPEP-AKE: 1-RTT Bidirectional Post-Quantum Mutually Authenticated Handshake (Official Release 1.1.0).
Combines THREE independent hybrid post-quantum KEM / DH exchanges:
  - ee: Ephemeral QLX + Ephemeral X448 (Forward Secrecy)
  - es: Initiator -> Responder static QLX + X448 (Post-Quantum Responder Authentication)
  - se: Responder -> Initiator static QLX + X448 (Post-Quantum Initiator Authentication)
into full-duplex CMT-4 CC-512 transport channels with deterministic nonce verification,
replay protection, 256-bit channel binding hash / SAS safety code, and SecretBuffer zeroization.
"""
import os
from dataclasses import dataclass
from typing import Tuple

from ..exceptions import QPEPMacVerificationError
from ..lattice.qlx_kem import QLXEngine
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.consttime import ct_eq
from ..primitives.hgc448 import x448_exchange, x448_keygen
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer, zeroize_bytes


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
        witness = qsponge_512(b"CALYX-AKE-ID-WITNESS-v1.0.0|" + name.encode("utf-8") + os.urandom(32))
        ek, dk = QLXEngine.keygen(qlx_tier, witness)
        xp, xs = x448_keygen()
        return cls(name=name, qlx_tier=qlx_tier, ek=ek, dk=dk, x448_pub=xp, x448_priv=xs)


class QPEPAKEChannel:
    def __init__(self, tx_key: bytes, rx_key: bytes, channel_binding: bytes):
        self._tx_key = bytearray(tx_key)
        self._rx_key = bytearray(rx_key)
        self.channel_binding_hex = channel_binding.hex().upper()
        self.sas_code = f"{int.from_bytes(channel_binding[:4], 'big') % 1000000:06d}"
        self._tx_seq = 0
        self._rx_seq = 0
        self._destroyed = False

    def send(self, plaintext: bytes) -> Tuple[int, bytes, bytes]:
        if self._destroyed:
            raise RuntimeError("QPEPAKEChannel has been destroyed and zeroized.")
        self._tx_seq += 1
        seq_b = self._tx_seq.to_bytes(8, "big")
        tx_k = bytes(self._tx_key)
        nonce24 = qsponge_512(b"CALYX-AKE-NONCE-v1.0.0|" + tx_k + seq_b)[:24]
        ct = cc512_encrypt(tx_k, nonce24, plaintext, b"CALYX-AKE-FRAME-v1.0.0|" + seq_b)
        return self._tx_seq, nonce24, ct

    def recv(self, seq: int, nonce24: bytes, ct: bytes) -> bytes:
        if self._destroyed:
            raise RuntimeError("QPEPAKEChannel has been destroyed and zeroized.")
        if seq <= self._rx_seq:
            raise ValueError("Replay or out-of-order transport frame rejected.")
        seq_b = seq.to_bytes(8, "big")
        rx_k = bytes(self._rx_key)
        expected_nonce = qsponge_512(b"CALYX-AKE-NONCE-v1.0.0|" + rx_k + seq_b)[:24]
        if not ct_eq(nonce24, expected_nonce):
            raise QPEPMacVerificationError("QPEP-AKE deterministic transport nonce mismatch.")
        pt = cc512_decrypt(rx_k, nonce24, ct, b"CALYX-AKE-FRAME-v1.0.0|" + seq_b)
        self._rx_seq = seq
        return pt

    def destroy(self) -> None:
        if not self._destroyed:
            zeroize_bytes(self._tx_key)
            zeroize_bytes(self._rx_key)
            self._destroyed = True


class QPEPAKEHandshake:
    @staticmethod
    def run_handshake(initiator: QPEPAKEIdentity, responder: QPEPAKEIdentity) -> Tuple[QPEPAKEChannel, QPEPAKEChannel]:
        # Message 1: Initiator ephemeral QLX + X448
        eph_witness = qsponge_512(b"CALYX-AKE-EPH-WITNESS-v1.0.0|" + os.urandom(32))
        i_epk_qlx, i_esk_qlx = QLXEngine.keygen(initiator.qlx_tier, eph_witness)
        i_epk_x, i_esk_x = x448_keygen()

        # Message 2: Responder encapsulates to initiator ephemeral (ee) AND initiator static QLX (se — PQ mutual auth!)
        ct_ee_qlx, ss_ee_qlx = QLXEngine.encaps(i_epk_qlx, initiator.qlx_tier)
        ct_se_qlx, ss_se_qlx = QLXEngine.encaps(initiator.ek, initiator.qlx_tier)
        r_epk_x, r_esk_x = x448_keygen()
        ss_ee_x = x448_exchange(r_esk_x, i_epk_x)

        # Message 3: Initiator encapsulates to responder static QLX (es) + static X448
        ct_es_qlx, ss_es_qlx = QLXEngine.encaps(responder.ek, responder.qlx_tier)
        ss_es_x = x448_exchange(i_esk_x, responder.x448_pub)
        ss_se_x = x448_exchange(initiator.x448_priv, r_epk_x)

        # Initiator decapsulates responder's ee and se QLX ciphertexts
        with SecretBuffer(i_esk_qlx) as iesk_buf, SecretBuffer(i_esk_x) as iesx_buf:
            ss_ee_qlx_i = QLXEngine.decaps(iesk_buf.as_bytes(), ct_ee_qlx, initiator.qlx_tier)
            ss_ee_x_i = x448_exchange(iesx_buf.as_bytes(), r_epk_x)
        ss_se_qlx_i = QLXEngine.decaps(initiator.dk, ct_se_qlx, initiator.qlx_tier)

        # Responder decapsulates initiator's es QLX ciphertext
        ss_es_qlx_r = QLXEngine.decaps(responder.dk, ct_es_qlx, responder.qlx_tier)
        with SecretBuffer(r_esk_x) as resx_buf:
            ss_es_x_r = x448_exchange(responder.x448_priv, i_epk_x)
            ss_se_x_r = x448_exchange(resx_buf.as_bytes(), initiator.x448_pub)

        transcript = qsponge_512(
            b"CALYX-AKE-TRANSCRIPT-v1.0.0|"
            + initiator.ek
            + initiator.x448_pub
            + responder.ek
            + responder.x448_pub
            + i_epk_qlx
            + i_epk_x
            + ct_ee_qlx
            + ct_se_qlx
            + r_epk_x
            + ct_es_qlx
        )

        with SecretBuffer(
            qsponge_512(
                b"CALYX-AKE-MASTER-v1.0.0|"
                + ss_ee_qlx_i + ss_ee_x_i + ss_es_qlx + ss_es_x + ss_se_qlx_i + ss_se_x + transcript
            )
        ) as mi_buf, SecretBuffer(
            qsponge_512(
                b"CALYX-AKE-MASTER-v1.0.0|"
                + ss_ee_qlx + ss_ee_x + ss_es_qlx_r + ss_es_x_r + ss_se_qlx + ss_se_x_r + transcript
            )
        ) as mr_buf:
            mi = mi_buf.as_bytes()
            mr = mr_buf.as_bytes()
            i_to_r_i = qsponge_512(b"CALYX-AKE-I2R-v1.0.0|" + mi)
            r_to_i_i = qsponge_512(b"CALYX-AKE-R2I-v1.0.0|" + mi)
            cb_i = qsponge_512(b"CALYX-AKE-CB-v1.0.0|" + mi)[:32]

            i_to_r_r = qsponge_512(b"CALYX-AKE-I2R-v1.0.0|" + mr)
            r_to_i_r = qsponge_512(b"CALYX-AKE-R2I-v1.0.0|" + mr)
            cb_r = qsponge_512(b"CALYX-AKE-CB-v1.0.0|" + mr)[:32]

        return QPEPAKEChannel(i_to_r_i, r_to_i_i, cb_i), QPEPAKEChannel(r_to_i_r, i_to_r_r, cb_r)
