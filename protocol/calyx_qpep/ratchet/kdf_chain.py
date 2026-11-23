"""
QPEP-Ratchet One-Way qSponge-XOF KDF Chains (Official Release 1.1.0).
Evolves root keys and per-message CMT-4 CC-512 encryption keys irreversibly on every step,
actively scrubbing intermediate key material via SecretBuffer for Forward Secrecy (FS).
"""
from typing import Tuple

from ..primitives.qsponge import qsponge_var
from ..primitives.zeroize import SecretBuffer


def kdf_root_step(root_key: bytes, pq_hybrid_secret: bytes) -> Tuple[bytes, bytes]:
    """
    Root-chain ratchet step injecting fresh QLX + HGC-448 (X448) entropy:
      (new_root_key_32, new_chain_key_32) = qSponge-XOF("CALYX-RATCHET-ROOT-v1.0.0|" || rk || ss, 64)
    """
    if len(root_key) != 32:
        raise ValueError("Root key must be 32 bytes.")
    with SecretBuffer(root_key + pq_hybrid_secret) as mix_buf:
        out = qsponge_var(b"CALYX-RATCHET-ROOT-v1.0.0|" + mix_buf.as_bytes(), 64)
    return out[:32], out[32:64]


def kdf_chain_step(chain_key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Symmetric sending/receiving chain step (strictly one-way):
      Returns (next_chain_key_32, cc512_msg_key_64, nonce_24).
    """
    if len(chain_key) != 32:
        raise ValueError("Chain key must be 32 bytes.")
    with SecretBuffer(chain_key) as ck_buf:
        ck = ck_buf.as_bytes()
        next_ck = qsponge_var(b"CALYX-RATCHET-CK-NEXT-v1.0.0|" + ck, 32)
        msg_mat = qsponge_var(b"CALYX-RATCHET-MSG-KEY-v1.0.0|" + ck, 88)
    return next_ck, msg_mat[:64], msg_mat[64:88]
