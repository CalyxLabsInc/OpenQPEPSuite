"""
QPEP-Ratchet Periodic Hybrid Post-Quantum Re-Encapsulation with Ephemeral Rotation (Official Release 1.0.0).
Provides true Post-Compromise Security (PCS) by rotating sender ephemeral QLX + HGC-448 key pairs
on every PCS epoch and encapsulating fresh hybrid post-quantum entropy into the root chain.
"""
import base64
import os
from typing import Dict, Optional, Tuple

from ..lattice.qlx_kem import QLXEngine
from ..primitives.hgc448 import x448_exchange, x448_keygen
from ..primitives.qsponge import qsponge_512
from ..primitives.zeroize import SecretBuffer


def generate_ephemeral_ratchet_keypair(qlx_tier: str = "QLX-4096") -> Dict[str, bytes]:
    """Generates a fresh ephemeral hybrid (QLX + X448) ratchet key pair."""
    ephemeral_witness = qsponge_512(b"CALYX-RATCHET-EPHEMERAL-WITNESS-v1.0.0|" + os.urandom(32))
    qlx_pk, qlx_sk = QLXEngine.keygen(qlx_tier, ephemeral_witness)
    hgc_pk, hgc_sk = x448_keygen()
    return {
        "qlx_pk": qlx_pk,
        "qlx_sk": qlx_sk,
        "hgc_pk": hgc_pk,
        "hgc_sk": hgc_sk,
    }


def perform_pq_rekey_encaps(
    peer_qlx_pk: bytes,
    peer_hgc_pk: bytes,
    qlx_tier: str = "QLX-4096",
    *,
    advertised_qlx_pk: Optional[bytes] = None,
    advertised_hgc_pk: Optional[bytes] = None,
) -> Tuple[Dict[str, str], bytes]:
    """
    Performs a fresh hybrid QLX + HGC-448 (X448) encapsulation toward the peer's current
    ephemeral ratchet public key, optionally advertising a freshly rotated local ephemeral key pair.
    """
    ct_qlx, ss_qlx = QLXEngine.encaps(peer_qlx_pk, qlx_tier)
    epk_hgc, esk_hgc = x448_keygen()
    with SecretBuffer(esk_hgc) as esk_buf:
        ss_hgc = x448_exchange(esk_buf.as_bytes(), peer_hgc_pk)
    with SecretBuffer(ss_qlx + ss_hgc) as ss_buf:
        hybrid_ss = qsponge_512(b"CALYX-RATCHET-PCS-COMBINE-v1.0.0|" + ss_buf.as_bytes() + ct_qlx + epk_hgc)
    header: Dict[str, str] = {
        "qlx_tier": qlx_tier,
        "ct_qlx_b64": base64.b64encode(ct_qlx).decode("ascii"),
        "epk_hgc_b64": base64.b64encode(epk_hgc).decode("ascii"),
    }
    if advertised_qlx_pk is not None and advertised_hgc_pk is not None:
        header["new_peer_qlx_pk_b64"] = base64.b64encode(advertised_qlx_pk).decode("ascii")
        header["new_peer_hgc_pk_b64"] = base64.b64encode(advertised_hgc_pk).decode("ascii")
    return header, hybrid_ss


def perform_pq_rekey_decaps(
    my_qlx_sk: bytes,
    my_hgc_sk: bytes,
    rekey_header: Dict[str, str],
    qlx_tier: str = "QLX-4096",
) -> bytes:
    """Decapsulates a peer's hybrid QLX + HGC-448 PCS rekey header to recover hybrid_shared_secret_64."""
    ct_qlx = base64.b64decode(rekey_header["ct_qlx_b64"])
    epk_hgc = base64.b64decode(rekey_header["epk_hgc_b64"])
    ss_qlx = QLXEngine.decaps(my_qlx_sk, ct_qlx, qlx_tier)
    ss_hgc = x448_exchange(my_hgc_sk, epk_hgc)
    with SecretBuffer(ss_qlx + ss_hgc) as ss_buf:
        return qsponge_512(b"CALYX-RATCHET-PCS-COMBINE-v1.0.0|" + ss_buf.as_bytes() + ct_qlx + epk_hgc)
