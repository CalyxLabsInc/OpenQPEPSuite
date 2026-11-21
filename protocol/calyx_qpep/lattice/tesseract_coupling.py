# OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc)
"""
4-Manifold Coupled Hyper-Tesseract Seed Coupling (Calyx Hyper-Tesseract QLX-16384, k=64).
Partitions 16,384 lattice dimensions into four 4,096-dim manifolds with unstructured dense
cross-manifold seed coupling and domain-separated per-manifold message commitments.
"""
from typing import List
from ..primitives.qsponge import qsponge_var


def derive_tesseract_manifold_seeds(rho: bytes, manifolds: int = 4) -> List[bytes]:
    """Derives domain-separated 32-byte matrix seeds for each coupled Tesseract manifold."""
    return [
        qsponge_var(b"CALYX-TESSERACT-DENSE-MANIFOLD|" + rho + bytes([m]), 32)
        for m in range(manifolds)
    ]


def derive_tesseract_mu_blocks(msg32: bytes, h_ek: bytes, manifolds: int = 4) -> List[bytes]:
    """Derives 4 coupled 32-byte manifold message commitments (mu_0 = msg32, mu_1..3 via qSponge-XOF)."""
    blocks = [msg32]
    for m in range(1, manifolds):
        blocks.append(qsponge_var(b"CALYX-TESSERACT-MU|" + msg32 + h_ek + bytes([m]), 32))
    return blocks
