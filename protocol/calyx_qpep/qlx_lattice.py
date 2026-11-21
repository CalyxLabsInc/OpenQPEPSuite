"""
Backward-compatible re-export facade for OpenQPEP lattice primitives (Production Candidate 1.1.0).
Direct implementations now live in calyx_qpep.primitives.* and calyx_qpep.lattice.*.
"""
from .constants import QLX_Q, QLX_N, QLX_ZETA, QLX_TIERS, QVS_Q, QVS_ZETA, QVS_GAMMA1, QVS_GAMMA2, QVS_ALPHA, QVS_TIERS
from .primitives.qsponge import qsponge_512, qsponge_var
from .lattice import (
    ntt_3329, inv_ntt_3329, ntt_base_mul_3329, poly_add_3329, poly_sub_3329,
    ntt_qvs, inv_ntt_qvs, center_qvs, decompose_qvs,
    sample_ntt_3329, sample_cbd2_3329, sample_cbd1_3329,
    byte_encode_12, byte_decode_12, compress_poly, decompress_poly,
    sample_ntt_qvs, sample_eta_qvs, sample_mask_y_qvs, sample_in_ball_qvs,
    pack_poly24_qvs, unpack_poly24_qvs,
    QLXEngine, QVSEngine,
)
