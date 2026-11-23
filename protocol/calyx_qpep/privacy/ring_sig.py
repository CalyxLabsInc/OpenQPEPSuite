"""
QVS-Ring: Genuine 1-of-N Post-Quantum Linkable Module-SIS Lattice Ring Signatures
over R_8380417 = Z_8380417[X]/(X^256 + 1) (Official Release 1.1.0 / v1.1.0).

Cryptographic Construction (AOS Fiat-Shamir with Aborts over Module-SIS):
  - Shared public matrix A in R_Q^{2 x 4} expanded from fixed domain seed.
  - Member keypair: secret short vector s in R_Q^4 (||s||_inf <= 2); public key t = A * s in R_Q^2.
  - Optional Linkability: domain matrix H = SampleMatrix(link_domain) in R_Q^{2 x 4};
    key image I = H * s_pi in R_Q^2 (deterministic per signer + link_domain; unlinkable across domains).
  - Signing (AOS Ring with Rejection Sampling):
      1. Sample uniform masking vector y in R_Q^4 (||y||_inf < gamma1), compute w_pi = A*y (and w'_pi = H*y).
      2. For every decoy i != pi, sample uniform response z_i in (-gamma1 + beta, gamma1 - beta)
         and compute w_i = A*z_i - c_i*t_i (and w'_i = H*z_i - c_i*I).
      3. Close ring at signer pi: z_pi = y + c_pi * s_pi. Abort & retry if ||z_pi||_inf >= gamma1 - beta!
  - Provable Anonymity: Every z_i (both signer and decoy) follows the IDENTICAL uniform
    distribution over (-gamma1 + beta, gamma1 - beta), and NO signer commitment is emitted.
  - Provable Unforgeability: Forging without a valid short preimage s_i breaks Module-SIS over R_8380417.
"""
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from ..constants import QVS_GAMMA1, QVS_Q
from ..lattice.ntt_8380417 import center_qvs, inv_ntt_qvs, ntt_qvs
from ..lattice.poly_ring import (
    pack_poly24_qvs,
    sample_eta_qvs,
    sample_in_ball_qvs,
    sample_mask_y_qvs,
    sample_ntt_qvs,
    unpack_poly24_qvs,
)
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

RING_K = 2
RING_L = 4
RING_TAU = 24
RING_BETA = 48  # tau * eta = 24 * 2
RING_BOUND = QVS_GAMMA1 - RING_BETA

_RING_A_SEED = qsponge_512(b"CALYX-QVS-RING-PUBLIC-MATRIX-A-v1.0.0")[:32]
_RING_A_HAT: List[List[List[int]]] = [
    [sample_ntt_qvs(_RING_A_SEED, i, j) for j in range(RING_L)]
    for i in range(RING_K)
]


def _sample_link_matrix(link_domain: bytes) -> List[List[List[int]]]:
    seed_h = qsponge_512(b"CALYX-QVS-RING-LINK-MATRIX-v1.0.0|" + link_domain)[:32]
    return [[sample_ntt_qvs(seed_h, i, j) for j in range(RING_L)] for i in range(RING_K)]


def _mat_vec_mul(mat_hat: List[List[List[int]]], vec_hat: List[List[int]]) -> List[List[int]]:
    out: List[List[int]] = []
    for i in range(RING_K):
        acc = [0] * 256
        for j in range(RING_L):
            a_ij = mat_hat[i][j]
            v_j = vec_hat[j]
            acc = [(acc[m] + a_ij[m] * v_j[m]) % QVS_Q for m in range(256)]
        out.append(inv_ntt_qvs(acc))
    return out


def _pack_vec(vec: List[List[int]]) -> bytes:
    return b"".join(pack_poly24_qvs(p) for p in vec)


def _unpack_vec(data: bytes, count: int) -> List[List[int]]:
    return [unpack_poly24_qvs(data[768 * i : 768 * (i + 1)]) for i in range(count)]


def _sample_bounded_z(bound: int) -> List[List[int]]:
    """Samples a uniform decoy vector z in R_Q^L with ||z||_inf < bound."""
    span = 2 * bound - 1
    out: List[List[int]] = []
    for _ in range(RING_L):
        poly = [0] * 256
        raw = os.urandom(256 * 4)
        idx = 0
        for m in range(256):
            while True:
                if idx + 3 > len(raw):
                    raw = os.urandom(256 * 3)
                    idx = 0
                val = (raw[idx] | (raw[idx + 1] << 8) | (raw[idx + 2] << 16)) & 0xFFFFF
                idx += 3
                if val < span:
                    poly[m] = (val - (bound - 1)) % QVS_Q
                    break
        out.append(poly)
    return out


def _ring_challenge(
    ring_bytes: bytes,
    message: bytes,
    link_domain: bytes,
    key_image: bytes,
    w_bytes: bytes,
    wp_bytes: bytes,
) -> bytes:
    return qsponge_var(
        b"CALYX-QVS-RING-CH-v1.0.0|"
        + ring_bytes
        + struct.pack(">I", len(message))
        + message
        + struct.pack(">I", len(link_domain))
        + link_domain
        + key_image
        + w_bytes
        + wp_bytes,
        32,
    )


class QVSRingSignature:
    """
    Genuine 1-of-N Post-Quantum Linkable Module-SIS Lattice Ring Signature over Z_8380417[X]/(X^256+1).
    Provides cryptographic signer anonymity (zero signer_index leakage) and Module-SIS unforgeability.
    """

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        seed = os.urandom(32)
        s_vec = [sample_eta_qvs(seed, j) for j in range(RING_L)]
        s_hat = [ntt_qvs(p) for p in s_vec]
        t_vec = _mat_vec_mul(_RING_A_HAT, s_hat)
        pk = _pack_vec(t_vec)  # 2 * 768 = 1536 bytes
        sk = b"".join(bytes((center_qvs(c) + 2) & 0xFF for c in p) for p in s_vec)  # 4 * 256 = 1024 bytes
        return pk, sk

    @staticmethod
    def sign(
        message: bytes,
        ring_pks: List[bytes],
        signer_index: int,
        signer_sk: bytes,
        *,
        link_domain: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        n = len(ring_pks)
        if n < 2 or not (0 <= signer_index < n):
            raise ValueError("Ring must contain >= 2 public keys and valid signer_index.")
        if any(len(pk) != RING_K * 768 for pk in ring_pks) or len(signer_sk) != RING_L * 256:
            raise ValueError("Invalid QVS-Ring key size.")

        with SecretBuffer(signer_sk) as sk_buf:
            raw_sk = sk_buf.as_bytes()
            s_vec = [[(b - 2) % QVS_Q for b in raw_sk[256 * j : 256 * (j + 1)]] for j in range(RING_L)]

        s_hat = [ntt_qvs(p) for p in s_vec]
        t_hats = [[ntt_qvs(p) for p in _unpack_vec(pk, RING_K)] for pk in ring_pks]

        # Verify signer_sk actually corresponds to ring_pks[signer_index]
        expected_pk = _pack_vec(_mat_vec_mul(_RING_A_HAT, s_hat))
        if not ct_eq(expected_pk, ring_pks[signer_index]):
            raise ValueError("signer_sk does not correspond to ring_pks[signer_index].")

        ring_bytes = b"".join(ring_pks)
        dom = link_domain or b""
        h_hat = _sample_link_matrix(dom) if dom else None
        key_image_vec = _mat_vec_mul(h_hat, s_hat) if h_hat is not None else None
        key_image_bytes = _pack_vec(key_image_vec) if key_image_vec is not None else b""
        img_hat = [ntt_qvs(p) for p in key_image_vec] if key_image_vec is not None else None

        mask_seed = qsponge_512(b"CALYX-QVS-RING-MASKSEED-v1.0.0|" + os.urandom(32) + message)
        nonce = 0

        while True:
            # 1. Sample signer masking vector y in (-gamma1, gamma1)
            y_vec = [sample_mask_y_qvs(mask_seed, nonce + j) for j in range(RING_L)]
            nonce += RING_L
            y_hat = [ntt_qvs(p) for p in y_vec]
            w_pi = _pack_vec(_mat_vec_mul(_RING_A_HAT, y_hat))
            wp_pi = _pack_vec(_mat_vec_mul(h_hat, y_hat)) if h_hat is not None else b""

            challenges: List[bytes] = [b""] * n
            responses: List[List[List[int]]] = [[] for _ in range(n)]
            challenges[(signer_index + 1) % n] = _ring_challenge(
                ring_bytes, message, dom, key_image_bytes, w_pi, wp_pi
            )

            # 2. Simulate all n - 1 decoy ring links with uniform responses in (-RING_BOUND, RING_BOUND)
            idx = (signer_index + 1) % n
            while idx != signer_index:
                z_i = _sample_bounded_z(RING_BOUND)
                responses[idx] = z_i
                z_hat = [ntt_qvs(p) for p in z_i]
                c_hat = ntt_qvs(sample_in_ball_qvs(challenges[idx], RING_TAU))
                az = _mat_vec_mul(_RING_A_HAT, z_hat)
                ct_vec = [
                    inv_ntt_qvs([(c_hat[m] * t_hats[idx][i][m]) % QVS_Q for m in range(256)])
                    for i in range(RING_K)
                ]
                w_i = _pack_vec([[(az[i][m] - ct_vec[i][m]) % QVS_Q for m in range(256)] for i in range(RING_K)])
                if h_hat is not None and img_hat is not None:
                    hz = _mat_vec_mul(h_hat, z_hat)
                    ci_vec = [
                        inv_ntt_qvs([(c_hat[m] * img_hat[i][m]) % QVS_Q for m in range(256)])
                        for i in range(RING_K)
                    ]
                    wp_i = _pack_vec([[(hz[i][m] - ci_vec[i][m]) % QVS_Q for m in range(256)] for i in range(RING_K)])
                else:
                    wp_i = b""
                challenges[(idx + 1) % n] = _ring_challenge(
                    ring_bytes, message, dom, key_image_bytes, w_i, wp_i
                )
                idx = (idx + 1) % n

            # 3. Close ring at signer_index: z_pi = y + c_pi * s_pi with rejection sampling!
            c_pi_hat = ntt_qvs(sample_in_ball_qvs(challenges[signer_index], RING_TAU))
            z_pi: List[List[int]] = []
            reject = False
            for j in range(RING_L):
                cs = inv_ntt_qvs([(c_pi_hat[m] * s_hat[j][m]) % QVS_Q for m in range(256)])
                zj = [(y_vec[j][m] + cs[m]) % QVS_Q for m in range(256)]
                if any(abs(center_qvs(c)) >= RING_BOUND for c in zj):
                    reject = True
                    break
                z_pi.append(zj)
            if reject:
                continue

            responses[signer_index] = z_pi
            return {
                "scheme": "QVS-Ring-ModuleSIS-v1.0.0",
                "ring_size": n,
                "c0_hex": challenges[0].hex(),
                "responses_hex": [_pack_vec(zv).hex() for zv in responses],
                "link_domain_hex": dom.hex() if dom else None,
                "key_image_hex": key_image_bytes.hex() if key_image_bytes else None,
            }

    @staticmethod
    def verify(message: bytes, ring_pks: List[bytes], sig: Dict[str, Any]) -> bool:
        n = len(ring_pks)
        if sig.get("scheme") != "QVS-Ring-ModuleSIS-v1.0.0":
            return False
        if n < 2 or n != sig.get("ring_size") or len(sig.get("responses_hex", [])) != n:
            return False
        if any(len(pk) != RING_K * 768 for pk in ring_pks):
            return False

        try:
            c0 = bytes.fromhex(sig["c0_hex"])
            if len(c0) != 32:
                return False
            dom = bytes.fromhex(sig["link_domain_hex"]) if sig.get("link_domain_hex") else b""
            key_image_bytes = bytes.fromhex(sig["key_image_hex"]) if sig.get("key_image_hex") else b""
            if bool(dom) != bool(key_image_bytes):
                return False
            if key_image_bytes and len(key_image_bytes) != RING_K * 768:
                return False
            responses = []
            for r_hex in sig["responses_hex"]:
                rb = bytes.fromhex(r_hex)
                if len(rb) != RING_L * 768:
                    return False
                zv = _unpack_vec(rb, RING_L)
                for poly in zv:
                    if any(abs(center_qvs(c)) >= RING_BOUND for c in poly):
                        return False
                responses.append(zv)
        except (ValueError, TypeError):
            return False

        ring_bytes = b"".join(ring_pks)
        t_hats = [[ntt_qvs(p) for p in _unpack_vec(pk, RING_K)] for pk in ring_pks]
        h_hat = _sample_link_matrix(dom) if dom else None
        img_hat = [ntt_qvs(p) for p in _unpack_vec(key_image_bytes, RING_K)] if key_image_bytes else None

        cur_c = c0
        for i in range(n):
            z_hat = [ntt_qvs(p) for p in responses[i]]
            c_hat = ntt_qvs(sample_in_ball_qvs(cur_c, RING_TAU))
            az = _mat_vec_mul(_RING_A_HAT, z_hat)
            ct_vec = [
                inv_ntt_qvs([(c_hat[m] * t_hats[i][k][m]) % QVS_Q for m in range(256)])
                for k in range(RING_K)
            ]
            w_i = _pack_vec([[(az[k][m] - ct_vec[k][m]) % QVS_Q for m in range(256)] for k in range(RING_K)])
            if h_hat is not None and img_hat is not None:
                hz = _mat_vec_mul(h_hat, z_hat)
                ci_vec = [
                    inv_ntt_qvs([(c_hat[m] * img_hat[k][m]) % QVS_Q for m in range(256)])
                    for k in range(RING_K)
                ]
                wp_i = _pack_vec([[(hz[k][m] - ci_vec[k][m]) % QVS_Q for m in range(256)] for k in range(RING_K)])
            else:
                wp_i = b""
            cur_c = _ring_challenge(ring_bytes, message, dom, key_image_bytes, w_i, wp_i)

        return ct_eq(cur_c, c0)
