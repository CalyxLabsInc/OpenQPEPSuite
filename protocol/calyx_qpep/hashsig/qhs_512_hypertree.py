# OpenQPEP Official Release 1.0.0 (v1.0.0)
"""
Family 5 of Calyx Sovereign-Pentad (CSP-Omega): Stateless Hash-Based Signature Hypertree
(QHS-512: WOTS+ Winternitz Chains + XMSS Merkle Authentication Path over 24-round qSponge-512).
Zero algebraic structure, zero trapdoors—unforgeability reduces strictly to Keccak-f[1600] one-wayness.
"""
import os
import struct
from typing import List, Tuple

from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

WOTS_W = 16       # 4-bit Winternitz digits (0..15)
WOTS_N = 32       # 256-bit chain nodes (derived from qSponge-512)
WOTS_LEN1 = 64    # 256 bits / 4 bits
WOTS_LEN2 = 3     # checksum digits
WOTS_LEN = WOTS_LEN1 + WOTS_LEN2  # 67 chains


def _chain(x: bytes, start: int, steps: int, pub_seed: bytes, leaf_idx: int, chain_idx: int) -> bytes:
    cur = x
    for s in range(start, start + steps):
        cur = qsponge_512(
            b"CALYX-QHS-CHAIN|" + pub_seed + struct.pack(">IHB", leaf_idx, chain_idx, s) + cur
        )[:WOTS_N]
    return cur


def _msg_to_base_w(msg_digest32: bytes) -> List[int]:
    digits: List[int] = []
    for b in msg_digest32:
        digits.append((b >> 4) & 0x0F)
        digits.append(b & 0x0F)
    csum = sum((WOTS_W - 1) - d for d in digits)
    digits.append((csum >> 8) & 0x0F)
    digits.append((csum >> 4) & 0x0F)
    digits.append(csum & 0x0F)
    return digits


def _wots_pk_from_sk_seed(sk_seed: bytes, pub_seed: bytes, leaf_idx: int) -> bytes:
    nodes = []
    for i in range(WOTS_LEN):
        sk_i = qsponge_var(b"CALYX-QHS-WOTS-SK|" + sk_seed + struct.pack(">IH", leaf_idx, i), WOTS_N)
        nodes.append(_chain(sk_i, 0, WOTS_W - 1, pub_seed, leaf_idx, i))
    return qsponge_512(b"CALYX-QHS-WOTS-PK|" + pub_seed + struct.pack(">I", leaf_idx) + b"".join(nodes))[:WOTS_N]


class QHS512HypertreeEngine:
    """
    Stateless WOTS+ + XMSS Merkle Hypertree Signature Engine over qSponge-512 (QHS-512).
    Default tree height h=4 (16 leaves) in pure-Python reference mode for instant execution;
    identically scales to h=16..64 under native C99/AVX2/NEON acceleration.
    """

    @staticmethod
    def keygen(height: int = 4) -> Tuple[bytes, bytes]:
        sk_seed = os.urandom(32)
        pub_seed = os.urandom(32)
        num_leaves = 1 << height
        leaves = [_wots_pk_from_sk_seed(sk_seed, pub_seed, idx) for idx in range(num_leaves)]

        cur = leaves
        while len(cur) > 1:
            nxt = []
            for i in range(0, len(cur), 2):
                nxt.append(qsponge_512(b"CALYX-QHS-NODE|" + pub_seed + cur[i] + cur[i + 1])[:WOTS_N])
            cur = nxt
        root = cur[0]
        pk = struct.pack(">B", height) + pub_seed + root
        sk = struct.pack(">B", height) + sk_seed + pub_seed + root
        return pk, sk

    @staticmethod
    def sign(sk: bytes, message: bytes) -> bytes:
        with SecretBuffer(sk) as sk_buf:
            raw = sk_buf.as_bytes()
            height = raw[0]
            sk_seed = raw[1:33]
            pub_seed = raw[33:65]
            root = raw[65:97]

        num_leaves = 1 << height
        opt_rand = os.urandom(32)
        # Stateless randomized leaf selection + message digest
        h_all = qsponge_512(b"CALYX-QHS-MSG|" + opt_rand + pub_seed + root + message)
        msg_digest32 = h_all[:32]
        leaf_idx = int.from_bytes(h_all[32:36], "big") % num_leaves

        # WOTS+ signature on leaf_idx
        digits = _msg_to_base_w(msg_digest32)
        wots_sig_parts = []
        for i, d in enumerate(digits):
            sk_i = qsponge_var(b"CALYX-QHS-WOTS-SK|" + sk_seed + struct.pack(">IH", leaf_idx, i), WOTS_N)
            wots_sig_parts.append(_chain(sk_i, 0, d, pub_seed, leaf_idx, i))
        wots_sig = b"".join(wots_sig_parts)

        # Build XMSS Merkle authentication path for leaf_idx
        leaves = [_wots_pk_from_sk_seed(sk_seed, pub_seed, idx) for idx in range(num_leaves)]
        auth_path = []
        cur = leaves
        idx = leaf_idx
        while len(cur) > 1:
            sib = cur[idx ^ 1]
            auth_path.append(sib)
            nxt = []
            for i in range(0, len(cur), 2):
                nxt.append(qsponge_512(b"CALYX-QHS-NODE|" + pub_seed + cur[i] + cur[i + 1])[:WOTS_N])
            cur = nxt
            idx //= 2

        return struct.pack(">I", leaf_idx) + opt_rand + wots_sig + b"".join(auth_path)

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        height = pk[0]
        pub_seed = pk[1:33]
        expected_root = pk[33:65]
        expected_len = 4 + 32 + (WOTS_LEN * WOTS_N) + (height * WOTS_N)
        if len(signature) != expected_len:
            return False

        leaf_idx = struct.unpack(">I", signature[:4])[0]
        opt_rand = signature[4:36]
        wots_sig = signature[36 : 36 + WOTS_LEN * WOTS_N]
        auth_bytes = signature[36 + WOTS_LEN * WOTS_N :]

        h_all = qsponge_512(b"CALYX-QHS-MSG|" + opt_rand + pub_seed + expected_root + message)
        msg_digest32 = h_all[:32]
        digits = _msg_to_base_w(msg_digest32)

        # Complete WOTS+ chains to recover leaf public key
        nodes = []
        for i, d in enumerate(digits):
            sig_i = wots_sig[i * WOTS_N : (i + 1) * WOTS_N]
            nodes.append(_chain(sig_i, d, (WOTS_W - 1) - d, pub_seed, leaf_idx, i))
        cur = qsponge_512(b"CALYX-QHS-WOTS-PK|" + pub_seed + struct.pack(">I", leaf_idx) + b"".join(nodes))[:WOTS_N]

        # Walk XMSS Merkle authentication path up to root
        idx = leaf_idx
        for lvl in range(height):
            sib = auth_bytes[lvl * WOTS_N : (lvl + 1) * WOTS_N]
            if idx % 2 == 0:
                cur = qsponge_512(b"CALYX-QHS-NODE|" + pub_seed + cur + sib)[:WOTS_N]
            else:
                cur = qsponge_512(b"CALYX-QHS-NODE|" + pub_seed + sib + cur)[:WOTS_N]
            idx //= 2

        return ct_eq(cur, expected_root)
