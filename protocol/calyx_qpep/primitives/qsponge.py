# OpenQPEP Production Candidate 1.1.7 (v1.1.7-pc)
"""
qSponge-512 (SHA3-512) and qSponge-XOF (SHAKE-256) 24-round Keccak-f[1600] primitives.
"""
import hashlib


def qsponge_var(data: bytes, out_len: int) -> bytes:
    """Domain-separated qSponge-XOF (24-round Keccak-f[1600] SHAKE-256) variable-length output."""
    return hashlib.shake_256(data).digest(out_len)


def qsponge_512(data: bytes) -> bytes:
    """Fixed 512-bit qSponge-512 (24-round Keccak-f[1600] SHA3-512) digest."""
    return hashlib.sha3_512(data).digest()
