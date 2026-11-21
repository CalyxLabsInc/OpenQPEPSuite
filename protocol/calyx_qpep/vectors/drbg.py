"""
Deterministic qSponge-XOF DRBG — STRICTLY FOR KNOWN ANSWER TEST (KAT) GENERATION & VERIFICATION.
NEVER use deterministic_urandom() in production key generation or encryption.
"""
import contextlib
import os
import struct
from typing import Iterator

from ..primitives.qsponge import qsponge_var


class QSpongeDRBG:
    """
    Domain-separated deterministic random byte generator backed by 24-round
    Keccak-f[1600] qSponge-XOF (SHAKE-256). Strictly isolated to KAT test mode.
    """

    DOMAIN_TAG = b"CALYX-OPENQPEP-KAT-DRBG-v1.0.0-rc|"

    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) < 16:
            raise ValueError("QSpongeDRBG requires at least 16 bytes of seed material.")
        self._state = qsponge_var(self.DOMAIN_TAG + bytes(seed), 64)
        self._counter = 0

    def random_bytes(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("Byte count must be non-negative.")
        if n == 0:
            return b""
        block = qsponge_var(
            self.DOMAIN_TAG + self._state + struct.pack(">Q", self._counter),
            n + 64,
        )
        self._counter += 1
        self._state = block[:64]
        return block[64:]


@contextlib.contextmanager
def deterministic_urandom(seed: bytes) -> Iterator[QSpongeDRBG]:
    """
    Context manager that temporarily routes os.urandom() through QSpongeDRBG for
    reproducible Known Answer Test (KAT) generation and cross-language verification.
    Restores the real OS CSPRNG unconditionally on exit.
    """
    drbg = QSpongeDRBG(seed)
    real_urandom = os.urandom
    os.urandom = drbg.random_bytes  # type: ignore[assignment]
    try:
        yield drbg
    finally:
        os.urandom = real_urandom
