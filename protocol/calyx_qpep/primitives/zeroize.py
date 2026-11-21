"""
Active Secret Memory Scrubbing (Production Candidate 1.1.7).
Stores unpacked secret lattice vectors, private keys, and CC-512 session keys in mutable
bytearray buffers and explicitly zeroes RAM via ctypes.memset upon exit.
"""
import ctypes
from typing import Union


def zeroize_bytes(buf: bytearray) -> None:
    """Explicitly overwrite every byte of a mutable bytearray in RAM with 0x00 via ctypes.memset."""
    if not isinstance(buf, bytearray):
        raise TypeError("zeroize_bytes requires a mutable bytearray buffer.")
    n = len(buf)
    if n == 0:
        return
    c_buf = (ctypes.c_char * n).from_buffer(buf)
    ctypes.memset(ctypes.addressof(c_buf), 0, n)


class SecretBuffer:
    """
    Context manager holding sensitive key material in a mutable bytearray that is
    deterministically scrubbed with ctypes.memset when exiting the context (even on error).
    """

    def __init__(self, data: Union[bytes, bytearray]):
        self._buf = bytearray(data)
        self._wiped = False

    @property
    def raw(self) -> bytearray:
        if self._wiped:
            raise RuntimeError("Attempted to access a wiped SecretBuffer.")
        return self._buf

    def as_bytes(self) -> bytes:
        if self._wiped:
            raise RuntimeError("Attempted to access a wiped SecretBuffer.")
        return bytes(self._buf)

    def wipe(self) -> None:
        if not self._wiped:
            zeroize_bytes(self._buf)
            self._wiped = True

    def __len__(self) -> int:
        return len(self._buf)

    def __enter__(self) -> "SecretBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            pass
