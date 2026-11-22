"""
OpenQPEP Native C99 / SIMD Vectorized Acceleration Loader (libopenqpep) — Official Release 1.0.0.
Loads libopenqpep.so / .dylib / .dll via ctypes with zero-copy array.array buffer marshaling.
Seamlessly falls back to the bit-exact pure-Python reference engine when absent or disabled.
"""
import array
import ctypes
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional

_NATIVE_DIR = Path(__file__).resolve().parent
_LIB: Optional[ctypes.CDLL] = None
_LIB_PATH: Optional[str] = None
_NATIVE_ENABLED: bool = os.environ.get("OPENQPEP_DISABLE_NATIVE", "0") != "1"

_c_void_p = ctypes.c_void_p
_ZERO_256_I32 = [0] * 256


def _try_load_library() -> Optional[ctypes.CDLL]:
    global _LIB, _LIB_PATH
    if _LIB is not None:
        return _LIB
    ext_map = {"Darwin": "dylib", "Windows": "dll"}
    ext = ext_map.get(platform.system(), "so")
    candidates = [
        _NATIVE_DIR / f"libopenqpep.{ext}",
        _NATIVE_DIR / "libopenqpep.so",
        _NATIVE_DIR / "libopenqpep.dylib",
        _NATIVE_DIR / "libopenqpep.dll",
    ]
    for path in candidates:
        if path.is_file():
            try:
                lib = ctypes.CDLL(str(path))
                _configure_signatures(lib)
                _LIB = lib
                _LIB_PATH = str(path)
                return lib
            except OSError:
                continue
    return None


def _configure_signatures(lib: ctypes.CDLL) -> None:
    lib.openqpep_native_abi_info.argtypes = []
    lib.openqpep_native_abi_info.restype = ctypes.c_uint32

    lib.openqpep_ntt_3329.argtypes = [_c_void_p]
    lib.openqpep_ntt_3329.restype = None

    lib.openqpep_inv_ntt_3329.argtypes = [_c_void_p]
    lib.openqpep_inv_ntt_3329.restype = None

    lib.openqpep_ntt_base_mul_3329.argtypes = [_c_void_p, _c_void_p, _c_void_p]
    lib.openqpep_ntt_base_mul_3329.restype = None

    lib.openqpep_poly_add_3329.argtypes = [_c_void_p, _c_void_p, _c_void_p]
    lib.openqpep_poly_add_3329.restype = None

    lib.openqpep_poly_sub_3329.argtypes = [_c_void_p, _c_void_p, _c_void_p]
    lib.openqpep_poly_sub_3329.restype = None

    lib.openqpep_ntt_qvs.argtypes = [_c_void_p]
    lib.openqpep_ntt_qvs.restype = None

    lib.openqpep_inv_ntt_qvs.argtypes = [_c_void_p]
    lib.openqpep_inv_ntt_qvs.restype = None

    lib.openqpep_ntt_mul_qvs.argtypes = [_c_void_p, _c_void_p, _c_void_p]
    lib.openqpep_ntt_mul_qvs.restype = None

    lib.openqpep_cbd2_3329.argtypes = [ctypes.c_char_p, _c_void_p]
    lib.openqpep_cbd2_3329.restype = None

    lib.openqpep_cbd1_3329.argtypes = [ctypes.c_char_p, _c_void_p]
    lib.openqpep_cbd1_3329.restype = None

    lib.openqpep_cbd2_qvs.argtypes = [ctypes.c_char_p, _c_void_p]
    lib.openqpep_cbd2_qvs.restype = None

    lib.openqpep_plain_lwe_row_accum_u16.argtypes = [_c_void_p, _c_void_p, ctypes.c_uint16, ctypes.c_uint32]
    lib.openqpep_plain_lwe_row_accum_u16.restype = None

    lib.openqpep_plain_lwe_keygen_row_u16.argtypes = [
        _c_void_p, _c_void_p, _c_void_p, _c_void_p, ctypes.c_uint32, ctypes.c_uint32
    ]
    lib.openqpep_plain_lwe_keygen_row_u16.restype = None

    if hasattr(lib, "openqpep_explicit_bzero"):
        lib.openqpep_explicit_bzero.argtypes = [_c_void_p, ctypes.c_size_t]
        lib.openqpep_explicit_bzero.restype = None
    if hasattr(lib, "openqpep_verify_wire_v5_magic"):
        lib.openqpep_verify_wire_v5_magic.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        lib.openqpep_verify_wire_v5_magic.restype = ctypes.c_int
    if hasattr(lib, "openqpep_ct_eq"):
        lib.openqpep_ct_eq.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        lib.openqpep_ct_eq.restype = ctypes.c_int
    if hasattr(lib, "openqpep_ct_cmov"):
        lib.openqpep_ct_cmov.argtypes = [ctypes.c_int, _c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        lib.openqpep_ct_cmov.restype = None


_try_load_library()


def is_native_available() -> bool:
    return _NATIVE_ENABLED and (_LIB is not None)


def set_native_enabled(enabled: bool) -> None:
    global _NATIVE_ENABLED
    _NATIVE_ENABLED = bool(enabled)


def native_backend_info() -> Dict[str, Any]:
    if _LIB is None:
        return {
            "loaded": False,
            "enabled": False,
            "backend": "pure-python",
            "simd": [],
            "arch": platform.machine(),
            "library_path": None,
        }
    flags = int(_LIB.openqpep_native_abi_info())
    simd: List[str] = []
    if flags & 0x01:
        simd.append("C99")
    if flags & 0x02:
        simd.append("AVX2")
    if flags & 0x04:
        simd.append("NEON")
    return {
        "loaded": True,
        "enabled": _NATIVE_ENABLED,
        "backend": "libopenqpep-c99" if _NATIVE_ENABLED else "pure-python (native disabled)",
        "simd": simd,
        "arch": platform.machine(),
        "library_path": _LIB_PATH,
    }


def native_ntt_3329(poly: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    arr = array.array("i", poly)
    _LIB.openqpep_ntt_3329(arr.buffer_info()[0])
    return arr.tolist()


def native_inv_ntt_3329(poly_hat: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    arr = array.array("i", poly_hat)
    _LIB.openqpep_inv_ntt_3329(arr.buffer_info()[0])
    return arr.tolist()


def native_ntt_base_mul_3329(a_hat: List[int], b_hat: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    a_arr = array.array("i", a_hat)
    b_arr = array.array("i", b_hat)
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_ntt_base_mul_3329(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
    return out.tolist()


def native_poly_add_3329(a: List[int], b: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    a_arr = array.array("i", a)
    b_arr = array.array("i", b)
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_poly_add_3329(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
    return out.tolist()


def native_poly_sub_3329(a: List[int], b: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    a_arr = array.array("i", a)
    b_arr = array.array("i", b)
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_poly_sub_3329(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
    return out.tolist()


def native_ntt_qvs(poly: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    arr = array.array("i", poly)
    _LIB.openqpep_ntt_qvs(arr.buffer_info()[0])
    return arr.tolist()


def native_inv_ntt_qvs(poly_hat: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    arr = array.array("i", poly_hat)
    _LIB.openqpep_inv_ntt_qvs(arr.buffer_info()[0])
    return arr.tolist()


def native_ntt_mul_qvs(a_hat: List[int], b_hat: List[int]) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    a_arr = array.array("i", a_hat)
    b_arr = array.array("i", b_hat)
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_ntt_mul_qvs(a_arr.buffer_info()[0], b_arr.buffer_info()[0], out.buffer_info()[0])
    return out.tolist()


def native_cbd2_3329(raw128: bytes) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_cbd2_3329(raw128, out.buffer_info()[0])
    return out.tolist()


def native_cbd1_3329(raw64: bytes) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_cbd1_3329(raw64, out.buffer_info()[0])
    return out.tolist()


def native_cbd2_qvs(raw128: bytes) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    out = array.array("i", _ZERO_256_I32)
    _LIB.openqpep_cbd2_qvs(raw128, out.buffer_info()[0])
    return out.tolist()


def native_plain_lwe_keygen_row(e_row: List[int], a_row: List[int], s_flat: List[int], n: int, nbar: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    b_out = array.array("H", [0] * nbar)
    e_arr = array.array("H", e_row)
    a_arr = array.array("H", a_row)
    s_arr = array.array("H", s_flat)
    _LIB.openqpep_plain_lwe_keygen_row_u16(
        b_out.buffer_info()[0], e_arr.buffer_info()[0], a_arr.buffer_info()[0], s_arr.buffer_info()[0], n, nbar
    )
    return b_out.tolist()


def native_plain_lwe_row_accum(dst: List[int], row: List[int], scalar: int) -> Optional[List[int]]:
    if not (_NATIVE_ENABLED and _LIB is not None):
        return None
    dst_arr = array.array("H", dst)
    row_arr = array.array("H", row)
    _LIB.openqpep_plain_lwe_row_accum_u16(dst_arr.buffer_info()[0], row_arr.buffer_info()[0], scalar & 0xFFFF, len(row))
    return dst_arr.tolist()


def native_explicit_bzero(addr: int, length: int) -> bool:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_explicit_bzero")):
        return False
    _LIB.openqpep_explicit_bzero(addr, length)
    return True


def native_verify_wire_v5_magic(hdr: bytes) -> Optional[int]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_verify_wire_v5_magic")):
        return None
    return int(_LIB.openqpep_verify_wire_v5_magic(hdr, len(hdr)))


def native_ct_eq(a: bytes, b: bytes) -> Optional[bool]:
    if not (_NATIVE_ENABLED and _LIB is not None and hasattr(_LIB, "openqpep_ct_eq")):
        return None
    if len(a) != len(b):
        return False
    return bool(_LIB.openqpep_ct_eq(a, b, len(a)))
