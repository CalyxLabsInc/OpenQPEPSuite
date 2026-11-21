# OpenQPEP v1.0.0-rc (Release Candidate 1.0.0)
"""Optional PyO3 Rust `openqpep_core` bridge with graceful fallback to C99/Python."""
from typing import Any, Dict

try:
    import openqpep_core as _rust_mod  # type: ignore
    RUST_AVAILABLE = True
except ImportError:
    _rust_mod = None
    RUST_AVAILABLE = False


def rust_backend_info() -> Dict[str, Any]:
    return {
        "rust_pyo3_loaded": RUST_AVAILABLE,
        "crate": "openqpep-core",
        "version": "1.0.0-rc",
        "fallback": "libopenqpep-c99 / pure-python",
    }
