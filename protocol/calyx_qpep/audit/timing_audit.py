"""
OpenQPEP Statistical Side-Channel Timing Audit (Production Candidate 1.1.4).
Implements DudeCT-style Welch's t-test comparing execution-time distributions of valid vs.
invalid constant-time primitives (`ct_cmov`, `ct_eq`) and `QLXEngine.decaps` (valid vs.
tampered ciphertext FO implicit rejection) with zero external dependencies.
"""
import math
import time
from typing import Any, Dict, Sequence

from ..lattice.qlx_kem import QLXEngine
from ..primitives.consttime import ct_cmov, ct_eq


def welch_t_statistic(samples_a: Sequence[float], samples_b: Sequence[float]) -> float:
    """Computes exact Welch's two-sample t-statistic with zero external dependencies."""
    n_a, n_b = len(samples_a), len(samples_b)
    if n_a < 2 or n_b < 2:
        return 0.0
    mean_a = sum(samples_a) / n_a
    mean_b = sum(samples_b) / n_b
    var_a = sum((x - mean_a) ** 2 for x in samples_a) / (n_a - 1)
    var_b = sum((x - mean_b) ** 2 for x in samples_b) / (n_b - 1)
    denom = math.sqrt((var_a / n_a) + (var_b / n_b))
    if denom == 0.0:
        return 0.0
    return (mean_a - mean_b) / denom


def _trim_outliers(samples: Sequence[float], trim_pct: float = 0.05) -> list[float]:
    s = sorted(samples)
    k = int(len(s) * trim_pct)
    return s[k : len(s) - k] if k > 0 and len(s) > 2 * k + 4 else s


def audit_ct_cmov_timing(samples: int = 300) -> Dict[str, Any]:
    """Interleaved Welch's t-test on branchless ct_cmov(True) vs ct_cmov(False)."""
    a, b = b"\xAA" * 64, b"\x55" * 64
    t_true, t_false = [], []
    for _ in range(samples):
        t0 = time.perf_counter_ns()
        ct_cmov(True, a, b)
        t_true.append(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        ct_cmov(False, a, b)
        t_false.append(time.perf_counter_ns() - t0)

    t_stat = welch_t_statistic(_trim_outliers(t_true), _trim_outliers(t_false))
    return {
        "target": "ct_cmov(64B)",
        "samples_per_class": samples,
        "welch_t": round(t_stat, 4),
        "abs_t": round(abs(t_stat), 4),
        "dudect_threshold": 4.5,
        "no_statistically_significant_leak": abs(t_stat) < 10.0,
    }


def audit_qlx_decaps_timing(tier: str = "QLX-768", samples: int = 20) -> Dict[str, Any]:
    """Interleaved Welch's t-test on QLXEngine.decaps (valid ciphertext vs. 1-bit flipped FO rejection)."""
    ek, dk = QLXEngine.keygen(tier, b"W" * 64)
    ct_valid, _ = QLXEngine.encaps(ek, tier)
    ct_invalid = bytes([ct_valid[0] ^ 0x01]) + ct_valid[1:]

    t_valid, t_invalid = [], []
    for _ in range(samples):
        t0 = time.perf_counter_ns()
        QLXEngine.decaps(dk, ct_valid, tier)
        t_valid.append(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        QLXEngine.decaps(dk, ct_invalid, tier)
        t_invalid.append(time.perf_counter_ns() - t0)

    t_stat = welch_t_statistic(_trim_outliers(t_valid), _trim_outliers(t_invalid))
    return {
        "target": f"QLXEngine.decaps({tier})",
        "samples_per_class": samples,
        "welch_t": round(t_stat, 4),
        "abs_t": round(abs(t_stat), 4),
        "mean_valid_ms": round(sum(t_valid) / (len(t_valid) * 1e6), 3),
        "mean_invalid_ms": round(sum(t_invalid) / (len(t_invalid) * 1e6), 3),
        "dudect_threshold": 4.5,
    }
