#!/usr/bin/env python3
"""
OpenQPEP Automated 6-Suite Benchmark Harness (Production Candidate 1.0.0).
Measures keygen, encaps/encrypt, decaps/decrypt, sign, verify, and peak RSS RAM across all 6 suites:
  1. QLX-768 + QVS-65 (Velocity)
  2. QLX-1024 + QVS-87 (Sovereign Hybrid)
  3. QLX-2048 + QVS-128 (Ultra-Grid)
  4. Calyx Signature: QLX-4096 + QVS-256 (Default)
  5. Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (Flagship 12GB+)
  6. Calyx Sovereign-Pentad: CSP-Omega (5-Family Beyond-LWE Citadel, Flagship 12GB+)
"""
import json
import resource
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.lattice.qvs_dsa import QVSEngine
from calyx_qpep.pentad import CalyxSovereignPentad

SUITES = [
    ("QLX-768 + QVS-65 (Velocity)", "QLX-768", "QVS-65"),
    ("QLX-1024 + QVS-87 (Sovereign)", "QLX-1024", "QVS-87"),
    ("QLX-2048 + QVS-128 (Ultra-Grid)", "QLX-2048", "QVS-128"),
    ("Calyx Signature (QLX-4096 + QVS-256)", "QLX-4096", "QVS-256"),
    ("Calyx Hyper-Tesseract (QLX-16384 + QVS-1024)", "QLX-16384", "QVS-1024"),
]


def _peak_rss_mib() -> float:
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2)


def run_benchmarks(include_heavy: bool = True) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    witness = b"B" * 64
    msg = b"OpenQPEP PC 1.0.0 Benchmark Message"

    target_suites = SUITES if include_heavy else SUITES[:2]
    for label, qlx_t, qvs_t in target_suites:
        t0 = time.perf_counter()
        ek, dk = QLXEngine.keygen(qlx_t, witness)
        pk_s, sk_s = QVSEngine.keygen(qvs_t, witness)
        kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        t0 = time.perf_counter()
        ct, _ss = QLXEngine.encaps(ek, qlx_t)
        enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        t0 = time.perf_counter()
        QLXEngine.decaps(dk, ct, qlx_t)
        dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        t0 = time.perf_counter()
        sig = QVSEngine.sign(sk_s, pk_s, msg, tier=qvs_t)
        sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        t0 = time.perf_counter()
        assert QVSEngine.verify(pk_s, msg, sig, tier=qvs_t)
        ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        rows.append({
            "suite": label,
            "keygen_ms": kg_ms,
            "encaps_ms": enc_ms,
            "decaps_ms": dec_ms,
            "sign_ms": sign_ms,
            "verify_ms": ver_ms,
            "peak_rss_mib": _peak_rss_mib(),
        })

    # Suite 6: Calyx Sovereign-Pentad (CSP-Omega)
    t0 = time.perf_counter()
    p_pub, p_priv = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
    kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    t0 = time.perf_counter()
    p_ct = CalyxSovereignPentad.encrypt(msg, p_pub)
    enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    t0 = time.perf_counter()
    assert CalyxSovereignPentad.decrypt(p_ct, p_priv) == msg
    dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    t0 = time.perf_counter()
    p_sig = CalyxSovereignPentad.sign(msg, p_pub, p_priv)
    sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    t0 = time.perf_counter()
    ok, _ = CalyxSovereignPentad.verify(p_sig, p_pub)
    assert ok
    ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    rows.append({
        "suite": "Calyx Sovereign-Pentad (CSP-Omega, 5-Family)",
        "keygen_ms": kg_ms,
        "encaps_ms": enc_ms,
        "decaps_ms": dec_ms,
        "sign_ms": sign_ms,
        "verify_ms": ver_ms,
        "peak_rss_mib": _peak_rss_mib(),
    })
    return rows


def format_markdown_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "| OpenQPEP Suite | Keygen (ms) | Encaps (ms) | Decaps (ms) | Sign (ms) | Verify (ms) | Peak RSS (MiB) |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        lines.append(
            f"| {r['suite']} | {r['keygen_ms']:.2f} | {r['encaps_ms']:.2f} | "
            f"{r['decaps_ms']:.2f} | {r['sign_ms']:.2f} | {r['verify_ms']:.2f} | {r['peak_rss_mib']:.2f} |"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    results = run_benchmarks(include_heavy=True)
    md = format_markdown_table(results)
    print(md)
    out_json = Path(__file__).resolve().parent / "benchmark_results.json"
    out_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
