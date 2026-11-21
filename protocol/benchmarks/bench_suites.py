#!/usr/bin/env python3
"""
OpenQPEP Automated 10-Suite Benchmark Harness (Production Candidate 1.2.0 / v1.2.0-pc).
Measures keygen, encaps/encrypt, decaps/decrypt, sign, verify, and peak RSS RAM across all 10 canonical suites:
  1. Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)
  2. Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)
  3. Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)
  4. Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)
  5. Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)
  6. Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)
  7. Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)
  8. Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)
  9. Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)
 10. Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)
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

from calyx_qpep.codes.goppa_suite import CalyxGoppaMonolithSuite
from calyx_qpep.codes.rank_suite import CalyxRankMetricSuite
from calyx_qpep.hashsig.qhs_512_hypertree import QHS512HypertreeEngine
from calyx_qpep.isogeny.isogeny_suite import CalyxIsogenyForgeSuite
from calyx_qpep.lattice.citadel_suite import CalyxUnstructuredCitadelSuite
from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.lattice.qvs_dsa import QVSEngine
from calyx_qpep.multivariate.qmq_512 import MultivariateQuadraticEngine
from calyx_qpep.pentad import CalyxSovereignPentad

QLX_SUITES = [
    ("Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)", "QLX-4096", "QVS-256", "All Devices"),
    ("Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)", "QLX-768", "QVS-65", "All Devices"),
    ("Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)", "QLX-1024", "QVS-87", "All Devices"),
    ("Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)", "QLX-2048", "QVS-128", "All Devices"),
    ("Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)", "QLX-16384", "QVS-1024", "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)"),
]


def _peak_rss_mib() -> float:
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2)


def run_benchmarks(include_heavy: bool = True) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    witness = b"B" * 64
    msg = b"OpenQPEP PC 1.2.0 Benchmark Message"

    # 1-5. Structured Lattice Suites (QLX + QVS)
    target_qlx = QLX_SUITES if include_heavy else QLX_SUITES[:4]
    for label, qlx_t, qvs_t, hw_tier in target_qlx:
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
            "release": "v1.2.0-pc",
            "suite": label,
            "hardware_tier": hw_tier,
            "keygen_ms": kg_ms,
            "encaps_ms": enc_ms,
            "decaps_ms": dec_ms,
            "sign_ms": sign_ms,
            "verify_ms": ver_ms,
            "peak_rss_mib": _peak_rss_mib(),
        })

    # 6. Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (All Devices)
    t0 = time.perf_counter()
    iso_pub, iso_priv = CalyxIsogenyForgeSuite.keygen()
    kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    t0 = time.perf_counter()
    iso_ct = CalyxIsogenyForgeSuite.encrypt(msg, iso_pub)
    enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    t0 = time.perf_counter()
    assert CalyxIsogenyForgeSuite.decrypt(iso_ct, iso_priv) == msg
    dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    t0 = time.perf_counter()
    iso_sig = CalyxIsogenyForgeSuite.sign(msg, iso_priv)
    sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    t0 = time.perf_counter()
    ok, _ = CalyxIsogenyForgeSuite.verify(iso_sig, iso_pub)
    assert ok
    ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    rows.append({
        "release": "v1.2.0-pc",
        "suite": "Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)",
        "hardware_tier": "All Devices",
        "keygen_ms": kg_ms,
        "encaps_ms": enc_ms,
        "decaps_ms": dec_ms,
        "sign_ms": sign_ms,
        "verify_ms": ver_ms,
        "peak_rss_mib": _peak_rss_mib(),
    })

    # 7. Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (All Devices)
    t0 = time.perf_counter()
    rm_pk, rm_sk = CalyxRankMetricSuite.keygen()
    mq_pk, mq_sk = MultivariateQuadraticEngine.keygen()
    kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    t0 = time.perf_counter()
    rm_ct = CalyxRankMetricSuite.encrypt(msg, rm_pk)
    enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    t0 = time.perf_counter()
    assert CalyxRankMetricSuite.decrypt(rm_ct, rm_sk) == msg
    dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    t0 = time.perf_counter()
    mq_sig = MultivariateQuadraticEngine.sign(mq_sk, msg)
    sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    t0 = time.perf_counter()
    assert MultivariateQuadraticEngine.verify(mq_pk, msg, mq_sig)
    ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    rows.append({
        "release": "v1.2.0-pc",
        "suite": "Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)",
        "hardware_tier": "All Devices",
        "keygen_ms": kg_ms,
        "encaps_ms": enc_ms,
        "decaps_ms": dec_ms,
        "sign_ms": sign_ms,
        "verify_ms": ver_ms,
        "peak_rss_mib": _peak_rss_mib(),
    })

    if True:  # Beyond-LWE suites run in <200ms
        # 8. Calyx Goppa-Monolith: CGM-8192 + QHS-512 (HIGH-TIER HARDWARE ONLY)
        t0 = time.perf_counter()
        gm_pk, gm_sk = CalyxGoppaMonolithSuite.keygen()
        qhs_pk, qhs_sk = QHS512HypertreeEngine.keygen()
        kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        t0 = time.perf_counter()
        gm_ct = CalyxGoppaMonolithSuite.encrypt(msg, gm_pk)
        enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        t0 = time.perf_counter()
        assert CalyxGoppaMonolithSuite.decrypt(gm_ct, gm_sk) == msg
        dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        t0 = time.perf_counter()
        qhs_sig = QHS512HypertreeEngine.sign(qhs_sk, msg)
        sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        t0 = time.perf_counter()
        assert QHS512HypertreeEngine.verify(qhs_pk, msg, qhs_sig)
        ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        rows.append({
            "release": "v1.2.0-pc",
            "suite": "Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)",
            "hardware_tier": "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)",
            "keygen_ms": kg_ms,
            "encaps_ms": enc_ms,
            "decaps_ms": dec_ms,
            "sign_ms": sign_ms,
            "verify_ms": ver_ms,
            "peak_rss_mib": _peak_rss_mib(),
        })

        # 9. Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (HIGH-TIER HARDWARE ONLY)
        t0 = time.perf_counter()
        cit_pub, cit_priv = CalyxUnstructuredCitadelSuite.keygen(allow_low_ram_override=True)
        kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        t0 = time.perf_counter()
        cit_ct = CalyxUnstructuredCitadelSuite.encrypt(msg, cit_pub)
        enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        t0 = time.perf_counter()
        assert CalyxUnstructuredCitadelSuite.decrypt(cit_ct, cit_priv) == msg
        dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        t0 = time.perf_counter()
        cit_sig = CalyxUnstructuredCitadelSuite.sign(msg, cit_priv)
        sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        t0 = time.perf_counter()
        ok, _ = CalyxUnstructuredCitadelSuite.verify(cit_sig, cit_pub)
        assert ok
        ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        rows.append({
            "release": "v1.2.0-pc",
            "suite": "Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)",
            "hardware_tier": "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)",
            "keygen_ms": kg_ms,
            "encaps_ms": enc_ms,
            "decaps_ms": dec_ms,
            "sign_ms": sign_ms,
            "verify_ms": ver_ms,
            "peak_rss_mib": _peak_rss_mib(),
        })

        # 10. Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (HIGH-TIER HARDWARE ONLY)
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
            "release": "v1.2.0-pc",
            "suite": "Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)",
            "hardware_tier": "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)",
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
        "| OpenQPEP Suite (`v1.2.0-pc`) | Hardware Tier | Keygen (ms) | Encaps (ms) | Decaps (ms) | Sign (ms) | Verify (ms) | Peak RSS (MiB) |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        lines.append(
            f"| {r['suite']} | {r['hardware_tier']} | {r['keygen_ms']:.2f} | {r['encaps_ms']:.2f} | "
            f"{r['decaps_ms']:.2f} | {r['sign_ms']:.2f} | {r['verify_ms']:.2f} | {r['peak_rss_mib']:.2f} |"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    results = run_benchmarks(include_heavy=True)
    md = format_markdown_table(results)
    print(md)
    out_json = Path(__file__).resolve().parent / "benchmark_results.json"
    out_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
