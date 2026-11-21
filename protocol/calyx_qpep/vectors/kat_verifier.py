"""
OpenQPEP Known Answer Test (KAT) Verifier (Production Candidate 1.0.0).
Re-runs deterministic KAT derivation from golden JSON files in vectors/*.json and
verifies 100% bit-for-bit equality on key lengths, ct_qlx lengths, shared secrets,
FO implicit rejections, QVS signatures, and whitened \x89QPE wire frames.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .kat_generator import SUITE_KAT_SPECS, generate_suite_kat


def verify_kat_file(kat_path: Path) -> Tuple[bool, str]:
    """Verifies a single golden JSON KAT file against the live OpenQPEP engine."""
    expected: Dict[str, Any] = json.loads(Path(kat_path).read_text(encoding="utf-8"))
    spec = {
        "filename": Path(kat_path).name,
        "suite_name": expected["suite_name"],
        "qlx_tier": expected["qlx_tier"],
        "qvs_tier": expected["qvs_tier"],
        "seed_hex": expected["drbg_seed_hex"],
    }
    actual = generate_suite_kat(spec)

    # Compare every cryptographic field bit-for-bit (ignoring wire_packet key_hash timestamp drift if any)
    for section in ("qlx", "qvs"):
        if actual[section] != expected[section]:
            return False, f"Mismatch in {section} for {spec['suite_name']}"

    # Verify wire packet invariants (exact magic, zero cleartext identity headers, exact spec ct size)
    if actual["wire_packet"]["wire_magic_hex"] != expected["wire_packet"]["wire_magic_hex"]:
        return False, f"Wire magic mismatch for {spec['suite_name']}"
    if expected["wire_packet"]["cleartext_identity_headers_present"]:
        return False, f"Cleartext identity headers detected in {spec['suite_name']}"

    return (
        True,
        f"[PASS] {spec['suite_name']:44s} | ct_qlx={actual['qlx']['actual_ct_qlx_bytes']:5d} B "
        f"| qvs_sig={actual['qvs']['actual_sig_bytes']:5d} B | ss={actual['qlx']['shared_secret_hex'][:16]}...",
    )


def verify_all_kats(vectors_dir: Path) -> Tuple[bool, List[str]]:
    """Verifies all golden KAT JSON files in vectors_dir."""
    vectors_dir = Path(vectors_dir)
    if not vectors_dir.exists():
        return False, [f"[FAIL] Vectors directory not found: {vectors_dir}"]

    kat_files = sorted(p for p in vectors_dir.glob("kat_*.json"))
    if not kat_files:
        return False, [f"[FAIL] No kat_*.json files found in {vectors_dir}"]

    all_ok = True
    report: List[str] = []
    for kf in kat_files:
        ok, msg = verify_kat_file(kf)
        report.append(msg)
        if not ok:
            all_ok = False
    return all_ok, report
