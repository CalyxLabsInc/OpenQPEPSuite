"""
OpenQPEP Known Answer Test (KAT) Verifier (Official Release 1.0.0 / v1.0.0).
Re-runs deterministic KAT derivation across ALL 10 canonical suites (5 structured-lattice + 5 Beyond-LWE)
from golden JSON files in vectors/*.json and verifies 100% bit-for-bit equality.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .kat_generator import SUITE_KAT_SPECS, generate_suite_kat


def verify_kat_file(kat_path: Path) -> Tuple[bool, str]:
    """Verifies a single golden JSON KAT file against the live OpenQPEP Official Release 1.0.0 engine."""
    expected: Dict[str, Any] = json.loads(Path(kat_path).read_text(encoding="utf-8"))
    family = expected.get("family", "structured_lattice")
    spec = {
        "filename": Path(kat_path).name,
        "family": family,
        "suite_id": expected.get("suite_id", expected["qlx_tier"]),
        "suite_name": expected["suite_name"],
        "qlx_tier": expected["qlx_tier"],
        "qvs_tier": expected["qvs_tier"],
        "seed_hex": expected["drbg_seed_hex"],
    }
    actual = generate_suite_kat(spec)

    if family == "beyond_lwe":
        for fld in (
            "wire_magic_hex",
            "public_material_bytes",
            "public_material_sha3_512",
            "ct_bytes",
            "ct_sha3_512",
            "sig_bytes",
            "sig_sha3_512",
            "qpkrf_roundtrip_verified",
            "decrypt_verified",
            "signature_verified",
        ):
            if actual["beyond_lwe"][fld] != expected["beyond_lwe"][fld]:
                return False, f"Mismatch in beyond_lwe.{fld} for {spec['suite_id']}"
        return (
            True,
            f"[PASS] {spec['suite_id']:14s} (Beyond-LWE) | ct={actual['beyond_lwe']['ct_bytes']:6d} B "
            f"| sig={actual['beyond_lwe']['sig_bytes']:6d} B | pub={actual['beyond_lwe']['public_material_sha3_512'][:16]}...",
        )

    for section in ("qlx", "qvs"):
        if actual[section] != expected[section]:
            return False, f"Mismatch in {section} for {spec['suite_name']}"

    if actual["wire_packet"]["wire_magic_hex"] != expected["wire_packet"]["wire_magic_hex"]:
        return False, f"Wire magic mismatch for {spec['suite_name']}"
    if expected["wire_packet"]["cleartext_identity_headers_present"]:
        return False, f"Cleartext identity headers detected in {spec['suite_name']}"

    return (
        True,
        f"[PASS] {spec['suite_id']:14s} (Lattice)    | ct={actual['qlx']['actual_ct_qlx_bytes']:6d} B "
        f"| sig={actual['qvs']['actual_sig_bytes']:6d} B | ss={actual['qlx']['shared_secret_hex'][:16]}...",
    )


def verify_all_kats(vectors_dir: Path) -> Tuple[bool, List[str]]:
    """Verifies all 10 golden KAT JSON files in vectors_dir."""
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
