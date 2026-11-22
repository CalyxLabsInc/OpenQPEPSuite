"""
OpenQPEP Known Answer Test (KAT) Generator (Official Release 1.0.0 / v1.0.0).
Generates deterministic, byte-exact ACVP-style JSON test vectors across ALL 10 canonical suites:
  1. Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)
  2. Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)
  3. Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)
  4. Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)
  5. Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)
  6. Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)
  7. Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)
  8. Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)
  9. Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)
 10. Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)
"""
import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from ..constants import ALL_TEN_SUITES, PROTOCOL_VERSION, QLX_TIERS, QVS_TIERS, UNIVERSAL_VERSION
from ..lattice.qlx_kem import QLXEngine
from ..lattice.qvs_dsa import QVSEngine
from ..primitives.qsponge import qsponge_512
from ..protocol import OpenQPEPProtocol
from .drbg import deterministic_urandom

SUITE_KAT_SPECS: List[Dict[str, str]] = [
    {
        "filename": "kat_qlx768_qvs65.json", "family": "structured_lattice", "suite_id": "QLX-768",
        "suite_name": ALL_TEN_SUITES["QLX-768"]["display_name"], "qlx_tier": "QLX-768", "qvs_tier": "QVS-65",
        "seed_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    },
    {
        "filename": "kat_qlx1024_qvs87.json", "family": "structured_lattice", "suite_id": "QLX-1024",
        "suite_name": ALL_TEN_SUITES["QLX-1024"]["display_name"], "qlx_tier": "QLX-1024", "qvs_tier": "QVS-87",
        "seed_hex": "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    },
    {
        "filename": "kat_qlx2048_qvs128.json", "family": "structured_lattice", "suite_id": "QLX-2048",
        "suite_name": ALL_TEN_SUITES["QLX-2048"]["display_name"], "qlx_tier": "QLX-2048", "qvs_tier": "QVS-128",
        "seed_hex": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    },
    {
        "filename": "kat_qlx4096_qvs256.json", "family": "structured_lattice", "suite_id": "QLX-4096",
        "suite_name": ALL_TEN_SUITES["QLX-4096"]["display_name"], "qlx_tier": "QLX-4096", "qvs_tier": "QVS-256",
        "seed_hex": "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    },
    {
        "filename": "kat_qlx16384_qvs1024.json", "family": "structured_lattice", "suite_id": "QLX-16384",
        "suite_name": ALL_TEN_SUITES["QLX-16384"]["display_name"], "qlx_tier": "QLX-16384", "qvs_tier": "QVS-1024",
        "seed_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    },
    {
        "filename": "kat_cif_sqi512.json", "family": "beyond_lwe", "suite_id": "CIF-SQI-512",
        "suite_name": ALL_TEN_SUITES["CIF-SQI-512"]["display_name"], "qlx_tier": "CIF-SQI-512", "qvs_tier": "QHS-512",
        "seed_hex": "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f",
    },
    {
        "filename": "kat_crt_rsd512.json", "family": "beyond_lwe", "suite_id": "CRT-RSD512",
        "suite_name": ALL_TEN_SUITES["CRT-RSD512"]["display_name"], "qlx_tier": "CRT-RSD512", "qvs_tier": "QMQ-512",
        "seed_hex": "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
    },
    {
        "filename": "kat_cgm8192.json", "family": "beyond_lwe", "suite_id": "CGM-8192",
        "suite_name": ALL_TEN_SUITES["CGM-8192"]["display_name"], "qlx_tier": "CGM-8192", "qvs_tier": "QHS-512",
        "seed_hex": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    },
    {
        "filename": "kat_culc2048.json", "family": "beyond_lwe", "suite_id": "CULC-2048",
        "suite_name": ALL_TEN_SUITES["CULC-2048"]["display_name"], "qlx_tier": "CULC-2048", "qvs_tier": "CGM-8192",
        "seed_hex": "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    },
    {
        "filename": "kat_csp_omega.json", "family": "beyond_lwe", "suite_id": "CSP-Omega",
        "suite_name": ALL_TEN_SUITES["CSP-Omega"]["display_name"], "qlx_tier": "CSP-Omega", "qvs_tier": "QHS-512",
        "seed_hex": "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    },
]

KAT_PASSPHRASE = "Calyx!@#$_2026Aa99"
KAT_MESSAGE = b"OpenQPEP Official Release 1.0.0 Deterministic Known Answer Test Vector"


def _sha3_512_hex(data: bytes) -> str:
    return qsponge_512(data).hex()


def _extract_raw_wire_frame(armored: str) -> bytes:
    lines = [l.strip() for l in armored.splitlines()]
    body = []
    in_body = False
    for line in lines:
        if line.startswith("-----BEGIN "):
            in_body = True
            continue
        if line.startswith("-----END "):
            break
        if not in_body or not line or line.startswith("=") or ":" in line:
            continue
        body.append(line)
    return base64.b64decode("".join(body))


def generate_suite_kat(spec: Dict[str, str]) -> Dict[str, Any]:
    """Generates a complete deterministic KAT record for any of the 10 canonical OpenQPEP suites."""
    seed = bytes.fromhex(spec["seed_hex"])
    family = spec.get("family", "structured_lattice")
    suite_id = spec.get("suite_id", spec["qlx_tier"])
    qlx_tier = spec["qlx_tier"]
    qvs_tier = spec["qvs_tier"]
    suite_name = spec["suite_name"]
    policy_witness = qsponge_512(b"CALYX-KAT-POLICY-WITNESS-v1.0.0|" + seed)

    if family == "beyond_lwe":
        prev_env = os.environ.get("OPENQPEP_DETERMINISTIC_KAT")
        os.environ["OPENQPEP_DETERMINISTIC_KAT"] = "1"
        try:
            with deterministic_urandom(seed):
                kr = OpenQPEPProtocol.generate_keypair(
                    "OpenQPEP KAT Vector", "kat@calyxlabsinc.org", KAT_PASSPHRASE, qlx_tier=suite_id,
                )
                pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
                priv_armor = OpenQPEPProtocol.export_qpkrf(kr, passphrase=KAT_PASSPHRASE, include_private=True)
                pub_kr = OpenQPEPProtocol.import_qpkrf(pub_armor)
                priv_kr = OpenQPEPProtocol.import_qpkrf(priv_armor, passphrase=KAT_PASSPHRASE)

                ct_armored = OpenQPEPProtocol.encrypt_beyond_lwe_packet(KAT_MESSAGE, pub_kr)
                pt_out = OpenQPEPProtocol.decrypt_beyond_lwe_packet(ct_armored, priv_kr, KAT_PASSPHRASE)
                assert pt_out == KAT_MESSAGE, f"Beyond-LWE KAT decrypt mismatch for {suite_id}"

                sig_armored = OpenQPEPProtocol.sign_beyond_lwe_bytes(KAT_MESSAGE, priv_kr, KAT_PASSPHRASE)
                ok_sig, verified_msg = OpenQPEPProtocol.verify_beyond_lwe_signature(sig_armored, pub_kr)
                assert ok_sig and verified_msg == KAT_MESSAGE, f"Beyond-LWE KAT sig verify failed for {suite_id}"
        finally:
            if prev_env is None:
                os.environ.pop("OPENQPEP_DETERMINISTIC_KAT", None)
            else:
                os.environ["OPENQPEP_DETERMINISTIC_KAT"] = prev_env

        ct_wire = _extract_raw_wire_frame(ct_armored)
        ct_bytes = ct_armored.encode("utf-8")
        sig_bytes = sig_armored.encode("utf-8")
        blwe_pub_json = json.dumps(pub_kr.public_bundle["beyond_lwe_public"], sort_keys=True).encode("utf-8")
        return {
            "schema": "openqpep-kat-v3",
            "family": "beyond_lwe",
            "protocol_version": PROTOCOL_VERSION,
            "universal_version": UNIVERSAL_VERSION,
            "suite_id": suite_id,
            "suite_name": suite_name,
            "qlx_tier": qlx_tier,
            "qvs_tier": qvs_tier,
            "drbg_algorithm": "qSponge-XOF (SHAKE-256, domain CALYX-OPENQPEP-KAT-DRBG-v1.0.0|)",
            "drbg_seed_hex": spec["seed_hex"],
            "message_utf8": KAT_MESSAGE.decode("utf-8"),
            "message_hex": KAT_MESSAGE.hex(),
            "beyond_lwe": {
                "key_hash": kr.key_hash,
                "wire_magic_hex": ct_wire[:6].hex(),
                "public_material_bytes": len(blwe_pub_json),
                "public_material_sha3_512": _sha3_512_hex(blwe_pub_json),
                "ct_bytes": len(ct_bytes),
                "ct_sha3_512": _sha3_512_hex(ct_bytes),
                "sig_bytes": len(sig_bytes),
                "sig_sha3_512": _sha3_512_hex(sig_bytes),
                "qpkrf_roundtrip_verified": True,
                "decrypt_verified": True,
                "signature_verified": True,
            },
        }

    with deterministic_urandom(seed):
        ek, dk = QLXEngine.keygen(qlx_tier, policy_witness)
        ct_qlx, ss_enc = QLXEngine.encaps(ek, qlx_tier)
        ss_dec = QLXEngine.decaps(dk, ct_qlx, qlx_tier)
        assert ss_enc == ss_dec, f"KAT decaps mismatch for {qlx_tier}"

        tampered_ct = bytes([ct_qlx[0] ^ 0x01]) + ct_qlx[1:]
        ss_reject = QLXEngine.decaps(dk, tampered_ct, qlx_tier)
        assert ss_reject != ss_enc and len(ss_reject) == 32

        qvs_pk, qvs_sk = QVSEngine.keygen(qvs_tier, policy_witness)
        qvs_sig = QVSEngine.sign(qvs_sk, qvs_pk, KAT_MESSAGE, tier=qvs_tier)
        assert QVSEngine.verify(qvs_pk, KAT_MESSAGE, qvs_sig, tier=qvs_tier)

        kr = OpenQPEPProtocol.generate_keypair(
            "OpenQPEP KAT Vector", "kat@calyxlabsinc.org", KAT_PASSPHRASE, qlx_tier=qlx_tier,
        )
        pub_kr = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(kr, include_private=False))
        armored_pkt = OpenQPEPProtocol.encrypt_text(
            KAT_MESSAGE.decode("utf-8"),
            recipient_keyring=pub_kr,
            encrypting_keyring=kr,
            passphrase=KAT_PASSPHRASE,
        )
        wire_frame = _extract_raw_wire_frame(armored_pkt)
        pt_out, _meta = OpenQPEPProtocol.decrypt_packet(armored_pkt, kr, KAT_PASSPHRASE)
        assert pt_out == KAT_MESSAGE

    return {
        "schema": "openqpep-kat-v3",
        "family": "structured_lattice",
        "protocol_version": PROTOCOL_VERSION,
        "universal_version": UNIVERSAL_VERSION,
        "suite_id": suite_id,
        "suite_name": suite_name,
        "qlx_tier": qlx_tier,
        "qvs_tier": qvs_tier,
        "drbg_algorithm": "qSponge-XOF (SHAKE-256, domain CALYX-OPENQPEP-KAT-DRBG-v1.0.0|)",
        "drbg_seed_hex": spec["seed_hex"],
        "message_utf8": KAT_MESSAGE.decode("utf-8"),
        "message_hex": KAT_MESSAGE.hex(),
        "qlx": {
            "spec_pk_bytes": QLX_TIERS[qlx_tier]["pk_bytes"],
            "spec_sk_bytes": QLX_TIERS[qlx_tier]["sk_bytes"],
            "spec_ct_bytes": QLX_TIERS[qlx_tier]["ct_bytes"],
            "actual_pk_bytes": len(ek),
            "actual_sk_bytes": len(dk),
            "actual_ct_qlx_bytes": len(ct_qlx),
            "pk_sha3_512": _sha3_512_hex(ek),
            "sk_sha3_512": _sha3_512_hex(dk),
            "ct_qlx_sha3_512": _sha3_512_hex(ct_qlx),
            "shared_secret_hex": ss_enc.hex(),
            "fo_implicit_rejection_hex": ss_reject.hex(),
        },
        "qvs": {
            "spec_pk_bytes": QVS_TIERS[qvs_tier]["pk_bytes"],
            "spec_sk_bytes": QVS_TIERS[qvs_tier]["sk_bytes"],
            "spec_sig_bytes": QVS_TIERS[qvs_tier]["sig_bytes"],
            "actual_pk_bytes": len(qvs_pk),
            "actual_sk_bytes": len(qvs_sk),
            "actual_sig_bytes": len(qvs_sig),
            "pk_sha3_512": _sha3_512_hex(qvs_pk),
            "sig_sha3_512": _sha3_512_hex(qvs_sig),
            "verified": True,
        },
        "wire_packet": {
            "key_hash": kr.key_hash,
            "wire_magic_hex": wire_frame[:6].hex(),
            "wire_frame_bytes": len(wire_frame),
            "wire_frame_sha3_512": _sha3_512_hex(wire_frame),
            "wire_frame_prefix_hex": wire_frame[:64].hex(),
            "cleartext_identity_headers_present": (
                "Sender-Key-Hash:" in armored_pkt
                or "Recipient-Key-Hash:" in armored_pkt
                or "Signer-Key-Hash:" in armored_pkt
                or "Encrypting-Key-Hash:" in armored_pkt
            ),
        },
    }


def generate_all_kats(output_dir: Path) -> List[Path]:
    """Generates all 10 golden JSON KAT files plus manifest.json in output_dir."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    manifest_entries = []

    for spec in SUITE_KAT_SPECS:
        kat = generate_suite_kat(spec)
        out_path = output_dir / spec["filename"]
        out_path.write_text(json.dumps(kat, indent=2) + "\n", encoding="utf-8")
        written.append(out_path)
        if spec["family"] == "beyond_lwe":
            manifest_entries.append({
                "file": spec["filename"],
                "family": "beyond_lwe",
                "suite_id": spec["suite_id"],
                "suite_name": spec["suite_name"],
                "wire_magic_hex": kat["beyond_lwe"]["wire_magic_hex"],
                "ct_bytes": kat["beyond_lwe"]["ct_bytes"],
                "sig_bytes": kat["beyond_lwe"]["sig_bytes"],
                "sha3_512": _sha3_512_hex(out_path.read_bytes()),
            })
        else:
            manifest_entries.append({
                "file": spec["filename"],
                "family": "structured_lattice",
                "suite_id": spec["suite_id"],
                "suite_name": spec["suite_name"],
                "wire_magic_hex": kat["wire_packet"]["wire_magic_hex"],
                "qlx_ct_bytes": kat["qlx"]["actual_ct_qlx_bytes"],
                "qvs_sig_bytes": kat["qvs"]["actual_sig_bytes"],
                "sha3_512": _sha3_512_hex(out_path.read_bytes()),
            })

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "protocol_version": PROTOCOL_VERSION,
                "universal_version": UNIVERSAL_VERSION,
                "suite_count": len(manifest_entries),
                "vectors": manifest_entries,
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    written.append(manifest_path)
    return written
