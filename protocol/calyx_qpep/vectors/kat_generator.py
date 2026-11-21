"""
OpenQPEP Known Answer Test (KAT) Generator (Production Candidate 1.0.0).
Generates deterministic, byte-exact ACVP-style JSON test vectors across all 5 suites:
  - QLX-768 + QVS-65 (Velocity)
  - QLX-1024 + QVS-87 (Sovereign Hybrid)
  - QLX-2048 + QVS-128 (Ultra-Grid)
  - Calyx Signature: QLX-4096 + QVS-256 (Default)
  - Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (High-Tier Flagship Hardware)
"""
import base64
import json
from pathlib import Path
from typing import Any, Dict, List

from ..constants import PROTOCOL_VERSION, QLX_TIERS, QVS_TIERS, UNIVERSAL_VERSION
from ..lattice.qlx_kem import QLXEngine
from ..lattice.qvs_dsa import QVSEngine
from ..primitives.qsponge import qsponge_512
from ..protocol import OpenQPEPProtocol, _armor_unwrap
from .drbg import deterministic_urandom

SUITE_KAT_SPECS: List[Dict[str, str]] = [
    {
        "filename": "kat_qlx768_qvs65.json",
        "suite_name": "QLX-768 + QVS-65",
        "qlx_tier": "QLX-768",
        "qvs_tier": "QVS-65",
        "seed_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    },
    {
        "filename": "kat_qlx1024_qvs87.json",
        "suite_name": "QLX-1024 + QVS-87",
        "qlx_tier": "QLX-1024",
        "qvs_tier": "QVS-87",
        "seed_hex": "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    },
    {
        "filename": "kat_qlx2048_qvs128.json",
        "suite_name": "QLX-2048 + QVS-128",
        "qlx_tier": "QLX-2048",
        "qvs_tier": "QVS-128",
        "seed_hex": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    },
    {
        "filename": "kat_qlx4096_qvs256.json",
        "suite_name": "Signature QLX-4096 + QVS-256",
        "qlx_tier": "QLX-4096",
        "qvs_tier": "QVS-256",
        "seed_hex": "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    },
    {
        "filename": "kat_qlx16384_qvs1024.json",
        "suite_name": "Calyx Hyper-Tesseract: QLX-16384 + QVS-1024",
        "qlx_tier": "QLX-16384",
        "qvs_tier": "QVS-1024",
        "seed_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    },
]

KAT_PASSPHRASE = "Calyx!@#$_2026Aa99"
KAT_MESSAGE = b"OpenQPEP PC 1.0.0 Deterministic Known Answer Test Vector"


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
    """Generates a complete deterministic KAT record for a single OpenQPEP suite."""
    seed = bytes.fromhex(spec["seed_hex"])
    qlx_tier = spec["qlx_tier"]
    qvs_tier = spec["qvs_tier"]
    suite_name = spec["suite_name"]
    policy_witness = qsponge_512(b"CALYX-KAT-POLICY-WITNESS|" + seed)

    with deterministic_urandom(seed):
        # 1. QLX KEM deterministic keygen + encaps + decaps + FO implicit rejection
        ek, dk = QLXEngine.keygen(qlx_tier, policy_witness)
        ct_qlx, ss_enc = QLXEngine.encaps(ek, qlx_tier)
        ss_dec = QLXEngine.decaps(dk, ct_qlx, qlx_tier)
        assert ss_enc == ss_dec, f"KAT decaps mismatch for {qlx_tier}"

        tampered_ct = bytes([ct_qlx[0] ^ 0x01]) + ct_qlx[1:]
        ss_reject = QLXEngine.decaps(dk, tampered_ct, qlx_tier)
        assert ss_reject != ss_enc and len(ss_reject) == 32

        # 2. QVS DSA deterministic keygen + sign + verify
        qvs_pk, qvs_sk = QVSEngine.keygen(qvs_tier, policy_witness)
        qvs_sig = QVSEngine.sign(qvs_sk, qvs_pk, KAT_MESSAGE, tier=qvs_tier)
        assert QVSEngine.verify(qvs_pk, KAT_MESSAGE, qvs_sig, tier=qvs_tier)

        # 3. Full OpenQPEP Protocol whitened binary wire packet (zero cleartext identity headers)
        kr = OpenQPEPProtocol.generate_keypair(
            "OpenQPEP KAT Vector",
            "kat@calyxlabsinc.org",
            KAT_PASSPHRASE,
            qlx_tier=qlx_tier,
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
        "schema": "openqpep-kat-v1",
        "protocol_version": PROTOCOL_VERSION,
        "universal_version": UNIVERSAL_VERSION,
        "suite_name": suite_name,
        "qlx_tier": qlx_tier,
        "qvs_tier": qvs_tier,
        "drbg_algorithm": "qSponge-XOF (SHAKE-256, domain CALYX-OPENQPEP-KAT-DRBG-v1.0.0-pc|)",
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
            ),
        },
    }


def generate_all_kats(output_dir: Path) -> List[Path]:
    """Generates all 5 golden JSON KAT files plus manifest.json in output_dir."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    manifest_entries = []

    for spec in SUITE_KAT_SPECS:
        kat = generate_suite_kat(spec)
        out_path = output_dir / spec["filename"]
        out_path.write_text(json.dumps(kat, indent=2) + "\n", encoding="utf-8")
        written.append(out_path)
        manifest_entries.append({
            "file": spec["filename"],
            "suite_name": spec["suite_name"],
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
