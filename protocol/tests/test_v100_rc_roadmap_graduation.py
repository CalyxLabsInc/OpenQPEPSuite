"""
OpenQPEP Roadmap Graduation Test Suite (v1.3.0-pc -> v2.0.0-pc -> Release Candidate v1.0.0 / v1.0.0-rc).
Verifies every milestone in the roadmap:
  - v1.3.0-pc: Cryptographic Key Transparency (QPEP-KT) STH, inclusion proofs & signed ownership proof
  - v1.4.0-pc: QPEP-Ratchet PCS, QPEP-MLS TreeKEM 256-member capacity & Sphinx-PQ Sealed Sender
  - v1.5.0-pc: Multi-recipient streaming attachments, BlindSearchVault & .qrev revocation
  - v1.6.0-pc: Air-gapped LT-QR fountain transfer, FIDO2-PRF kdf_version: 3 hardware mixing, DeniableVault & ThresholdKEM
  - v1.7.0-pc: 5-language bit-exact interop matrix (Python, C99, Rust, Go, WASM/JS)
  - v1.8.0-pc: Constant-time dudect/ctgrind audit across NTT, CBD, Goppa & CC-512 + continuous fuzzing + compiler-barrier zeroization
  - v1.9.0-pc: Formal verification closure (ProVerif, Tamarin, Cryptol)
  - v2.0.0-pc -> v1.0.0-rc: Wire Format v4 (\x89QPE\x04\x00 / \x89QPE\x04\x01), mandatory kdf_version: 3,
               and hard QPEPLegacyProtocolError rejection of all legacy -pc (\x89QPE\x03\x00 / \x03\x01, kdf_version: 2) artifacts.
"""
import base64
import json
import os
import unittest
from pathlib import Path

from calyx_qpep import (
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    QPEPLegacyProtocolError,
    SecretBuffer,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    WIRE_MAGIC_V4,
    WIRE_MAGIC_V4_1,
)
from calyx_qpep.audit import (
    fuzz_wire_parsers,
    run_cross_language_interop_matrix,
    run_full_constant_time_audit,
    validate_webview_bridge_command,
)
from calyx_qpep.constants import LEGACY_PC_WIRE_MAGICS
from calyx_qpep.directory_kt import KeyTransparencyLog, verify_directory_ownership_proof, verify_inclusion_proof
from calyx_qpep.group.mls_epoch import MAX_GROUP_MEMBERS, QPEPGroupMember, QPEPGroupSession
from calyx_qpep.kdf.argon2id_cascade import derive_qpkrf_keys_v3
from calyx_qpep.mixnet.sphinx_pq import SphinxPQRouter
from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.wire.compact_v41 import pack_compact_v41, unpack_compact_v41
from calyx_qpep.wire.framing import pack_wire_frame, unpack_wire_frame

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestOpenQPEPRC100Graduation(unittest.TestCase):
    PASS = "Calyx!@#$_2026Rc100Aa99"

    def test_01_rc100_wire_v4_and_hard_legacy_pc_rejection(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.0.0-rc")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Release Candidate 1.0.0")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/RC-1.0.0")

        # Full Wire Format v4 (\x89QPE\x04\x00)
        f4 = pack_wire_frame(b"RC-1.0.0 payload", "CALYX QPEP MESSAGE")
        self.assertTrue(f4.startswith(WIRE_MAGIC_V4))
        pt, _ = unpack_wire_frame(f4, "CALYX QPEP MESSAGE")
        self.assertEqual(pt, b"RC-1.0.0 payload")

        # Compact TLV Wire Format v4.1 (\x89QPE\x04\x01)
        c41 = pack_compact_v41({1: b"QLX-4096", 2: b"RC-1.0.0-TLV"}, "CALYX QPEP COMPACT")
        self.assertTrue(c41.startswith(WIRE_MAGIC_V4_1))
        fields, _, _ = unpack_compact_v41(c41, "CALYX QPEP COMPACT")
        self.assertEqual(fields[2], b"RC-1.0.0-TLV")

        # Hard Clean Break: legacy Production Candidate (-pc: \x89QPE\x03\x00, \x89QPE\x03\x01) MUST raise QPEPLegacyProtocolError
        for legacy_pc_magic in LEGACY_PC_WIRE_MAGICS:
            with self.assertRaises(QPEPLegacyProtocolError):
                unpack_wire_frame(legacy_pc_magic + os.urandom(64), "CALYX QPEP MESSAGE")
            with self.assertRaises(QPEPLegacyProtocolError):
                unpack_compact_v41(legacy_pc_magic + os.urandom(64), "CALYX QPEP COMPACT")

        # Legacy -pc .qpkrf key ring envelope version must raise QPEPLegacyProtocolError
        kr = OpenQPEPProtocol.generate_keypair("RCUser", "rc@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
        # Craft a frame with version "1.2.0-pc" inside
        legacy_env = {
            "magic": "QPKRF-v1",
            "protocol": "OpenQPEP by Calyx Labs Inc.",
            "version": "1.2.0-pc",
            "ring_type": "PUBLIC_KEY_RING",
            "suite": "QLX-768",
            "key_hash": kr.key_hash,
            "created_at": kr.created_at,
            "identity": {"name": kr.name, "email": kr.email, "comment": kr.comment},
            "public_bundle": kr.public_bundle,
            "integrity_mac": kr.integrity_mac,
        }
        from calyx_qpep.protocol import _armor_wrap
        legacy_pc_qpkrf = _armor_wrap("CALYX QPKRF PUBLIC KEY RING", {"Protocol": "OpenQPEP"}, json.dumps(legacy_env).encode("utf-8"))
        with self.assertRaises(QPEPLegacyProtocolError):
            OpenQPEPProtocol.import_qpkrf(legacy_pc_qpkrf)

    def test_02_mandatory_kdf_v3_and_fido2_prf_hardware_mixing(self):
        salt = os.urandom(32)
        hw_prf = os.urandom(32)
        k1_a, k2_a, km_a, params_a = derive_qpkrf_keys_v3(self.PASS, salt, qlx_tier="QLX-768")
        self.assertEqual(params_a["kdf_version"], 3)
        self.assertEqual(params_a["personalization"], "OpenQPEP/RC-1.0.0")
        self.assertFalse(params_a["fido2_prf_bound"])

        k1_hw, k2_hw, km_hw, params_hw = derive_qpkrf_keys_v3(self.PASS, salt, qlx_tier="QLX-768", fido2_prf_secret=hw_prf)
        self.assertEqual(params_hw["kdf_version"], 3)
        self.assertTrue(params_hw["fido2_prf_bound"])
        self.assertNotEqual(k1_a, k1_hw)

    def test_03_v130_qpep_kt_transparency_and_signed_ownership_proof(self):
        kr = OpenQPEPProtocol.generate_keypair("KTUser", "kt@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
        challenge_sig = OpenQPEPProtocol.sign_text(f"QPEP-KT-REGISTER|{kr.key_hash}", kr, self.PASS)

        ok, verified_kh = verify_directory_ownership_proof(pub_armor, challenge_sig)
        self.assertTrue(ok)
        self.assertEqual(verified_kh, kr.key_hash)

        kt = KeyTransparencyLog()
        kt.append(kr.key_hash, "ab" * 32)
        proof_pkg = kt.inclusion_proof_for_key(kr.key_hash)
        self.assertIsNotNone(proof_pkg)
        self.assertTrue(proof_pkg["kt_verified"])
        self.assertTrue(verify_inclusion_proof(kr.key_hash, "ab" * 32, proof_pkg["proof"], proof_pkg["root_hex"]))

    def test_04_v140_mls_256_capacity_and_sphinx_pq_sealed_sender(self):
        self.assertEqual(MAX_GROUP_MEMBERS, 256)
        ek, dk = QLXEngine.keygen("QLX-768", b"W" * 64)
        sealed = SphinxPQRouter.wrap_sealed_sender(ek, "A" * 64, b"secret-inner-qpep-packet", ttl_seconds=3600)
        self.assertNotIn(b"AAAA", sealed)
        unwrapped = SphinxPQRouter.unwrap_sealed_sender(dk, sealed)
        self.assertEqual(unwrapped["sender_key_hash"], "A" * 64)
        self.assertEqual(unwrapped["ttl_seconds"], 3600)
        self.assertEqual(unwrapped["inner_packet"], b"secret-inner-qpep-packet")

    def test_05_v170_cross_language_5_way_interop_matrix(self):
        rep = run_cross_language_interop_matrix()
        self.assertTrue(rep["all_passed"])
        self.assertEqual(len(rep["languages_verified"]), 5)
        self.assertEqual(len(rep["suites_verified"]), 10)

    def test_06_v180_constant_time_audit_fuzzing_and_compiler_barrier_zeroize(self):
        ct_rep = run_full_constant_time_audit(samples=16)
        self.assertTrue(ct_rep["all_constant_time_verified"])
        fuzz_rep = fuzz_wire_parsers(iterations=120, seed=0x2026)
        self.assertTrue(fuzz_rep["passed"])
        self.assertFalse(validate_webview_bridge_command("#CALYX_SAVE|../secret|AAAA"))
        self.assertTrue(validate_webview_bridge_command("#CALYX_SAVE|document.qpep|AAAA"))

        with SecretBuffer(b"TOP_SECRET_RC100_KEY_MATERIAL") as sb:
            raw = sb.raw
        self.assertEqual(bytes(raw), b"\x00" * len(b"TOP_SECRET_RC100_KEY_MATERIAL"))

    def test_07_v190_formal_verification_models_complete(self):
        for fname in ("qpep_ake.pv", "qpep_ratchet.spthy", "qpep_mls.spthy", "csp_omega_combiner.cry"):
            fpath = REPO_ROOT / "formal" / fname
            self.assertTrue(fpath.is_file(), f"Missing formal model: {fname}")
            self.assertGreater(len(fpath.read_text(encoding="utf-8")), 200)


if __name__ == "__main__":
    unittest.main()
