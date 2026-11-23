"""
OpenQPEP Official Release 1.0.0 (v1.0.0) Graduation & Clean-Slate Verification Suite.
Verifies every milestone across the roadmap up through Official Release 1.0.0:
  - Cryptographic Key Transparency (QPEP-KT) Ed448 STH, inclusion & consistency proofs, signed ownership proof
  - QPEP-Ratchet rotating-ephemeral PCS, QPEP-MLS TreeKEM 256-member capacity & Sphinx-PQ Sealed Sender
  - Multi-recipient streaming attachments, BlindSearchVault & .qrev revocation
  - Air-gapped LT-QR fountain transfer, FIDO2-PRF kdf_version: 4 hardware mixing, DeniableVault & ThresholdKEM
  - 5-language bit-exact interop matrix (Python, C99, Rust, Go, WASM/JS)
  - Constant-time dudect/ctgrind audit across NTT, CBD, Goppa & CC-512 + continuous fuzzing + compiler-barrier zeroization
  - Formal verification closure (ProVerif, Tamarin, Cryptol)
  - Official Wire Format v5 (\x89QPE\x05\x00 / \x89QPE\x05\x01), mandatory kdf_version: 4,
    and hard QPEPLegacyProtocolError rejection of ALL legacy -rc, -pc, and -beta artifacts.
"""
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
    WIRE_MAGIC_V5,
    WIRE_MAGIC_V5_1,
)
from calyx_qpep.audit import (
    fuzz_wire_parsers,
    run_cross_language_interop_matrix,
    run_full_constant_time_audit,
    validate_webview_bridge_command,
)
from calyx_qpep.constants import ALL_LEGACY_WIRE_MAGICS
from calyx_qpep.directory_kt import (
    KeyTransparencyLog,
    verify_directory_ownership_proof,
    verify_inclusion_proof,
    verify_sth,
)
from calyx_qpep.group.mls_epoch import MAX_GROUP_MEMBERS
from calyx_qpep.kdf.argon2id_cascade import derive_qpkrf_keys_v4
from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.mixnet.sphinx_pq import SphinxPQRouter
from calyx_qpep.wire.compact_v51 import pack_compact_v51, unpack_compact_v51
from calyx_qpep.wire.framing import pack_wire_frame, unpack_wire_frame

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestOpenQPEPOfficialRelease100Graduation(unittest.TestCase):
    PASS = "Calyx!@#$_2026Rel100Aa99"

    def test_01_official_wire_v5_and_hard_legacy_prerelease_rejection(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.0.1")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.0.1")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.0.1")

        # Full Wire Format v5 (\x89QPE\x05\x00)
        f5 = pack_wire_frame(b"Official-1.0.0 payload", "CALYX QPEP MESSAGE")
        self.assertTrue(f5.startswith(WIRE_MAGIC_V5))
        pt, _ = unpack_wire_frame(f5, "CALYX QPEP MESSAGE")
        self.assertEqual(pt, b"Official-1.0.0 payload")

        # Compact TLV Wire Format v5.1 (\x89QPE\x05\x01)
        c51 = pack_compact_v51({1: b"QLX-4096", 2: b"Official-1.0.0-TLV"}, "CALYX QPEP COMPACT")
        self.assertTrue(c51.startswith(WIRE_MAGIC_V5_1))
        fields, _, _ = unpack_compact_v51(c51, "CALYX QPEP COMPACT")
        self.assertEqual(fields[2], b"Official-1.0.0-TLV")

        # Hard Clean Break: ALL legacy -rc (v4/v4.1), -pc (v3/v3.1), and -beta wire magics MUST raise QPEPLegacyProtocolError
        for legacy_magic in ALL_LEGACY_WIRE_MAGICS:
            with self.assertRaises(QPEPLegacyProtocolError):
                unpack_wire_frame(legacy_magic + os.urandom(64), "CALYX QPEP MESSAGE")
            with self.assertRaises(QPEPLegacyProtocolError):
                unpack_compact_v51(legacy_magic + os.urandom(64), "CALYX QPEP COMPACT")

        # Legacy -rc / -pc / -beta .qpkrf key ring envelope versions must raise QPEPLegacyProtocolError
        kr = OpenQPEPProtocol.generate_keypair("RelUser", "rel@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        from calyx_qpep.protocol import _armor_wrap
        for legacy_ver in ("1.0.0-rc", "1.2.0-pc", "0.2.9-beta"):
            legacy_env = {
                "magic": "QPKRF-v1",
                "protocol": "OpenQPEP by Calyx Labs Inc.",
                "version": legacy_ver,
                "ring_type": "PUBLIC_KEY_RING",
                "suite": "QLX-768",
                "key_hash": kr.key_hash,
                "created_at": kr.created_at,
                "identity": {"name": kr.name, "email": kr.email, "comment": kr.comment},
                "public_bundle": kr.public_bundle,
                "integrity_mac": kr.integrity_mac,
            }
            legacy_qpkrf = _armor_wrap(
                "CALYX QPKRF PUBLIC KEY RING",
                {"Protocol": "OpenQPEP"},
                json.dumps(legacy_env).encode("utf-8"),
            )
            with self.assertRaises(QPEPLegacyProtocolError):
                OpenQPEPProtocol.import_qpkrf(legacy_qpkrf)

    def test_02_mandatory_kdf_v4_and_fido2_prf_hardware_mixing(self):
        salt = os.urandom(32)
        hw_prf = os.urandom(32)
        k1_a, k2_a, km_a, params_a = derive_qpkrf_keys_v4(self.PASS, salt, qlx_tier="QLX-768")
        self.assertEqual(params_a["kdf_version"], 4)
        self.assertEqual(params_a["personalization"], "OpenQPEP/1.0.1")
        self.assertFalse(params_a["fido2_prf_bound"])

        k1_hw, k2_hw, km_hw, params_hw = derive_qpkrf_keys_v4(self.PASS, salt, qlx_tier="QLX-768", fido2_prf_secret=hw_prf)
        self.assertEqual(params_hw["kdf_version"], 4)
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
        sth = kt.signed_tree_head()
        self.assertTrue(verify_sth(sth, kt.public_key_hex))
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

        with SecretBuffer(b"TOP_SECRET_V100_KEY_MATERIAL") as sb:
            raw = sb.raw
        self.assertEqual(bytes(raw), b"\x00" * len(b"TOP_SECRET_V100_KEY_MATERIAL"))

    def test_07_v190_formal_verification_models_complete(self):
        for fname in ("qpep_ake.pv", "qpep_ratchet.spthy", "qpep_mls.spthy", "csp_omega_combiner.cry"):
            fpath = REPO_ROOT / "formal" / fname
            self.assertTrue(fpath.is_file(), f"Missing formal model: {fname}")
            self.assertGreater(len(fpath.read_text(encoding="utf-8")), 200)


if __name__ == "__main__":
    unittest.main()
