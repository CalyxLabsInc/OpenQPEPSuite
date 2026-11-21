"""
Unit tests for OpenQPEP Production Candidate 1.1.7 Deterministic KATs & Cross-Language Vectors.
"""
import json
import unittest
from pathlib import Path

from calyx_qpep.vectors import QSpongeDRBG, deterministic_urandom, verify_all_kats


class TestOpenQPEPv022KATVectors(unittest.TestCase):
    def setUp(self):
        self.vectors_dir = Path(__file__).resolve().parent.parent / "vectors"

    def test_01_qsponge_drbg_determinism_and_os_urandom_restoration(self):
        import os
        seed = b"A" * 32
        d1 = QSpongeDRBG(seed)
        d2 = QSpongeDRBG(seed)
        self.assertEqual(d1.random_bytes(64), d2.random_bytes(64))
        self.assertEqual(d1.random_bytes(32), d2.random_bytes(32))

        orig = os.urandom
        with deterministic_urandom(seed):
            b1 = os.urandom(32)
        self.assertIs(os.urandom, orig)
        with deterministic_urandom(seed):
            b2 = os.urandom(32)
        self.assertEqual(b1, b2)

    def test_02_all_five_golden_kat_files_present_with_exact_spec_ct_lengths(self):
        expected_ct = {
            "kat_qlx768_qvs65.json": (1088, 1600),
            "kat_qlx1024_qvs87.json": (1568, 2368),
            "kat_qlx2048_qvs128.json": (2976, 3904),
            "kat_qlx4096_qvs256.json": (5792, 5440),
            "kat_qlx16384_qvs1024.json": (23168, 10816),
        }
        for fname, (ct_len, sig_len) in expected_ct.items():
            p = self.vectors_dir / fname
            self.assertTrue(p.exists(), f"Missing KAT file: {fname}")
            data = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(data["qlx"]["actual_ct_qlx_bytes"], ct_len)
            self.assertEqual(data["qvs"]["actual_sig_bytes"], sig_len)
            self.assertFalse(data["wire_packet"]["cleartext_identity_headers_present"])
            self.assertEqual(data["wire_packet"]["wire_magic_hex"], "895150450300")

    def test_03_bit_exact_kat_verification_all_five_suites(self):
        ok, report = verify_all_kats(self.vectors_dir)
        self.assertTrue(ok, "\n".join(report))
        self.assertEqual(len(report), 10)


if __name__ == "__main__":
    unittest.main()
