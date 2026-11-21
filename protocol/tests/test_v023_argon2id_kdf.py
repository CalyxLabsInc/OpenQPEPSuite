"""
Unit tests for OpenQPEP Release Candidate 1.0.0 Memory-Hard QPKD-Argon2id KDF & Hardware Auto-Tuner.
"""
import copy
import json
import unittest

from calyx_qpep import OpenQPEPProtocol
from calyx_qpep.kdf import (
    select_kdf_profile,
    benchmark_kdf,
        get_active_kdf_backend,
)
from calyx_qpep.protocol import _b64d, _b64e, _cc512_encrypt, qsponge_512


class TestOpenQPEPv023Argon2idKDF(unittest.TestCase):
    def setUp(self):
        self.pw = "Calyx!@#$_2026KdfAa99"

    def test_01_hardware_auto_tuner_profiles(self):
        std = select_kdf_profile("QLX-4096", override_ram_mib=8192)
        self.assertEqual(std.m_kib, 65536)
        self.assertEqual(std.t_cost, 3)

        tess = select_kdf_profile("QLX-16384", override_ram_mib=16384)
        self.assertEqual(tess.m_kib, 262144)
        self.assertEqual(tess.t_cost, 4)

        low = select_kdf_profile("QLX-768", override_ram_mib=1024)
        self.assertEqual(low.m_kib, 32768)
        self.assertEqual(low.p_lanes, min(2, low.detected_cpus))

    def test_02_kdf_v2_envelope_embedded_in_new_qpkrf_keyrings(self):
        kr = OpenQPEPProtocol.generate_keypair("KDFv3User", "kdf@calyxlabsinc.org", self.pw, qlx_tier="QLX-768")
        priv = kr.encrypted_private_bundle
        self.assertEqual(priv["kdf_version"], 3)
        self.assertEqual(priv["kdf_params"]["algorithm"], "QPKD-Argon2id+qSponge-512")
        self.assertEqual(priv["kdf_params"]["personalization"], "OpenQPEP/RC-1.0.0")
        self.assertEqual(priv["kdf_params"]["m_kib"], 65536)
        self.assertEqual(len(_b64d(priv["kdf_salt_b64"])), 32)

        pub = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(kr, include_private=False))
        pkt = OpenQPEPProtocol.encrypt_text("Argon2id v3 protected payload", pub, kr, self.pw)
        pt, _ = OpenQPEPProtocol.decrypt_packet(pkt, kr, self.pw)
        self.assertEqual(pt.decode("utf-8"), "Argon2id v3 protected payload")

    def test_03_strict_rejection_of_legacy_beta_kdf_v1(self):
        from calyx_qpep.exceptions import QPEPLegacyProtocolError
        pw = "Calyx!@#$_2026StrictKdfAa99"
        kr = OpenQPEPProtocol.generate_keypair("StrictKDF", "kdf@calyxlabsinc.org", pw, qlx_tier="QLX-768")
        for legacy_ver in (1, 2):
            kr.encrypted_private_bundle["kdf_version"] = legacy_ver
            kr.encrypted_private_bundle["kdf_params"] = {"kdf_version": legacy_ver}
            with self.assertRaises(QPEPLegacyProtocolError):
                OpenQPEPProtocol.unlock_private_keys(kr, pw)

    def test_04_wrong_passphrase_rejected(self):
        kr = OpenQPEPProtocol.generate_keypair("WrongPw", "wp@calyxlabsinc.org", self.pw, qlx_tier="QLX-768")
        with self.assertRaises(ValueError):
            OpenQPEPProtocol.unlock_private_keys(kr, "Wrong!@#$_2026PassBb88")

    def test_05_kdf_benchmark_helper(self):
        res = benchmark_kdf("QLX-768")
        self.assertEqual(res["m_kib"], 65536)
        self.assertGreaterEqual(res["elapsed_ms"], 0.0)
        self.assertEqual(res["backend"], get_active_kdf_backend())


if __name__ == "__main__":
    unittest.main()
