# OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc)
"""
OpenQPEP Production Candidate 1.1.0 (v1.1.0-pc) Verification Tests:
  - Tier 7: Calyx Isogeny-Forge (CIF-SQI-512 + QHS-512) encrypt/decrypt & sign/verify
  - Tier 9: Calyx Unstructured-Citadel (CULC-2048 + CGM-8192) encrypt/decrypt, sign/verify & >=12GB RAM guardrail
  - Canonical 10-Suite Registry naming format & per-tier hardware classification
"""
import re
import unittest
from unittest.mock import patch

from calyx_qpep.constants import ALL_TEN_SUITES, PROTOCOL_VERSION, UNIVERSAL_VERSION
from calyx_qpep.exceptions import QPEPSuiteError
from calyx_qpep.isogeny.isogeny_suite import CalyxIsogenyForgeSuite
from calyx_qpep.lattice.citadel_suite import CalyxUnstructuredCitadelSuite


class TestOpenQPEPPC110All10Tiers(unittest.TestCase):
    def test_01_version_and_canonical_10_tier_naming(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.1.0-pc")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/PC-1.1.0")
        self.assertEqual(len(ALL_TEN_SUITES), 10)
        pattern = re.compile(r"^Calyx [A-Za-z -]+: [A-Za-z0-9-]+ \+ [A-Za-z0-9-]+ \(.+\)$")
        for suite_id, meta in ALL_TEN_SUITES.items():
            self.assertRegex(meta["display_name"], pattern, f"Suite {suite_id} violates canonical format: {meta['display_name']}")
        high_tier = {k for k, v in ALL_TEN_SUITES.items() if v["high_tier_only"]}
        self.assertEqual(high_tier, {"QLX-16384", "CGM-8192", "CULC-2048", "CSP-Omega"})

    def test_02_tier7_calyx_isogeny_forge_roundtrip_and_signature(self):
        pub, priv = CalyxIsogenyForgeSuite.keygen()
        msg = b"Tier 7 Calyx Isogeny-Forge CIF-SQI-512 + QHS-512 v1.1.0-pc payload"
        ct = CalyxIsogenyForgeSuite.encrypt(msg, pub)
        self.assertEqual(CalyxIsogenyForgeSuite.decrypt(ct, priv), msg)
        sig = CalyxIsogenyForgeSuite.sign(msg, priv)
        ok, extracted = CalyxIsogenyForgeSuite.verify(sig, pub)
        self.assertTrue(ok)
        self.assertEqual(extracted, msg)

    def test_03_tier9_calyx_unstructured_citadel_roundtrip_and_ram_guardrail(self):
        with patch("calyx_qpep.lattice.citadel_suite.detect_system_ram_mib", return_value=4096):
            with self.assertRaises(QPEPSuiteError):
                CalyxUnstructuredCitadelSuite.keygen()
        pub, priv = CalyxUnstructuredCitadelSuite.keygen(allow_low_ram_override=True)
        msg = b"Tier 9 Calyx Unstructured-Citadel CULC-2048 + CGM-8192 v1.1.0-pc payload"
        ct = CalyxUnstructuredCitadelSuite.encrypt(msg, pub)
        self.assertEqual(CalyxUnstructuredCitadelSuite.decrypt(ct, priv), msg)
        sig = CalyxUnstructuredCitadelSuite.sign(msg, priv)
        ok, extracted = CalyxUnstructuredCitadelSuite.verify(sig, pub)
        self.assertTrue(ok)
        self.assertEqual(extracted, msg)


if __name__ == "__main__":
    unittest.main()
