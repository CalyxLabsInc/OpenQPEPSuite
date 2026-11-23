"""
Unit tests for OpenQPEP Official Release 1.1.0:
  1. End-to-End Beyond-LWE native .qpkrf v3 keygen, public/private armor round-trip,
     and encrypt/decrypt/sign/verify parity for all 5 Beyond-LWE suites.
  2. All 10 canonical deterministic KAT vectors verified bit-for-bit.
  3. CLI Polish: Switch Suite, Benchmark All 10, Inspect Packet & colored hardware-tier badges.
"""
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from calyx_qpep.beyond_lwe_bridge import BEYOND_LWE_SUITES
from calyx_qpep.cli import cmd_inspect_packet, _hw_badge
from calyx_qpep.protocol import OpenQPEPProtocol
from calyx_qpep.vectors import verify_all_kats


class TestOpenQPEPv117PCBeyondLWEAnd10KATs(unittest.TestCase):
    PASS = "Calyx!@#$_2026Aa99"

    def test_01_all_5_beyond_lwe_suites_native_qpkrf_and_crypto_parity(self):
        msg = b"OpenQPEP v1.1.0 End-to-End Beyond-LWE .qpkrf Parity Test"
        for suite_id in BEYOND_LWE_SUITES:
            kr = OpenQPEPProtocol.generate_keypair(
                f"Test {suite_id}",
                f"{suite_id.lower()}@calyxmail.org",
                self.PASS,
                qlx_tier=suite_id,
            )
            self.assertEqual(OpenQPEPProtocol.get_keyring_suite_id(kr), suite_id)
            pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
            priv_armor = OpenQPEPProtocol.export_qpkrf(kr, passphrase=self.PASS, include_private=True)

            pub_kr = OpenQPEPProtocol.import_qpkrf(pub_armor)
            priv_kr = OpenQPEPProtocol.import_qpkrf(priv_armor, passphrase=self.PASS)
            self.assertEqual(OpenQPEPProtocol.get_keyring_suite_id(pub_kr), suite_id)
            self.assertEqual(OpenQPEPProtocol.get_keyring_suite_id(priv_kr), suite_id)

            ct = OpenQPEPProtocol.encrypt_beyond_lwe_packet(msg, pub_kr)
            pt = OpenQPEPProtocol.decrypt_beyond_lwe_packet(ct, priv_kr, self.PASS)
            self.assertEqual(pt, msg, f"Decrypt failed for {suite_id}")

            sig = OpenQPEPProtocol.sign_beyond_lwe_bytes(msg, priv_kr, self.PASS)
            ok, vmsg = OpenQPEPProtocol.verify_beyond_lwe_signature(sig, pub_kr)
            self.assertTrue(ok, f"Signature verify failed for {suite_id}")
            self.assertEqual(vmsg, msg)

    def test_02_all_10_deterministic_kats_verified_bit_for_bit(self):
        vdir = Path(__file__).resolve().parent.parent / "vectors"
        manifest = json.loads((vdir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["suite_count"], 10)
        for expected_fn in [
            "kat_cif_sqi512.json",
            "kat_crt_rsd512.json",
            "kat_cgm8192.json",
            "kat_culc2048.json",
            "kat_csp_omega.json",
        ]:
            self.assertTrue((vdir / expected_fn).is_file(), f"Missing Beyond-LWE KAT: {expected_fn}")
        ok, report = verify_all_kats(vdir)
        self.assertTrue(ok, "\n".join(report))
        self.assertEqual(len(report), 10)

    def test_03_cli_badges_and_inspect_packet(self):
        self.assertIn("ALL DEVICES", _hw_badge("QLX-4096"))
        self.assertIn("HIGH-TIER", _hw_badge("CSP-Omega"))
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_inspect_packet("-----BEGIN CALYX QPKRF PUBLIC KEY RING-----\nQUFBQQ==\n-----END CALYX QPKRF PUBLIC KEY RING-----")
        out = buf.getvalue()
        self.assertIn("Wire Format:", out)
        self.assertIn("Decoded Size:", out)


if __name__ == "__main__":
    unittest.main()
