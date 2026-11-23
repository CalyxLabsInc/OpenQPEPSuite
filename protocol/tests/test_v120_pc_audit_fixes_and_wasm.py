"""
Unit tests for OpenQPEP Official Release 1.1.0:
  - AUD-06: Automatic Beyond-LWE dispatch in OpenQPEPProtocol.encrypt_text/decrypt_text/sign_text/verify_text_signature
  - AUD-08: Zero broad `except Exception:` blocks in cli.py, hardware_tuner.py, zeroize.py, deniable_vault.py
  - WASM SIMD128 binary integrity & Web Worker presence
"""
import unittest
from pathlib import Path

from calyx_qpep.beyond_lwe_bridge import BEYOND_LWE_SUITES
from calyx_qpep.protocol import OpenQPEPProtocol


class TestOpenQPEPv120PCAuditAndWasm(unittest.TestCase):
    PASS = "Calyx!@#$_2026Aa99"

    def test_01_auto_dispatch_beyond_lwe_via_standard_protocol_api(self):
        for suite_id in BEYOND_LWE_SUITES:
            kr = OpenQPEPProtocol.generate_keypair(f"Auto {suite_id}", "auto@calyxmail.org", self.PASS, qlx_tier=suite_id)
            ct = OpenQPEPProtocol.encrypt_text("Auto-dispatch test v1.1.0", recipient_keyring=kr, encrypting_keyring=kr, passphrase=self.PASS)
            pt_b, meta = OpenQPEPProtocol.decrypt_packet(ct, kr, self.PASS)
            self.assertEqual(pt_b.decode("utf-8"), "Auto-dispatch test v1.1.0")
            self.assertEqual(meta.get("suite_id"), suite_id)

            sig = OpenQPEPProtocol.sign_text("Auto-sign v1.1.0", kr, self.PASS)
            ok, vtxt, matched_kr = OpenQPEPProtocol.verify_text_signature(sig, kr)
            self.assertTrue(ok)
            self.assertEqual(vtxt, "Auto-sign v1.1.0")
            self.assertEqual(OpenQPEPProtocol.get_keyring_suite_id(matched_kr), suite_id)

    def test_02_wasm_binary_and_worker_present(self):
        base = Path(__file__).resolve().parent.parent / "calyx_qpep/native/wasm"
        wb = (base / "openqpep_wasm.wasm").read_bytes()
        self.assertTrue(wb.startswith(b"\x00asm\x01\x00\x00\x00"))
        self.assertTrue((base / "qpep_worker.js").is_file())

    def test_03_zero_broad_except_exception_in_audited_modules(self):
        root = Path(__file__).resolve().parent.parent
        for rel in [
            "calyx_qpep/cli.py",
            "calyx_qpep/kdf/hardware_tuner.py",
            "calyx_qpep/primitives/zeroize.py",
            "calyx_qpep/privacy/deniable_vault.py",
        ]:
            src = (root / rel).read_text(encoding="utf-8")
            self.assertNotIn("except Exception:", src, f"Broad except Exception remains in {rel}")


if __name__ == "__main__":
    unittest.main()
