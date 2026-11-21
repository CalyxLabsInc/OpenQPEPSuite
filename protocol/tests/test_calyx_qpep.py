import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from calyx_qpep import (
    OpenQPEPProtocol,
    CalyxQPEPProtocol,
    QPEPPassphrasePolicyError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
)
from calyx_qpep.cli import interactive_shell


class TestOpenQPEPProtocol(unittest.TestCase):
    def setUp(self):
        self.valid_pass_1 = "Calyx!@#$_26Qp"
        self.valid_pass_2 = "Tristen$%^&99Az"

    def test_universal_version_0_1_6(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.0.0-pc")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Production Candidate 1.0.0")

    def test_hardcoded_passphrase_policy(self):
        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.generate_keypair("User", "u@calyxlabsinc.org", "")
        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.generate_keypair("User", "u@calyxlabsinc.org", "Short1!aA")
        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.generate_keypair("User", "u@calyxlabsinc.org", "NoSpecials1234ABCDabcd")

    def test_key_hash_and_public_vs_private_qpkrf_rules(self):
        kr = OpenQPEPProtocol.generate_keypair("Alice", "alice@calyxlabsinc.org", self.valid_pass_1)
        self.assertEqual(len(kr.key_hash), 64)

        pub_str = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
        self.assertIn("Key-Hash:", pub_str)
        self.assertIn("OpenQPEP by Calyx Labs Inc.", pub_str)
        self.assertIn("Production Candidate 1.0.0", pub_str)
        imported_pub = OpenQPEPProtocol.import_qpkrf(pub_str)
        self.assertFalse(imported_pub.has_private_key)
        self.assertEqual(imported_pub.key_hash, kr.key_hash)

        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.export_qpkrf(kr, include_private=True)

        priv_str = OpenQPEPProtocol.export_qpkrf(kr, passphrase=self.valid_pass_1, include_private=True)
        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.import_qpkrf(priv_str)

        imported_priv = OpenQPEPProtocol.import_qpkrf(priv_str, passphrase=self.valid_pass_1)
        self.assertTrue(imported_priv.has_private_key)

    def test_dual_key_encrypt_decrypt_and_attached_signature_verify(self):
        sender_kr = OpenQPEPProtocol.generate_keypair("Sender", "sender@calyxlabsinc.org", self.valid_pass_1)
        recip_kr = OpenQPEPProtocol.generate_keypair("Recip", "recip@calyxlabsinc.org", self.valid_pass_2)

        recip_pub = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(recip_kr, include_private=False))
        sender_pub = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(sender_kr, include_private=False))

        pkt = OpenQPEPProtocol.encrypt_text(
            "Classified OpenQPEP Payload",
            recipient_keyring=recip_pub,
            encrypting_keyring=sender_kr,
            passphrase=self.valid_pass_1,
        )
        pt_bytes, meta = OpenQPEPProtocol.decrypt_packet(
            pkt,
            recipient_private_keyring=recip_kr,
            passphrase=self.valid_pass_2,
            sender_public_keyring=sender_pub,
        )
        self.assertEqual(pt_bytes.decode("utf-8"), "Classified OpenQPEP Payload")
        self.assertEqual(meta["encrypting_key_hash"], sender_kr.key_hash)
        self.assertTrue(meta["signature_verified"])

        sig = OpenQPEPProtocol.sign_text("Signed Announcement", sender_kr, self.valid_pass_1)
        self.assertIn("CALYX QPEP ATTACHED SIGNATURE", sig)

        ok, extracted_msg, matched_kr = OpenQPEPProtocol.verify_text_signature(sig, keyring_pool=[recip_pub, sender_pub])
        self.assertTrue(ok)
        self.assertEqual(extracted_msg, "Signed Announcement")
        self.assertEqual(matched_kr.key_hash, sender_kr.key_hash)

    def test_interactive_english_cli_create_and_export_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ks_path = Path(tmpdir) / "keyring.json"
            pub_export_path = Path(tmpdir) / "Tristen_public.qpkrf"
            priv_export_path = Path(tmpdir) / "Tristen_private.qpkrf"
            simulated_inputs = "\n".join(
                [
                    "Create Key",
                    "1",
                    "Tristen",
                    "tristen@calyxlabsinc.org",
                    "OpenQPEP Lead Architect",
                    self.valid_pass_1,
                    self.valid_pass_1,
                    "no",
                    "List Keys",
                    "Export Public Tristen",
                    str(pub_export_path),
                    "Export Private Tristen",
                    self.valid_pass_1,
                    str(priv_export_path),
                    "Exit",
                ]
            ) + "\n"
            with patch("sys.stdin", io.StringIO(simulated_inputs)), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = interactive_shell(ks_path)
                output = mock_out.getvalue()
            self.assertEqual(rc, 0)
            self.assertIn("Specify Key Type:", output)
            self.assertIn("Successfully generated OpenQPEP Key Pair!", output)
            self.assertTrue(pub_export_path.exists())
            self.assertTrue(priv_export_path.exists())



    def test_08_multi_extension_binary_file_encryption_roundtrip(self):
        """Verifies binary .jpg, .png, .pdf, and .zip encryption & decryption preserve exact bytes and extension."""
        import tempfile
        from calyx_qpep.protocol import SUPPORTED_FILE_EXTENSIONS
        self.assertGreaterEqual(len(SUPPORTED_FILE_EXTENSIONS), 150)

        samples = {
            "test_photo.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C" + os.urandom(2048) + b"\xff\xd9",
            "diagram.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + os.urandom(1024),
            "contract.pdf": b"%PDF-1.7\n" + os.urandom(1024) + b"\n%%EOF",
            "bundle.zip": b"PK\x03\x04" + os.urandom(1024),
        }
        alice = OpenQPEPProtocol.generate_keypair("Alice", "alice@calyxlabsinc.org", self.valid_pass_1)
        bob = OpenQPEPProtocol.generate_keypair("Bob", "bob@calyxlabsinc.org", self.valid_pass_2)
        alice_pub = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(alice, include_private=False))
        bob_pub = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(bob, include_private=False))
        with tempfile.TemporaryDirectory() as tmpd:
            tmp_dir = Path(tmpd)
            for fname, raw_bytes in samples.items():
                src_file = tmp_dir / fname
                src_file.write_bytes(raw_bytes)
                _, qpep_path = CalyxQPEPProtocol.encrypt_file(
                    src_file,
                    recipient_keyring=bob_pub,
                    encrypting_keyring=alice,
                    passphrase=self.valid_pass_1,
                )
                out_dir = tmp_dir / "out"
                out_dir.mkdir(exist_ok=True)
                dec_bytes, dec_path, meta = CalyxQPEPProtocol.decrypt_file(
                    qpep_path,
                    recipient_private_keyring=bob,
                    passphrase=self.valid_pass_2,
                    output_path_or_dir=out_dir,
                    sender_public_keyring=alice_pub,
                )
                self.assertEqual(dec_bytes, raw_bytes)
                self.assertEqual(dec_path.name, fname)
                self.assertEqual(dec_path.suffix.lower(), "." + fname.rsplit(".", 1)[-1])
                self.assertTrue(meta["signature_verified"])



    def test_09_signature_qlx_4096_qvs_256_quantum_immunity_and_roundtrip(self):
        """Verifies the new default Signature QLX-4096 + QVS-256 tier, sizes, roundtrip, and threat matrix."""
        from calyx_qpep.protocol import QUANTUM_IMMUNITY_MATRIX
        from calyx_qpep.qlx_lattice import QLX_TIERS, QVS_TIERS, QVSEngine

        self.assertEqual(len(QUANTUM_IMMUNITY_MATRIX), 6)
        self.assertIn("QLX-4096", QLX_TIERS)
        self.assertIn("QVS-256", QVS_TIERS)
        self.assertEqual(QLX_TIERS["QLX-4096"]["pk_bytes"], 6176)
        self.assertEqual(QLX_TIERS["QLX-4096"]["sk_bytes"], 12384)
        self.assertEqual(QLX_TIERS["QLX-4096"]["ct_bytes"], 5792)
        self.assertEqual(QVS_TIERS["QVS-256"]["pk_bytes"], 6176)
        self.assertEqual(QVS_TIERS["QVS-256"]["sk_bytes"], 10112)
        self.assertEqual(QVS_TIERS["QVS-256"]["sig_bytes"], 5440)

        # Default generate_keypair must create a QLX-4096 + QVS-256 keypair
        apex_sender = OpenQPEPProtocol.generate_keypair("ApexSender", "apex@calyxlabsinc.org", self.valid_pass_1)
        apex_recip = OpenQPEPProtocol.generate_keypair("ApexRecip", "recip4096@calyxlabsinc.org", self.valid_pass_2)
        self.assertEqual(apex_sender.qlx_tier, "QLX-4096")
        self.assertEqual(apex_sender.qvs_tier, "QVS-256")
        self.assertTrue(OpenQPEPProtocol.verify_public_keyring_self_signature(apex_sender))

        pkt = OpenQPEPProtocol.encrypt_text(
            "QLX-4096 + QVS-256 Post-Quantum Sovereign Payload",
            recipient_keyring=apex_recip,
            encrypting_keyring=apex_sender,
            passphrase=self.valid_pass_1,
        )
        pt, meta = OpenQPEPProtocol.decrypt_packet(
            pkt,
            recipient_private_keyring=apex_recip,
            passphrase=self.valid_pass_2,
            sender_public_keyring=apex_sender,
        )
        self.assertEqual(pt.decode("utf-8"), "QLX-4096 + QVS-256 Post-Quantum Sovereign Payload")
        self.assertTrue(meta["signature_verified"])
        self.assertEqual(meta["qlx_tier"], "QLX-4096")
        self.assertEqual(meta["qvs_tier"], "QVS-256")

        sig_text = OpenQPEPProtocol.sign_text("QLX-4096 Signed Directive", apex_sender, self.valid_pass_1)
        ok, msg, matched = OpenQPEPProtocol.verify_text_signature(sig_text, keyring_pool=[apex_sender])
        self.assertTrue(ok)
        self.assertEqual(msg, "QLX-4096 Signed Directive")
        self.assertEqual(matched.key_hash, apex_sender.key_hash)



    def test_10_calyx_hyper_tesseract_qlx_16384_qvs_1024_roundtrip(self):
        """Verifies the new Calyx Hyper-Tesseract (QLX-16384 + QVS-1024) 16,384-Dim tier, sizes, and roundtrip."""
        from calyx_qpep.qlx_lattice import QLX_TIERS, QVS_TIERS
        from calyx_qpep.protocol import CALYX_HYPER_TESSERACT_HARDWARE_WARNING

        self.assertIn("HIGH-TIER HARDWARE REQUIRED", CALYX_HYPER_TESSERACT_HARDWARE_WARNING)
        self.assertIn("QLX-16384", QLX_TIERS)
        self.assertIn("QVS-1024", QVS_TIERS)
        self.assertEqual(QLX_TIERS["QLX-16384"]["pk_bytes"], 24608)
        self.assertEqual(QLX_TIERS["QLX-16384"]["sk_bytes"], 49248)
        self.assertEqual(QLX_TIERS["QLX-16384"]["ct_bytes"], 23168)
        self.assertEqual(QVS_TIERS["QVS-1024"]["pk_bytes"], 12320)
        self.assertEqual(QVS_TIERS["QVS-1024"]["sk_bytes"], 20096)
        self.assertEqual(QVS_TIERS["QVS-1024"]["sig_bytes"], 10816)

        tess_sender = OpenQPEPProtocol.generate_keypair(
            "TesseractSender", "tesseract@calyxlabsinc.org", self.valid_pass_1, qlx_tier="QLX-16384"
        )
        tess_recip = OpenQPEPProtocol.generate_keypair(
            "TesseractRecip", "recip16384@calyxlabsinc.org", self.valid_pass_2, qlx_tier="QLX-16384"
        )
        self.assertEqual(tess_sender.qlx_tier, "QLX-16384")
        self.assertEqual(tess_sender.qvs_tier, "QVS-1024")
        self.assertTrue(OpenQPEPProtocol.verify_public_keyring_self_signature(tess_sender))

        pkt = OpenQPEPProtocol.encrypt_text(
            "Calyx Hyper-Tesseract 16,384-Dim Flagship Hardware Payload",
            recipient_keyring=tess_recip,
            encrypting_keyring=tess_sender,
            passphrase=self.valid_pass_1,
        )
        pt, meta = OpenQPEPProtocol.decrypt_packet(
            pkt,
            recipient_private_keyring=tess_recip,
            passphrase=self.valid_pass_2,
            sender_public_keyring=tess_sender,
        )
        self.assertEqual(pt.decode("utf-8"), "Calyx Hyper-Tesseract 16,384-Dim Flagship Hardware Payload")
        self.assertTrue(meta["signature_verified"])
        self.assertEqual(meta["qlx_tier"], "QLX-16384")
        self.assertEqual(meta["qvs_tier"], "QVS-1024")



    def test_11_v020_zero_cleartext_armor_headers(self):
        """Verifies PC 1.0.0 omits cleartext Recipient-Key-Hash and Signer-Key-Hash armor headers."""
        sender = OpenQPEPProtocol.generate_keypair("Alice", "alice@calyxlabsinc.org", self.valid_pass_1)
        recip = OpenQPEPProtocol.generate_keypair("Bob", "bob@calyxlabsinc.org", self.valid_pass_2)
        recip_pub = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(recip, include_private=False))
        enc = OpenQPEPProtocol.encrypt_text("Zero metadata armor test", recipient_keyring=recip_pub, encrypting_keyring=sender, passphrase=self.valid_pass_1)
        self.assertNotIn("Recipient-Key-Hash:", enc)
        self.assertNotIn("Sender-Key-Hash:", enc)
        self.assertNotIn("Signer-Key-Hash:", enc)
        pt_bytes, _meta = OpenQPEPProtocol.decrypt_packet(enc, recip, self.valid_pass_2)
        self.assertEqual(pt_bytes.decode("utf-8"), "Zero metadata armor test")
        sig = OpenQPEPProtocol.sign_text("Zero metadata sig test", sender, self.valid_pass_1)
        self.assertNotIn("Signer-Key-Hash:", sig)
        ok, extracted_msg, _matched = OpenQPEPProtocol.verify_text_signature(sig, keyring_pool=[sender])
        self.assertTrue(ok)
        self.assertEqual(extracted_msg, "Zero metadata sig test")

if __name__ == "__main__":
    unittest.main()
