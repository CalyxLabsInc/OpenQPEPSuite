"""
Unit tests for OpenQPEP Release Candidate 1.0.0 Anonymous Mixed-Tier Multi-Recipient Encryption
& Traffic-Analysis Padding (calyx_qpep/wire/).
"""
import unittest

from calyx_qpep import OpenQPEPProtocol, QPEPMacVerificationError
from calyx_qpep.wire import (
    MULTI_RECIPIENT_ARMOR_LABEL,
    armor_unwrap,
    pad_to_bucket,
    unpad_from_bucket,
)


class TestOpenQPEPv024MultiRecipient(unittest.TestCase):
    def setUp(self):
        self.pw_a = "Calyx!@#$_2026RecipAa11"
        self.pw_b = "Calyx!@#$_2026RecipBb22"
        self.pw_c = "Calyx!@#$_2026RecipCc33"
        self.pw_x = "Calyx!@#$_2026OutsdXx99"

    def test_01_bucket_payload_padding_4k_16k_64k(self):
        for bucket in (4096, 16384, 65536):
            msg = b"Traffic-analysis resistant OpenQPEP payload"
            padded = pad_to_bucket(msg, bucket_size=bucket)
            self.assertEqual(len(padded), bucket)
            self.assertEqual(unpad_from_bucket(padded), msg)

    def test_02_mixed_tier_multi_recipient_roundtrip_and_dummy_slot_padding(self):
        # Mix 3 different OpenQPEP suites in ONE broadcast packet: QLX-768 + QLX-1024 + QLX-4096
        kr_a = OpenQPEPProtocol.generate_keypair("RecipA", "a@calyxlabsinc.org", self.pw_a, qlx_tier="QLX-768")
        kr_b = OpenQPEPProtocol.generate_keypair("RecipB", "b@calyxlabsinc.org", self.pw_b, qlx_tier="QLX-1024")
        kr_c = OpenQPEPProtocol.generate_keypair("RecipC", "c@calyxlabsinc.org", self.pw_c, qlx_tier="QLX-4096")
        kr_outsider = OpenQPEPProtocol.generate_keypair("Outsider", "x@calyxlabsinc.org", self.pw_x, qlx_tier="QLX-768")

        pubs = [
            OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(k, include_private=False))
            for k in (kr_a, kr_b, kr_c)
        ]
        secret_msg = b"Classified OpenQPEP v1.0.0 Mixed-Tier Broadcast Directive"
        pkt = OpenQPEPProtocol.encrypt_multi_recipient(
            secret_msg, pubs, bucket_size=4096, pad_slots_power_of_2=True, min_slots=8, use_blind_hint=True
        )

        # Zero recipient key hashes in armor OR unwrapped inner JSON!
        for k in (kr_a, kr_b, kr_c):
            self.assertNotIn(k.key_hash, pkt)
        raw_inner, _ = armor_unwrap(pkt, MULTI_RECIPIENT_ARMOR_LABEL)
        for k in (kr_a, kr_b, kr_c):
            self.assertNotIn(k.key_hash.encode("ascii"), raw_inner)

        # All 3 mixed-tier recipients decrypt cleanly and see 8 padded slots
        for kr, pw in ((kr_a, self.pw_a), (kr_b, self.pw_b), (kr_c, self.pw_c)):
            pt, meta = OpenQPEPProtocol.decrypt_multi_recipient(pkt, kr, pw)
            self.assertEqual(pt, secret_msg)
            self.assertEqual(meta["slot_count"], 8)
            self.assertTrue(meta["bucket_padded"])
            self.assertEqual(meta["bucket_size"], 4096)

        # Unauthorized outsider cannot decrypt
        with self.assertRaises(QPEPMacVerificationError):
            OpenQPEPProtocol.decrypt_multi_recipient(pkt, kr_outsider, self.pw_x)

    def test_03_pure_trial_decapsulation_without_blind_hints(self):
        kr_a = OpenQPEPProtocol.generate_keypair("TrialA", "ta@calyxlabsinc.org", self.pw_a, qlx_tier="QLX-768")
        kr_b = OpenQPEPProtocol.generate_keypair("TrialB", "tb@calyxlabsinc.org", self.pw_b, qlx_tier="QLX-768")
        pkt = OpenQPEPProtocol.encrypt_multi_recipient(
            b"Zero-hint pure trial decapsulation test",
            [kr_a, kr_b],
            bucket_size=4096,
            pad_slots_power_of_2=True,
            min_slots=4,
            use_blind_hint=False,
        )
        pt_a, meta_a = OpenQPEPProtocol.decrypt_multi_recipient(pkt, kr_a, self.pw_a)
        pt_b, meta_b = OpenQPEPProtocol.decrypt_multi_recipient(pkt, kr_b, self.pw_b)
        self.assertEqual(pt_a, b"Zero-hint pure trial decapsulation test")
        self.assertEqual(pt_b, b"Zero-hint pure trial decapsulation test")
        self.assertFalse(meta_a["blind_hint_enabled"])
        self.assertEqual(meta_b["slot_count"], 4)

    def test_04_mixed_tier_with_hyper_tesseract_recipient(self):
        kr_std = OpenQPEPProtocol.generate_keypair("StdRecip", "std@calyxlabsinc.org", self.pw_a, qlx_tier="QLX-768")
        kr_tess = OpenQPEPProtocol.generate_keypair("TessRecip", "tess@calyxlabsinc.org", self.pw_b, qlx_tier="QLX-16384")
        pkt = OpenQPEPProtocol.encrypt_multi_recipient(
            b"Hyper-Tesseract + Velocity mixed broadcast",
            [kr_std, kr_tess],
            bucket_size=16384,
            pad_slots_power_of_2=False,
        )
        pt1, _ = OpenQPEPProtocol.decrypt_multi_recipient(pkt, kr_std, self.pw_a)
        pt2, m2 = OpenQPEPProtocol.decrypt_multi_recipient(pkt, kr_tess, self.pw_b)
        self.assertEqual(pt1, b"Hyper-Tesseract + Velocity mixed broadcast")
        self.assertEqual(pt2, b"Hyper-Tesseract + Velocity mixed broadcast")
        self.assertEqual(m2["recipient_tier"], "QLX-16384")


if __name__ == "__main__":
    unittest.main()
