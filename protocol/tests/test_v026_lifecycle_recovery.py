"""
Unit tests for OpenQPEP Production Candidate 1.1.4 Cryptographic Key Lifecycle & Shamir Recovery:
  - Master Identity Key + rotatable operational Encryption & Signing subkeys + UTC expiration
  - Self-authenticating .qrev Revocation Certificates (KEY_COMPROMISED / SUPERSEDED / RETIRED)
  - Verifiable t-of-n Shamir Secret Sharing over GF(256) (.qshare) + tampered shard MAC rejection
"""
import datetime
import json
import unittest

from calyx_qpep import OpenQPEPProtocol, QPEPMacVerificationError, QPEPWireFormatError
from calyx_qpep.keyring import (
    create_revocation_certificate,
    issue_subkey,
    verify_revocation_certificate,
    verify_subkey,
)
from calyx_qpep.recovery import (
    QSHARE_ARMOR_LABEL,
    create_recovery_shards,
    reconstruct_secret,
    recover_secret_from_shards,
    split_secret,
)
from calyx_qpep.wire import armor_unwrap, armor_wrap


class TestOpenQPEPv026LifecycleAndRecovery(unittest.TestCase):
    def setUp(self):
        self.pw = "Calyx!@#$_2026MasterAa99"
        self.master = OpenQPEPProtocol.generate_keypair("MasterID", "m@calyxlabsinc.org", self.pw, qlx_tier="QLX-768")
        self.master_pub = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(self.master, include_private=False))

    def test_01_rotatable_encryption_and_signing_subkeys_with_utc_expiration(self):
        enc_sub = issue_subkey(self.master, self.pw, role="encryption", validity_days=30, qlx_tier="QLX-768")
        sig_sub = issue_subkey(self.master, self.pw, role="signing", validity_days=60)

        self.assertEqual(enc_sub.master_key_hash, self.master.key_hash)
        self.assertEqual(sig_sub.master_key_hash, self.master.key_hash)
        self.assertNotEqual(enc_sub.subkey_id, sig_sub.subkey_id)

        ok1, _ = verify_subkey(enc_sub, self.master_pub)
        ok2, _ = verify_subkey(sig_sub, self.master_pub)
        self.assertTrue(ok1)
        self.assertTrue(ok2)

        # Past expiration date must fail verification
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=45)
        ok_exp, msg_exp = verify_subkey(enc_sub, self.master_pub, now_utc=future)
        self.assertFalse(ok_exp)
        self.assertIn("expired", msg_exp.lower())

    def test_02_revocation_certificates_all_reason_codes(self):
        for reason in ("KEY_COMPROMISED", "KEY_SUPERSEDED", "KEY_RETIRED"):
            qrev = create_revocation_certificate(self.master, self.pw, reason=reason, comment=f"Testing {reason}")
            ok, body = verify_revocation_certificate(qrev, self.master_pub)
            self.assertTrue(ok)
            self.assertEqual(body["reason"], reason)
            self.assertEqual(body["key_hash"], self.master.key_hash)

        # Wrong master public key must reject the revocation certificate
        other = OpenQPEPProtocol.generate_keypair("Other", "o@calyxlabsinc.org", self.pw, qlx_tier="QLX-768")
        qrev = create_revocation_certificate(self.master, self.pw, reason="KEY_COMPROMISED")
        ok_other, _ = verify_revocation_certificate(qrev, other)
        self.assertFalse(ok_other)

    def test_03_gf256_shamir_split_and_reconstruct_any_subset(self):
        secret = b"OpenQPEP-Master-Seed-256-Bit-Recovery-Secret-2026!!"
        shares = split_secret(secret, threshold=3, total_shares=5)
        self.assertEqual(len(shares), 5)
        # Reconstruct from 3 different subsets of size 3
        self.assertEqual(reconstruct_secret([shares[0], shares[2], shares[4]]), secret)
        self.assertEqual(reconstruct_secret([shares[1], shares[3], shares[4]]), secret)
        self.assertEqual(reconstruct_secret([shares[0], shares[1], shares[2]]), secret)
        # 2 shares (t-1) cannot reconstruct the secret
        self.assertNotEqual(reconstruct_secret([shares[0], shares[1]]), secret)

    def test_04_verifiable_qshare_shards_and_tamper_detection(self):
        master_seed = b"CalyxLabs-Master-Recovery-Seed-0123456789ABCDEF"
        shards = create_recovery_shards(master_seed, threshold=3, total_shares=5, key_hash=self.master.key_hash)
        self.assertEqual(len(shards), 5)

        recovered, meta = recover_secret_from_shards([shards[0], shards[2], shards[4]])
        self.assertEqual(recovered, master_seed)
        self.assertEqual(meta["threshold"], 3)
        self.assertEqual(meta["key_hash"], self.master.key_hash)

        # Fewer than threshold shards must raise QPEPWireFormatError
        with self.assertRaises(QPEPWireFormatError):
            recover_secret_from_shards([shards[0], shards[1]])

        # Tampering with a shard's share_b64 must fail qSponge-512 commitment MAC check
        raw_j, _ = armor_unwrap(shards[1], QSHARE_ARMOR_LABEL)
        obj = json.loads(raw_j.decode("utf-8"))
        obj["share_b64"] = "AAAA" + obj["share_b64"][4:]
        tampered_shard = armor_wrap(QSHARE_ARMOR_LABEL, json.dumps(obj, separators=(",", ":")).encode("utf-8"))
        with self.assertRaises(QPEPMacVerificationError):
            recover_secret_from_shards([shards[0], tampered_shard, shards[2]])


if __name__ == "__main__":
    unittest.main()
