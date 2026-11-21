"""
Unit tests for OpenQPEP Release Candidate 1.0.0:
  - m-of-n Threshold Multi-Party Cosigning Bundles (2-of-3 QVS + Ed448)
  - Duplicate cosigner & unauthorized signer rejection
  - Cryptographic Timestamp Proofs (Hash-Chain Anchor + TSA QVS + Ed448 Attestation)
"""
import unittest

from calyx_qpep import OpenQPEPProtocol, QPEPKeyRingError
from calyx_qpep.signatures import (
    cosign_payload,
    create_multisig_policy,
    create_timestamp_proof,
    verify_multisig_bundle,
    verify_timestamp_proof,
)


class TestOpenQPEPv028MultisigAndTimestamp(unittest.TestCase):
    def setUp(self):
        self.pw = "Calyx!@#$_2026SignAa99"
        self.m1 = OpenQPEPProtocol.generate_keypair("Maintainer1", "m1@calyxlabsinc.org", self.pw, qlx_tier="QLX-768")
        self.m2 = OpenQPEPProtocol.generate_keypair("Maintainer2", "m2@calyxlabsinc.org", self.pw, qlx_tier="QLX-768")
        self.m3 = OpenQPEPProtocol.generate_keypair("Maintainer3", "m3@calyxlabsinc.org", self.pw, qlx_tier="QLX-768")
        self.outsider = OpenQPEPProtocol.generate_keypair("Outsider", "x@calyxlabsinc.org", self.pw, qlx_tier="QLX-768")
        self.pubs = [
            OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(k, include_private=False))
            for k in (self.m1, self.m2, self.m3)
        ]

    def test_01_two_of_three_threshold_multisig_cosigning(self):
        policy = create_multisig_policy(threshold=2, authorized_signers=self.pubs, policy_name="Calyx Release 2-of-3")
        release_artifact = b"OpenQPEP Suite v1.0.0-rc Official Release Manifest SHA3-512"

        # 1st signature alone (1-of-3) must NOT satisfy threshold=2
        b1 = cosign_payload(release_artifact, self.m1, self.pw, policy)
        ok1, rep1 = verify_multisig_bundle(b1, self.pubs, expected_payload=release_artifact)
        self.assertFalse(ok1)
        self.assertEqual(rep1["valid_signature_count"], 1)

        # Duplicate cosigning by Maintainer1 must be rejected
        with self.assertRaises(QPEPKeyRingError):
            cosign_payload(release_artifact, self.m1, self.pw, policy, existing_bundle=b1)

        # Outsider cosigning must be rejected
        with self.assertRaises(QPEPKeyRingError):
            cosign_payload(release_artifact, self.outsider, self.pw, policy, existing_bundle=b1)

        # 2nd independent maintainer cosigns -> 2-of-3 threshold satisfied!
        b2 = cosign_payload(release_artifact, self.m3, self.pw, policy, existing_bundle=b1)
        ok2, rep2 = verify_multisig_bundle(b2, self.pubs, expected_payload=release_artifact)
        self.assertTrue(ok2)
        self.assertEqual(rep2["valid_signature_count"], 2)
        self.assertEqual(rep2["payload"], release_artifact)

        # Mismatched expected payload must fail verification
        ok_bad, _ = verify_multisig_bundle(b2, self.pubs, expected_payload=b"tampered release")
        self.assertFalse(ok_bad)

    def test_02_cryptographic_timestamp_proof_hashchain_and_tsa(self):
        doc = b"Legal Patent Disclosure & OpenQPEP Prior Art Record 2026"
        tsa_pub = self.pubs[0]
        proof = create_timestamp_proof(
            doc,
            tsa_keyring=self.m1,
            tsa_passphrase=self.pw,
            anchor_chain_id="calyx-public-hashchain-v1",
            anchor_block_height=420819,
            anchor_prev_hash_hex="ab" * 32,
            utc_timestamp="2026-11-20T17:25:00+00:00",
        )
        ok, info = verify_timestamp_proof(proof, doc, tsa_public_keyring=tsa_pub)
        self.assertTrue(ok)
        self.assertTrue(info["tsa_verified"])
        self.assertEqual(info["block_height"], 420819)
        self.assertEqual(info["utc_timestamp"], "2026-11-20T17:25:00+00:00")

        # Altered document must fail timestamp binding verification
        ok_tamper, _ = verify_timestamp_proof(proof, doc + b"!", tsa_public_keyring=tsa_pub)
        self.assertFalse(ok_tamper)

        # Wrong TSA public key must fail attestation verification
        ok_wrong_tsa, _ = verify_timestamp_proof(proof, doc, tsa_public_keyring=self.pubs[1])
        self.assertFalse(ok_wrong_tsa)


if __name__ == "__main__":
    unittest.main()
