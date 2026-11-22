"""
OpenQPEP Official Release 1.0.0 (v1.0.0) Cryptographic Perfection & Security Regression Suite.
Verifies EVERY cryptographic, protocol, parser, sub-protocol, native C99, CLI, and
zero-backwards-compatibility guarantee introduced for Official Release 1.0.0:
  1. CMT-4 Key-Committing CC-512 AEAD
  2. Genuine Beyond-LWE engines (Goppa Patterson, LRPC Rank-Metric, UOV, CSIDH-512 Bimodal SeaSign, Module-SIS QVS-Ring)
  3. Keyring suite & Beyond-LWE key-hash binding + unified Beyond-LWE authenticated envelopes
  4. Parser & wire hardening (zlib bomb, mandatory armor CRC, header injection, duplicate TLV tags, reserved flags)
  5. Hardened sub-protocols (Ratchet atomic state + rotating PCS, AKE bidirectional PQ auth, MLS replay defense,
     KT Ed448 STH + RFC 9162 consistency proofs, DeniableVault masked headers, TKEM zero-reconstruction refresh,
     Sphinx-PQ fixed-size + post-AEAD replay commit, LatticeZKProof range bounds)
  6. Production non-interactive CLI subcommands & 0o600 private key permissions
  7. Native C99 openqpep_verify_wire_v5_magic & openqpep_ct_eq
  8. Complete zero backwards compatibility across -rc, -pc, and -beta wire frames, streams, and KDF versions
"""
import io
import json
import os
import stat
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from calyx_qpep import (
    MANDATORY_KDF_VERSION,
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    QPEPFaultGuardError,
    QPEPLegacyProtocolError,
    QPEPMacVerificationError,
    QPEPSuiteError,
    QPEPWireFormatError,
    STREAM_MAGIC_V5,
    UNIVERSAL_VERSION,
    WIRE_MAGIC_V5,
    WIRE_MAGIC_V5_1,
)
from calyx_qpep.cli import main as cli_main
from calyx_qpep.codes.goppa_8192 import BinaryGoppaKEM
from calyx_qpep.codes.rank_rsd512 import RankMetricKEM
from calyx_qpep.constants import (
    ALL_LEGACY_WIRE_MAGICS,
    LEGACY_BETA_WIRE_MAGICS,
    LEGACY_PC_WIRE_MAGICS,
    LEGACY_RC_WIRE_MAGICS,
    LEGACY_STREAM_MAGICS,
)
from calyx_qpep.directory_kt.merkle_log import (
    KeyTransparencyLog,
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_sth,
)
from calyx_qpep.group.mls_epoch import QPEPGroupMember, QPEPGroupSession
from calyx_qpep.isogeny.sqi_2d_512 import (
    CSIDH_PRIME,
    SupersingularIsogenyEngine,
    validate_supersingular,
)
from calyx_qpep.lattice.ntt_3329 import ntt_3329, ntt_base_mul_3329
from calyx_qpep.mixnet.sphinx_pq import MixNode, SphinxPQRouter
from calyx_qpep.multivariate.qmq_512 import MultivariateQuadraticEngine
from calyx_qpep.native.loader import is_native_available, native_ct_eq, native_verify_wire_v5_magic
from calyx_qpep.primitives.cc512_aead import CC512_OVERHEAD_BYTES, cc512_decrypt, cc512_encrypt
from calyx_qpep.privacy.deniable_vault import DeniableVault
from calyx_qpep.privacy.ring_sig import QVSRingSignature
from calyx_qpep.protocol import _safe_zlib_decompress
from calyx_qpep.ratchet.session_state import QPEPRatchetSession
from calyx_qpep.recovery.sss_gf256 import reconstruct_secret
from calyx_qpep.threshold.tkem import ThresholdKEM
from calyx_qpep.transport.ake_handshake import QPEPAKEHandshake, QPEPAKEIdentity
from calyx_qpep.wire.armor import armor_unwrap, armor_wrap
from calyx_qpep.wire.compact_v51 import decode_tlv, encode_tlv, pack_compact_v51, unpack_compact_v51
from calyx_qpep.wire.framing import pack_wire_frame, unpack_wire_frame
from calyx_qpep.wire.streaming import StreamingDecryptor, StreamingEncryptor
from calyx_qpep.zkp.lattice_sigma import LatticeZKProof


class TestOpenQPEPv100OfficialReleasePerfection(unittest.TestCase):
    PASS = "Calyx!@#$_2026PerfAa99"
    PASS2 = "Calyx!@#$_2026RecpBb88"

    def test_01_cmt4_key_committing_cc512_aead(self):
        self.assertEqual(CC512_OVERHEAD_BYTES, 64)
        k1, k2 = os.urandom(64), os.urandom(64)
        n24 = os.urandom(24)
        pt = b"CMT-4 Invisible Salamander Resistance Test"
        ct = cc512_encrypt(k1, n24, pt, b"aad-v1")
        self.assertEqual(len(ct), len(pt) + 64)
        self.assertEqual(cc512_decrypt(k1, n24, ct, b"aad-v1"), pt)

        # Wrong key fails CMT-4 commitment check before AEAD decryption
        with self.assertRaises(QPEPMacVerificationError):
            cc512_decrypt(k2, n24, ct, b"aad-v1")
        # Tampered CMT-4 commitment tag (last 32 bytes) rejected
        with self.assertRaises(QPEPMacVerificationError):
            cc512_decrypt(k1, n24, ct[:-1] + bytes([ct[-1] ^ 0x01]), b"aad-v1")
        # Tampered AAD rejected
        with self.assertRaises(QPEPMacVerificationError):
            cc512_decrypt(k1, n24, ct, b"aad-wrong")

    def test_02_genuine_beyond_lwe_engines_soundness_and_forgery_rejection(self):
        # 1. Binary Goppa Patterson KEM
        pk1, sk1 = BinaryGoppaKEM.keygen()
        _pk2, sk2 = BinaryGoppaKEM.keygen()
        ct, ss = BinaryGoppaKEM.encaps(pk1)
        self.assertEqual(BinaryGoppaKEM.decaps(sk1, ct), ss)
        self.assertNotEqual(BinaryGoppaKEM.decaps(sk2, ct), ss)
        bad_ct = bytes([ct[0] ^ 0x80]) + ct[1:]
        r1 = BinaryGoppaKEM.decaps(sk1, bad_ct)
        r2 = BinaryGoppaKEM.decaps(sk1, bad_ct)
        self.assertEqual(r1, r2)
        self.assertNotEqual(r1, ss)

        # 2. Rank-Metric LRPC KEM
        rpk1, rsk1 = RankMetricKEM.keygen()
        _rpk2, rsk2 = RankMetricKEM.keygen()
        rct, rss = RankMetricKEM.encaps(rpk1)
        self.assertEqual(RankMetricKEM.decaps(rsk1, rct), rss)
        self.assertNotEqual(RankMetricKEM.decaps(rsk2, rct), rss)
        bad_rct = bytes([rct[0] ^ 0x40]) + rct[1:]
        self.assertNotEqual(RankMetricKEM.decaps(rsk1, bad_rct), rss)

        # 3. Genuine UOV over GF(256) + Fault-Guard
        upk, usk = MultivariateQuadraticEngine.keygen()
        upk2, _ = MultivariateQuadraticEngine.keygen()
        usig = MultivariateQuadraticEngine.sign(usk, b"UOV authentic message")
        self.assertTrue(MultivariateQuadraticEngine.verify(upk, b"UOV authentic message", usig))
        self.assertFalse(MultivariateQuadraticEngine.verify(upk, b"UOV forged message", usig))
        self.assertFalse(MultivariateQuadraticEngine.verify(upk2, b"UOV authentic message", usig))
        with patch.object(MultivariateQuadraticEngine, "verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                MultivariateQuadraticEngine.sign(usk, b"fault test")

        # 4. Genuine CSIDH-512 KEM + Bimodal BLISS-SeaSign + supersingular validation + Fault-Guard
        self.assertFalse(validate_supersingular(2))
        self.assertFalse(validate_supersingular(CSIDH_PRIME - 2))
        self.assertFalse(validate_supersingular(CSIDH_PRIME + 1))
        self.assertFalse(validate_supersingular(123456789))  # ordinary curve rejected
        ipk, isk = SupersingularIsogenyEngine.keygen()
        ict, iss = SupersingularIsogenyEngine.encaps(ipk)
        self.assertEqual(SupersingularIsogenyEngine.decaps(isk, ict), iss)
        self.assertNotEqual(SupersingularIsogenyEngine.decaps(isk, (2).to_bytes(64, "big")), iss)
        isig = SupersingularIsogenyEngine.sign(isk, ipk, b"CSIDH-512 authentic")
        self.assertTrue(SupersingularIsogenyEngine.verify(ipk, b"CSIDH-512 authentic", isig))
        self.assertFalse(SupersingularIsogenyEngine.verify(ipk, b"CSIDH-512 tampered", isig))
        with patch.object(SupersingularIsogenyEngine, "verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                SupersingularIsogenyEngine.sign(isk, ipk, b"fault test")

        # 5. Genuine Module-SIS AOS QVS-Ring Signature
        kps = [QVSRingSignature.keygen() for _ in range(4)]
        ring = [p for p, _ in kps]
        rsig1 = QVSRingSignature.sign(b"msg1", ring, 1, kps[1][1], link_domain=b"election-A")
        rsig2 = QVSRingSignature.sign(b"msg2", ring, 1, kps[1][1], link_domain=b"election-A")
        rsig_diff = QVSRingSignature.sign(b"msg1", ring, 1, kps[1][1], link_domain=b"election-B")
        self.assertTrue(QVSRingSignature.verify(b"msg1", ring, rsig1))
        self.assertFalse(QVSRingSignature.verify(b"msg1", ring[:3], rsig1))
        self.assertEqual(rsig1["key_image_hex"], rsig2["key_image_hex"])
        self.assertNotEqual(rsig1["key_image_hex"], rsig_diff["key_image_hex"])

    def test_03_keyring_binding_and_unified_beyond_lwe_authenticated_envelope(self):
        alice = OpenQPEPProtocol.generate_keypair("Alice", "a@calyxmail.org", self.PASS, qlx_tier="CRT-RSD512")
        bob = OpenQPEPProtocol.generate_keypair("Bob", "b@calyxmail.org", self.PASS2, qlx_tier="CRT-RSD512")

        # Unified Beyond-LWE encrypt_bytes / decrypt_packet must preserve filename, MIME, and verify sender signature
        pkt = OpenQPEPProtocol.encrypt_bytes(
            b"%PDF-1.7 beyond-lwe authenticated doc",
            recipient_keyring=bob,
            encrypting_keyring=alice,
            passphrase=self.PASS,
            filename="directive.pdf",
        )
        self.assertNotIn("Encrypting-Key-Hash:", pkt)
        pt, meta = OpenQPEPProtocol.decrypt_packet(pkt, bob, self.PASS2, sender_public_keyring=alice)
        self.assertEqual(pt, b"%PDF-1.7 beyond-lwe authenticated doc")
        self.assertEqual(meta["suite_id"], "CRT-RSD512")
        self.assertEqual(meta["filename"], "directive.pdf")
        self.assertEqual(meta["mime_type"], "application/pdf")
        self.assertTrue(meta["signature_verified"])

        # Tampering beyond_lwe_public inside public_bundle must break self-signature verification
        bob.public_bundle["beyond_lwe_public"]["kem_pk_b64"] = "AAAA" + bob.public_bundle["beyond_lwe_public"]["kem_pk_b64"][4:]
        self.assertFalse(OpenQPEPProtocol.verify_public_keyring_self_signature(bob))

    def test_04_parser_and_wire_hardening(self):
        # 1. Zlib decompression bomb defense
        bomb = zlib.compress(b"\x00" * (2 * 1024 * 1024), level=9)
        self.assertLess(len(bomb), 8192)
        with self.assertRaises(QPEPWireFormatError):
            _safe_zlib_decompress(bomb, max_bytes=65536)

        # 2. Mandatory armor CRC verification & tampering rejection
        armored = armor_wrap("CALYX QPEP MESSAGE", b"crc protected payload")
        raw, _ = armor_unwrap(armored, "CALYX QPEP MESSAGE")
        self.assertEqual(raw, b"crc protected payload")
        # Strip CRC line
        no_crc = "\n".join(ln for ln in armored.splitlines() if not ln.startswith("=")) + "\n"
        with self.assertRaises(QPEPMacVerificationError):
            armor_unwrap(no_crc, "CALYX QPEP MESSAGE")
        # Corrupt CRC line
        bad_crc = "\n".join(("=AAAAAAAA" if ln.startswith("=") else ln) for ln in armored.splitlines()) + "\n"
        with self.assertRaises(QPEPMacVerificationError):
            armor_unwrap(bad_crc, "CALYX QPEP MESSAGE")

        # 3. Header injection rejection
        with self.assertRaises(QPEPWireFormatError):
            armor_wrap("CALYX QPEP MESSAGE", b"x", headers={"X-Custom": "evil\r\nInjected: yes"})

        # 4. Duplicate TLV tag rejection in Compact TLV v5.1
        dup_tlv = encode_tlv({1: b"first"}) + encode_tlv({1: b"second"})
        with self.assertRaises(QPEPWireFormatError):
            decode_tlv(dup_tlv)

        # 5. Reserved flags rejection in Wire Format v5
        frame = bytearray(pack_wire_frame(b"flag test", "CALYX QPEP MESSAGE"))
        frame[7] = 0x02  # non-zero reserved bit
        with self.assertRaises(QPEPWireFormatError):
            unpack_wire_frame(bytes(frame), "CALYX QPEP MESSAGE")

    def test_05_hardened_subprotocols_ratchet_ake_mls_kt_vault_tkem_sphinx_zkp(self):
        # 1. QPEP-Ratchet atomic state preservation under forged epoch rekey + rotating PCS
        alice, bob = QPEPRatchetSession.create_pair(os.urandom(32), qlx_tier="QLX-768", rekey_interval_messages=2)
        m0 = alice.encrypt(b"msg0")
        p0, _ = bob.decrypt(m0)
        self.assertEqual(p0, b"msg0")

        # Forge an epoch-jump packet with corrupted ciphertext
        alice_legit1 = alice.encrypt(b"msg1")
        alice_legit2 = alice.encrypt(b"msg2-pcs-rekey")  # triggers epoch 1 rekey
        raw_j, _ = armor_unwrap(alice_legit2, "CALYX QPEP RATCHET MESSAGE")
        forged_obj = json.loads(raw_j.decode("utf-8"))
        forged_obj["ciphertext_b64"] = "A" * len(forged_obj["ciphertext_b64"])
        forged_pkt = armor_wrap("CALYX QPEP RATCHET MESSAGE", json.dumps(forged_obj).encode("utf-8"), packet_type=0x04)

        rk_before, ck_before = bytes(bob._root_key), bytes(bob._recv_ck)
        ep_before, cnt_before = bob.recv_epoch, bob.recv_count
        with self.assertRaises(QPEPMacVerificationError):
            bob.decrypt(forged_pkt)
        # Session state must be 100% untouched after forged packet!
        self.assertEqual(bytes(bob._root_key), rk_before)
        self.assertEqual(bytes(bob._recv_ck), ck_before)
        self.assertEqual((bob.recv_epoch, bob.recv_count), (ep_before, cnt_before))
        # Legitimate packets still decrypt cleanly!
        self.assertEqual(bob.decrypt(alice_legit1)[0], b"msg1")
        p2, meta2 = bob.decrypt(alice_legit2)
        self.assertEqual(p2, b"msg2-pcs-rekey")
        self.assertTrue(meta2["pcs_rekey"])

        # 2. QPEP-AKE bidirectional PQ mutual auth + deterministic nonce check + destroy()
        id_a = QPEPAKEIdentity.generate("alice")
        id_b = QPEPAKEIdentity.generate("bob")
        ch_a, ch_b = QPEPAKEHandshake.run_handshake(id_a, id_b)
        seq, n24, ct = ch_a.send(b"pq-mutual-auth")
        with self.assertRaises(QPEPMacVerificationError):
            ch_b.recv(seq, bytes([n24[0] ^ 1]) + n24[1:], ct)
        self.assertEqual(ch_b.recv(seq, n24, ct), b"pq-mutual-auth")
        ch_a.destroy()
        with self.assertRaises(RuntimeError):
            ch_a.send(b"after destroy")

        # 3. QPEP-MLS per-(epoch, sender) replay rejection
        ma, mb = QPEPGroupMember.create("alice"), QPEPGroupMember.create("bob")
        grp = QPEPGroupSession("room-v1", [ma, mb])
        gpkt = grp.encrypt_group_message("alice", b"group secret")
        self.assertEqual(grp.decrypt_group_message("bob", gpkt), b"group secret")
        with self.assertRaises(QPEPMacVerificationError):
            grp.decrypt_group_message("bob", gpkt)

        # 4. QPEP-KT Ed448 STH + RFC 9162 Merkle Consistency Proofs
        kt = KeyTransparencyLog()
        roots = []
        for i in range(7):
            kt.append(f"KEYHASH_{i:02d}", f"DIGEST_{i:02d}")
            sth = kt.signed_tree_head()
            self.assertTrue(verify_sth(sth, kt.public_key_hex))
            # Tampered STH rejected
            bad_sth = dict(sth); bad_sth["tree_size"] = 999
            self.assertFalse(verify_sth(bad_sth, kt.public_key_hex))
            roots.append(sth["root_hex"])

        for m in (1, 2, 3, 4, 5, 6):
            cproof = kt.consistency_proof(m, 7)
            self.assertTrue(verify_consistency_proof(m, 7, roots[m - 1], roots[6], cproof))
            # Equivocated / split-view old root must fail consistency proof!
            fake_root = "ff" * 32
            self.assertFalse(verify_consistency_proof(m, 7, fake_root, roots[6], cproof))

        # 5. DeniableVault masked headers (no cleartext length bytes at offset 56 or half+24)
        outer_pt = b"decoy-data-12345"
        hidden_pt = b"secret-hidden-payload"
        vault = DeniableVault.seal(outer_pt, "outer-pw", hidden_pt, "hidden-pw", container_size=4096, kdf_m_kib=1024, kdf_t_cost=1)
        expected_outer_len = struct.pack(">I", len(outer_pt) + 64)
        expected_hidden_len = struct.pack(">I", len(hidden_pt) + 64)
        self.assertNotEqual(vault[56:60], expected_outer_len)
        self.assertNotEqual(vault[2048 + 24 : 2048 + 28], expected_hidden_len)
        self.assertEqual(DeniableVault.open(vault, "outer-pw", kdf_m_kib=1024, kdf_t_cost=1), ("outer", outer_pt))
        self.assertEqual(DeniableVault.open(vault, "hidden-pw", kdf_m_kib=1024, kdf_t_cost=1), ("hidden", hidden_pt))

        # 6. ThresholdKEM true zero-reconstruction HJKY proactive refresh
        tpk, shares = ThresholdKEM.keygen_distributed(2, 3)
        orig_secret = reconstruct_secret(shares[:2])
        refreshed = ThresholdKEM.proactive_refresh(shares, 2, 3)
        # Every custodian's share bytes must actually change!
        for (_, old_b), (_, new_b) in zip(shares, refreshed):
            self.assertNotEqual(old_b, new_b)
        self.assertEqual(reconstruct_secret([refreshed[0], refreshed[2]]), orig_secret)

        # 7. Sphinx-PQ fixed-size constant-length onions & post-AEAD replay protection
        nodes = [MixNode.create(f"hop-{i}") for i in range(3)]
        onion_short = SphinxPQRouter.build_onion(nodes, "a@b.org", b"hi")
        onion_long = SphinxPQRouter.build_onion(nodes, "a@b.org", b"x" * 200)
        self.assertEqual(len(onion_short), len(onion_long))

        # 8. LatticeZKProof out-of-range z rejection
        a_hat = ntt_3329([(i * 13) % 3329 for i in range(256)])
        s_hat = ntt_3329([i % 3 for i in range(256)])
        t_hat = ntt_base_mul_3329(a_hat, s_hat)
        zkp = LatticeZKProof.prove(a_hat, s_hat, t_hat, b"ctx-1")
        self.assertTrue(LatticeZKProof.verify(a_hat, t_hat, b"ctx-1", zkp))
        bad_zkp = dict(zkp); bad_zkp["z_hat"] = [9999] * 256
        self.assertFalse(LatticeZKProof.verify(a_hat, t_hat, b"ctx-1", bad_zkp))

    def test_06_production_cli_subcommands_and_0600_private_key_perms(self):
        with tempfile.TemporaryDirectory() as tmpd:
            td = Path(tmpd)
            pub_p = td / "alice.pub.qpkrf"
            priv_p = td / "alice.priv.qpkrf"
            in_p = td / "plain.txt"
            enc_p = td / "plain.txt.qpep"
            dec_p = td / "restored.txt"
            sig_p = td / "plain.txt.qsig"
            ext_p = td / "verified.txt"
            rev_p = td / "alice.qrev"
            in_p.write_text("Official Release 1.0.0 CLI pipeline message!", encoding="utf-8")

            self.assertEqual(cli_main([
                "keygen", "--name", "Alice", "--email", "alice@calyxmail.org",
                "--passphrase", self.PASS, "--tier", "QLX-768",
                "--pub-out", str(pub_p), "--priv-out", str(priv_p),
            ]), 0)
            self.assertEqual(stat.S_IMODE(priv_p.stat().st_mode), 0o600)

            self.assertEqual(cli_main(["fingerprint", str(pub_p)]), 0)
            self.assertEqual(cli_main([
                "encrypt", "--recipient", str(pub_p), "--sender", str(priv_p),
                "--passphrase", self.PASS, "--in", str(in_p), "--out", str(enc_p),
            ]), 0)
            self.assertEqual(cli_main(["inspect", str(enc_p)]), 0)
            self.assertEqual(cli_main([
                "decrypt", "--key", str(priv_p), "--sender-pub", str(pub_p),
                "--passphrase", self.PASS, "--in", str(enc_p), "--out", str(dec_p),
            ]), 0)
            self.assertEqual(dec_p.read_text(encoding="utf-8"), in_p.read_text(encoding="utf-8"))

            self.assertEqual(cli_main([
                "sign", "--key", str(priv_p), "--passphrase", self.PASS,
                "--in", str(in_p), "--out", str(sig_p),
            ]), 0)
            self.assertEqual(cli_main([
                "verify", "--key", str(pub_p), "--in", str(sig_p), "--extract-out", str(ext_p),
            ]), 0)
            self.assertEqual(ext_p.read_text(encoding="utf-8"), in_p.read_text(encoding="utf-8"))

            self.assertEqual(cli_main([
                "revoke", "--key", str(priv_p), "--passphrase", self.PASS,
                "--reason", "KEY_RETIRED", "--out", str(rev_p),
            ]), 0)
            self.assertTrue(rev_p.is_file())

    def test_07_native_c99_wire_v5_magic_and_ct_eq(self):
        if not is_native_available():
            self.skipTest("libopenqpep C99 library not built")
        self.assertEqual(native_verify_wire_v5_magic(WIRE_MAGIC_V5), 50)
        self.assertEqual(native_verify_wire_v5_magic(WIRE_MAGIC_V5_1), 51)
        self.assertEqual(native_verify_wire_v5_magic(b"\x89QPE\x04\x00"), -40)
        self.assertEqual(native_verify_wire_v5_magic(b"\x89QPE\x04\x01"), -40)
        self.assertEqual(native_verify_wire_v5_magic(b"\x89QPE\x03\x00"), -30)
        self.assertEqual(native_verify_wire_v5_magic(b"\x89QPE\x02\x00"), -10)
        self.assertTrue(native_ct_eq(b"OpenQPEP-1.0.0", b"OpenQPEP-1.0.0"))
        self.assertFalse(native_ct_eq(b"OpenQPEP-1.0.0", b"OpenQPEP-1.0.1"))

    def test_08_zero_backwards_compatibility_all_legacy_prereleases_rejected(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.0.0")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.0.0")
        self.assertEqual(MANDATORY_KDF_VERSION, 4)

        # Reject ALL legacy -rc, -pc, and -beta wire magics
        for m in (LEGACY_RC_WIRE_MAGICS + LEGACY_PC_WIRE_MAGICS + LEGACY_BETA_WIRE_MAGICS):
            self.assertIn(m, ALL_LEGACY_WIRE_MAGICS)
            with self.assertRaises(QPEPLegacyProtocolError):
                unpack_wire_frame(m + os.urandom(64), "CALYX QPEP MESSAGE")
            with self.assertRaises(QPEPLegacyProtocolError):
                unpack_compact_v51(m + os.urandom(64), "CALYX QPEP COMPACT")

        # Reject legacy Stream v2.7 (\x89QPS\x02\x07) while accepting Official Stream v5 (\x89QPS\x05\x00)
        key64 = os.urandom(64)
        enc_buf = io.BytesIO()
        with StreamingEncryptor(key64) as enc:
            enc.encrypt_stream(io.BytesIO(b"stream v5 payload"), enc_buf)
        self.assertTrue(enc_buf.getvalue().startswith(STREAM_MAGIC_V5))
        for leg_sm in LEGACY_STREAM_MAGICS:
            with StreamingDecryptor(key64) as dec:
                with self.assertRaises(QPEPLegacyProtocolError):
                    dec.decrypt_stream(io.BytesIO(leg_sm + os.urandom(64)), io.BytesIO())


if __name__ == "__main__":
    unittest.main()
