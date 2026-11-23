"""
OpenQPEP Official Release 1.1.0 Comprehensive Verification Suite (Arc I + Arc II).
"""
import os
import subprocess
import unittest
from pathlib import Path

from calyx_qpep.airgap.lt_fountain import QRFountainDecoder, QRFountainEncoder
from calyx_qpep.audit.reproducible_build import generate_spdx_sbom
from calyx_qpep.codes.goppa_suite import CalyxGoppaMonolithSuite
from calyx_qpep.codes.rank_suite import CalyxRankMetricSuite
from calyx_qpep.constants import PROTOCOL_VERSION, UNIVERSAL_VERSION, WIRE_MAGIC_V5_1
from calyx_qpep.directory_kt.merkle_log import KeyTransparencyLog, verify_inclusion_proof
from calyx_qpep.exceptions import QPEPMacVerificationError, QPEPSuiteError
from calyx_qpep.group.mls_epoch import QPEPGroupMember, QPEPGroupSession
from calyx_qpep.hardware.fido2_prf import HardwareKeyWrapper, unwrap_with_fido2_prf, wrap_with_fido2_prf
from calyx_qpep.lattice.ntt_3329 import ntt_3329, ntt_base_mul_3329
from calyx_qpep.mixnet.sphinx_pq import MixNode, SphinxPQRouter
from calyx_qpep.native.rust_loader import rust_backend_info
from calyx_qpep.privacy.deniable_vault import DeniableVault
from calyx_qpep.privacy.ring_sig import QVSRingSignature
from calyx_qpep.sync.encrypted_crdt import EncryptedLWWMapCRDT
from calyx_qpep.threshold.tkem import ThresholdKEM
from calyx_qpep.timelock.hash_chain_vdf import TimeLockCapsule
from calyx_qpep.transport.ake_handshake import QPEPAKEHandshake, QPEPAKEIdentity
from calyx_qpep.vault.blind_index import BlindSearchVault
from calyx_qpep.wire.compact_v51 import pack_compact_v51, unpack_compact_v51
from calyx_qpep.zkp.lattice_sigma import LatticeZKProof


REPO_ROOT = Path(__file__).resolve().parent.parent


class TestOpenQPEPv050Arc1AndArc2(unittest.TestCase):
    def test_01_v031_wasm_bridge_js_parity_with_python(self):
        # Verify WASM/JS bridge ntt3329/invNtt3329 roundtrip via Node.js when available, else verify WASM binary + JS bridge exports
        import shutil
        wasm_js = REPO_ROOT / "calyx_qpep/native/wasm/wasm_bridge.mjs"
        self.assertTrue(wasm_js.is_file())
        if shutil.which("node"):
            code = (
                f"import {{ OpenQPEPWasmBridge }} from '{wasm_js}';"
                "const b = new OpenQPEPWasmBridge();"
                "const p = Array.from({length:256}, (_,i) => (i * 17) % 3329);"
                "const back = b.invNtt3329(b.ntt3329(p));"
                "if (JSON.stringify(p) !== JSON.stringify(back)) process.exit(1);"
                "console.log('WASM_BRIDGE_OK');"
            )
            r = subprocess.run(["node", "--input-type=module", "-e", code], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("WASM_BRIDGE_OK", r.stdout)
        else:
            js_src = wasm_js.read_text(encoding="utf-8")
            self.assertIn("export class OpenQPEPWasmBridge", js_src)
            self.assertIn("ntt3329(poly)", js_src)
            self.assertIn("invNtt3329(polyHat)", js_src)

    def test_02_v032_rust_crate_and_loader_present(self):
        self.assertTrue((REPO_ROOT / "rust/openqpep-core/Cargo.toml").is_file())
        self.assertTrue((REPO_ROOT / "rust/openqpep-core/src/ntt.rs").is_file())
        info = rust_backend_info()
        self.assertEqual(info["version"], "1.1.0")

    def test_03_v033_qpep_mls_group_epoch_add_remove_eviction(self):
        alice = QPEPGroupMember.create("alice")
        bob = QPEPGroupMember.create("bob")
        carol = QPEPGroupMember.create("carol")
        grp = QPEPGroupSession("calyx-dev-room", [alice, bob])
        c1 = grp.commit_epoch("alice", add=[carol])
        self.assertEqual(grp.epoch, 1)
        self.assertEqual(len(grp.unwrap_commit_seed(c1, carol)), 32)
        pkt = grp.encrypt_group_message("alice", b"hello post-quantum group")
        self.assertEqual(grp.decrypt_group_message("carol", pkt), b"hello post-quantum group")

        # Evict bob -> bob cannot unwrap epoch 2 or decrypt epoch 2 messages
        c2 = grp.commit_epoch("alice", remove=["bob"])
        with self.assertRaises(QPEPMacVerificationError):
            grp.unwrap_commit_seed(c2, bob)
        pkt2 = grp.encrypt_group_message("carol", b"post-eviction secret")
        with self.assertRaises(QPEPMacVerificationError):
            grp.decrypt_group_message("bob", pkt2)
        self.assertEqual(grp.decrypt_group_message("alice", pkt2), b"post-eviction secret")

    def test_04_v034_hardware_fido2_prf_wrap_and_guardrail(self):
        pw_key = os.urandom(32)
        hw_prf = HardwareKeyWrapper.simulate_prf_eval(b"yubikey-secret-seed", b"calyx-salt")
        with self.assertRaises(QPEPSuiteError):
            wrap_with_fido2_prf(b"secret", pw_key, hw_prf, credential_id="cred-1", recovery_verified=False)
        env = wrap_with_fido2_prf(b"master-keyring-seed", pw_key, hw_prf, credential_id="cred-1", recovery_verified=True)
        self.assertEqual(unwrap_with_fido2_prf(env, pw_key, hw_prf), b"master-keyring-seed")
        with self.assertRaises(QPEPMacVerificationError):
            unwrap_with_fido2_prf(env, pw_key, os.urandom(32))

    def test_05_v035_qpep_ake_1rtt_handshake_and_duplex_channel(self):
        alice = QPEPAKEIdentity.generate("alice")
        bob = QPEPAKEIdentity.generate("bob")
        ch_a, ch_b = QPEPAKEHandshake.run_handshake(alice, bob)
        self.assertEqual(ch_a.channel_binding_hex, ch_b.channel_binding_hex)
        self.assertEqual(ch_a.sas_code, ch_b.sas_code)
        seq, n24, ct = ch_a.send(b"live encrypted audio frame")
        self.assertEqual(ch_b.recv(seq, n24, ct), b"live encrypted audio frame")
        with self.assertRaises(ValueError):
            ch_b.recv(seq, n24, ct)

    def test_06_v036_key_transparency_merkle_log_proofs(self):
        kt = KeyTransparencyLog()
        idx0 = kt.append("HASH_ALICE", "DIGEST_A")
        idx1 = kt.append("HASH_BOB", "DIGEST_B")
        idx2 = kt.append("HASH_CAROL", "DIGEST_C")
        sth = kt.signed_tree_head()
        for idx, kh, dg in [(idx0, "HASH_ALICE", "DIGEST_A"), (idx1, "HASH_BOB", "DIGEST_B"), (idx2, "HASH_CAROL", "DIGEST_C")]:
            proof = kt.inclusion_proof(idx)
            self.assertTrue(verify_inclusion_proof(kh, dg, proof, sth["root_hex"]))
            self.assertFalse(verify_inclusion_proof(kh, "TAMPERED", proof, sth["root_hex"]))

    def test_07_v037_qvs_ring_deniable_and_linkable_signatures(self):
        ring_pairs = [QVSRingSignature.keygen() for _ in range(5)]
        ring_pks = [p for p, _ in ring_pairs]
        sig = QVSRingSignature.sign(b"whistleblower report", ring_pks, 2, ring_pairs[2][1], link_domain=b"vote-2026")
        self.assertTrue(QVSRingSignature.verify(b"whistleblower report", ring_pks, sig))
        self.assertFalse(QVSRingSignature.verify(b"tampered report", ring_pks, sig))
        sig2 = QVSRingSignature.sign(b"second vote", ring_pks, 2, ring_pairs[2][1], link_domain=b"vote-2026")
        self.assertEqual(sig["key_image_hex"], sig2["key_image_hex"])

    def test_08_v038_standalone_beyond_lwe_goppa_and_rank_suites(self):
        gpk, gsk = CalyxGoppaMonolithSuite.keygen()
        gct = CalyxGoppaMonolithSuite.encrypt(b"pure code-based payload", gpk)
        self.assertEqual(CalyxGoppaMonolithSuite.decrypt(gct, gsk), b"pure code-based payload")

        rpk, rsk = CalyxRankMetricSuite.keygen()
        rct = CalyxRankMetricSuite.encrypt(b"pure rank-metric payload", rpk)
        self.assertEqual(CalyxRankMetricSuite.decrypt(rct, rsk), b"pure rank-metric payload")

    def test_09_v039_v040_blind_vault_and_compact_wire_v31(self):
        vault = BlindSearchVault(os.urandom(64))
        vault.put("note-1", "Calyx Sovereign Pentad deployment checklist")
        vault.put("note-2", "Cleveland Ohio office keys")
        hits = vault.search("sovereign")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], "note-1")

        raw_v51 = pack_compact_v51({1: b"suite-qlx4096", 2: b"compact-payload"}, "CALYX QPEP COMPACT", packet_type=0x01)
        self.assertTrue(raw_v51.startswith(WIRE_MAGIC_V5_1))
        fields, ptype, _ = unpack_compact_v51(raw_v51, "CALYX QPEP COMPACT")
        self.assertEqual(ptype, 0x01)
        self.assertEqual(fields[2], b"compact-payload")

    def test_10_v041_to_v050_arc2_full_stack(self):
        # Official Release 1.1.0 TKEM 2-of-3 + proactive refresh
        pk, shares = ThresholdKEM.keygen_distributed(2, 3)
        refreshed = ThresholdKEM.proactive_refresh(shares, 2, 3)
        from calyx_qpep.recovery.sss_gf256 import reconstruct_secret
        pkt = ThresholdKEM.encrypt_to_group(b"treasury key", pk, reconstruct_secret(shares[:2]))
        self.assertEqual(ThresholdKEM.threshold_decrypt(pkt, pk, [refreshed[0], refreshed[2]]), b"treasury key")

        # Official Release 1.1.0 Sphinx-PQ 3-hop onion + replay protection
        nodes = [MixNode.create(f"mix-{i}") for i in range(3)]
        onion = SphinxPQRouter.build_onion(nodes, "alice@calyxmail.org", b"anonymous onion email")
        cur = onion
        for i, node in enumerate(nodes):
            nxt, cur, is_final = SphinxPQRouter.peel_layer(node, cur)
            if i < 2:
                self.assertFalse(is_final)
                self.assertEqual(nxt, nodes[i + 1].node_id)
            else:
                self.assertTrue(is_final)
                self.assertEqual(nxt, "alice@calyxmail.org")
                self.assertEqual(cur, b"anonymous onion email")
        with self.assertRaises(ValueError):
            SphinxPQRouter.peel_layer(nodes[0], onion)

        # Official Release 1.1.0 Air-gapped QR fountain (drop frame 1 and recover from parity frames)
        blob = os.urandom(900)
        enc = QRFountainEncoder(blob, block_size=256)
        dec = QRFountainDecoder()
        recovered = None
        for seq in [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]:
            recovered = dec.feed_frame(enc.next_frame(seq))
            if recovered is not None:
                break
        self.assertEqual(recovered, blob)

        # Official Release 1.1.0 Plausible-deniability dual volume
        cont = DeniableVault.seal(b"decoy shopping list", "outer-pass", b"true whistleblower keys", "hidden-pass")
        self.assertEqual(DeniableVault.open(cont, "outer-pass"), ("outer", b"decoy shopping list"))
        self.assertEqual(DeniableVault.open(cont, "hidden-pass"), ("hidden", b"true whistleblower keys"))

        # Official Release 1.1.0 Time-lock capsule
        cap = TimeLockCapsule.seal(b"embargoed disclosure", steps=50)
        self.assertEqual(TimeLockCapsule.unlock(cap), b"embargoed disclosure")

        # Official Release 1.1.0 Lattice ZK proof
        a_hat = ntt_3329([(i * 13) % 3329 for i in range(256)])
        s_hat = ntt_3329([(i % 3) for i in range(256)])
        t_hat = ntt_base_mul_3329(a_hat, s_hat)
        proof = LatticeZKProof.prove(a_hat, s_hat, t_hat, b"auth-session-1")
        self.assertTrue(LatticeZKProof.verify(a_hat, t_hat, b"auth-session-1", proof))
        self.assertFalse(LatticeZKProof.verify(a_hat, t_hat, b"wrong-session", proof))

        # Official Release 1.1.0 Encrypted multi-device CRDT sync
        skey = os.urandom(64)
        dev_a = EncryptedLWWMapCRDT("phone", skey)
        dev_b = EncryptedLWWMapCRDT("desktop", skey)
        op1 = dev_a.set("contact:bob", "KEYHASH_BOB_V1")
        op2 = dev_b.set("contact:carol", "KEYHASH_CAROL_V1")
        dev_b.merge_encrypted_op(op1)
        dev_a.merge_encrypted_op(op2)
        self.assertEqual(dev_a.snapshot(), dev_b.snapshot())

        # v1.1.0 Formal models, Go port, Spec freeze, SPDX SBOM
        self.assertEqual(UNIVERSAL_VERSION, "1.1.0")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.1.0")
        self.assertTrue((REPO_ROOT / "formal/qpep_ake.pv").is_file())
        self.assertTrue((REPO_ROOT / "go/openqpep/wire_v5.go").is_file())
        self.assertTrue((REPO_ROOT / "specs/OPENQPEP_v1.1.0_OFFICIAL_RELEASE_SPEC.md").is_file())
        sbom = generate_spdx_sbom(REPO_ROOT, version="1.1.0")
        self.assertEqual(sbom["dataLicense"], "CPOSLS-1.0")
        self.assertGreater(sbom["filesAnalyzed"], 40)


if __name__ == "__main__":
    unittest.main()
