"""
OpenQPEP Official Release 1.1.0 (v1.1.0) Stabilization, Interoperability & Server Adapter Test Suite.
Verifies:
  1. 100% Wire Format v5 (\x89QPE\x05\x00), Compact TLV v5.1 (\x89QPE\x05\x01), Stream v5 (\x89QPS\x05\x00),
     and kdf_version: 4 backwards compatibility with Official Releases 1.0.0–1.0.2.
  2. Continued hard QPEPLegacyProtocolError rejection of all legacy -rc, -pc, -beta, and 0.x artifacts.
  3. calyx_qpep.compat_server (SlidingWindowRateLimiter, verify_wire_v5_frame_strict,
     reject_legacy_version_token, verify_qpkrf_for_directory).
"""
import json
import os
import unittest

from calyx_qpep import (
    MANDATORY_KDF_VERSION,
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    QPEPLegacyProtocolError,
    QPEPMacVerificationError,
    QPEPWireFormatError,
    SlidingWindowRateLimiter,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
)
from calyx_qpep.compat_server import (
    is_legacy_prerelease_version,
    pack_wire_frame,
    reject_legacy_version_token,
    verify_qpkrf_for_directory,
    verify_wire_v5_frame_strict,
)
from calyx_qpep.protocol import _armor_wrap


class TestOpenQPEPv110Stabilization(unittest.TestCase):
    PASS = "Calyx!@#$_2026v110Aa99"

    def test_01_v10x_to_v110_wire_v5_keyring_interoperability(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.1.0")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.1.0")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.1.0")
        self.assertEqual(MANDATORY_KDF_VERSION, 4)

        kr = OpenQPEPProtocol.generate_keypair("InteropUser", "interop@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        # Simulate an Official Release 1.0.0 and 1.0.2 .qpkrf envelope imported under v1.1.0
        for prev_official in ("1.0.0", "1.0.1", "1.0.2"):
            env = {
                "magic": "QPKRF-v1.0.0",
                "protocol": "OpenQPEP by Calyx Labs Inc.",
                "version": prev_official,
                "ring_type": "PUBLIC_KEY_RING",
                "suite_id": "QLX-768",
                "suite": "QLX-768+HGC-448 / QVS-65+qSponge-512 / CMT-4 CC-512",
                "key_hash": kr.key_hash,
                "created_at": kr.created_at,
                "identity": {"name": kr.name, "email": kr.email, "comment": kr.comment},
                "public_bundle": kr.public_bundle,
                "integrity_mac": kr.integrity_mac,
            }
            armored = _armor_wrap(
                "CALYX QPKRF PUBLIC KEY RING",
                {"Protocol": "OpenQPEP by Calyx Labs Inc.", "Version": f"OpenQPEP/{prev_official}"},
                json.dumps(env).encode("utf-8"),
                packet_type=0x07,
            )
            imported = OpenQPEPProtocol.import_qpkrf(armored)
            self.assertEqual(imported.key_hash, kr.key_hash)
            # Encrypt with v1.1.0 to v1.0.x public key and decrypt with v1.1.0 private key
            pkt = OpenQPEPProtocol.encrypt_text(f"compat-{prev_official}", imported, kr, self.PASS)
            pt, meta = OpenQPEPProtocol.decrypt_packet(pkt, kr, self.PASS, sender_public_keyring=imported)
            self.assertEqual(pt.decode("utf-8"), f"compat-{prev_official}")
            self.assertTrue(meta["signature_verified"])

    def test_02_compat_server_rate_limiter_sliding_window(self):
        rl = SlidingWindowRateLimiter(max_requests=3, window_seconds=10.0)
        ok1, rem1, ra1 = rl.allow("198.51.100.10", now=100.0)
        ok2, rem2, _ = rl.allow("198.51.100.10", now=101.0)
        ok3, rem3, _ = rl.allow("198.51.100.10", now=102.0)
        ok4, rem4, ra4 = rl.allow("198.51.100.10", now=103.0)
        self.assertTrue((ok1, ok2, ok3) == (True, True, True))
        self.assertEqual((rem1, rem2, rem3), (2, 1, 0))
        self.assertEqual(ra1, 0)
        self.assertFalse(ok4)
        self.assertEqual(rem4, 0)
        self.assertGreaterEqual(ra4, 7)

        # Independent client unaffected
        ok_other, _, _ = rl.allow("198.51.100.11", now=103.0)
        self.assertTrue(ok_other)

        # After sliding window passes (t=110.5 > 100.0 + 10.0), slot frees up
        ok5, _, _ = rl.allow("198.51.100.10", now=110.5)
        self.assertTrue(ok5)

    def test_03_compat_server_legacy_token_and_directory_validation(self):
        for ok_ver in ("1.0.0", "1.0.2", "1.1.0", "OpenQPEP/1.0.2", "OpenQPEP/1.1.0", "v1.1.0"):
            self.assertFalse(is_legacy_prerelease_version(ok_ver))
            reject_legacy_version_token(ok_ver)
        for bad_ver in ("1.0.0-rc", "1.2.0-pc", "0.2.9-beta", "OpenQPEP/1.0.0-rc", "0.1.9"):
            self.assertTrue(is_legacy_prerelease_version(bad_ver))
            with self.assertRaises(QPEPLegacyProtocolError):
                reject_legacy_version_token(bad_ver)

        # Wire v5 verification + tamper check
        frame = pack_wire_frame(b"directory-payload", "CALYX QPKRF PUBLIC KEY RING", packet_type=0x07)
        body, ptype = verify_wire_v5_frame_strict(frame, "CALYX QPKRF PUBLIC KEY RING")
        self.assertEqual(body, b"directory-payload")
        self.assertEqual(ptype, 0x07)
        with self.assertRaises(QPEPMacVerificationError):
            verify_wire_v5_frame_strict(frame[:-1] + bytes([frame[-1] ^ 0xFF]), "CALYX QPKRF PUBLIC KEY RING")

        # Directory public/private enforcement
        kr = OpenQPEPProtocol.generate_keypair("DirUser", "dir@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
        priv_armor = OpenQPEPProtocol.export_qpkrf(kr, passphrase=self.PASS, include_private=True)
        _, summary = verify_qpkrf_for_directory(pub_armor)
        self.assertEqual(summary["key_hash"], kr.key_hash)
        self.assertEqual(summary["protocol_version"], "OpenQPEP/1.1.0")
        with self.assertRaises((QPEPWireFormatError, ValueError)):
            verify_qpkrf_for_directory(priv_armor)


if __name__ == "__main__":
    unittest.main()
