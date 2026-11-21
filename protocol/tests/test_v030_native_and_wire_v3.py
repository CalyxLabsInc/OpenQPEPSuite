"""
OpenQPEP Production Candidate 1.1.4 (v1.1.4-pc) Verification Tests:
  - Native C99 / AVX2 Acceleration (libopenqpep) bit-for-bit parity with pure-Python reference
  - Strict Wire Format v3 (\x89QPE\x03\x00) emission & STRICT REJECTION of all legacy -beta wire magics
  - Calyx Sovereign-Pentad (CSP-Omega) Wire Format v3 + Plain-LWE native acceleration
  - Dual-engine KAT verification under both Native C99 and Pure-Python engines
"""
import base64
import os
import random
import time
import unittest
from pathlib import Path

from calyx_qpep.constants import (
    PACKET_TYPE_PENTAD,
    PROTOCOL_VERSION,
    UNIVERSAL_VERSION,
    WIRE_MAGIC_V3,
)
from calyx_qpep.exceptions import QPEPWireFormatError
from calyx_qpep.lattice.ntt_3329 import inv_ntt_3329, ntt_3329, ntt_base_mul_3329, poly_add_3329, poly_sub_3329
from calyx_qpep.lattice.ntt_8380417 import inv_ntt_qvs, ntt_qvs
from calyx_qpep.lattice.plain_lwe import PlainLWEEngine
from calyx_qpep.lattice.poly_ring import sample_cbd1_3329, sample_cbd2_3329, sample_eta_qvs
from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.native.loader import is_native_available, native_backend_info, set_native_enabled
from calyx_qpep.pentad.sovereign_pentad import CalyxSovereignPentad
from calyx_qpep.vectors.kat_verifier import verify_all_kats
from calyx_qpep.wire.framing import pack_wire_frame, unpack_wire_frame


class TestOpenQPEPPC100NativeAndStrictWireV3(unittest.TestCase):
    def tearDown(self):
        set_native_enabled(True)

    def test_01_native_c99_bit_exact_parity_with_pure_python(self):
        info = native_backend_info()
        self.assertTrue(info["loaded"])
        self.assertTrue(is_native_available())

        rng = random.Random(0x1000)
        p1 = [rng.randrange(3329) for _ in range(256)]
        p2 = [rng.randrange(3329) for _ in range(256)]
        q1 = [rng.randrange(8380417) for _ in range(256)]
        sigma = os.urandom(32)

        set_native_enabled(True)
        n_ntt3, n_add3, n_sub3 = ntt_3329(p1), poly_add_3329(p1, p2), poly_sub_3329(p1, p2)
        n_inv3 = inv_ntt_3329(n_ntt3)
        n_mul3 = ntt_base_mul_3329(ntt_3329(p1), ntt_3329(p2))
        n_nttq = ntt_qvs(q1)
        n_invq = inv_ntt_qvs(n_nttq)
        n_cbd1, n_cbd2, n_etaq = sample_cbd1_3329(sigma, 7), sample_cbd2_3329(sigma, 3), sample_eta_qvs(sigma, 5)

        set_native_enabled(False)
        self.assertEqual(n_ntt3, ntt_3329(p1))
        self.assertEqual(n_inv3, p1)
        self.assertEqual(n_mul3, ntt_base_mul_3329(ntt_3329(p1), ntt_3329(p2)))
        self.assertEqual(n_add3, poly_add_3329(p1, p2))
        self.assertEqual(n_sub3, poly_sub_3329(p1, p2))
        self.assertEqual(n_nttq, ntt_qvs(q1))
        self.assertEqual(n_invq, q1)
        self.assertEqual(n_cbd1, sample_cbd1_3329(sigma, 7))
        self.assertEqual(n_cbd2, sample_cbd2_3329(sigma, 3))
        self.assertEqual(n_etaq, sample_eta_qvs(sigma, 5))

    def test_02_native_acceleration_speedup_on_qlx4096(self):
        ek, dk = QLXEngine.keygen("QLX-4096", b"W" * 64)
        ct, ss_ref = QLXEngine.encaps(ek, "QLX-4096")
        set_native_enabled(False)
        t0 = time.perf_counter()
        ss_py = QLXEngine.decaps(dk, ct, "QLX-4096")
        t_py = time.perf_counter() - t0
        set_native_enabled(True)
        t0 = time.perf_counter()
        ss_nat = QLXEngine.decaps(dk, ct, "QLX-4096")
        t_nat = time.perf_counter() - t0
        self.assertEqual(ss_nat, ss_ref)
        self.assertEqual(ss_py, ss_ref)
        self.assertLess(t_nat, t_py)

    def test_03_wire_format_v3_and_strict_beta_magic_rejection(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.1.0-pc")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/PC-1.1.4")
        payload = b"OpenQPEP Production Candidate 1.1.4 strict wire payload"
        label = "CALYX QPEP MESSAGE"

        f_v3 = pack_wire_frame(payload, label)
        self.assertTrue(f_v3.startswith(WIRE_MAGIC_V3))
        out_v3, _ = unpack_wire_frame(f_v3, label)
        self.assertEqual(out_v3, payload)

        # All legacy beta wire magics MUST be strictly rejected in PC 1.1.4
        for legacy_magic in (b"\x89QPE\x01\x01", b"\x89QPE\x01\x09", b"\x89QPE\x02\x00"):
            forged = legacy_magic + os.urandom(64)
            with self.assertRaises(QPEPWireFormatError):
                unpack_wire_frame(forged, label)

    def test_04_sovereign_pentad_wire_v3_and_native_plain_lwe(self):
        pk, sk = PlainLWEEngine.keygen(n=32, nbar=8)
        ct, ss = PlainLWEEngine.encaps(pk)
        set_native_enabled(True)
        self.assertEqual(PlainLWEEngine.decaps(sk, ct), ss)
        set_native_enabled(False)
        self.assertEqual(PlainLWEEngine.decaps(sk, ct), ss)

        set_native_enabled(True)
        pub, priv = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
        msg = b"Sovereign-Pentad PC 1.1.4 strict v3 directive"
        armored_v3 = CalyxSovereignPentad.encrypt(msg, pub)
        sep = armored_v3.find("\n\n")
        end = armored_v3.rfind("\n=")
        raw_v3 = base64.b64decode("".join(armored_v3[sep + 2 : end].split()))
        self.assertTrue(raw_v3.startswith(WIRE_MAGIC_V3))
        self.assertEqual(raw_v3[6], PACKET_TYPE_PENTAD)
        self.assertEqual(CalyxSovereignPentad.decrypt(armored_v3, priv), msg)

    def test_05_kat_vectors_identical_native_and_pure_python(self):
        vec_dir = Path(__file__).resolve().parent.parent / "vectors"
        set_native_enabled(True)
        ok_nat, _ = verify_all_kats(vec_dir)
        self.assertTrue(ok_nat)
        set_native_enabled(False)
        ok_py, _ = verify_all_kats(vec_dir)
        self.assertTrue(ok_py)


if __name__ == "__main__":
    unittest.main()
