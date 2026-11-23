"""
Unit tests for OpenQPEP Release Candidate 1.0.0 Modular Cryptographic Kernel:
  - Module layout & backward-compatible facade
  - Branchless ct_cmov & Fujisaki-Okamoto constant-time implicit rejection
  - SecretBuffer & ctypes.memset RAM zeroization
  - Typed cryptographic exception hierarchy
"""
import unittest
from unittest.mock import patch

import calyx_qpep
from calyx_qpep import (
    OpenQPEPProtocol,
    OpenQPEPError,
    QPEPPassphrasePolicyError,
    QPEPMacVerificationError,
    QPEPFaultGuardError,
    QPEPWireFormatError,
    QPEPTruncationError,
    QPEPSuiteError,
    SecretBuffer,
    zeroize_bytes,
    ct_cmov,
    ct_eq,
)
from calyx_qpep.primitives import qsponge_512, qsponge_var, cc512_encrypt, cc512_decrypt, x448_keygen, x448_exchange
from calyx_qpep.lattice import QLXEngine, QVSEngine, ntt_3329, inv_ntt_3329, derive_tesseract_manifold_seeds


class TestOpenQPEPv021ModularKernel(unittest.TestCase):
    def test_01_modular_imports_and_facade_version(self):
        self.assertEqual(calyx_qpep.__version__, "1.0.1")
        self.assertEqual(calyx_qpep.UNIVERSAL_VERSION_LABEL, "Official Release 1.0.1")
        self.assertEqual(len(derive_tesseract_manifold_seeds(b"A" * 32, 4)), 4)

    def test_02_branchless_ct_cmov_and_fo_implicit_rejection(self):
        a = b"\xAA" * 32
        b = b"\x55" * 32
        self.assertEqual(ct_cmov(True, a, b), a)
        self.assertEqual(ct_cmov(False, a, b), b)
        self.assertTrue(ct_eq(a, a))
        self.assertFalse(ct_eq(a, b))

        ek, dk = QLXEngine.keygen("QLX-768", b"W" * 64)
        ct, ss_enc = QLXEngine.encaps(ek, "QLX-768")
        ss_dec = QLXEngine.decaps(dk, ct, "QLX-768")
        self.assertEqual(ss_enc, ss_dec)

        # Flip 1 bit in ciphertext -> branchless FO implicit rejection returns deterministic 32B pseudorandom key
        tampered_ct = bytes([ct[0] ^ 0x01]) + ct[1:]
        ss_rej_1 = QLXEngine.decaps(dk, tampered_ct, "QLX-768")
        ss_rej_2 = QLXEngine.decaps(dk, tampered_ct, "QLX-768")
        self.assertEqual(len(ss_rej_1), 32)
        self.assertEqual(ss_rej_1, ss_rej_2)
        self.assertNotEqual(ss_rej_1, ss_enc)

    def test_03_secret_buffer_ctypes_zeroization(self):
        secret = b"SUPER_SECRET_LATTICE_KEY_MATERIAL_2026"
        with SecretBuffer(secret) as sb:
            raw_ref = sb.raw
            self.assertEqual(bytes(raw_ref), secret)
        # After context exit, every byte in RAM must be overwritten with 0x00
        self.assertEqual(bytes(raw_ref), b"\x00" * len(secret))
        with self.assertRaises(RuntimeError):
            _ = sb.as_bytes()

    def test_04_secret_buffer_zeroizes_on_exception(self):
        buf_ref = None
        try:
            with SecretBuffer(b"SENSITIVE_SESSION_KEY_64B") as sb:
                buf_ref = sb.raw
                raise ZeroDivisionError("simulated crash")
        except ZeroDivisionError:
            pass
        self.assertEqual(bytes(buf_ref), b"\x00" * len(b"SENSITIVE_SESSION_KEY_64B"))

    def test_05_typed_exception_hierarchy_and_cc512_mac_error(self):
        for exc_cls in [
            QPEPPassphrasePolicyError,
            QPEPMacVerificationError,
            QPEPFaultGuardError,
            QPEPWireFormatError,
            QPEPTruncationError,
            QPEPSuiteError,
        ]:
            self.assertTrue(issubclass(exc_cls, OpenQPEPError))
            self.assertTrue(issubclass(exc_cls, ValueError))

        key64 = b"K" * 64
        nonce24 = b"N" * 24
        ct = cc512_encrypt(key64, nonce24, b"hello", b"aad")
        self.assertEqual(cc512_decrypt(key64, nonce24, ct, b"aad"), b"hello")
        with self.assertRaises(QPEPMacVerificationError):
            cc512_decrypt(key64, nonce24, bytes([ct[0] ^ 0xFF]) + ct[1:], b"aad")

    def test_06_qvs_fault_guard_raises_typed_exception(self):
        pk, sk = QVSEngine.keygen("QVS-65", b"W" * 64)
        with patch.object(QVSEngine, "verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                QVSEngine.sign(sk, pk, b"fault injection test", tier="QVS-65")

    def test_07_hgc448_and_ntt_roundtrip(self):
        pub1, priv1 = x448_keygen()
        pub2, priv2 = x448_keygen()
        self.assertEqual(x448_exchange(priv1, pub2), x448_exchange(priv2, pub1))
        poly = [i % 3329 for i in range(256)]
        self.assertEqual(inv_ntt_3329(ntt_3329(poly)), poly)


if __name__ == "__main__":
    unittest.main()
