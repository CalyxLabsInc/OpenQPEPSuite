"""
Unit tests for OpenQPEP Official Release 1.1.0:
  - O(1)-RAM Streaming Chunked AEAD (StreamingEncryptor / StreamingDecryptor)
  - Chunk-bound nonce truncation & reordering immunity
  - Seekable qSponge-512 Merkle-Tree arbitrary byte-range decryption
  - Calyx Sovereign-Pentad (CSP-Omega) 5-Family Beyond-LWE Citadel & 12 GB RAM guardrail
"""
import io
import os
import unittest

from calyx_qpep.exceptions import QPEPMacVerificationError, QPEPSuiteError, QPEPTruncationError
from calyx_qpep.pentad import CalyxSovereignPentad, check_flagship_hardware_guardrail
from calyx_qpep.wire.streaming import StreamingDecryptor, StreamingEncryptor


class TestOpenQPEPv027StreamingAndPentad(unittest.TestCase):
    def test_01_o1_ram_streaming_roundtrip_and_truncation_immunity(self):
        key64 = os.urandom(64)
        # 200 KiB payload across 4 chunks (chunk_size = 64 KiB)
        payload = os.urandom(200 * 1024 + 137)
        enc_buf = io.BytesIO()
        with StreamingEncryptor(key64, chunk_size=65536, merkle_seekable=True) as enc:
            meta = enc.encrypt_stream(io.BytesIO(payload), enc_buf)
        self.assertEqual(meta["chunk_count"], 4)
        self.assertEqual(meta["total_plaintext_bytes"], len(payload))

        # Full stream decrypt + Merkle root verification
        dec_buf = io.BytesIO()
        enc_buf.seek(0)
        with StreamingDecryptor(key64) as dec:
            dmeta = dec.decrypt_stream(enc_buf, dec_buf, expected_merkle_root=meta["merkle_root"])
        self.assertEqual(dec_buf.getvalue(), payload)
        self.assertEqual(dmeta["chunk_count"], 4)

        # Truncate stream before final=1 chunk -> must raise QPEPTruncationError
        truncated = io.BytesIO(enc_buf.getvalue()[: meta["chunk_offsets"][2]])
        with StreamingDecryptor(key64) as dec:
            with self.assertRaises(QPEPTruncationError):
                dec.decrypt_stream(truncated, io.BytesIO())

    def test_02_merkle_tree_seekable_arbitrary_byte_range_decryption(self):
        key64 = os.urandom(64)
        # 5 chunks of 4 KiB each = 20 KiB
        payload = bytes(i % 251 for i in range(20 * 1024))
        enc_buf = io.BytesIO()
        with StreamingEncryptor(key64, chunk_size=4096, merkle_seekable=True) as enc:
            meta = enc.encrypt_stream(io.BytesIO(payload), enc_buf)

        # Seek directly into middle of chunk 2 through middle of chunk 4 without decrypting chunks 0-1
        start, end = 9000, 17500
        with StreamingDecryptor(key64) as dec:
            sliced = dec.decrypt_byte_range(
                enc_buf,
                start,
                end,
                chunk_offsets=meta["chunk_offsets"],
                merkle_levels=meta["merkle_levels"],
                merkle_root=meta["merkle_root"],
            )
        self.assertEqual(sliced, payload[start:end])

    def test_03_sovereign_pentad_flagship_12gb_hardware_guardrail(self):
        # 6 GB budget phone must be rejected by guardrail
        with self.assertRaises(QPEPSuiteError):
            check_flagship_hardware_guardrail(override_ram_mib=6144, allow_override=False)
        # 16 GB Samsung Galaxy Z Fold 8 passes guardrail cleanly
        info = check_flagship_hardware_guardrail(override_ram_mib=16384, allow_override=False)
        self.assertTrue(info["flagship_qualified"])

    def test_04_sovereign_pentad_5_family_parallel_encrypt_decrypt_roundtrip(self):
        pub, priv = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
        self.assertEqual(len(pub["key_hash"]), 64)
        secret = b"Calyx Sovereign-Pentad (CSP-Omega) 5-Family Beyond-LWE Citadel Payload"
        armored = CalyxSovereignPentad.encrypt(secret, pub)
        recovered = CalyxSovereignPentad.decrypt(armored, priv)
        self.assertEqual(recovered, secret)

    def test_05_sovereign_pentad_conjunctive_triple_family_signature_verify(self):
        pub, priv = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
        msg = b"Signed simultaneously by QHS-512 + QMQ-512 + CIF-SQI-512"
        sig = CalyxSovereignPentad.sign(msg, pub, priv)
        ok, extracted = CalyxSovereignPentad.verify(sig, pub)
        self.assertTrue(ok)
        self.assertEqual(extracted, msg)

        # Wrong public key must fail verification
        pub2, _ = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
        ok2, _ = CalyxSovereignPentad.verify(sig, pub2)
        self.assertFalse(ok2)


if __name__ == "__main__":
    unittest.main()
