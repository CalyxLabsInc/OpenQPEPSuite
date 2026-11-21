"""
Unit tests for OpenQPEP Production Candidate 1.1.7 Post-Quantum Double Ratchet (QPEP-Ratchet):
  - Bidirectional Forward Secrecy & per-message CC-512 ratcheting
  - Out-of-order delivery via bounded skipped-key cache (MAX_SKIP = 256)
  - Periodic hybrid QLX + HGC-448 PCS re-encapsulation across epochs
  - TTL expiration scrubbing & session destroy() memory zeroization
"""
import os
import time
import unittest

from calyx_qpep.exceptions import QPEPMacVerificationError, QPEPWireFormatError
from calyx_qpep.ratchet import MAX_SKIP, QPEPRatchetSession


class TestOpenQPEPv025PQRatchet(unittest.TestCase):
    def test_01_bidirectional_forward_secrecy_and_replay_rejection(self):
        alice, bob = QPEPRatchetSession.create_pair(os.urandom(32), qlx_tier="QLX-768")
        c0 = alice.encrypt(b"Message 0 from Alice")
        c1 = alice.encrypt(b"Message 1 from Alice")
        r0 = bob.encrypt(b"Reply 0 from Bob")

        p0, m0 = bob.decrypt(c0)
        p1, m1 = bob.decrypt(c1)
        pr0, mr0 = alice.decrypt(r0)

        self.assertEqual(p0, b"Message 0 from Alice")
        self.assertEqual(p1, b"Message 1 from Alice")
        self.assertEqual(pr0, b"Reply 0 from Bob")
        self.assertEqual((m0["msg_num"], m1["msg_num"], mr0["msg_num"]), (0, 1, 0))

        # Replaying an already-consumed message must fail (Forward Secrecy key already wiped)
        with self.assertRaises(QPEPMacVerificationError):
            bob.decrypt(c0)

    def test_02_out_of_order_delivery_via_skipped_key_cache(self):
        alice, bob = QPEPRatchetSession.create_pair(os.urandom(32), qlx_tier="QLX-768")
        packets = [alice.encrypt(f"Packet #{i}".encode("utf-8")) for i in range(5)]

        # Deliver severely out of order: 3, 1, 4, 0, 2
        order = [3, 1, 4, 0, 2]
        for idx in order:
            pt, meta = bob.decrypt(packets[idx])
            self.assertEqual(pt, f"Packet #{idx}".encode("utf-8"))
            if idx in (1, 0, 2):
                self.assertTrue(meta["from_skipped_cache"])

    def test_03_periodic_pq_pcs_rekey_across_epochs(self):
        # Trigger automatic QLX + HGC-448 PCS re-encapsulation every 3 messages
        alice, bob = QPEPRatchetSession.create_pair(
            os.urandom(32), qlx_tier="QLX-768", rekey_interval_messages=3
        )
        # Send 7 messages (epochs 0, 1, 2)
        pkts = [alice.encrypt(f"PCS Msg {i}".encode("utf-8")) for i in range(7)]
        self.assertEqual(alice.send_epoch, 2)

        rekey_events = 0
        for i, pkt in enumerate(pkts):
            pt, meta = bob.decrypt(pkt)
            self.assertEqual(pt, f"PCS Msg {i}".encode("utf-8"))
            if meta["pcs_rekey"]:
                rekey_events += 1
        self.assertEqual(rekey_events, 2)
        self.assertEqual(bob.recv_epoch, 2)

    def test_04_skipped_key_ttl_zeroization_and_session_destroy(self):
        alice, bob = QPEPRatchetSession.create_pair(
            os.urandom(32), qlx_tier="QLX-768", skipped_key_ttl_seconds=10
        )
        p0 = alice.encrypt(b"Delayed 0")
        p1 = alice.encrypt(b"Delivered 1")
        # Delivering p1 caches key for p0
        pt1, _ = bob.decrypt(p1)
        self.assertEqual(pt1, b"Delivered 1")
        self.assertEqual(len(bob._skipped_keys), 1)

        # Simulate TTL expiry -> key must be zeroized and evicted
        evicted = bob.purge_expired_skipped_keys(now_ts=time.time() + 20)
        self.assertEqual(evicted, 1)
        self.assertEqual(len(bob._skipped_keys), 0)
        with self.assertRaises(QPEPMacVerificationError):
            bob.decrypt(p0)

        # Destroy wipes all RAM buffers
        alice.destroy()
        bob.destroy()
        self.assertEqual(bytes(alice._root_key), b"\x00" * 32)
        self.assertEqual(bytes(bob._send_ck), b"\x00" * 32)
        with self.assertRaises(RuntimeError):
            alice.encrypt(b"after destroy")

    def test_05_max_skip_bound_enforced(self):
        self.assertEqual(MAX_SKIP, 256)
        alice, bob = QPEPRatchetSession.create_pair(os.urandom(32), qlx_tier="QLX-768", rekey_interval_messages=500)
        # Advance Alice beyond MAX_SKIP without delivering to Bob
        last_pkt = None
        for i in range(MAX_SKIP + 2):
            last_pkt = alice.encrypt(b"x")
        with self.assertRaises(QPEPWireFormatError):
            bob.decrypt(last_pkt)


if __name__ == "__main__":
    unittest.main()
