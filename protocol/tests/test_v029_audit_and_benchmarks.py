"""
Unit tests for OpenQPEP Production Candidate 1.1.7 Adversarial Audit Suite, Wire Fuzzer,
Welch's t-Test Side-Channel Timing Audit & 6-Suite Benchmark Harness.
"""
import unittest

from benchmarks.bench_suites import format_markdown_table, run_benchmarks
from calyx_qpep.audit import (
    audit_ct_cmov_timing,
    audit_qlx_decaps_timing,
    fuzz_wire_parsers,
    run_all_attack_simulations,
    welch_t_statistic,
)


class TestOpenQPEPv029AuditAndBenchmarks(unittest.TestCase):
    def test_01_wire_format_mutation_fuzzer_zero_crashes(self):
        # Fast 300-mutation CI pass (CLI supports 10,000+ iterations)
        rep = fuzz_wire_parsers(iterations=300, seed=0x2026)
        self.assertTrue(rep["passed"])
        self.assertEqual(rep["unhandled_crashes"], 0)
        self.assertEqual(rep["false_accepts"], 0)

    def test_02_active_cryptographic_attack_simulator_all_defended(self):
        rep = run_all_attack_simulations()
        self.assertTrue(rep["all_passed"])
        self.assertEqual(len(rep["simulations"]), 4)

    def test_03_welch_t_test_and_side_channel_timing_audit(self):
        self.assertAlmostEqual(welch_t_statistic([10, 11, 10, 11], [10, 11, 10, 11]), 0.0, places=5)
        r1 = audit_ct_cmov_timing(samples=200)
        self.assertIn("welch_t", r1)
        r2 = audit_qlx_decaps_timing(tier="QLX-768", samples=10)
        self.assertIn("welch_t", r2)
        self.assertGreater(r2["mean_valid_ms"], 0.0)

    def test_04_benchmark_harness_markdown_export(self):
        rows = run_benchmarks(include_heavy=False)
        self.assertGreaterEqual(len(rows), 3)
        md = format_markdown_table(rows)
        self.assertIn("Calyx Sovereign-Pentad", md)
        self.assertIn("Peak RSS (MiB)", md)


if __name__ == "__main__":
    unittest.main()
