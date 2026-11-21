"""OpenQPEP Adversarial Security Audit Suite: Wire Fuzzer, Attack Simulator & Timing Audit (Production Candidate 1.1.4)."""
from .fuzz_wire import fuzz_wire_parsers
from .attack_sim import (
    simulate_fo_cca2_malleability,
    simulate_qvs_fault_injection,
    simulate_stream_truncation_and_reorder,
    simulate_suite_downgrade_attack,
    run_all_attack_simulations,
)
from .timing_audit import welch_t_statistic, audit_ct_cmov_timing, audit_qlx_decaps_timing

__all__ = [
    "fuzz_wire_parsers",
    "simulate_fo_cca2_malleability",
    "simulate_qvs_fault_injection",
    "simulate_stream_truncation_and_reorder",
    "simulate_suite_downgrade_attack",
    "run_all_attack_simulations",
    "welch_t_statistic",
    "audit_ct_cmov_timing",
    "audit_qlx_decaps_timing",
]
