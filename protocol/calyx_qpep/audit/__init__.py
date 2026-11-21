"""OpenQPEP Adversarial Security Audit Suite: Wire Fuzzer, Attack Simulator, Timing Audit & 5-Language Interop Matrix (Release Candidate 1.0.0)."""
from .fuzz_wire import fuzz_wire_parsers, validate_webview_bridge_command
from .attack_sim import (
    simulate_fo_cca2_malleability,
    simulate_qvs_fault_injection,
    simulate_stream_truncation_and_reorder,
    simulate_suite_downgrade_attack,
    run_all_attack_simulations,
)
from .timing_audit import (
    welch_t_statistic,
    audit_ct_cmov_timing,
    audit_qlx_decaps_timing,
    run_full_constant_time_audit,
)
from .interop_matrix import run_cross_language_interop_matrix

__all__ = [
    "fuzz_wire_parsers",
    "validate_webview_bridge_command",
    "simulate_fo_cca2_malleability",
    "simulate_qvs_fault_injection",
    "simulate_stream_truncation_and_reorder",
    "simulate_suite_downgrade_attack",
    "run_all_attack_simulations",
    "welch_t_statistic",
    "audit_ct_cmov_timing",
    "audit_qlx_decaps_timing",
    "run_full_constant_time_audit",
    "run_cross_language_interop_matrix",
]
