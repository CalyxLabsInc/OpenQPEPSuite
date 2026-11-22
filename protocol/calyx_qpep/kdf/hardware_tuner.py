"""
OpenQPEP Hardware Auto-Tuner for QPKD-Argon2id Key Derivation (Official Release 1.0.0 / kdf_version: 4).
Calibrates memory-hard parameters (m_kib, t_cost, p_lanes) for standard devices
(64 MiB, t=3, p=4), Calyx Hyper-Tesseract flagship hardware (256 MiB, t=4, p=4),
or low-RAM constrained environments (32 MiB, t=3, p=2).
"""
import os
import time
from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class KDFHardwareProfile:
    profile_name: str
    m_kib: int
    t_cost: int
    p_lanes: int
    detected_ram_mib: int
    detected_cpus: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "hardware_profile": self.profile_name,
            "m_kib": self.m_kib,
            "t_cost": self.t_cost,
            "p_lanes": self.p_lanes,
            "detected_ram_mib": self.detected_ram_mib,
            "detected_cpus": self.detected_cpus,
        }


def detect_system_ram_mib() -> int:
    """Returns total system RAM in MiB without external dependencies."""
    try:
        if hasattr(os, "sysconf"):
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            if isinstance(pages, int) and isinstance(page_size, int) and pages > 0:
                return max(512, (pages * page_size) // (1024 * 1024))
    except (OSError, ValueError, AttributeError):
        pass
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return max(512, kb // 1024)
    except (OSError, ValueError, AttributeError):
        pass
    return 4096


def select_kdf_profile(qlx_tier: str = "QLX-4096", override_ram_mib: int = 0) -> KDFHardwareProfile:
    """
    Auto-tunes QPKD-Argon2id parameters per OpenQPEP Official Release 1.0.0 specification:
      - Calyx Hyper-Tesseract (QLX-16384): m = 262,144 KiB (256 MiB), t = 4, p = 4 (when RAM >= 4 GiB)
      - Standard devices (QLX-768 .. QLX-4096): m = 65,536 KiB (64 MiB), t = 3, p = 4
      - Low-RAM constrained devices (< 1.5 GiB usable RAM): m = 32,768 KiB (32 MiB), t = 3, p = 2
    """
    ram_mib = override_ram_mib if override_ram_mib > 0 else detect_system_ram_mib()
    cpus = max(1, os.cpu_count() or 2)
    is_tesseract = "16384" in str(qlx_tier) or "Tesseract" in str(qlx_tier)

    if is_tesseract and ram_mib >= 4096:
        return KDFHardwareProfile(
            profile_name="hyper_tesseract_256m",
            m_kib=262144,
            t_cost=4,
            p_lanes=min(4, max(1, cpus)),
            detected_ram_mib=ram_mib,
            detected_cpus=cpus,
        )
    if ram_mib < 1536:
        return KDFHardwareProfile(
            profile_name="constrained_32m",
            m_kib=32768,
            t_cost=3,
            p_lanes=min(2, max(1, cpus)),
            detected_ram_mib=ram_mib,
            detected_cpus=cpus,
        )
    return KDFHardwareProfile(
        profile_name="standard_64m",
        m_kib=65536,
        t_cost=3,
        p_lanes=min(4, max(1, cpus)),
        detected_ram_mib=ram_mib,
        detected_cpus=cpus,
    )


def benchmark_kdf(qlx_tier: str = "QLX-4096") -> Dict[str, object]:
    """Benchmarks QPKD-Argon2id (kdf_version: 4) derivation latency on the current hardware."""
    from .argon2id_cascade import derive_qpkrf_keys_v4

    profile = select_kdf_profile(qlx_tier)
    salt = b"\x42" * 32
    t0 = time.perf_counter()
    _k1, _k2, _kmac, params = derive_qpkrf_keys_v4(
        "Calyx!@#$_2026BenchAa99", salt, qlx_tier=qlx_tier
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "qlx_tier": qlx_tier,
        "kdf_version": params["kdf_version"],
        "profile": profile.profile_name,
        "backend": params["backend"],
        "m_kib": params["m_kib"],
        "t_cost": params["t_cost"],
        "p_lanes": params["p_lanes"],
        "elapsed_ms": elapsed_ms,
    }
