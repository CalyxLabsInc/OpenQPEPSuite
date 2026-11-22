"""
OpenQPEP Cryptographic & Protocol Constants (Official Release 1.0.0 / v1.0.0).
Project: OpenQPEP by Calyx Labs Inc. (Creator: Tristen Martinez)
License: Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0)
"""
from typing import Dict

PROJECT_NAME = "OpenQPEP by Calyx Labs Inc."
APP_NAME = "OpenQPEP"
UNIVERSAL_VERSION = "1.0.0"
UNIVERSAL_VERSION_LABEL = "Official Release 1.0.0"
PROTOCOL_VERSION = "OpenQPEP/1.0.0"
RELEASE_CHANNEL = "RELEASE"
API_STABILITY = "v1.0.0-stable"
MANDATORY_KDF_VERSION = 4

DEFAULT_SUITE = "QLX-4096"
QPKRF_EXTENSION = ".qpkrf"
CHUNK_SIZE = 65536
MAX_ARMOR_BYTES = 64 * 1024 * 1024        # 64 MiB hard armor parser ceiling
MAX_WIRE_FRAME_BYTES = 64 * 1024 * 1024   # 64 MiB hard wire frame ceiling
MAX_DECOMPRESSED_BYTES = 128 * 1024 * 1024  # 128 MiB zlib decompression-bomb defense

# Hardware Warning for Calyx Hyper-Tesseract (QLX-16384 + QVS-1024) & Flagship Beyond-LWE Suites
CALYX_HYPER_TESSERACT_HARDWARE_WARNING = (
    "HIGH-TIER HARDWARE ONLY: Calyx Hyper-Tesseract (QLX-16384 + QVS-1024) requires a flagship device "
    "with >= 12 GB RAM and a modern desktop/flagship CPU (e.g., Samsung Galaxy Z Fold 8 / high-spec PC). "
    "Do NOT use on low-RAM budget devices (<= 6 GB RAM) due to ~69 KB secret vectors and heavy 16,384-dim NTT math."
)

# Official Release 1.0.0 Binary Wire Framing Constants (Clean-Slate v5 / v5.1 — Zero Legacy Compatibility)
WIRE_MAGIC_V5 = b"\x89QPE\x05\x00"        # Official Release 1.0.0 Canonical Wire Format v5
WIRE_MAGIC_V5_1 = b"\x89QPE\x05\x01"      # Official Release 1.0.0 Compact Binary TLV Wire Format v5.1
STREAM_MAGIC_V5 = b"\x89QPS\x05\x00"      # Official Release 1.0.0 O(1)-RAM Chunked Streaming AEAD Magic

# Explicitly rejected legacy magics (Release Candidate -rc, Production Candidate -pc, Beta -beta)
LEGACY_RC_WIRE_MAGICS = (b"\x89QPE\x04\x00", b"\x89QPE\x04\x01")
LEGACY_PC_WIRE_MAGICS = (b"\x89QPE\x03\x00", b"\x89QPE\x03\x01")
LEGACY_BETA_WIRE_MAGICS = (b"\x89QPE\x01\x01", b"\x89QPE\x01\x09", b"\x89QPE\x02\x00")
LEGACY_STREAM_MAGICS = (b"\x89QPS\x02\x07",)
ALL_LEGACY_WIRE_MAGICS = LEGACY_RC_WIRE_MAGICS + LEGACY_PC_WIRE_MAGICS + LEGACY_BETA_WIRE_MAGICS

# Packet type identifiers (byte 6 of Wire Format v5 / v5.1)
PACKET_TYPE_SINGLE = 0x01
PACKET_TYPE_MULTI_RECIPIENT = 0x02
PACKET_TYPE_STREAM = 0x03
PACKET_TYPE_RATCHET = 0x04
PACKET_TYPE_MULTISIG = 0x05
PACKET_TYPE_PENTAD = 0x06
PACKET_TYPE_KEYRING = 0x07
PACKET_TYPE_SIGNATURE = 0x08
PACKET_TYPE_GROUP_MLS = 0x09

# Standardized Traffic-Analysis Padding Bucket Sizes (bytes)
BUCKET_SIZES = (4096, 16384, 65536)

# ---------------------------------------------------------------------------
# QLX (Quantum Lattice Exchange — Module-LWE KEM over R_3329 = Z_3329[X]/(X^256+1))
# ---------------------------------------------------------------------------
QLX_Q = 3329
QLX_N = 256
QLX_ZETA = 17

QLX_TIERS: Dict[str, Dict[str, object]] = {
    "QLX-768": {
        "k": 3, "du": 10, "dv": 4, "manifolds": 1, "cbd": 2,
        "qvs_tier": "QVS-65",
        "pk_bytes": 1184, "sk_bytes": 2400, "ct_bytes": 1088,
        "display_name": "Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)",
        "hardware_tier": "All Devices",
        "high_tier_only": False,
    },
    "QLX-1024": {
        "k": 4, "du": 11, "dv": 5, "manifolds": 1, "cbd": 2,
        "qvs_tier": "QVS-87",
        "pk_bytes": 1568, "sk_bytes": 3168, "ct_bytes": 1568,
        "display_name": "Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)",
        "hardware_tier": "All Devices",
        "high_tier_only": False,
    },
    "QLX-2048": {
        "k": 8, "du": 11, "dv": 5, "manifolds": 1, "cbd": 2,
        "qvs_tier": "QVS-128",
        "pk_bytes": 3104, "sk_bytes": 6240, "ct_bytes": 2976,
        "display_name": "Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)",
        "hardware_tier": "All Devices",
        "high_tier_only": False,
    },
    "QLX-4096": {
        "k": 16, "du": 11, "dv": 5, "manifolds": 1, "cbd": 2,
        "qvs_tier": "QVS-256",
        "pk_bytes": 6176, "sk_bytes": 12384, "ct_bytes": 5792,
        "display_name": "Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)",
        "hardware_tier": "All Devices",
        "high_tier_only": False,
    },
    "QLX-16384": {
        "k": 64, "du": 11, "dv": 5, "manifolds": 4, "cbd": 1,
        "qvs_tier": "QVS-1024",
        "pk_bytes": 24608, "sk_bytes": 49248, "ct_bytes": 23168,
        "display_name": "Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)",
        "hardware_tier": "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)",
        "high_tier_only": True,
    },
}

# ---------------------------------------------------------------------------
# QVS (Quantum Vector Signature — Lattice Fiat-Shamir with Aborts over Z_8380417[X]/(X^256+1))
# ---------------------------------------------------------------------------
QVS_Q = 8380417
QVS_ZETA = 1753
QVS_GAMMA1 = 1 << 19
QVS_GAMMA2 = (QVS_Q - 1) // 32
QVS_ALPHA = 2 * QVS_GAMMA2

QVS_TIERS: Dict[str, Dict[str, int]] = {
    "QVS-65":   {"k": 3, "l": 2, "tau": 24, "eta": 2, "beta": 48, "pk_bytes": 32 + 3 * 768, "sk_bytes": 128 + (2 + 3) * 256 + 3 * 768, "sig_bytes": 64 + 2 * 768},
    "QVS-87":   {"k": 4, "l": 3, "tau": 32, "eta": 2, "beta": 64, "pk_bytes": 32 + 4 * 768, "sk_bytes": 128 + (3 + 4) * 256 + 4 * 768, "sig_bytes": 64 + 3 * 768},
    "QVS-128":  {"k": 6, "l": 5, "tau": 40, "eta": 2, "beta": 80, "pk_bytes": 32 + 6 * 768, "sk_bytes": 128 + (5 + 6) * 256 + 6 * 768, "sig_bytes": 64 + 5 * 768},
    "QVS-256":  {"k": 8, "l": 7, "tau": 48, "eta": 2, "beta": 96, "pk_bytes": 32 + 8 * 768, "sk_bytes": 128 + (7 + 8) * 256 + 8 * 768, "sig_bytes": 64 + 7 * 768},
    "QVS-1024": {"k": 16, "l": 14, "tau": 60, "eta": 2, "beta": 120, "pk_bytes": 32 + 16 * 768, "sk_bytes": 128 + (14 + 16) * 256 + 16 * 768, "sig_bytes": 64 + 14 * 768},
}

# ---------------------------------------------------------------------------
# All 10 Canonical OpenQPEP Post-Quantum Suites (Official Release 1.0.0)
# Uniform Naming Standard: "Calyx <Key-Name>: <KEM> + <SIG> (<Short Description>)"
# ---------------------------------------------------------------------------
ALL_TEN_SUITES: Dict[str, Dict[str, object]] = {
    "QLX-4096": {
        "display_name": "Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)",
        "kem": "QLX-4096", "sig": "QVS-256", "family": "Structured Module-LWE + HGC-448",
        "hardware_tier": "All Devices", "high_tier_only": False, "default": True,
    },
    "QLX-768": {
        "display_name": "Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)",
        "kem": "QLX-768", "sig": "QVS-65", "family": "Structured Module-LWE + HGC-448",
        "hardware_tier": "All Devices", "high_tier_only": False, "default": False,
    },
    "QLX-1024": {
        "display_name": "Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)",
        "kem": "QLX-1024", "sig": "QVS-87", "family": "Structured Module-LWE + HGC-448",
        "hardware_tier": "All Devices", "high_tier_only": False, "default": False,
    },
    "QLX-2048": {
        "display_name": "Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)",
        "kem": "QLX-2048", "sig": "QVS-128", "family": "Structured Module-LWE + HGC-448",
        "hardware_tier": "All Devices", "high_tier_only": False, "default": False,
    },
    "CIF-SQI-512": {
        "display_name": "Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)",
        "kem": "CIF-SQI-512", "sig": "QHS-512", "family": "CSIDH-512 Supersingular Isogeny + Hash Hypertree",
        "hardware_tier": "All Devices", "high_tier_only": False, "default": False,
    },
    "CRT-RSD512": {
        "display_name": "Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)",
        "kem": "CRT-RSD512", "sig": "QMQ-512", "family": "LRPC Rank-Metric Code + UOV Multivariate Quadratic",
        "hardware_tier": "All Devices", "high_tier_only": False, "default": False,
    },
    "QLX-16384": {
        "display_name": "Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)",
        "kem": "QLX-16384", "sig": "QVS-1024", "family": "4-Manifold Coupled Module-LWE + HGC-448",
        "hardware_tier": "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)", "high_tier_only": True, "default": False,
    },
    "CGM-8192": {
        "display_name": "Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)",
        "kem": "CGM-8192", "sig": "QHS-512", "family": "Binary Goppa Patterson Code + Hash Hypertree",
        "hardware_tier": "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)", "high_tier_only": True, "default": False,
    },
    "CULC-2048": {
        "display_name": "Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)",
        "kem": "CULC-2048+CGM-8192", "sig": "QHS-512", "family": "Zero-Ring Plain-LWE + Binary Goppa Patterson",
        "hardware_tier": "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)", "high_tier_only": True, "default": False,
    },
    "CSP-Omega": {
        "display_name": "Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)",
        "kem": "CSP-Omega (5-Family)", "sig": "QHS-512+QMQ-512+CIF-SQI-512", "family": "5-Family Beyond-LWE Combiner",
        "hardware_tier": "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)", "high_tier_only": True, "default": False,
    },
}
