"""
OpenQPEP Protocol Constants, Lattice Suite Parameters, and Frozen Wire Format v4 Identifiers
(Release Candidate 1.0.0 / v1.0.0-rc — Graduated from v2.0.0-pc).
Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).
"""
from typing import Dict

PROJECT_NAME = "OpenQPEP by Calyx Labs Inc."
APP_NAME = "Calyx QPEP Client"
UNIVERSAL_VERSION = "1.0.0-rc"
UNIVERSAL_VERSION_LABEL = "Release Candidate 1.0.0"
PROTOCOL_VERSION = "OpenQPEP/RC-1.0.0"
RELEASE_CHANNEL = "RC"
API_STABILITY = "v1.0.0-rc-frozen"
LICENSE_SPDX = "CPOSLS-1.0"
DEFAULT_SUITE = "Signature QLX-4096 + QVS-256"
QPKRF_EXTENSION = ".qpkrf"
CHUNK_SIZE = 65536

# Strict Release Candidate 1.0.0 Wire Magics (Wire Format v4 / v4.1)
# Zero backwards-compatibility: all legacy -pc (\x89QPE\x03\x00, \x89QPE\x03\x01) and -beta wire magics are strictly rejected.
WIRE_MAGIC_V4 = b"\x89QPE\x04\x00"
WIRE_MAGIC_V4_1 = b"\x89QPE\x04\x01"
LEGACY_PC_WIRE_MAGICS = (b"\x89QPE\x03\x00", b"\x89QPE\x03\x01")
LEGACY_BETA_WIRE_MAGICS = (b"\x89QPE\x01\x01", b"\x89QPE\x01\x09", b"\x89QPE\x02\x00")
WIRE_MAGIC = WIRE_MAGIC_V4
SUPPORTED_WIRE_MAGICS = (WIRE_MAGIC_V4, WIRE_MAGIC_V4_1)

# Unified Wire Format v4 Packet Type Identifiers
PACKET_TYPE_SINGLE = 0x01
PACKET_TYPE_MULTI = 0x02
PACKET_TYPE_STREAM = 0x03
PACKET_TYPE_RATCHET = 0x04
PACKET_TYPE_MULTISIG = 0x05
PACKET_TYPE_PENTAD = 0x06
PACKET_TYPE_KEYRING = 0x07
PACKET_TYPE_SIGNATURE = 0x08
PACKET_TYPE_GROUP = 0x09

CALYX_HYPER_TESSERACT_HARDWARE_WARNING = (
    "WARNING — HIGH-TIER HARDWARE REQUIRED (Calyx Hyper-Tesseract: QLX-16384 + QVS-1024): "
    "This 16,384-dimensional 4-manifold lattice tier performs ~320,000+ NTT butterfly operations "
    "and stores ~69.3 KB of raw secret lattice vectors per key ring. Use ONLY on flagship high-RAM "
    "smartphones (e.g., Samsung Galaxy Z Fold 8, Galaxy S25/S26 Ultra, Pixel 10 Pro with 12 GB+ RAM) "
    "or high-spec desktop/server PCs. Running Calyx Hyper-Tesseract on low-tier or budget phones "
    "(<=6 GB RAM) can cause severe UI freezes, Android ANR timeouts, thermal throttling, or WebView "
    "Out-Of-Memory (OOM) crashes. Use Calyx Signature (QLX-4096 + QVS-256) on standard devices."
)

QLX_Q = 3329
QLX_N = 256
QLX_ZETA = 17


def _bitrev7(x: int) -> int:
    r = 0
    for _ in range(7):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


_ZETAS_3329 = [pow(QLX_ZETA, _bitrev7(i), QLX_Q) for i in range(128)]
_ZETAS_BASE_3329 = [pow(QLX_ZETA, 2 * _bitrev7(i) + 1, QLX_Q) for i in range(128)]
_INV_128_3329 = pow(128, QLX_Q - 2, QLX_Q)

QLX_TIERS = {
    "QLX-768": {
        "k": 3, "du": 10, "dv": 4,
        "pk_bytes": 384 * 3 + 32,
        "sk_bytes": 384 * 3 + (384 * 3 + 32) + 64,
        "ct_bytes": 320 * 3 + 128,
        "qvs_tier": "QVS-65",
    },
    "QLX-1024": {
        "k": 4, "du": 11, "dv": 5,
        "pk_bytes": 384 * 4 + 32,
        "sk_bytes": 384 * 4 + (384 * 4 + 32) + 64,
        "ct_bytes": 352 * 4 + 160,
        "qvs_tier": "QVS-87",
    },
    "QLX-2048": {
        "k": 8, "du": 11, "dv": 5,
        "pk_bytes": 384 * 8 + 32,
        "sk_bytes": 384 * 8 + (384 * 8 + 32) + 64,
        "ct_bytes": 352 * 8 + 160,
        "qvs_tier": "QVS-128",
    },
    "QLX-4096": {
        "k": 16, "manifolds": 1, "du": 11, "dv": 5,
        "pk_bytes": 384 * 16 + 32,
        "sk_bytes": 384 * 16 + (384 * 16 + 32) + 64,
        "ct_bytes": 352 * 16 + 160,
        "qvs_tier": "QVS-256",
        "nickname": "Calyx Signature",
        "high_tier_only": False,
    },
    "QLX-16384": {
        "k": 64, "manifolds": 4, "du": 11, "dv": 5,
        "pk_bytes": 384 * 64 + 32,
        "sk_bytes": 384 * 64 + (384 * 64 + 32) + 64,
        "ct_bytes": 352 * 64 + 160 * 4,
        "qvs_tier": "QVS-1024",
        "nickname": "Calyx Hyper-Tesseract",
        "high_tier_only": True,
    },
}

QVS_Q = 8380417
QVS_ZETA = 1753
QVS_GAMMA1 = 1 << 19
QVS_GAMMA2 = (QVS_Q - 1) // 32
QVS_ALPHA = 2 * QVS_GAMMA2


def _bitrev8(x: int) -> int:
    r = 0
    for _ in range(8):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


_ZETAS_QVS = [pow(QVS_ZETA, _bitrev8(i), QVS_Q) for i in range(256)]
_INV_256_QVS = pow(256, QVS_Q - 2, QVS_Q)

QVS_TIERS = {
    "QVS-65": {
        "k": 3, "l": 2, "eta": 2, "tau": 39, "beta": 78,
        "pk_bytes": 32 + 3 * 256 * 3,
        "sk_bytes": 128 + (2 + 3) * 256 + 3 * 256 * 3,
        "sig_bytes": 64 + 2 * 256 * 3,
    },
    "QVS-87": {
        "k": 4, "l": 3, "eta": 2, "tau": 49, "beta": 98,
        "pk_bytes": 32 + 4 * 256 * 3,
        "sk_bytes": 128 + (3 + 4) * 256 + 4 * 256 * 3,
        "sig_bytes": 64 + 3 * 256 * 3,
    },
    "QVS-128": {
        "k": 6, "l": 5, "eta": 2, "tau": 60, "beta": 120,
        "pk_bytes": 32 + 6 * 256 * 3,
        "sk_bytes": 128 + (5 + 6) * 256 + 6 * 256 * 3,
        "sig_bytes": 64 + 5 * 256 * 3,
    },
    "QVS-256": {
        "k": 8, "l": 7, "eta": 2, "tau": 60, "beta": 120,
        "pk_bytes": 32 + 8 * 256 * 3,
        "sk_bytes": 128 + (7 + 8) * 256 + 8 * 256 * 3,
        "sig_bytes": 64 + 7 * 256 * 3,
    },
    "QVS-1024": {
        "k": 16, "l": 14, "eta": 2, "tau": 60, "beta": 120,
        "pk_bytes": 32 + 16 * 256 * 3,
        "sk_bytes": 128 + (14 + 16) * 256 + 16 * 256 * 3,
        "sig_bytes": 64 + 14 * 256 * 3,
    },
}

# Canonical 10-Suite Unified Registry (Release Candidate 1.0.0 / v1.0.0-rc)
# Strict uniform format: "Calyx <Key-Name>: <KEM-XXXX> + <SIG-XXXX> (<Key Tier Short Description>)"
ALL_TEN_SUITES = {
    "QLX-4096": {
        "display_name": "Calyx Signature: QLX-4096 + QVS-256 (Recommended Default — All Devices)",
        "high_tier_only": False,
    },
    "QLX-768": {
        "display_name": "Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)",
        "high_tier_only": False,
    },
    "QLX-1024": {
        "display_name": "Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)",
        "high_tier_only": False,
    },
    "QLX-2048": {
        "display_name": "Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)",
        "high_tier_only": False,
    },
    "QLX-16384": {
        "display_name": "Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)",
        "high_tier_only": True,
    },
    "CGM-8192": {
        "display_name": "Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)",
        "high_tier_only": True,
    },
    "CIF-SQI-512": {
        "display_name": "Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)",
        "high_tier_only": False,
    },
    "CRT-RSD512": {
        "display_name": "Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (Rank-Syndrome Code-Based — All Devices)",
        "high_tier_only": False,
    },
    "CULC-2048": {
        "display_name": "Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)",
        "high_tier_only": True,
    },
    "CSP-Omega": {
        "display_name": "Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (5-Family Beyond-LWE Citadel — HIGH-TIER HARDWARE ONLY)",
        "high_tier_only": True,
    },
}
