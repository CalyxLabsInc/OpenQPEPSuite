# OpenQPEP Production Candidate 1.1.4 (v1.1.4-pc)
"""OpenQPEP Supersingular Isogeny Cryptography Plugin (CIF-SQI-512)."""
from .sqi_2d_512 import SQI_PRIME_512, Fp2, SupersingularIsogenyEngine

__all__ = ["SQI_PRIME_512", "Fp2", "SupersingularIsogenyEngine"]
