# OpenQPEP Production Candidate 1.1.4 (v1.1.4-pc)
"""OpenQPEP Stateless Hash-Based Signature Hypertree Plugin (QHS-512 over qSponge-512)."""
from .qhs_512_hypertree import QHS512HypertreeEngine

__all__ = ["QHS512HypertreeEngine"]
