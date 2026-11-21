# OpenQPEP Production Candidate 1.1.7 (v1.1.7-pc)
"""Canonical .qpkrf export/import codec facade under calyx_qpep.keyring."""
from ..protocol import OpenQPEPProtocol, QPEPKeyRing


def export_qpkrf(keyring: QPEPKeyRing, include_private: bool = False) -> str:
    return OpenQPEPProtocol.export_qpkrf(keyring, include_private=include_private)


def import_qpkrf(armored_qpkrf: str) -> QPEPKeyRing:
    return OpenQPEPProtocol.import_qpkrf(armored_qpkrf)


__all__ = ["export_qpkrf", "import_qpkrf"]
