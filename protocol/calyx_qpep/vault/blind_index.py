# OpenQPEP Release Candidate 1.0.0 (v1.0.0-rc)
"""
QPEP-Vault: Zero-knowledge keyed qSponge-512 blind-indexed search over encrypted records.
"""
import os
import re
from typing import Dict, List, Set

from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512


class BlindSearchVault:
    def __init__(self, master_key64: bytes):
        self._enc_key = qsponge_512(b"CALYX-VAULT-ENC|" + master_key64)
        self._idx_key = qsponge_512(b"CALYX-VAULT-IDX|" + master_key64)
        self._records: Dict[str, tuple[bytes, bytes]] = {}
        self._index: Dict[str, Set[str]] = {}

    def _trapdoor(self, token: str) -> str:
        norm = token.strip().lower().encode("utf-8")
        return qsponge_512(b"CALYX-VAULT-TRAP|" + self._idx_key + norm)[:16].hex()

    def put(self, doc_id: str, text: str) -> None:
        nonce24 = os.urandom(24)
        ct = cc512_encrypt(self._enc_key, nonce24, text.encode("utf-8"), doc_id.encode("utf-8"))
        self._records[doc_id] = (nonce24, ct)
        for tok in set(re.findall(r"[a-zA-Z0-9_]{2,}", text)):
            td = self._trapdoor(tok)
            self._index.setdefault(td, set()).add(doc_id)

    def search(self, query_token: str) -> List[tuple[str, str]]:
        td = self._trapdoor(query_token)
        hits = []
        for doc_id in sorted(self._index.get(td, set())):
            nonce24, ct = self._records[doc_id]
            pt = cc512_decrypt(self._enc_key, nonce24, ct, doc_id.encode("utf-8")).decode("utf-8")
            hits.append((doc_id, pt))
        return hits
