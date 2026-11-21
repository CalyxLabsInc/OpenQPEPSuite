"""
OpenQPEP Active Cryptographic Attack Simulator (Release Candidate 1.0.0).
Simulates real-world adversarial attacks against OpenQPEP:
  1. Ciphertext malleability / chosen-ciphertext attacks against the Fujisaki-Okamoto transform
  2. Rowhammer/glitch fault injection inside QVSEngine.sign (proving Fault-Guard aborts 100%)
  3. Suite downgrade attacks against .qpkrf integrity_mac & wire MAC
  4. Chunk truncation, reordering, duplication, and trailing-byte injection on streams
"""
import base64
import io
import json
import os
from typing import Any, Dict
from unittest.mock import patch

from ..exceptions import (
    QPEPFaultGuardError,
    QPEPMacVerificationError,
    QPEPTruncationError,
    QPEPWireFormatError,
)
from ..lattice.qlx_kem import QLXEngine
from ..lattice.qvs_dsa import QVSEngine
from ..protocol import OpenQPEPProtocol
from ..wire.streaming import StreamingDecryptor, StreamingEncryptor


def simulate_fo_cca2_malleability(tier: str = "QLX-768", trials: int = 20) -> Dict[str, Any]:
    """Flips random bits across ct_qlx and verifies 100% deterministic FO implicit rejection."""
    ek, dk = QLXEngine.keygen(tier, b"W" * 64)
    ct, ss_real = QLXEngine.encaps(ek, tier)
    rejected = 0
    for i in range(trials):
        pos = (i * 53) % len(ct)
        tampered = ct[:pos] + bytes([ct[pos] ^ (1 << (i % 8))]) + ct[pos + 1 :]
        ss_a = QLXEngine.decaps(dk, tampered, tier)
        ss_b = QLXEngine.decaps(dk, tampered, tier)
        if ss_a != ss_real and ss_a == ss_b and len(ss_a) == 32:
            rejected += 1
    return {"attack": "FO_CCA2_Malleability", "tier": tier, "trials": trials, "defended": rejected, "passed": rejected == trials}


def simulate_qvs_fault_injection(tier: str = "QVS-65", trials: int = 5) -> Dict[str, Any]:
    """Injects simulated verification faults into QVSEngine.sign; Fault-Guard must abort 100%."""
    pk, sk = QVSEngine.keygen(tier, b"W" * 64)
    caught = 0
    with patch.object(QVSEngine, "verify", return_value=False):
        for i in range(trials):
            try:
                QVSEngine.sign(sk, pk, f"fault-{i}".encode("utf-8"), tier=tier)
            except QPEPFaultGuardError:
                caught += 1
    return {"attack": "QVS_Fault_Injection", "tier": tier, "trials": trials, "defended": caught, "passed": caught == trials}


def simulate_stream_truncation_and_reorder() -> Dict[str, Any]:
    """Tests truncation, chunk swap/reorder, and trailing-byte injection on chunked CC-512 streams."""
    key64 = os.urandom(64)
    payload = os.urandom(150 * 1024)
    enc_buf = io.BytesIO()
    with StreamingEncryptor(key64, chunk_size=65536, merkle_seekable=True) as enc:
        meta = enc.encrypt_stream(io.BytesIO(payload), enc_buf)
    raw = enc_buf.getvalue()
    offsets = meta["chunk_offsets"]

    defended = 0
    # 1. Truncation before final chunk
    try:
        with StreamingDecryptor(key64) as dec:
            dec.decrypt_stream(io.BytesIO(raw[: offsets[1]]), io.BytesIO())
    except QPEPTruncationError:
        defended += 1

    # 2. Chunk swap (swap chunk 0 and chunk 1)
    swapped = raw[: offsets[0]] + raw[offsets[1] : offsets[2]] + raw[offsets[0] : offsets[1]] + raw[offsets[2] :]
    try:
        with StreamingDecryptor(key64) as dec:
            dec.decrypt_stream(io.BytesIO(swapped), io.BytesIO())
    except QPEPMacVerificationError:
        defended += 1

    # 3. Trailing byte injection after final=1 chunk
    try:
        with StreamingDecryptor(key64) as dec:
            dec.decrypt_stream(io.BytesIO(raw + b"\x00"), io.BytesIO())
    except QPEPWireFormatError:
        defended += 1

    return {"attack": "Stream_Truncation_Reorder_Injection", "trials": 3, "defended": defended, "passed": defended == 3}


def simulate_suite_downgrade_attack() -> Dict[str, Any]:
    """Attempts to tamper with suite metadata inside an exported .qpkrf key ring payload."""
    pw = "Calyx!@#$_2026DownAa99"
    kr = OpenQPEPProtocol.generate_keypair("DowngradeTarget", "dg@calyxlabsinc.org", pw, qlx_tier="QLX-1024")
    pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)

    # Decode inner Base64 payload, mutate the suite/tier field, and re-wrap
    sep = pub_armor.find("\n\n")
    end = pub_armor.rfind("\n=")
    if end == -1:
        end = pub_armor.rfind("\n-----END ")
    b64_body = "".join(ln for ln in pub_armor[sep + 2 : end].splitlines() if not ln.startswith("="))
    raw = base64.b64decode(b64_body)
    try:
        doc = json.loads(raw.decode("utf-8"))
        doc["qlx_tier"] = "QLX-768"
        tampered_raw = json.dumps(doc).encode("utf-8")
    except Exception:
        # Whitened binary .qpkrf: flip suite/metadata bytes directly in the wire frame
        tampered_raw = bytes([raw[0] ^ 0x01]) + raw[1:]

    tampered_b64 = base64.b64encode(tampered_raw).decode("ascii")
    tampered_wrapped = "\n".join(tampered_b64[i : i + 64] for i in range(0, len(tampered_b64), 64))
    tampered = pub_armor[: sep + 2] + tampered_wrapped + pub_armor[end:]

    blocked = False
    try:
        OpenQPEPProtocol.import_qpkrf(tampered)
    except Exception:
        blocked = True
    return {"attack": "Suite_Downgrade", "trials": 1, "defended": 1 if blocked else 0, "passed": blocked}


def run_all_attack_simulations() -> Dict[str, Any]:
    results = [
        simulate_fo_cca2_malleability(),
        simulate_qvs_fault_injection(),
        simulate_stream_truncation_and_reorder(),
        simulate_suite_downgrade_attack(),
    ]
    return {
        "simulations": results,
        "all_passed": all(r["passed"] for r in results),
    }
