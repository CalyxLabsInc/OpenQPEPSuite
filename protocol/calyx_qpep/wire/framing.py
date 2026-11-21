"""
OpenQPEP Frozen Binary Wire Format v3 (\x89QPE\x03\x00) — Production Candidate 1.1.0 (v1.1.0-pc).
All legacy beta wire formats (\x89QPE\x01\x01, \x89QPE\x01\x09, \x89QPE\x02\x00) are strictly rejected.
"""
import os
import struct
from typing import Optional, Tuple

from ..constants import (
    PACKET_TYPE_KEYRING,
    PACKET_TYPE_MULTI,
    PACKET_TYPE_MULTISIG,
    PACKET_TYPE_PENTAD,
    PACKET_TYPE_RATCHET,
    PACKET_TYPE_SIGNATURE,
    PACKET_TYPE_SINGLE,
    PACKET_TYPE_STREAM,
    WIRE_MAGIC_V3,
)
from ..exceptions import QPEPMacVerificationError, QPEPWireFormatError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var

BUCKET_SIZES = (4096, 16384, 65536)


def infer_packet_type(header_label: str) -> int:
    lbl = header_label.upper()
    if "PENTAD" in lbl:
        return PACKET_TYPE_PENTAD
    if "MULTI" in lbl and "SIG" not in lbl:
        return PACKET_TYPE_MULTI
    if "MULTISIG" in lbl or "THRESHOLD" in lbl:
        return PACKET_TYPE_MULTISIG
    if "RATCHET" in lbl:
        return PACKET_TYPE_RATCHET
    if "STREAM" in lbl:
        return PACKET_TYPE_STREAM
    if "KEY" in lbl or "QPKRF" in lbl or "REVOCATION" in lbl or "SHARE" in lbl:
        return PACKET_TYPE_KEYRING
    if "SIGNATURE" in lbl or "TIMESTAMP" in lbl:
        return PACKET_TYPE_SIGNATURE
    return PACKET_TYPE_SINGLE


def pad_to_bucket(payload: bytes, bucket_size: int = 4096) -> bytes:
    if bucket_size < 64:
        raise ValueError("bucket_size must be at least 64 bytes.")
    header = struct.pack(">I", len(payload))
    total_raw = 4 + len(payload)
    padded_len = ((total_raw + bucket_size - 1) // bucket_size) * bucket_size
    pad_len = padded_len - total_raw
    return header + payload + (os.urandom(pad_len) if pad_len > 0 else b"")


def unpad_from_bucket(padded: bytes) -> bytes:
    if len(padded) < 4:
        raise QPEPWireFormatError("Padded bucket buffer is too short.")
    orig_len = struct.unpack(">I", padded[:4])[0]
    if 4 + orig_len > len(padded):
        raise QPEPWireFormatError("Invalid bucket padding length prefix.")
    return padded[4 : 4 + orig_len]


def pack_wire_frame(
    payload_bytes: bytes,
    header_label: str,
    *,
    packet_type: Optional[int] = None,
    flags: int = 0,
) -> bytes:
    """Encapsulates payload_bytes into a strict Frozen Wire Format v3 (\x89QPE\x03\x00) frame."""
    wire_nonce = os.urandom(16)
    label_b = header_label.encode("utf-8")
    ptype = infer_packet_type(header_label) if packet_type is None else (packet_type & 0xFF)
    hdr = WIRE_MAGIC_V3 + bytes([ptype, flags & 0xFF])
    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v3|" + hdr + wire_nonce + label_b, len(payload_bytes))
    whitened = bytes(a ^ b for a, b in zip(payload_bytes, mask))
    wire_mac = qsponge_512(b"CALYX-WIRE-MAC-v3|" + hdr + wire_nonce + label_b + whitened)[:32]
    return hdr + wire_nonce + whitened + wire_mac


def unpack_wire_frame(raw_frame: bytes, begin_label: str) -> Tuple[bytes, bytes]:
    """
    Verifies the 256-bit wire MAC and unwhitens a Frozen Wire Format v3 (\x89QPE\x03\x00) frame.
    Strictly rejects all legacy beta wire magics (\x89QPE\x01\x01, \x01\x09, \x02\x00).
    """
    if not raw_frame.startswith(WIRE_MAGIC_V3):
        raise QPEPWireFormatError(
            "Unsupported or legacy beta wire magic. OpenQPEP Production Candidate 1.1.0 requires Wire Format v3 (\x89QPE\x03\x00)."
        )
    if len(raw_frame) < 8 + 16 + 32:
        raise QPEPWireFormatError("Truncated OpenQPEP Wire Format v3 frame.")
    label_b = begin_label.encode("utf-8")
    hdr = raw_frame[:8]
    wire_nonce = raw_frame[8:24]
    whitened = raw_frame[24:-32]
    wire_mac = raw_frame[-32:]
    expected_mac = qsponge_512(b"CALYX-WIRE-MAC-v3|" + hdr + wire_nonce + label_b + whitened)[:32]
    if not ct_eq(wire_mac, expected_mac):
        raise QPEPMacVerificationError("Wire Format v3 integrity MAC verification failed.")
    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v3|" + hdr + wire_nonce + label_b, len(whitened))
    payload_bytes = bytes(a ^ b for a, b in zip(whitened, mask))
    return payload_bytes, wire_nonce
