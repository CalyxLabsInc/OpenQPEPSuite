"""
OpenQPEP v1.0.0-rc (Release Candidate 1.0.0) — Compact Binary Wire Format v4.1 (\x89QPE\x04\x01).
Replaces inner JSON + Base64 field overhead with deterministic length-prefixed TLV records
inside the whitened binary wire frame, cutting packet overhead by ~28–35%.
Zero backwards-compatibility with any legacy Production Candidate (-pc) or Beta wire formats.
"""
import os
import struct
from typing import Dict, Tuple

from ..constants import LEGACY_BETA_WIRE_MAGICS, LEGACY_PC_WIRE_MAGICS, WIRE_MAGIC_V4_1
from ..exceptions import QPEPLegacyProtocolError, QPEPMacVerificationError, QPEPWireFormatError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var


def encode_tlv(fields: Dict[int, bytes]) -> bytes:
    out = bytearray()
    for tag in sorted(fields.keys()):
        val = fields[tag]
        out.extend(struct.pack(">BI", tag & 0xFF, len(val)))
        out.extend(val)
    return bytes(out)


def decode_tlv(buf: bytes) -> Dict[int, bytes]:
    fields: Dict[int, bytes] = {}
    idx = 0
    n = len(buf)
    while idx < n:
        if idx + 5 > n:
            raise QPEPWireFormatError("Truncated TLV header in Wire Format v4.1 frame.")
        tag, length = struct.unpack(">BI", buf[idx : idx + 5])
        idx += 5
        if idx + length > n:
            raise QPEPWireFormatError("Truncated TLV value in Wire Format v4.1 frame.")
        fields[tag] = buf[idx : idx + length]
        idx += length
    return fields


def pack_compact_v41(fields: Dict[int, bytes], header_label: str, *, packet_type: int = 0x01, flags: int = 0) -> bytes:
    tlv = encode_tlv(fields)
    hdr = WIRE_MAGIC_V4_1 + bytes([packet_type & 0xFF, flags & 0xFF])
    wire_nonce = os.urandom(16)
    label_b = header_label.encode("utf-8")
    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v41-RC-1.0.0|" + hdr + wire_nonce + label_b, len(tlv))
    whitened = bytes(a ^ b for a, b in zip(tlv, mask))
    wire_mac = qsponge_512(b"CALYX-WIRE-MAC-v41-RC-1.0.0|" + hdr + wire_nonce + label_b + whitened)[:32]
    return hdr + wire_nonce + whitened + wire_mac


def unpack_compact_v41(raw_frame: bytes, begin_label: str) -> Tuple[Dict[int, bytes], int, bytes]:
    if len(raw_frame) >= 6 and raw_frame[:6] in (LEGACY_PC_WIRE_MAGICS + LEGACY_BETA_WIRE_MAGICS):
        raise QPEPLegacyProtocolError(
            "Legacy Production Candidate (-pc) or Beta compact wire format is strictly rejected in Release Candidate v1.0.0 (\\x89QPE\\x04\\x01 required)."
        )
    if not raw_frame.startswith(WIRE_MAGIC_V4_1):
        raise QPEPLegacyProtocolError("Invalid or legacy compact wire magic; \\x89QPE\\x04\\x01 required in RC 1.0.0.")
    if len(raw_frame) < 8 + 16 + 32:
        raise QPEPWireFormatError("Invalid or truncated Wire Format v4.1 frame.")
    hdr = raw_frame[:8]
    packet_type = hdr[6]
    wire_nonce = raw_frame[8:24]
    whitened = raw_frame[24:-32]
    wire_mac = raw_frame[-32:]
    label_b = begin_label.encode("utf-8")
    expected = qsponge_512(b"CALYX-WIRE-MAC-v41-RC-1.0.0|" + hdr + wire_nonce + label_b + whitened)[:32]
    if not ct_eq(wire_mac, expected):
        raise QPEPMacVerificationError("Wire Format v4.1 integrity MAC verification failed.")
    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v41-RC-1.0.0|" + hdr + wire_nonce + label_b, len(whitened))
    tlv = bytes(a ^ b for a, b in zip(whitened, mask))
    return decode_tlv(tlv), packet_type, wire_nonce
