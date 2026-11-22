"""
OpenQPEP Compact Binary TLV Wire Format v5.1 (\\x89QPE\\x05\\x01) — Official Release 1.0.0.
Replaces verbose JSON + Base64 inner envelopes with canonical sorted Tag-Length-Value (TLV)
binary records, reducing serialized packet overhead by ~28–35% while retaining full qSponge-XOF
whitening and 256-bit qSponge-512 MAC authentication.

Hard Clean Break: Strictly rejects ALL legacy -rc (\\x04\\x00 / \\x04\\x01), -pc (\\x03\\x00 / \\x03\\x01),
and -beta frames with QPEPLegacyProtocolError.
Hardening: Strictly rejects duplicate TLV tags, reserved flags, and truncated/trailing bytes.
"""
import os
import struct
from typing import Dict, Tuple

from ..constants import (
    ALL_LEGACY_WIRE_MAGICS,
    MAX_WIRE_FRAME_BYTES,
    WIRE_MAGIC_V5_1,
)
from ..exceptions import QPEPLegacyProtocolError, QPEPMacVerificationError, QPEPWireFormatError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var


def encode_tlv(fields: Dict[int, bytes]) -> bytes:
    """Encodes a dict of {tag_u8: raw_bytes} into canonical tag-sorted TLV binary."""
    out = bytearray()
    for tag in sorted(fields.keys()):
        if not (0 <= tag <= 255):
            raise QPEPWireFormatError(f"TLV tag out of uint8 range: {tag}")
        val = fields[tag]
        if not isinstance(val, (bytes, bytearray)):
            raise QPEPWireFormatError(f"TLV value for tag {tag} must be bytes.")
        out.append(tag & 0xFF)
        out.extend(struct.pack(">I", len(val)))
        out.extend(val)
    return bytes(out)


def decode_tlv(raw: bytes) -> Dict[int, bytes]:
    """Decodes binary TLV records, strictly rejecting duplicate tags and truncated records."""
    out: Dict[int, bytes] = {}
    idx = 0
    n = len(raw)
    while idx < n:
        if idx + 5 > n:
            raise QPEPWireFormatError("Truncated TLV header in Compact Wire v5.1.")
        tag = raw[idx]
        if tag in out:
            raise QPEPWireFormatError(f"Duplicate TLV tag 0x{tag:02x} rejected in Compact Wire v5.1.")
        length = struct.unpack(">I", raw[idx + 1 : idx + 5])[0]
        idx += 5
        if idx + length > n:
            raise QPEPWireFormatError("Truncated TLV value in Compact Wire v5.1.")
        out[tag] = raw[idx : idx + length]
        idx += length
    return out


def pack_compact_v51(fields: Dict[int, bytes], label: str, packet_type: int = 0x01, flags: int = 0x00) -> bytes:
    """Packs canonical TLV fields into Compact Binary Wire Format v5.1 (\\x89QPE\\x05\\x01)."""
    if flags != 0:
        raise QPEPWireFormatError("Reserved Compact Wire v5.1 flag bits must be zero.")
    body = encode_tlv(fields)
    if len(body) > MAX_WIRE_FRAME_BYTES:
        raise QPEPWireFormatError("Compact Wire v5.1 payload exceeds maximum frame size.")
    wire_nonce = os.urandom(16)
    hdr = WIRE_MAGIC_V5_1 + bytes([packet_type & 0xFF, flags & 0xFF])
    lbl = label.encode("ascii")
    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v51-1.0.0|" + hdr + wire_nonce + lbl, len(body))
    whitened = bytes(a ^ b for a, b in zip(body, mask))
    mac = qsponge_512(b"CALYX-WIRE-MAC-v51-1.0.0|" + hdr + wire_nonce + lbl + whitened)[:32]
    return hdr + wire_nonce + whitened + mac


def unpack_compact_v51(frame: bytes, label: str) -> Tuple[Dict[int, bytes], int, int]:
    """Unpacks and verifies a Compact Binary Wire Format v5.1 (\\x89QPE\\x05\\x01) frame."""
    if len(frame) > MAX_WIRE_FRAME_BYTES:
        raise QPEPWireFormatError("Compact Wire v5.1 frame exceeds maximum allowed size.")
    if len(frame) < 6:
        raise QPEPWireFormatError("Truncated Compact Wire v5.1 frame.")
    magic = frame[:6]
    if magic in ALL_LEGACY_WIRE_MAGICS:
        raise QPEPLegacyProtocolError(
            "Legacy pre-release (-rc / -pc / -beta) compact wire frame rejected in Official Release 1.0.0 "
            "(zero backwards compatibility). Compact TLV v5.1 (\\x89QPE\\x05\\x01) is required."
        )
    if magic != WIRE_MAGIC_V5_1 or len(frame) < 56:
        raise QPEPWireFormatError("Invalid or truncated Compact Wire v5.1 frame.")

    hdr = frame[:8]
    if hdr[7] != 0:
        raise QPEPWireFormatError("Non-zero reserved flag bits in Compact Wire v5.1 header.")
    wire_nonce = frame[8:24]
    whitened = frame[24:-32]
    mac = frame[-32:]
    lbl = label.encode("ascii")

    expected = qsponge_512(b"CALYX-WIRE-MAC-v51-1.0.0|" + hdr + wire_nonce + lbl + whitened)[:32]
    if not ct_eq(mac, expected):
        raise QPEPMacVerificationError("Compact Wire v5.1 MAC verification failed.")

    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v51-1.0.0|" + hdr + wire_nonce + lbl, len(whitened))
    body = bytes(a ^ b for a, b in zip(whitened, mask))
    return decode_tlv(body), hdr[6], hdr[7]
