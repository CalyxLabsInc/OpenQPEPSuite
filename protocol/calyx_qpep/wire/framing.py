"""
OpenQPEP Official Binary Wire Framing v5 (\\x89QPE\\x05\\x00) & Standardized Traffic-Analysis Padding
(Official Release 1.0.0 / v1.0.0 — Clean-Slate Zero Legacy Backwards Compatibility).

Binary Wire Format v5 Layout:
  - Bytes 0..5   : WIRE_MAGIC_V5 (\\x89QPE\\x05\\x00)
  - Byte  6      : packet_type (0x01=Single, 0x02=Multi-Recipient, 0x03=Stream, 0x04=Ratchet,
                   0x05=Multisig, 0x06=Sovereign-Pentad, 0x07=Keyring, 0x08=Signature, 0x09=GroupMLS)
  - Byte  7      : flags (bit 0 = standardized bucket padding active; bits 1..7 reserved 0)
  - Bytes 8..23  : 16-byte CSPRNG wire_nonce
  - Bytes 24..-32: whitened payload = payload ^ qSponge-XOF("CALYX-WIRE-WHITEN-v5-1.0.0|" || hdr || nonce || label)
  - Bytes -32..  : 32-byte wire MAC = qSponge-512("CALYX-WIRE-MAC-v5-1.0.0|" || hdr || nonce || label || whitened)[:32]

Hard Clean Break:
  ALL legacy Release Candidate (-rc: \\x89QPE\\x04\\x00 / \\x04\\x01), Production Candidate
  (-pc: \\x89QPE\\x03\\x00 / \\x03\\x01), and Beta (-beta: \\x89QPE\\x01\\x01 / \\x01\\x09 / \\x02\\x00)
  frames are strictly rejected with QPEPLegacyProtocolError.
"""
import os
import struct
from typing import Tuple

from ..constants import (
    ALL_LEGACY_WIRE_MAGICS,
    BUCKET_SIZES,
    LEGACY_BETA_WIRE_MAGICS,
    LEGACY_PC_WIRE_MAGICS,
    LEGACY_RC_WIRE_MAGICS,
    MAX_WIRE_FRAME_BYTES,
    PACKET_TYPE_SINGLE,
    WIRE_MAGIC_V5,
)
from ..exceptions import QPEPLegacyProtocolError, QPEPMacVerificationError, QPEPWireFormatError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var

WIRE_FLAG_BUCKET_PADDED = 0x01


def pad_to_bucket(data: bytes, bucket_size: int = 4096) -> bytes:
    """
    Standardized Traffic-Analysis Padding (4 KiB / 16 KiB / 64 KiB buckets).
    Format: [4-byte big-endian original length][data][CSPRNG random padding up to next multiple of bucket_size].
    """
    if bucket_size <= 0:
        raise ValueError("bucket_size must be positive.")
    raw = struct.pack(">I", len(data)) + data
    rem = len(raw) % bucket_size
    pad_len = (bucket_size - rem) if rem != 0 else 0
    return raw + (os.urandom(pad_len) if pad_len else b"")


def unpad_from_bucket(padded: bytes) -> bytes:
    """Reverses standardized bucket padding and validates length bounds."""
    if len(padded) < 4:
        raise QPEPWireFormatError("Truncated padded OpenQPEP bucket.")
    orig_len = struct.unpack(">I", padded[:4])[0]
    if 4 + orig_len > len(padded):
        raise QPEPWireFormatError("Corrupted padded OpenQPEP bucket length header.")
    return padded[4 : 4 + orig_len]


def pack_wire_frame(
    payload: bytes,
    label: str,
    *,
    packet_type: int = PACKET_TYPE_SINGLE,
    flags: int = 0,
    bucket_size: int = 0,
) -> bytes:
    """
    Packs `payload` into Official Release 1.0.0 Binary Wire Format v5 (\\x89QPE\\x05\\x00).
    """
    if len(payload) > MAX_WIRE_FRAME_BYTES:
        raise QPEPWireFormatError(f"Wire frame payload exceeds maximum limit ({MAX_WIRE_FRAME_BYTES} bytes).")
    if flags & ~WIRE_FLAG_BUCKET_PADDED:
        raise QPEPWireFormatError("Reserved Wire Format v5 header flag bits must be zero.")

    body = payload
    eff_flags = flags & 0xFF
    if bucket_size and bucket_size > 0:
        body = pad_to_bucket(payload, bucket_size=bucket_size)
        eff_flags |= WIRE_FLAG_BUCKET_PADDED

    wire_nonce = os.urandom(16)
    hdr = WIRE_MAGIC_V5 + bytes([packet_type & 0xFF, eff_flags])
    lbl = label.encode("ascii")
    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v5-1.0.0|" + hdr + wire_nonce + lbl, len(body))
    whitened = bytes(a ^ b for a, b in zip(body, mask))
    mac = qsponge_512(b"CALYX-WIRE-MAC-v5-1.0.0|" + hdr + wire_nonce + lbl + whitened)[:32]
    return hdr + wire_nonce + whitened + mac


def unpack_wire_frame(frame: bytes, label: str) -> Tuple[bytes, int]:
    """
    Unpacks and authenticates an Official Release 1.0.0 Binary Wire Format v5 (\\x89QPE\\x05\\x00) frame.
    Strictly rejects ALL legacy -rc, -pc, and -beta wire magics with QPEPLegacyProtocolError.
    Returns (plaintext_payload, packet_type).
    """
    if len(frame) > MAX_WIRE_FRAME_BYTES:
        raise QPEPWireFormatError(f"Wire frame exceeds maximum allowed size ({MAX_WIRE_FRAME_BYTES} bytes).")
    if len(frame) < 6:
        raise QPEPWireFormatError("Truncated OpenQPEP wire frame.")

    magic = frame[:6]
    if magic in LEGACY_RC_WIRE_MAGICS:
        raise QPEPLegacyProtocolError(
            "Legacy Release Candidate (-rc) wire format (\\x89QPE\\x04\\x00 / \\x04\\x01) is strictly rejected in "
            "OpenQPEP Official Release 1.0.0 (zero backwards compatibility). Re-encrypt using Wire Format v5 (\\x89QPE\\x05\\x00)."
        )
    if magic in LEGACY_PC_WIRE_MAGICS:
        raise QPEPLegacyProtocolError(
            "Legacy Production Candidate (-pc) wire format (\\x89QPE\\x03\\x00 / \\x03\\x01) is strictly rejected in "
            "OpenQPEP Official Release 1.0.0 (zero backwards compatibility)."
        )
    if magic in LEGACY_BETA_WIRE_MAGICS:
        raise QPEPLegacyProtocolError(
            "Legacy Beta (-beta) wire format is strictly rejected in OpenQPEP Official Release 1.0.0."
        )
    if magic != WIRE_MAGIC_V5:
        raise QPEPWireFormatError(
            f"Unsupported OpenQPEP wire magic ({magic.hex().upper()}); Official Release 1.0.0 requires Wire Format v5 (895150450500)."
        )
    if len(frame) < 56:  # 6 magic + 2 hdr + 16 nonce + 32 mac
        raise QPEPWireFormatError("Truncated OpenQPEP Wire Format v5 frame.")

    hdr = frame[:8]
    packet_type = hdr[6]
    flags = hdr[7]
    if flags & ~WIRE_FLAG_BUCKET_PADDED:
        raise QPEPWireFormatError("Non-zero reserved flag bits in Wire Format v5 header.")

    wire_nonce = frame[8:24]
    whitened = frame[24:-32]
    mac = frame[-32:]
    lbl = label.encode("ascii")

    expected_mac = qsponge_512(b"CALYX-WIRE-MAC-v5-1.0.0|" + hdr + wire_nonce + lbl + whitened)[:32]
    if not ct_eq(mac, expected_mac):
        raise QPEPMacVerificationError("OpenQPEP Wire Format v5 frame MAC verification failed.")

    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v5-1.0.0|" + hdr + wire_nonce + lbl, len(whitened))
    body = bytes(a ^ b for a, b in zip(whitened, mask))
    if flags & WIRE_FLAG_BUCKET_PADDED:
        body = unpad_from_bucket(body)
    return body, packet_type
