"""
OpenQPEP Zero-Metadata ASCII Armor Codec (Official Release 1.1.0 / Wire Format v5 \\x89QPE\\x05\\x00).

Security Guarantees:
  - Zero cleartext identity metadata headers (never emits Sender/Recipient/Signer Key Hashes).
  - Mandatory 48-bit qSponge-512 armor CRC checksum (`={crc}`), strictly verified in constant time
    via `ct_eq` on unwrap (missing or corrupted checksums are rejected!).
  - Strict armor header validation rejecting control characters and CR/LF header injection.
  - Strict max-size ceiling (`MAX_ARMOR_BYTES`) preventing memory-exhaustion DoS.
  - Strictly enforces Official Wire Format v5 (\\x89QPE\\x05\\x00) and hard-rejects all legacy
    -rc, -pc, and -beta frames with QPEPLegacyProtocolError.
"""
import base64
from typing import Dict, Optional, Tuple

from ..constants import (
    MAX_ARMOR_BYTES,
    PACKET_TYPE_SINGLE,
    PROTOCOL_VERSION,
    UNIVERSAL_VERSION_LABEL,
)
from ..exceptions import QPEPMacVerificationError, QPEPWireFormatError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_var
from .framing import pack_wire_frame, unpack_wire_frame

FORBIDDEN_ARMOR_HEADERS = frozenset({
    "sender-key-hash",
    "recipient-key-hash",
    "signer-key-hash",
    "encrypting-key-hash",
})


def _compute_armor_crc(wire_frame: bytes) -> str:
    """Computes canonical 48-bit Base64 qSponge-XOF armor checksum bound to Wire Format v5."""
    return base64.b64encode(
        qsponge_var(b"CALYX-ARMOR-CRC-v5-1.0.0|" + wire_frame, 6)
    ).decode("ascii")


def _validate_header_token(key: str, value: str) -> None:
    if any(ch in key for ch in ("\r", "\n", "\x00", ":")) or any(ch in value for ch in ("\r", "\n", "\x00")):
        raise QPEPWireFormatError("Invalid control character or header injection detected in ASCII armor header.")


def armor_wrap(
    label: str,
    payload: bytes,
    headers: Optional[Dict[str, str]] = None,
    *,
    packet_type: int = PACKET_TYPE_SINGLE,
    bucket_size: int = 0,
) -> str:
    """Wraps raw payload into Official Wire Format v5 (\\x89QPE\\x05\\x00) and zero-metadata ASCII armor."""
    wire_frame = pack_wire_frame(payload, label, packet_type=packet_type, bucket_size=bucket_size)
    b64 = base64.b64encode(wire_frame).decode("ascii")
    wrapped_lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    crc = _compute_armor_crc(wire_frame)

    hdr_lines = [
        f"Protocol: OpenQPEP ({UNIVERSAL_VERSION_LABEL})",
        f"Version: {PROTOCOL_VERSION}",
    ]
    if headers:
        for k, v in headers.items():
            if k.lower() in FORBIDDEN_ARMOR_HEADERS:
                continue
            if k.lower() in ("protocol", "version"):
                continue
            _validate_header_token(str(k), str(v))
            hdr_lines.append(f"{k}: {v}")

    return (
        f"-----BEGIN {label}-----\n"
        + "\n".join(hdr_lines)
        + "\n\n"
        + "\n".join(wrapped_lines)
        + f"\n={crc}\n"
        + f"-----END {label}-----\n"
    )


def armor_unwrap(armored: str, expected_label: str) -> Tuple[bytes, Dict[str, str]]:
    """
    Parses ASCII armor, strictly verifies the mandatory `={crc}` checksum in constant time,
    unwraps Official Wire Format v5 (\\x89QPE\\x05\\x00), and returns (payload_bytes, headers).
    """
    if not isinstance(armored, str) or len(armored) > MAX_ARMOR_BYTES:
        raise QPEPWireFormatError("ASCII armor input missing or exceeds maximum allowed size.")

    begin_marker = f"-----BEGIN {expected_label}-----"
    end_marker = f"-----END {expected_label}-----"
    lines = [ln.strip() for ln in armored.strip().splitlines()]
    try:
        start_idx = lines.index(begin_marker)
        end_idx = lines.index(end_marker, start_idx + 1)
    except ValueError as exc:
        raise QPEPWireFormatError(f"Missing or mismatched ASCII armor markers for '{expected_label}'.") from exc

    headers: Dict[str, str] = {}
    body_lines = []
    checksum_line: Optional[str] = None
    in_body = False

    for line in lines[start_idx + 1 : end_idx]:
        if not in_body:
            if line == "":
                in_body = True
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
            else:
                in_body = True
                if line.startswith("="):
                    checksum_line = line[1:].strip()
                else:
                    body_lines.append(line)
        else:
            if not line:
                continue
            if line.startswith("="):
                if checksum_line is not None:
                    raise QPEPWireFormatError("Duplicate armor checksum line detected.")
                checksum_line = line[1:].strip()
                continue
            body_lines.append(line)

    if not body_lines:
        raise QPEPWireFormatError("Empty ASCII armor payload.")

    try:
        raw_frame = base64.b64decode("".join(body_lines), validate=True)
    except Exception as exc:
        raise QPEPWireFormatError("Invalid Base64 encoding inside ASCII armor body.") from exc

    # Unpack wire frame FIRST so legacy -rc / -pc / -beta frames raise QPEPLegacyProtocolError deterministically
    payload, _ptype = unpack_wire_frame(raw_frame, expected_label)

    # Strictly enforce constant-time armor CRC verification
    if not checksum_line:
        raise QPEPMacVerificationError("Missing mandatory OpenQPEP ASCII armor checksum line (=CRC).")
    expected_crc = _compute_armor_crc(raw_frame)
    if not ct_eq(checksum_line.encode("ascii", errors="ignore"), expected_crc.encode("ascii")):
        raise QPEPMacVerificationError("OpenQPEP ASCII armor checksum verification failed.")

    return payload, headers
