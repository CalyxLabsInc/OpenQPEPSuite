"""
OpenQPEP Zero-Metadata ASCII Armor Encoder & Decoder — Production Candidate 1.0.0 (v1.0.0-pc).
Wraps Frozen Wire Format v3 (\x89QPE\x03\x00) binary frames with zero cleartext identity headers.
"""
import base64
from typing import Dict, List, Optional, Tuple

from ..constants import PROTOCOL_VERSION, UNIVERSAL_VERSION_LABEL
from ..exceptions import QPEPWireFormatError
from ..primitives.qsponge import qsponge_512
from .framing import pack_wire_frame, unpack_wire_frame


def armor_wrap(
    header_label: str,
    payload_bytes: bytes,
    meta_headers: Optional[Dict[str, str]] = None,
    *,
    packet_type: Optional[int] = None,
    flags: int = 0,
) -> str:
    wire_frame = pack_wire_frame(payload_bytes, header_label, packet_type=packet_type, flags=flags)
    b64 = base64.b64encode(wire_frame).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    crc = base64.b64encode(qsponge_512(wire_frame)[:3]).decode("ascii")

    out: List[str] = [f"-----BEGIN {header_label}-----"]
    hdrs = meta_headers if meta_headers is not None else {
        "Version": f"{PROTOCOL_VERSION} ({UNIVERSAL_VERSION_LABEL})",
        "Cipher": "Calyx-Cascade-512 (CC-512)",
    }
    for k, v in hdrs.items():
        if k in ("Sender-Key-Hash", "Recipient-Key-Hash", "Signer-Key-Hash"):
            continue
        out.append(f"{k}: {v}")
    out.append("")
    out.extend(lines)
    out.append(f"={crc}")
    out.append(f"-----END {header_label}-----")
    return "\n".join(out)


def armor_unwrap(armored_text: str, expected_label: str) -> Tuple[bytes, Dict[str, str]]:
    begin_marker = f"-----BEGIN {expected_label}-----"
    end_marker = f"-----END {expected_label}-----"
    lines = [l.strip() for l in armored_text.strip().splitlines()]
    if begin_marker not in lines or end_marker not in lines:
        raise QPEPWireFormatError(f"Missing armored markers for {expected_label}.")
    start_idx = lines.index(begin_marker) + 1
    end_idx = lines.index(end_marker)
    headers: Dict[str, str] = {}
    b64_parts: List[str] = []
    in_body = False
    for line in lines[start_idx:end_idx]:
        if not in_body:
            if line == "":
                in_body = True
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
                continue
            in_body = True
        if line.startswith("="):
            continue
        if line:
            b64_parts.append(line)
    raw_frame = base64.b64decode("".join(b64_parts))
    payload_bytes, _nonce = unpack_wire_frame(raw_frame, expected_label)
    return payload_bytes, headers
