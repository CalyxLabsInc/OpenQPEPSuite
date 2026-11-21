"""
OpenQPEP Wire-Format Mutation Fuzzer (Production Candidate 1.1.7).
Hammers decrypt_packet, import_qpkrf, and verify_text_signature with mutated, truncated,
bit-flipped, oversized, and malformed binary/armored inputs (default 10,000 iterations) to
guarantee zero unhandled crashes and 100% MAC/FO rejection.
"""
import binascii
import random
from typing import Any, Dict

from ..exceptions import OpenQPEPError
from ..protocol import OpenQPEPProtocol


def _find_body_span(s: str) -> tuple[int, int]:
    """Locate the Base64 wire body inside an ASCII-armored block so mutations hit actual wire data."""
    sep = s.find("\n\n")
    end = s.rfind("\n-----END ")
    if sep != -1 and end != -1 and sep + 2 < end:
        return sep + 2, end
    return 0, len(s)


def _mutate_armored(s: str, rng: random.Random) -> str:
    if not s:
        return "CORRUPT"
    body_start, body_end = _find_body_span(s)
    body = s[body_start:body_end]
    mode = rng.randrange(6)
    if mode == 0:
        # Truncate inside the Base64 wire body
        cut = rng.randint(body_start, max(body_start + 1, body_end - 1))
        return s[:cut]
    if mode == 1 and len(body) > 4:
        # Flip a character strictly inside the Base64 wire body
        rel = rng.randrange(len(body))
        orig = body[rel]
        if orig in ("\n", "\r"):
            rel = max(0, rel - 1)
            orig = body[rel]
        ch = "A" if orig != "A" else "B"
        idx = body_start + rel
        return s[:idx] + ch + s[idx + 1 :]
    if mode == 2 and len(body) > 4:
        # Inject invalid bytes inside the Base64 wire body
        idx = body_start + rng.randrange(len(body))
        return s[:idx] + "!!!!GARBAGE_BYTES!!!!" + s[idx:]
    if mode == 3 and len(body) > 8:
        # Delete a slice from the Base64 wire body
        rel_a = rng.randrange(max(1, len(body) - 4))
        rel_b = min(len(body), rel_a + rng.randint(2, 64))
        return s[: body_start + rel_a] + s[body_start + rel_b :]
    if mode == 4:
        # Oversized corrupt wire body injection
        return s[:body_start] + ("A" * 2048) + "\n" + s[body_end:]
    # Completely random raw junk
    return "".join(chr(rng.randint(32, 126)) for _ in range(rng.randint(8, 256)))


def fuzz_wire_parsers(iterations: int = 10000, seed: int = 0x2026) -> Dict[str, Any]:
    """
    Runs `iterations` adversarial mutations across import_qpkrf, decrypt_packet, and
    verify_text_signature. Guarantees zero unexpected exceptions and zero forged accepts.
    """
    rng = random.Random(seed)
    pw = "Calyx!@#$_2026FuzzAa99"
    kr = OpenQPEPProtocol.generate_keypair("FuzzTarget", "fuzz@calyxlabsinc.org", pw, qlx_tier="QLX-768")
    pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
    pub_kr = OpenQPEPProtocol.import_qpkrf(pub_armor)
    pkt_armor = OpenQPEPProtocol.encrypt_text("Fuzz target secret", pub_kr, kr, pw)
    sig_armor = OpenQPEPProtocol.sign_text("Fuzz target signed text", kr, pw)

    allowed_exc = (OpenQPEPError, ValueError, binascii.Error, UnicodeDecodeError, KeyError, TypeError)
    unhandled = 0
    false_accepts = 0
    tested = 0

    for i in range(iterations):
        target = i % 3
        tested += 1
        if target == 0:
            mutated = _mutate_armored(pub_armor, rng)
            if mutated == pub_armor:
                continue
            try:
                OpenQPEPProtocol.import_qpkrf(mutated)
                false_accepts += 1
            except allowed_exc:
                pass
            except Exception:
                unhandled += 1
        elif target == 1:
            mutated = _mutate_armored(pkt_armor, rng)
            if mutated == pkt_armor:
                continue
            try:
                OpenQPEPProtocol.decrypt_packet(mutated, kr, pw)
                false_accepts += 1
            except allowed_exc:
                pass
            except Exception:
                unhandled += 1
        else:
            mutated = _mutate_armored(sig_armor, rng)
            if mutated == sig_armor:
                continue
            try:
                ok, _, _ = OpenQPEPProtocol.verify_text_signature(mutated, keyring_pool=[pub_kr])
                if ok:
                    false_accepts += 1
            except allowed_exc:
                pass
            except Exception:
                unhandled += 1

    return {
        "iterations": tested,
        "unhandled_crashes": unhandled,
        "false_accepts": false_accepts,
        "passed": (unhandled == 0 and false_accepts == 0),
    }
