"""
OpenQPEP Anonymous Mixed-Tier Multi-Recipient Broadcast Encryption (Production Candidate 1.1.4).

Features:
  1. Single-Pass CEK Encryption: Encrypts payload once with a fresh 512-bit CC-512 Content
     Encryption Key (CEK), optionally padded to a 4 KiB / 16 KiB / 64 KiB traffic-analysis bucket.
  2. Mixed-Tier Recipient Slots: Encapsulates the 64-byte CEK independently for N recipients
     across ANY combination of OpenQPEP suites (QLX-768, QLX-1024, QLX-2048, Calyx Signature
     QLX-4096, and Calyx Hyper-Tesseract QLX-16384).
  3. Anonymous Blinded Recipient Slots: Never writes recipient Key Hashes into the packet.
     Uses either a blinded 64-bit hint `H_slot = qSponge-XOF("CALYX-SLOT-TAG|" || slot_nonce || key_hash, 8)`
     or pure trial-decapsulation (`blind_hint=False`), with cryptographically shuffled slot order.
  4. Dummy Slot Padding: Optionally pads recipient slot count to the next power of 2 (4, 8, 16, ...)
     with indistinguishable random-looking dummy ciphertexts so observers cannot learn recipient count.
"""
import base64
import json
import os
import secrets
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..constants import PROTOCOL_VERSION, QLX_TIERS, UNIVERSAL_VERSION
from ..exceptions import QPEPKeyRingError, QPEPMacVerificationError, QPEPWireFormatError
from ..lattice.qlx_kem import QLXEngine
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.consttime import ct_eq
from ..primitives.hgc448 import x448_exchange, x448_keygen
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer
from .armor import armor_unwrap, armor_wrap
from .framing import pad_to_bucket, unpad_from_bucket

MULTI_RECIPIENT_ARMOR_LABEL = "CALYX QPEP MULTI-RECIPIENT PACKET"


def compute_blinded_slot_tag(slot_nonce: bytes, recipient_key_hash: str) -> bytes:
    """Computes the 64-bit anonymous blinded slot hint H_slot = qSponge-XOF('CALYX-SLOT-TAG|' || slot_nonce || key_hash, 8)."""
    return qsponge_var(b"CALYX-SLOT-TAG|" + slot_nonce + recipient_key_hash.encode("ascii"), 8)


def _next_power_of_two(n: int, minimum: int = 4) -> int:
    p = max(1, minimum)
    while p < n:
        p <<= 1
    return p


def _make_dummy_slot(slot_nonce: bytes, tier: str = "QLX-4096", use_blind_hint: bool = True) -> Dict[str, Any]:
    """Generates an indistinguishable random dummy recipient slot matching real ciphertext geometry."""
    ct_len = QLX_TIERS.get(tier, QLX_TIERS["QLX-4096"])["ct_bytes"]
    # Wrapped 64B CEK under CC-512 = 64 + 16 (AES-GCM tag) + 16 (ChaCha20-Poly1305 tag) = 96 bytes
    return {
        "slot_tag_hex": os.urandom(8).hex() if use_blind_hint else "",
        "qlx_tier": tier,
        "ct_qlx_b64": base64.b64encode(os.urandom(ct_len)).decode("ascii"),
        "epk_hgc_b64": base64.b64encode(os.urandom(56)).decode("ascii"),
        "wrap_nonce24_b64": base64.b64encode(os.urandom(24)).decode("ascii"),
        "wrapped_cek_b64": base64.b64encode(os.urandom(96)).decode("ascii"),
    }


def encrypt_multi_recipient(
    payload: bytes,
    recipient_keyrings: Sequence[Any],
    *,
    bucket_size: int = 4096,
    pad_slots_power_of_2: bool = True,
    min_slots: int = 4,
    use_blind_hint: bool = True,
) -> str:
    """
    Encrypts `payload` once under a fresh 512-bit CC-512 CEK (with optional standardized bucket
    payload padding) and encapsulates the CEK into anonymous mixed-tier recipient slots.
    """
    if not recipient_keyrings:
        raise QPEPKeyRingError("At least one recipient keyring is required for multi-recipient encryption.")

    slot_nonce = os.urandom(16)
    payload_nonce24 = os.urandom(24)

    # 1. Encrypt payload once with ephemeral 512-bit CC-512 CEK (actively zeroized via SecretBuffer)
    with SecretBuffer(os.urandom(64)) as cek_buf:
        cek64 = cek_buf.as_bytes()
        if bucket_size and bucket_size > 0:
            body_plain = pad_to_bucket(payload, bucket_size=bucket_size)
        else:
            body_plain = payload
        payload_aad = b"CALYX-QPEP-MULTI-PAYLOAD-v1.1.4-pc|" + slot_nonce
        payload_ct = cc512_encrypt(cek64, payload_nonce24, body_plain, payload_aad)

        # 2. Encapsulate CEK independently for each recipient (supports mixed tiers!)
        slots: List[Dict[str, Any]] = []
        tier_pool: List[str] = []
        for rkr in recipient_keyrings:
            qlx_tier = rkr.qlx_tier
            tier_pool.append(qlx_tier)
            qlx_pk = base64.b64decode(rkr.public_bundle["qlx_public_b64"])
            hgc_pk = base64.b64decode(rkr.public_bundle["hgc_448_public_b64"])

            ct_qlx, ss_qlx = QLXEngine.encaps(qlx_pk, qlx_tier)
            epk_hgc, esk_hgc = x448_keygen()
            with SecretBuffer(esk_hgc) as esk_buf:
                ss_hgc = x448_exchange(esk_buf.as_bytes(), hgc_pk)

            # Derive 512-bit per-slot KEK via qSponge-512
            with SecretBuffer(qsponge_512(b"CALYX-MULTI-SLOT-KEK|" + slot_nonce + ss_qlx + ss_hgc)) as kek_buf:
                wrap_nonce24 = os.urandom(24)
                slot_aad = b"CALYX-MULTI-SLOT-AAD|" + slot_nonce + qlx_tier.encode("ascii")
                wrapped_cek = cc512_encrypt(kek_buf.as_bytes(), wrap_nonce24, cek64, slot_aad)

            slot_tag_hex = compute_blinded_slot_tag(slot_nonce, rkr.key_hash).hex() if use_blind_hint else ""
            slots.append({
                "slot_tag_hex": slot_tag_hex,
                "qlx_tier": qlx_tier,
                "ct_qlx_b64": base64.b64encode(ct_qlx).decode("ascii"),
                "epk_hgc_b64": base64.b64encode(epk_hgc).decode("ascii"),
                "wrap_nonce24_b64": base64.b64encode(wrap_nonce24).decode("ascii"),
                "wrapped_cek_b64": base64.b64encode(wrapped_cek).decode("ascii"),
            })

    # 3. Optional dummy slot padding to power of 2 (hides exact recipient count!)
    if pad_slots_power_of_2:
        target_count = _next_power_of_two(len(slots), minimum=min_slots)
        rng = secrets.SystemRandom()
        while len(slots) < target_count:
            dummy_tier = rng.choice(tier_pool)
            slots.append(_make_dummy_slot(slot_nonce, tier=dummy_tier, use_blind_hint=use_blind_hint))

    # 4. Cryptographically shuffle slots so position leaks zero recipient ordering
    secrets.SystemRandom().shuffle(slots)

    envelope = {
        "type": "openqpep-multi-recipient",
        "version": UNIVERSAL_VERSION,
        "protocol": PROTOCOL_VERSION,
        "slot_nonce_b64": base64.b64encode(slot_nonce).decode("ascii"),
        "bucket_padded": bool(bucket_size and bucket_size > 0),
        "bucket_size": int(bucket_size) if bucket_size else 0,
        "blind_hint_enabled": bool(use_blind_hint),
        "slot_count": len(slots),
        "slots": slots,
        "payload_nonce24_b64": base64.b64encode(payload_nonce24).decode("ascii"),
        "payload_ciphertext_b64": base64.b64encode(payload_ct).decode("ascii"),
    }
    raw_json = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    return armor_wrap(MULTI_RECIPIENT_ARMOR_LABEL, raw_json)


def decrypt_multi_recipient(
    armored_packet: str,
    recipient_keyring: Any,
    passphrase: str,
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Decrypts an anonymous multi-recipient OpenQPEP packet for `recipient_keyring`.
    Uses blinded 64-bit slot hint matching (or pure trial decapsulation if blind hints are disabled).
    """
    from ..protocol import OpenQPEPProtocol

    raw_json, _headers = armor_unwrap(armored_packet, MULTI_RECIPIENT_ARMOR_LABEL)
    envelope = json.loads(raw_json.decode("utf-8"))
    if envelope.get("type") != "openqpep-multi-recipient":
        raise QPEPWireFormatError("Not a valid OpenQPEP multi-recipient packet.")

    slot_nonce = base64.b64decode(envelope["slot_nonce_b64"])
    my_tag_hex = compute_blinded_slot_tag(slot_nonce, recipient_keyring.key_hash).hex()
    priv_keys = OpenQPEPProtocol.unlock_private_keys(recipient_keyring, passphrase)
    my_qlx_sk = priv_keys["qlx_private"]
    my_hgc_sk = priv_keys["hgc_448_private"]
    my_tier = recipient_keyring.qlx_tier

    # Candidate slots: match blinded 64-bit hint if enabled, else trial-decapsulate all matching-tier slots
    candidates = []
    for idx, slot in enumerate(envelope["slots"]):
        if slot.get("qlx_tier") != my_tier:
            continue
        if envelope.get("blind_hint_enabled", True) and slot.get("slot_tag_hex"):
            if ct_eq(slot["slot_tag_hex"].encode("ascii"), my_tag_hex.encode("ascii")):
                candidates.append((idx, slot))
        else:
            candidates.append((idx, slot))

    recovered_cek: Optional[bytes] = None
    matched_slot_idx = -1

    for idx, slot in candidates:
        try:
            ct_qlx = base64.b64decode(slot["ct_qlx_b64"])
            epk_hgc = base64.b64decode(slot["epk_hgc_b64"])
            wrap_nonce24 = base64.b64decode(slot["wrap_nonce24_b64"])
            wrapped_cek = base64.b64decode(slot["wrapped_cek_b64"])

            ss_qlx = QLXEngine.decaps(my_qlx_sk, ct_qlx, my_tier)
            ss_hgc = x448_exchange(my_hgc_sk, epk_hgc)
            with SecretBuffer(qsponge_512(b"CALYX-MULTI-SLOT-KEK|" + slot_nonce + ss_qlx + ss_hgc)) as kek_buf:
                slot_aad = b"CALYX-MULTI-SLOT-AAD|" + slot_nonce + my_tier.encode("ascii")
                recovered_cek = cc512_decrypt(kek_buf.as_bytes(), wrap_nonce24, wrapped_cek, slot_aad)
                matched_slot_idx = idx
                break
        except Exception:
            continue

    if recovered_cek is None:
        raise QPEPMacVerificationError("No matching recipient slot could be decrypted with this key ring.")

    with SecretBuffer(recovered_cek) as cek_buf:
        payload_nonce24 = base64.b64decode(envelope["payload_nonce24_b64"])
        payload_ct = base64.b64decode(envelope["payload_ciphertext_b64"])
        payload_aad = b"CALYX-QPEP-MULTI-PAYLOAD-v1.1.4-pc|" + slot_nonce
        body_plain = cc512_decrypt(cek_buf.as_bytes(), payload_nonce24, payload_ct, payload_aad)

    plaintext = unpad_from_bucket(body_plain) if envelope.get("bucket_padded") else body_plain
    meta = {
        "version": envelope.get("version"),
        "slot_count": envelope.get("slot_count"),
        "matched_slot_index": matched_slot_idx,
        "recipient_tier": my_tier,
        "bucket_padded": envelope.get("bucket_padded"),
        "bucket_size": envelope.get("bucket_size"),
        "blind_hint_enabled": envelope.get("blind_hint_enabled"),
    }
    return plaintext, meta
