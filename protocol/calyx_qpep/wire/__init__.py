"""OpenQPEP Binary Wire Framing, Zero-Metadata Armor, File Registry & Multi-Recipient Engine (Production Candidate 1.1.0)."""
from .framing import BUCKET_SIZES, pad_to_bucket, unpad_from_bucket, pack_wire_frame, unpack_wire_frame
from .armor import armor_wrap, armor_unwrap
from .file_registry import SUPPORTED_FILE_EXTENSIONS, detect_file_extension_and_mime
from .multi_recipient import (
    MULTI_RECIPIENT_ARMOR_LABEL,
    compute_blinded_slot_tag,
    encrypt_multi_recipient,
    decrypt_multi_recipient,
)

from .streaming import (
    STREAM_MAGIC, FLAG_MERKLE_SEEKABLE, derive_chunk_nonce24,
    build_chunk_merkle_tree, get_merkle_proof, verify_merkle_proof,
    StreamingEncryptor, StreamingDecryptor,
)

__all__ = [
    "STREAM_MAGIC", "FLAG_MERKLE_SEEKABLE", "derive_chunk_nonce24",
    "build_chunk_merkle_tree", "get_merkle_proof", "verify_merkle_proof",
    "StreamingEncryptor", "StreamingDecryptor",

    "BUCKET_SIZES", "pad_to_bucket", "unpad_from_bucket", "pack_wire_frame", "unpack_wire_frame",
    "armor_wrap", "armor_unwrap",
    "SUPPORTED_FILE_EXTENSIONS", "detect_file_extension_and_mime",
    "MULTI_RECIPIENT_ARMOR_LABEL", "compute_blinded_slot_tag",
    "encrypt_multi_recipient", "decrypt_multi_recipient",
]
