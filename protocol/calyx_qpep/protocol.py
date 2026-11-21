"""
OpenQPEP by Calyx Labs Inc. — Production Candidate 1.1.7 (v1.1.7-pc)
Canonical Post-Quantum Hybrid Protocol Reference Engine.
Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).

Wire Format: Strict Frozen Wire Format v3 (\x89QPE\x03\x00) & Compact TLV v3.1 (\x89QPE\x03\x01).
KDF Envelope: Strict kdf_version: 2 (RFC 9106 QPKD-Argon2id + qSponge-512).
Legacy -beta backwards compatibility has been completely removed for Production Candidate 1.1.7.
"""
import os
import json
from .beyond_lwe_bridge import (
    BEYOND_LWE_SUITES,
    decrypt_beyond_lwe,
    encrypt_beyond_lwe,
    generate_beyond_lwe_material,
    sign_beyond_lwe,
    verify_beyond_lwe,
)
import zlib
import base64
import hashlib
import hmac
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x448, ed448
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .passphrase import enforce_passphrase_policy, analyze_passphrase, QPEPPassphrasePolicyError
from .exceptions import (
    OpenQPEPError,
    QPEPMacVerificationError,
    QPEPFaultGuardError,
    QPEPWireFormatError,
    QPEPTruncationError,
    QPEPKeyRingError,
    QPEPSuiteError,
)
from .primitives.cc512_aead import cc512_encrypt as _cc512_encrypt_mod, cc512_decrypt as _cc512_decrypt_mod
from .primitives.consttime import ct_eq
from .primitives.zeroize import SecretBuffer
from .kdf.argon2id_cascade import derive_qpkrf_keys_v2
from .qlx_lattice import QLXEngine, QVSEngine, QLX_TIERS, QVS_TIERS, qsponge_var, qsponge_512

PROJECT_NAME = "OpenQPEP by Calyx Labs Inc."
APP_NAME = "Calyx QPEP Client"
UNIVERSAL_VERSION = "1.1.0-pc"
UNIVERSAL_VERSION_LABEL = "Production Candidate 1.1.7"
PROTOCOL_VERSION = "OpenQPEP/PC-1.1.7"
DEFAULT_SUITE = "Signature QLX-4096 + QVS-256"
QPKRF_EXTENSION = ".qpkrf"

CALYX_HYPER_TESSERACT_HARDWARE_WARNING = (
    "WARNING — HIGH-TIER HARDWARE REQUIRED FOR CALYX HYPER-TESSERACT (QLX-16384 + QVS-1024): "
    "Calyx Hyper-Tesseract operates over a 16,384-dimensional 4-Manifold Coupled Module-LWE lattice (k=64 polynomials) "
    "and a (16x14) QVS-1024 vector signature matrix (7,680 polynomial dimensions), executing over 320,000+ modular "
    "NTT butterfly operations and allocating ~69.3 KB of raw secret lattice vectors per key ring. "
    "Use ONLY on flagship smartphones (e.g., Samsung Galaxy Z Fold 8, Galaxy S25/S26 Ultra, Pixel 10 Pro with 12 GB+ RAM) "
    "or high-RAM desktop/server PCs. Running Calyx Hyper-Tesseract on low-tier or budget mobile devices (<=6 GB RAM) "
    "will cause severe UI freezes, Android Application Not Responding (ANR) timeouts, thermal throttling, or WebView "
    "Out-Of-Memory (OOM) crashes. On standard or low-tier devices, use Calyx Signature (QLX-4096 + QVS-256) or QLX-1024 + QVS-87."
)


# Hardened 2026 Post-Quantum & AI-Cryptanalysis Immunity Profile for Signature QLX-4096 + QVS-256
QUANTUM_IMMUNITY_MATRIX: Dict[str, Dict[str, str]] = {
    "JVG_AND_SHOR": {
        "threat": "Jesse-Victor-Gharabaghi (JVG) Hybrid QNTT Factorization & Shor's Algorithm",
        "mitigation": (
            "Anchors key encapsulation and signatures in 4096-dimensional Module-LWE (QLX-4096, k=16, n=256, q=3329) "
            "and (8x7) Module-SIS/LWE (QVS-256, Q=8380417) fused with HGC-448 via 512-bit qSponge-512. "
            "Eliminates reliance on RSA composite factorization or abelian period finding exploited by QNTT/JVG and IQFT/Shor."
        ),
    },
    "GROVER_ENHANCED_BKZ_SIEVING": {
        "threat": "Quantum-Accelerated Lattice Sieving (Grover-Enhanced BKZ-beta)",
        "mitigation": (
            "Scales module rank to k=16 (4,096 polynomial ring dimensions in QLX-4096) and (k=8, l=7) (3,840 total vector "
            "dimensions in QVS-256), pushing required BKZ block sizes to beta > 1650 (>512-bit post-quantum work factor "
            "even under quantum-walk and Grover-accelerated 2^(0.265*beta) sieving bounds)."
        ),
    },
    "DIHEDRAL_COSET_PROBLEM_DCP": {
        "threat": "Quantum Algorithms for the Dihedral Coset Problem (DCP / Extrapolated DCP)",
        "mitigation": (
            "Applies Fujisaki-Okamoto (FO) IND-CCA2 re-encryption verification with H_ek transcript binding, lossy (du=11, dv=5) "
            "rounding compression, and constant-time implicit rejection (CALYX-QLX-FO-REJECT|), preventing coherent quantum "
            "coset state sampling and faulty-sample extrapolation reductions."
        ),
    },
    "CLAUDE_MYTHOS_HAWK256_AND_AES": {
        "threat": "Anthropic Claude Mythos Preview (July 2026) HAWK-256 Lattice Symmetry & 7-Round AES Mobius Bridge",
        "mitigation": (
            "Replaces structured NTRU rank-2 isomorphisms (vulnerable to HAWK-256 Galois/rotational symmetry shortcuts) with "
            "asymmetric (8x7) Module-SIS Fiat-Shamir with Aborts and per-coordinate domain-separated qSponge-XOF matrix expansion "
            "(CALYX-QVS-MAT-A|), while Calyx-Cascade-512 (CC-512) cascades full 14-round AES-256-GCM inside full 20-round "
            "ChaCha20-Poly1305 (512-bit independent symmetric keys across SPN + ARX families)."
        ),
    },
    "GROVER_SYMMETRIC_AND_HASH": {
        "threat": "Grover's Algorithm on Symmetric Ciphers & Hash Primitives",
        "mitigation": (
            "Enforces 512-bit qSponge-512 (SHA3-512) and qSponge-XOF (SHAKE-256) over a 1600-bit Keccak state (zero SHA-256 usage) "
            "together with 512-bit cascaded CC-512 payload encryption, preserving >=256 bits of post-quantum security under "
            "Grover's O(2^(n/2)) quadratic speedup."
        ),
    },
    "SIDE_CHANNEL_AND_FAULT_INJECTION": {
        "threat": "Side-Channel Timing & Glitch/Rowhammer Fault Injection Attacks",
        "mitigation": (
            "Enforces Verify-Before-Emit Fault-Guard inside QVSEngine.sign (verifying every lattice signature against pk before output), "
            "constant-time hmac.compare_digest verification across all MACs/FO-CCA2 checks, and qSponge-XOF XOR secret-key masking "
            "(CALYX-QPEP-SK-MASK|) at rest."
        ),
    },
}

# Comprehensive Hardcoded Registry of Supported File Extensions & MIME Types for OpenQPEP File Encryption
SUPPORTED_FILE_EXTENSIONS: Dict[str, str] = {
    # Images & Graphics
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".jpe": "image/jpeg", ".jfif": "image/jpeg",
    ".png": "image/png", ".webp": "image/webp", ".gif": "image/gif", ".bmp": "image/bmp",
    ".dib": "image/bmp", ".svg": "image/svg+xml", ".svgz": "image/svg+xml", ".ico": "image/x-icon",
    ".heic": "image/heic", ".heif": "image/heif", ".avif": "image/avif", ".tif": "image/tiff",
    ".tiff": "image/tiff", ".raw": "image/x-raw", ".cr2": "image/x-canon-cr2", ".nef": "image/x-nikon-nef",
    ".arw": "image/x-sony-arw", ".dng": "image/x-adobe-dng", ".psd": "image/vnd.adobe.photoshop",
    ".ai": "application/postscript", ".eps": "application/postscript",
    # Documents, Office & Publishing
    ".pdf": "application/pdf", ".txt": "text/plain", ".text": "text/plain", ".md": "text/markdown",
    ".markdown": "text/markdown", ".rst": "text/x-rst", ".rtf": "application/rtf",
    ".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint", ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odt": "application/vnd.oasis.opendocument.text", ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation", ".pages": "application/x-iwork-pages-sffpages",
    ".numbers": "application/x-iwork-numbers-sffnumbers", ".key": "application/x-iwork-keynote-sffkey",
    ".epub": "application/epub+zip", ".mobi": "application/x-mobipocket-ebook", ".azw3": "application/vnd.amazon.ebook",
    ".kpf": "application/octet-stream", ".tex": "application/x-tex", ".bib": "text/x-bibtex",
    # Data, Config & Structured Text
    ".csv": "text/csv", ".tsv": "text/tab-separated-values", ".json": "application/json",
    ".jsonl": "application/json", ".ndjson": "application/json", ".xml": "application/xml",
    ".yaml": "application/x-yaml", ".yml": "application/x-yaml", ".toml": "application/toml",
    ".ini": "text/plain", ".cfg": "text/plain", ".conf": "text/plain", ".env": "text/plain",
    ".properties": "text/plain", ".log": "text/plain", ".sql": "application/sql",
    # Source Code & Web
    ".html": "text/html", ".htm": "text/html", ".css": "text/css", ".scss": "text/x-scss",
    ".less": "text/x-less", ".js": "application/javascript", ".mjs": "application/javascript",
    ".cjs": "application/javascript", ".ts": "application/typescript", ".jsx": "text/jsx",
    ".tsx": "text/tsx", ".py": "text/x-python", ".pyw": "text/x-python", ".ipynb": "application/x-ipynb+json",
    ".java": "text/x-java-source", ".kt": "text/x-kotlin", ".kts": "text/x-kotlin",
    ".scala": "text/x-scala", ".groovy": "text/x-groovy", ".c": "text/x-c", ".h": "text/x-c",
    ".cpp": "text/x-c++", ".cc": "text/x-c++", ".cxx": "text/x-c++", ".hpp": "text/x-c++",
    ".cs": "text/x-csharp", ".go": "text/x-go", ".rs": "text/rust", ".swift": "text/x-swift",
    ".m": "text/x-objectivec", ".mm": "text/x-objectivec++", ".rb": "text/x-ruby",
    ".php": "application/x-httpd-php", ".pl": "text/x-perl", ".lua": "text/x-lua",
    ".r": "text/x-r", ".jl": "text/x-julia", ".dart": "application/vnd.dart",
    ".sh": "application/x-sh", ".bash": "application/x-sh", ".zsh": "application/x-sh",
    ".fish": "application/x-sh", ".bat": "application/x-msdos-program", ".cmd": "application/x-msdos-program",
    ".ps1": "application/x-powershell", ".wasm": "application/wasm", ".sol": "text/plain",
    # Archives, Packages & Disk Images
    ".zip": "application/zip", ".tar": "application/x-tar", ".gz": "application/gzip",
    ".tgz": "application/gzip", ".bz2": "application/x-bzip2", ".tbz2": "application/x-bzip2",
    ".xz": "application/x-xz", ".txz": "application/x-xz", ".zst": "application/zstd",
    ".7z": "application/x-7z-compressed", ".rar": "application/vnd.rar", ".cab": "application/vnd.ms-cab-compressed",
    ".iso": "application/x-iso9660-image", ".img": "application/octet-stream", ".dmg": "application/x-apple-diskimage",
    ".vhd": "application/x-virtualbox-vhd", ".vmdk": "application/x-vmdk", ".qcow2": "application/x-qemu-disk",
    # Android, JVM & Executables
    ".apk": "application/vnd.android.package-archive", ".aab": "application/x-authorware-bin",
    ".apks": "application/zip", ".xapk": "application/zip", ".jar": "application/java-archive",
    ".war": "application/java-archive", ".dex": "application/octet-stream", ".class": "application/java-vm",
    ".so": "application/x-sharedlib", ".dll": "application/x-msdownload", ".exe": "application/x-msdownload",
    ".msi": "application/x-msi", ".deb": "application/vnd.debian.binary-package",
    ".rpm": "application/x-rpm", ".appimage": "application/x-executable", ".elf": "application/x-executable",
    ".bin": "application/octet-stream", ".dat": "application/octet-stream", ".pak": "application/octet-stream",
    # Databases & Scientific Data
    ".db": "application/x-sqlite3", ".sqlite": "application/x-sqlite3", ".sqlite3": "application/x-sqlite3",
    ".mdb": "application/x-msaccess", ".accdb": "application/x-msaccess", ".parquet": "application/vnd.apache.parquet",
    ".feather": "application/octet-stream", ".avro": "application/octet-stream", ".orc": "application/octet-stream",
    ".h5": "application/x-hdf5", ".hdf5": "application/x-hdf5", ".npy": "application/octet-stream",
    ".npz": "application/zip", ".pt": "application/octet-stream", ".pth": "application/octet-stream",
    ".onnx": "application/octet-stream", ".safetensors": "application/octet-stream", ".gguf": "application/octet-stream",
    # Audio & Music
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".flac": "audio/flac", ".aac": "audio/aac",
    ".ogg": "audio/ogg", ".oga": "audio/ogg", ".opus": "audio/opus", ".m4a": "audio/mp4",
    ".wma": "audio/x-ms-wma", ".aiff": "audio/x-aiff", ".mid": "audio/midi", ".midi": "audio/midi",
    # Video & Multimedia
    ".mp4": "video/mp4", ".m4v": "video/x-m4v", ".mkv": "video/x-matroska", ".webm": "video/webm",
    ".mov": "video/quicktime", ".avi": "video/x-msvideo", ".wmv": "video/x-ms-wmv",
    ".flv": "video/x-flv", ".ts": "video/mp2t", ".mts": "video/mp2t", ".3gp": "video/3gpp",
    # Fonts
    ".ttf": "font/ttf", ".otf": "font/otf", ".woff": "font/woff", ".woff2": "font/woff2",
    # Cryptographic Keys, Certificates & OpenQPEP Formats
    ".qpkrf": "application/x-calyx-qpkrf", ".qpep": "application/x-calyx-qpep", ".qpsig": "application/x-calyx-qpsig",
    ".asc": "application/pgp-keys", ".pgp": "application/pgp-encrypted", ".gpg": "application/pgp-encrypted",
    ".sig": "application/pgp-signature", ".pem": "application/x-pem-file", ".crt": "application/x-x509-ca-cert",
    ".cer": "application/pkix-cert", ".der": "application/x-x509-ca-cert", ".p12": "application/x-pkcs12",
    ".pfx": "application/x-pkcs12", ".jks": "application/x-java-keystore", ".keystore": "application/x-java-keystore",
    ".key": "application/pkcs8", ".csr": "application/pkcs10", ".kdbx": "application/x-keepass2",
}


def detect_file_extension_and_mime(data: bytes, filename: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Determines the exact (normalized_filename, extension, mime_type) for any file payload
    using both the provided filename and binary magic-byte header inspection.
    """
    ext = ""
    base_name = (filename or "").strip()
    if base_name and "." in base_name:
        candidate_ext = "." + base_name.rsplit(".", 1)[-1].lower().strip()
        if candidate_ext != ".qpep" and len(candidate_ext) <= 14:
            ext = candidate_ext

    # Inspect binary magic-byte headers if extension is missing or generic (.bin / .txt / .qpep)
    if not ext or ext in (".bin", ".dat", ".qpep"):
        if data.startswith(b"\xff\xd8\xff"):
            ext = ".jpg"
        elif data.startswith(b"\x89PNG\r\n\x1a\n"):
            ext = ".png"
        elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
            ext = ".gif"
        elif len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            ext = ".webp"
        elif data.startswith(b"BM"):
            ext = ".bmp"
        elif data.startswith(b"%PDF-"):
            ext = ".pdf"
        elif data.startswith(b"PK\x03\x04"):
            if b"AndroidManifest.xml" in data[:4096] or b"classes.dex" in data[:4096]:
                ext = ".apk"
            elif b"word/" in data[:2048]:
                ext = ".docx"
            elif b"xl/" in data[:2048]:
                ext = ".xlsx"
            elif b"ppt/" in data[:2048]:
                ext = ".pptx"
            else:
                ext = ".zip"
        elif data.startswith(b"\x1f\x8b\x08"):
            ext = ".gz"
        elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
            ext = ".7z"
        elif data.startswith(b"Rar!\x1a\x07"):
            ext = ".rar"
        elif data.startswith(b"SQLite format 3\x00"):
            ext = ".sqlite"
        elif data.startswith(b"ID3") or data.startswith(b"\xff\xfb") or data.startswith(b"\xff\xf3"):
            ext = ".mp3"
        elif len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE":
            ext = ".wav"
        elif data.startswith(b"fLaC"):
            ext = ".flac"
        elif data.startswith(b"OggS"):
            ext = ".ogg"
        elif len(data) >= 12 and data[4:8] == b"ftyp":
            ext = ".mp4"
        elif data.startswith(b"\x1a\x45\xdf\xa3"):
            ext = ".mkv"
        elif data.startswith(b"\x7fELF"):
            ext = ".elf"
        elif data.startswith(b"dex\n035\x00"):
            ext = ".dex"
        elif b"-----BEGIN CALYX QPKRF" in data[:256] or b"-----BEGIN OPENQPEP QPKRF" in data[:256]:
            ext = ".qpkrf"
        elif not ext:
            try:
                data[:1024].decode("utf-8")
                ext = ".txt"
            except UnicodeDecodeError:
                ext = ".bin"

    mime_type = SUPPORTED_FILE_EXTENSIONS.get(ext, "application/octet-stream")
    if not base_name or base_name in ("encrypted_payload.qpep", "inline_message.txt"):
        stem = "decrypted_file" if ext != ".txt" else "message"
        normalized_filename = f"{stem}{ext}"
    elif base_name.lower().endswith(".qpep"):
        stem = base_name[:-5]
        if "." in stem:
            normalized_filename = stem
        else:
            normalized_filename = f"{stem}{ext}"
    elif not base_name.lower().endswith(ext):
        normalized_filename = f"{base_name}{ext}"
    else:
        normalized_filename = base_name

    return normalized_filename, ext, mime_type

CHUNK_SIZE = 65536
from .wire.framing import pack_wire_frame, unpack_wire_frame
from .constants import WIRE_MAGIC_V3 as WIRE_MAGIC, SUPPORTED_WIRE_MAGICS


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _compute_keyring_integrity_mac(
    key_hash: str,
    created_at: str,
    name: str,
    email: str,
    public_bundle: Dict[str, str],
) -> str:
    mac_input = json.dumps(
        {
            "key_hash": key_hash,
            "created_at": created_at,
            "name": name,
            "email": email,
            "public_bundle": public_bundle,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return qsponge_512(b"CALYX-QPKRF-INTEGRITY|" + mac_input).hex().upper()


def _armor_wrap(header_label: str, metadata: Dict[str, str], payload_bytes: bytes) -> str:
    """
    Encapsulates payload_bytes into a binary OpenQPEP wire frame (WIRE_MAGIC + 16-byte nonce +
    qSponge-XOF stream-whitened payload + 32-byte qSponge-512 frame MAC) before Base64 armoring
    so raw Base64 decoding never exposes plaintext or JSON structure.
    """
    wire_frame = pack_wire_frame(payload_bytes, header_label)

    b64_raw = _b64e(wire_frame)
    lines = [b64_raw[i : i + 64] for i in range(0, len(b64_raw), 64)]
    crc_digest = _b64e(qsponge_var(b"CALYX-ARMOR-CRC-v1|" + wire_frame, 6))
    meta_lines = [f"{k}: {v}" for k, v in metadata.items()]
    body = "\n".join(
        [f"-----BEGIN {header_label}-----"]
        + meta_lines
        + [""]
        + lines
        + [f"={crc_digest}", f"-----END {header_label}-----"]
    )
    return body + "\n"


def _armor_unwrap(armored_text: str, expected_label: Optional[str] = None) -> Tuple[str, Dict[str, str], bytes]:
    lines = [line.strip() for line in armored_text.strip().splitlines()]
    if not lines or not lines[0].startswith("-----BEGIN ") or not lines[-1].startswith("-----END "):
        raise ValueError("Invalid OpenQPEP armor header/footer.")
    begin_label = lines[0][len("-----BEGIN ") : -len("-----")]
    end_label = lines[-1][len("-----END ") : -len("-----")]
    if begin_label != end_label:
        raise ValueError(f"Mismatched armor labels: {begin_label} vs {end_label}")
    if expected_label and begin_label != expected_label:
        # Allow seamless alias between OPENQPEP and CALYX QPEP armor labels
        norm_begin = begin_label.replace("OPENQPEP", "CALYX QPEP").replace("CALYX QPEP QPKRF", "CALYX QPKRF")
        norm_exp = expected_label.replace("OPENQPEP", "CALYX QPEP").replace("CALYX QPEP QPKRF", "CALYX QPKRF")
        if norm_begin != norm_exp:
            raise ValueError(f"Expected armor label '{expected_label}', got '{begin_label}'")

    metadata: Dict[str, str] = {}
    idx = 1
    while idx < len(lines) - 1 and lines[idx] != "":
        if ":" in lines[idx]:
            k, v = lines[idx].split(":", 1)
            metadata[k.strip()] = v.strip()
        idx += 1
    if idx < len(lines) - 1 and lines[idx] == "":
        idx += 1

    b64_chunks = []
    checksum_line = None
    for line in lines[idx:-1]:
        if line.startswith("="):
            checksum_line = line[1:]
        elif line:
            b64_chunks.append(line)

    raw_frame = _b64d("".join(b64_chunks))
    if not raw_frame.startswith(WIRE_MAGIC):
        raise ValueError("Unsupported or legacy beta wire format. OpenQPEP Production Candidate 1.1.7 requires Wire Format v3 (\\x89QPE\\x03\\x00).")
    if checksum_line:
        expected_crc = _b64e(qsponge_var(b"CALYX-ARMOR-CRC-v1|" + raw_frame, 6))
        if not hmac.compare_digest(checksum_line, expected_crc):
            raise ValueError("OpenQPEP qSponge checksum mismatch (corrupted packet).")
    payload_bytes, _wire_nonce = unpack_wire_frame(raw_frame, begin_label)
    return begin_label, metadata, payload_bytes


def _cc512_encrypt(plaintext: bytes, k_s1: bytes, k_s2: bytes, aad: bytes) -> Tuple[bytes, bytes, bytes]:
    n1 = os.urandom(12)
    n2 = os.urandom(12)
    inner_ct = AESGCM(k_s1).encrypt(n1, plaintext, aad)
    outer_ct = ChaCha20Poly1305(k_s2).encrypt(n2, inner_ct, aad)
    return n1, n2, outer_ct


def _cc512_decrypt(outer_ct: bytes, k_s1: bytes, k_s2: bytes, n1: bytes, n2: bytes, aad: bytes) -> bytes:
    inner_ct = ChaCha20Poly1305(k_s2).decrypt(n2, outer_ct, aad)
    return AESGCM(k_s1).decrypt(n1, inner_ct, aad)


@dataclass
class QPEPKeyRing:
    key_hash: str
    created_at: str
    name: str
    email: str
    qlx_tier: str
    qvs_tier: str
    comment: str
    public_bundle: Dict[str, str]
    encrypted_private_bundle: Optional[Dict[str, Any]]
    integrity_mac: str

    @property
    def has_private_key(self) -> bool:
        return self.encrypted_private_bundle is not None


class CalyxQPEPProtocol:
    """
    Official Reference Implementation of OpenQPEP by Calyx Labs Inc. (Production Candidate 1.1.7).
    """

    @staticmethod
    def generate_keypair(
        name: str,
        email: str,
        passphrase: str,
        qlx_tier: str = "QLX-4096",
        comment: str = "OpenQPEP by Calyx Labs Inc.",
    ) -> QPEPKeyRing:
        policy_witness = enforce_passphrase_policy(passphrase)
        requested_suite = qlx_tier
        is_beyond_lwe = requested_suite in BEYOND_LWE_SUITES
        if qlx_tier not in QLX_TIERS:
            qlx_tier = "QLX-4096"
        qvs_tier = QLX_TIERS[qlx_tier]["qvs_tier"]
        blwe_pub, blwe_priv = (
            generate_beyond_lwe_material(requested_suite, allow_low_ram_override=True)
            if is_beyond_lwe
            else (None, None)
        )

        hgc_sk = x448.X448PrivateKey.generate()
        hgc_pk = hgc_sk.public_key()
        hgc_sk_bytes = hgc_sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        hgc_pk_bytes = hgc_pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        hgc_sig_sk = ed448.Ed448PrivateKey.generate()
        hgc_sig_pk = hgc_sig_sk.public_key()
        hgc_sig_sk_bytes = hgc_sig_sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        hgc_sig_pk_bytes = hgc_sig_pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        qlx_pk, qlx_sk = QLXEngine.keygen(tier=qlx_tier, policy_witness=policy_witness)
        qvs_pk, qvs_sk = QVSEngine.keygen(tier=qvs_tier, policy_witness=policy_witness)

        full_hash = qsponge_512(
            b"CALYX-QPEP-KEY-HASH-v1|" + hgc_pk_bytes + qlx_pk + hgc_sig_pk_bytes + qvs_pk
        ).hex().upper()
        key_hash = full_hash[:64]
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        cert_transcript = (
            f"CALYX-QPEP-SELFCERT|{key_hash}|{created_at}|{name}|{email}|{qlx_tier}|{qvs_tier}|{comment}".encode("utf-8")
            + hgc_pk_bytes
            + qlx_pk
            + hgc_sig_pk_bytes
            + qvs_pk
        )
        sig_part1 = hgc_sig_sk.sign(cert_transcript)
        sig_part2 = QVSEngine.sign(qvs_sk, qvs_pk, cert_transcript, tier=qvs_tier)
        self_sig_blob = sig_part1 + sig_part2

        public_bundle = {
            "suite_id": requested_suite if is_beyond_lwe else qlx_tier,
            "qlx_tier": qlx_tier,
            "qvs_tier": qvs_tier,
            "hgc_448_public_b64": _b64e(hgc_pk_bytes),
            "qlx_public_b64": _b64e(qlx_pk),
            "hgc_sig_public_b64": _b64e(hgc_sig_pk_bytes),
            "qvs_public_b64": _b64e(qvs_pk),
            "self_signature_b64": _b64e(self_sig_blob),
        }
        if is_beyond_lwe and blwe_pub is not None:
            public_bundle["beyond_lwe_public"] = blwe_pub

        kdf_salt = os.urandom(32)
        k_s1, k_s2, k_mac, kdf_v2_params = derive_qpkrf_keys_v2(passphrase, kdf_salt, qlx_tier=qlx_tier)

        mask_stream = qsponge_var(b"CALYX-QPEP-SK-MASK|" + k_mac + key_hash.encode("ascii"), len(qlx_sk))
        masked_qlx_sk = bytes(a ^ b for a, b in zip(qlx_sk, mask_stream))

        priv_payload_obj = {
            "hgc_448_private_b64": _b64e(hgc_sk_bytes),
            "qlx_masked_private_b64": _b64e(masked_qlx_sk),
            "hgc_sig_private_b64": _b64e(hgc_sig_sk_bytes),
            "qvs_private_b64": _b64e(qvs_sk),
        }
        if is_beyond_lwe and blwe_priv is not None:
            priv_payload_obj["beyond_lwe_private"] = blwe_priv
        private_raw = json.dumps(priv_payload_obj, separators=(",", ":")).encode("utf-8")

        aad = f"CALYX-QPEP-PRIVRING|{key_hash}".encode("utf-8")
        n1, n2, ct_priv = _cc512_encrypt(private_raw, k_s1, k_s2, aad)

        encrypted_private_bundle = {
            "kdf_version": 2,
            "kdf_salt_b64": _b64e(kdf_salt),
            "kdf_params": kdf_v2_params,
            "cc512_n1_b64": _b64e(n1),
            "cc512_n2_b64": _b64e(n2),
            "ciphertext_b64": _b64e(ct_priv),
        }

        integrity_mac = _compute_keyring_integrity_mac(key_hash, created_at, name, email, public_bundle)

        return QPEPKeyRing(
            key_hash=key_hash,
            created_at=created_at,
            name=name,
            email=email,
            qlx_tier=qlx_tier,
            qvs_tier=qvs_tier,
            comment=comment,
            public_bundle=public_bundle,
            encrypted_private_bundle=encrypted_private_bundle,
            integrity_mac=integrity_mac,
        )

    @staticmethod
    def verify_public_keyring_self_signature(keyring: QPEPKeyRing) -> bool:
        expected_mac = _compute_keyring_integrity_mac(
            keyring.key_hash,
            keyring.created_at,
            keyring.name,
            keyring.email,
            keyring.public_bundle,
        )
        if not hmac.compare_digest(keyring.integrity_mac, expected_mac):
            return False

        hgc_pk_bytes = _b64d(keyring.public_bundle["hgc_448_public_b64"])
        qlx_pk = _b64d(keyring.public_bundle["qlx_public_b64"])
        hgc_sig_pk_bytes = _b64d(keyring.public_bundle["hgc_sig_public_b64"])
        qvs_pk = _b64d(keyring.public_bundle["qvs_public_b64"])
        self_sig_blob = _b64d(keyring.public_bundle["self_signature_b64"])

        # Verify Key Hash binding to the actual public keys
        expected_hash = qsponge_512(
            b"CALYX-QPEP-KEY-HASH-v1|" + hgc_pk_bytes + qlx_pk + hgc_sig_pk_bytes + qvs_pk
        ).hex().upper()[:64]
        if not hmac.compare_digest(keyring.key_hash, expected_hash):
            return False

        qvs_tier = keyring.qvs_tier
        expected_sig_len = 114 + QVS_TIERS[qvs_tier]["sig_bytes"]
        if len(self_sig_blob) != expected_sig_len:
            return False
        sig1 = self_sig_blob[:114]
        sig2 = self_sig_blob[114:]

        cert_transcript = (
            f"CALYX-QPEP-SELFCERT|{keyring.key_hash}|{keyring.created_at}|{keyring.name}|{keyring.email}|{keyring.qlx_tier}|{keyring.qvs_tier}|{keyring.comment}".encode("utf-8")
            + hgc_pk_bytes
            + qlx_pk
            + hgc_sig_pk_bytes
            + qvs_pk
        )
        try:
            ed_pk = ed448.Ed448PublicKey.from_public_bytes(hgc_sig_pk_bytes)
            ed_pk.verify(sig1, cert_transcript)
        except Exception:
            return False

        return QVSEngine.verify(qvs_pk, cert_transcript, sig2, tier=qvs_tier)

    @staticmethod
    def unlock_private_keys(keyring: QPEPKeyRing, passphrase: str) -> Dict[str, bytes]:
        enforce_passphrase_policy(passphrase)
        if not keyring.encrypted_private_bundle:
            raise ValueError("This QPKRF key ring contains only a public key.")

        priv_enc = keyring.encrypted_private_bundle
        kdf_salt = _b64d(priv_enc["kdf_salt_b64"])
        kdf_params = priv_enc.get("kdf_params") or {}
        kdf_version = int(priv_enc.get("kdf_version") or kdf_params.get("kdf_version") or 0)
        if kdf_version < 2:
            raise ValueError(
                "Legacy beta kdf_version < 2 key rings are rejected in OpenQPEP Production Candidate 1.1.7 (kdf_version >= 2 required)."
            )
        k_s1, k_s2, k_mac, _ = derive_qpkrf_keys_v2(passphrase, kdf_salt, kdf_params=kdf_params)
        aad = f"CALYX-QPEP-PRIVRING|{keyring.key_hash}".encode("utf-8")

        try:
            decrypted_json = _cc512_decrypt(
                outer_ct=_b64d(priv_enc["ciphertext_b64"]),
                k_s1=k_s1,
                k_s2=k_s2,
                n1=_b64d(priv_enc["cc512_n1_b64"]),
                n2=_b64d(priv_enc["cc512_n2_b64"]),
                aad=aad,
            )
        except Exception as exc:
            raise ValueError("Invalid passphrase or tampered QPKRF private key ring.") from exc

        parsed = json.loads(decrypted_json.decode("utf-8"))
        masked_qlx_sk = _b64d(parsed["qlx_masked_private_b64"])
        mask_stream = qsponge_var(b"CALYX-QPEP-SK-MASK|" + k_mac + keyring.key_hash.encode("ascii"), len(masked_qlx_sk))
        qlx_sk = bytes(a ^ b for a, b in zip(masked_qlx_sk, mask_stream))

        out_keys: Dict[str, Any] = {
            "hgc_448_private": _b64d(parsed["hgc_448_private_b64"]),
            "qlx_private": qlx_sk,
            "hgc_sig_private": _b64d(parsed["hgc_sig_private_b64"]),
            "qvs_private": _b64d(parsed["qvs_private_b64"]),
        }
        if "beyond_lwe_private" in parsed:
            out_keys["beyond_lwe_private"] = parsed["beyond_lwe_private"]
        return out_keys

    @staticmethod
    def export_qpkrf(
        keyring: QPEPKeyRing,
        passphrase: Optional[str] = None,
        include_private: bool = False,
        output_path: Optional[str | Path] = None,
    ) -> str:
        """
        Exports a Public or Private .qpkrf Key Ring File.
        - Exporting a Public Key Ring does NOT require a passphrase.
        - Exporting a Private Key Ring strictly requires and verifies the owner's QPKD-Argon2id passphrase.
        """
        if include_private:
            if not passphrase:
                raise QPEPPassphrasePolicyError("Exporting a private .qpkrf key ring requires the key's mandatory passphrase.")
            CalyxQPEPProtocol.unlock_private_keys(keyring, passphrase)

        ring_type = "PRIVATE_KEY_RING" if include_private else "PUBLIC_KEY_RING"
        envelope: Dict[str, Any] = {
            "magic": "QPKRF-v1",
            "protocol": PROJECT_NAME,
            "version": UNIVERSAL_VERSION,
            "ring_type": ring_type,
            "suite": f"{keyring.qlx_tier}+HGC-448 / {keyring.qvs_tier}+qSponge-512 / CC-512",
            "key_hash": keyring.key_hash,
            "created_at": keyring.created_at,
            "identity": {
                "name": keyring.name,
                "email": keyring.email,
                "comment": keyring.comment,
            },
            "public_bundle": keyring.public_bundle,
            "integrity_mac": keyring.integrity_mac,
        }
        if include_private:
            envelope["encrypted_private_bundle"] = keyring.encrypted_private_bundle

        payload_bytes = json.dumps(envelope, indent=2).encode("utf-8")
        label = (
            "CALYX QPKRF PRIVATE KEY RING"
            if include_private
            else "CALYX QPKRF PUBLIC KEY RING"
        )
        metadata = {
            "Protocol": PROJECT_NAME,
            "Version": f"{PROTOCOL_VERSION} ({UNIVERSAL_VERSION_LABEL})",
            "Suite": f"{keyring.qlx_tier}+HGC-448 / {keyring.qvs_tier}+qSponge-512 / CC-512",
            "Key-Hash": keyring.key_hash,
            "Identity": f"{keyring.name} <{keyring.email}>",
        }
        armored = _armor_wrap(label, metadata, payload_bytes)

        if output_path is not None:
            out_p = Path(output_path)
            if out_p.suffix.lower() != QPKRF_EXTENSION:
                raise ValueError(f"Exported key ring files MUST use the '{QPKRF_EXTENSION}' file extension.")
            out_p.write_text(armored, encoding="utf-8")

        return armored

    @staticmethod
    def import_qpkrf(armored_or_path: str | Path, passphrase: Optional[str] = None) -> QPEPKeyRing:
        """
        Imports a .qpkrf Key Ring File.
        - Importing a Public Key Ring (receiver key) does NOT require a passphrase.
        - Importing a Private Key Ring strictly requires and verifies the owner's QPKD-Argon2id passphrase.
        """
        if isinstance(armored_or_path, Path) or (
            isinstance(armored_or_path, str)
            and "\n" not in armored_or_path
            and Path(armored_or_path).exists()
        ):
            p = Path(armored_or_path)
            if p.suffix.lower() != QPKRF_EXTENSION:
                raise ValueError(f"Key ring file MUST have the '{QPKRF_EXTENSION}' extension.")
            armored_text = p.read_text(encoding="utf-8")
        else:
            armored_text = str(armored_or_path)

        label, _, payload_bytes = _armor_unwrap(armored_text)
        valid_labels = (
            "CALYX QPKRF PUBLIC KEY RING",
            "CALYX QPKRF PRIVATE KEY RING",
            "OPENQPEP QPKRF PUBLIC KEY RING",
            "OPENQPEP QPKRF PRIVATE KEY RING",
        )
        if label not in valid_labels:
            raise ValueError(f"Unexpected QPKRF armor header: {label}")

        envelope = json.loads(payload_bytes.decode("utf-8"))
        identity = envelope["identity"]
        pub_b = envelope["public_bundle"]
        keyring = QPEPKeyRing(
            key_hash=envelope["key_hash"],
            created_at=envelope["created_at"],
            name=identity["name"],
            email=identity["email"],
            qlx_tier=pub_b.get("qlx_tier", "QLX-1024"),
            qvs_tier=pub_b.get("qvs_tier", "QVS-87"),
            comment=identity.get("comment", ""),
            public_bundle=pub_b,
            encrypted_private_bundle=envelope.get("encrypted_private_bundle"),
            integrity_mac=envelope["integrity_mac"],
        )

        if not CalyxQPEPProtocol.verify_public_keyring_self_signature(keyring):
            raise ValueError("QPKRF self-certification signature or integrity_mac verification failed.")

        if keyring.has_private_key:
            if not passphrase:
                raise QPEPPassphrasePolicyError("Importing a private .qpkrf key ring requires its mandatory QPKD-Argon2id passphrase.")
            CalyxQPEPProtocol.unlock_private_keys(keyring, passphrase)

        return keyring

    @staticmethod
    def encrypt_bytes(
        plaintext: bytes,
        recipient_keyring: QPEPKeyRing,
        encrypting_keyring: QPEPKeyRing,
        passphrase: str,
        filename: Optional[str] = None,
        compress: bool = True,
    ) -> str:
        """
        Encrypts raw bytes using both the sender's Encrypting Key (unlocked via mandatory passphrase)
        and the Recipient's Key (.qpkrf).
        """
        enforce_passphrase_policy(passphrase)
        if not CalyxQPEPProtocol.verify_public_keyring_self_signature(recipient_keyring):
            raise ValueError("Recipient public key ring self-signature is invalid.")

        embedded_sig = CalyxQPEPProtocol.sign_bytes(plaintext, encrypting_keyring, passphrase)

        qlx_tier = recipient_keyring.qlx_tier
        recip_hgc_pk_bytes = _b64d(recipient_keyring.public_bundle["hgc_448_public_b64"])
        recip_qlx_pk_bytes = _b64d(recipient_keyring.public_bundle["qlx_public_b64"])
        recip_hgc_pk = x448.X448PublicKey.from_public_bytes(recip_hgc_pk_bytes)

        eph_hgc_sk = x448.X448PrivateKey.generate()
        eph_hgc_pk_bytes = eph_hgc_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ss_hgc = eph_hgc_sk.exchange(recip_hgc_pk)
        ct_qlx, ss_qlx = QLXEngine.encaps(recip_qlx_pk_bytes, tier=qlx_tier)

        ss_hybrid = qsponge_var(
            b"CALYX-QPEP-KEM-v1|"
            + ss_qlx
            + ss_hgc
            + ct_qlx
            + eph_hgc_pk_bytes
            + recip_qlx_pk_bytes
            + recip_hgc_pk_bytes,
            64,
        )

        pkt_salt = os.urandom(32)
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=128,
            salt=pkt_salt,
            info=b"CALYX-QPEP-CC512-SUBKEYS|" + recipient_keyring.key_hash.encode("ascii"),
        )
        okm = hkdf.derive(ss_hybrid)
        k_s1, k_s2, k_transcript_mac = okm[:32], okm[32:64], okm[64:128]

        norm_fname, file_ext, mime_type = detect_file_extension_and_mime(plaintext, filename)
        inner_envelope = {
            "filename": norm_fname,
            "file_extension": file_ext,
            "mime_type": mime_type,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "plaintext_qsponge_512": qsponge_512(plaintext).hex().upper(),
            "plaintext_size": len(plaintext),
            "compressed": compress,
            "encrypting_key_hash": encrypting_keyring.key_hash,
            "embedded_signature": embedded_sig,
            "data_b64": _b64e(zlib.compress(plaintext, level=6) if compress else plaintext),
        }

        serialized_inner = json.dumps(inner_envelope, separators=(",", ":")).encode("utf-8")

        chunks_out = []
        total_len = len(serialized_inner)
        offset = 0
        chunk_idx = 0
        while offset < total_len or (total_len == 0 and chunk_idx == 0):
            piece = serialized_inner[offset : offset + CHUNK_SIZE]
            offset += len(piece)
            is_final = 1 if offset >= total_len else 0
            aad = f"CALYX-QPEP-CC512|recip={recipient_keyring.key_hash}|idx={chunk_idx}|final={is_final}".encode("utf-8")
            n1, n2, ct_chunk = _cc512_encrypt(piece, k_s1, k_s2, aad)
            chunks_out.append(
                {
                    "idx": chunk_idx,
                    "final": is_final,
                    "cc512_n1_b64": _b64e(n1),
                    "cc512_n2_b64": _b64e(n2),
                    "ct_b64": _b64e(ct_chunk),
                }
            )
            chunk_idx += 1
            if total_len == 0:
                break

        transcript_bytes = json.dumps(chunks_out, sort_keys=True, separators=(",", ":")).encode("utf-8")
        transcript_tag = hmac.new(k_transcript_mac, b"CALYX-QPEP-TRANSCRIPT|" + transcript_bytes, hashlib.sha3_512).hexdigest().upper()

        packet_obj = {
            "magic": "QPEP-v1",
            "protocol": PROJECT_NAME,
            "version": UNIVERSAL_VERSION,
            "qlx_tier": qlx_tier,
            "recipient_key_hash": recipient_keyring.key_hash,
            "encrypting_key_hash": encrypting_keyring.key_hash,
            "pkt_salt_b64": _b64e(pkt_salt),
            "ephemeral_hgc_448_pk_b64": _b64e(eph_hgc_pk_bytes),
            "qlx_ct_b64": _b64e(ct_qlx),
            "chunks": chunks_out,
            "transcript_qsponge_512": transcript_tag,
        }

        metadata = {
            "Protocol": PROJECT_NAME,
            "Version": f"{PROTOCOL_VERSION} ({UNIVERSAL_VERSION_LABEL})",
            "Suite": f"{qlx_tier}+HGC-448 / CC-512",
            "Encrypting-Key-Hash": encrypting_keyring.key_hash,
        }
        return _armor_wrap("CALYX QPEP ENCRYPTED PACKET", metadata, json.dumps(packet_obj).encode("utf-8"))

    @staticmethod
    def decrypt_packet(
        armored_packet: str,
        recipient_private_keyring: QPEPKeyRing,
        passphrase: str,
        sender_public_keyring: Optional[QPEPKeyRing] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        enforce_passphrase_policy(passphrase)
        priv_keys = CalyxQPEPProtocol.unlock_private_keys(recipient_private_keyring, passphrase)

        _, _, payload_bytes = _armor_unwrap(armored_packet, expected_label="CALYX QPEP ENCRYPTED PACKET")
        packet_obj = json.loads(payload_bytes.decode("utf-8"))

        if packet_obj.get("recipient_key_hash") != recipient_private_keyring.key_hash:
            raise ValueError("Packet is addressed to a different Key Hash.")

        qlx_tier = recipient_private_keyring.qlx_tier
        recip_hgc_pk_bytes = _b64d(recipient_private_keyring.public_bundle["hgc_448_public_b64"])
        recip_qlx_pk_bytes = _b64d(recipient_private_keyring.public_bundle["qlx_public_b64"])

        eph_hgc_pk_bytes = _b64d(packet_obj["ephemeral_hgc_448_pk_b64"])
        ct_qlx = _b64d(packet_obj["qlx_ct_b64"])

        hgc_sk = x448.X448PrivateKey.from_private_bytes(priv_keys["hgc_448_private"])
        eph_hgc_pk = x448.X448PublicKey.from_public_bytes(eph_hgc_pk_bytes)
        ss_hgc = hgc_sk.exchange(eph_hgc_pk)
        ss_qlx = QLXEngine.decaps(priv_keys["qlx_private"], ct_qlx, tier=qlx_tier)

        ss_hybrid = qsponge_var(
            b"CALYX-QPEP-KEM-v1|"
            + ss_qlx
            + ss_hgc
            + ct_qlx
            + eph_hgc_pk_bytes
            + recip_qlx_pk_bytes
            + recip_hgc_pk_bytes,
            64,
        )

        pkt_salt = _b64d(packet_obj["pkt_salt_b64"])
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=128,
            salt=pkt_salt,
            info=b"CALYX-QPEP-CC512-SUBKEYS|" + recipient_private_keyring.key_hash.encode("ascii"),
        )
        okm = hkdf.derive(ss_hybrid)
        k_s1, k_s2, k_transcript_mac = okm[:32], okm[32:64], okm[64:128]

        chunks = packet_obj.get("chunks", [])
        if not chunks:
            raise QPEPWireFormatError("Malformed OpenQPEP packet: empty chunk list.")
        if chunks[-1].get("final") != 1 or any(ch.get("final") != 0 for ch in chunks[:-1]):
            raise ValueError("Stream truncation or invalid final frame flag detected.")

        transcript_bytes = json.dumps(chunks, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_tag = hmac.new(k_transcript_mac, b"CALYX-QPEP-TRANSCRIPT|" + transcript_bytes, hashlib.sha3_512).hexdigest().upper()
        if not hmac.compare_digest(expected_tag, packet_obj["transcript_qsponge_512"]):
            raise ValueError("Packet transcript qSponge-512 verification failed.")

        reassembled = bytearray()
        for expected_idx, ch in enumerate(chunks):
            if ch["idx"] != expected_idx:
                raise ValueError("Chunk sequence tampering detected.")
            is_final = ch["final"]
            aad = f"CALYX-QPEP-CC512|recip={recipient_private_keyring.key_hash}|idx={expected_idx}|final={is_final}".encode("utf-8")
            pt_piece = _cc512_decrypt(
                outer_ct=_b64d(ch["ct_b64"]),
                k_s1=k_s1,
                k_s2=k_s2,
                n1=_b64d(ch["cc512_n1_b64"]),
                n2=_b64d(ch["cc512_n2_b64"]),
                aad=aad,
            )
            reassembled.extend(pt_piece)

        inner_envelope = json.loads(bytes(reassembled).decode("utf-8"))
        raw_data = _b64d(inner_envelope["data_b64"])
        plaintext = zlib.decompress(raw_data) if inner_envelope.get("compressed") else raw_data

        actual_hash = qsponge_512(plaintext).hex().upper()
        if not hmac.compare_digest(actual_hash, inner_envelope["plaintext_qsponge_512"]):
            raise ValueError("Plaintext qSponge-512 integrity check failed.")

        effective_sender = sender_public_keyring
        if effective_sender is None and inner_envelope.get("encrypting_key_hash") == recipient_private_keyring.key_hash:
            effective_sender = recipient_private_keyring

        sig_verified = None
        if "embedded_signature" in inner_envelope and effective_sender is not None:
            sig_verified, _, _ = CalyxQPEPProtocol.verify_signature(
                inner_envelope["embedded_signature"], signer_public_keyring=effective_sender
            )

        norm_fname, file_ext, mime_type = detect_file_extension_and_mime(
            plaintext, inner_envelope.get("filename")
        )
        meta_info = {
            "qlx_tier": qlx_tier,
            "qvs_tier": QLX_TIERS[qlx_tier]["qvs_tier"],
            "filename": norm_fname,
            "file_extension": inner_envelope.get("file_extension") or file_ext,
            "mime_type": inner_envelope.get("mime_type") or mime_type,
            "timestamp": inner_envelope.get("timestamp"),
            "plaintext_qsponge_512": actual_hash,
            "plaintext_size": inner_envelope.get("plaintext_size"),
            "encrypting_key_hash": inner_envelope.get("encrypting_key_hash"),
            "signature_verified": sig_verified,
        }
        return plaintext, meta_info

    @staticmethod
    def encrypt_file(
        input_path: str | Path,
        recipient_keyring: QPEPKeyRing,
        encrypting_keyring: QPEPKeyRing,
        passphrase: str,
        output_path: Optional[str | Path] = None,
    ) -> Tuple[str, Path]:
        in_p = Path(input_path)
        raw_bytes = in_p.read_bytes()
        armored = CalyxQPEPProtocol.encrypt_bytes(
            raw_bytes,
            recipient_keyring=recipient_keyring,
            encrypting_keyring=encrypting_keyring,
            passphrase=passphrase,
            filename=in_p.name,
        )
        out_p = Path(output_path) if output_path else in_p.with_name(in_p.name + ".qpep")
        out_p.write_text(armored, encoding="utf-8")
        return armored, out_p

    @staticmethod
    def decrypt_file(
        input_qpep_path: str | Path,
        recipient_private_keyring: QPEPKeyRing,
        passphrase: str,
        output_path_or_dir: Optional[str | Path] = None,
        sender_public_keyring: Optional[QPEPKeyRing] = None,
    ) -> Tuple[bytes, Path, Dict[str, Any]]:
        in_p = Path(input_qpep_path)
        armored = in_p.read_text(encoding="utf-8")
        pt_bytes, meta = CalyxQPEPProtocol.decrypt_packet(
            armored,
            recipient_private_keyring=recipient_private_keyring,
            passphrase=passphrase,
            sender_public_keyring=sender_public_keyring,
        )
        rec_name = meta.get("filename") or "decrypted_file.bin"
        if output_path_or_dir is None:
            out_p = in_p.parent / rec_name
        else:
            cand = Path(output_path_or_dir)
            out_p = (cand / rec_name) if cand.is_dir() else cand
        out_p.write_bytes(pt_bytes)
        return pt_bytes, out_p, meta

    @staticmethod
    def encrypt_text(
        plaintext: str,
        recipient_keyring: QPEPKeyRing,
        encrypting_keyring: QPEPKeyRing,
        passphrase: str,
    ) -> str:
        return CalyxQPEPProtocol.encrypt_bytes(
            plaintext.encode("utf-8"),
            recipient_keyring=recipient_keyring,
            encrypting_keyring=encrypting_keyring,
            passphrase=passphrase,
            filename="message.txt",
        )

    @staticmethod
    def decrypt_text(
        armored_packet: str,
        recipient_private_keyring: QPEPKeyRing,
        passphrase: str,
        sender_public_keyring: Optional[QPEPKeyRing] = None,
    ) -> str:
        pt_bytes, _ = CalyxQPEPProtocol.decrypt_packet(
            armored_packet,
            recipient_private_keyring=recipient_private_keyring,
            passphrase=passphrase,
            sender_public_keyring=sender_public_keyring,
        )
        return pt_bytes.decode("utf-8")

    @staticmethod
    def sign_bytes(data: bytes, signer_private_keyring: QPEPKeyRing, passphrase: str) -> str:
        """
        Creates an Attached OpenQPEP Signature (CALYX QPEP ATTACHED SIGNATURE) where the signed
        message payload is encapsulated directly inside the signature packet alongside the QVS
        and HGC-448 signature vectors. Detached signatures are prohibited in OpenQPEP.
        """
        enforce_passphrase_policy(passphrase)
        priv_keys = CalyxQPEPProtocol.unlock_private_keys(signer_private_keyring, passphrase)
        qvs_pk = _b64d(signer_private_keyring.public_bundle["qvs_public_b64"])
        qvs_tier = signer_private_keyring.qvs_tier

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg_digest = qsponge_512(data).hex().upper()
        transcript = f"CALYX-QPEP-ATTACHED-SIG-v1|{signer_private_keyring.key_hash}|{timestamp}|{msg_digest}".encode("utf-8")

        ed_sk = ed448.Ed448PrivateKey.from_private_bytes(priv_keys["hgc_sig_private"])
        sig1 = ed_sk.sign(transcript)
        sig2 = QVSEngine.sign(priv_keys["qvs_private"], qvs_pk, transcript, tier=qvs_tier)

        sig_obj = {
            "magic": "QPSIG-ATTACHED-v1",
            "protocol": PROJECT_NAME,
            "version": UNIVERSAL_VERSION,
            "signature_mode": "ATTACHED_ENVELOPE",
            "suite": f"{qvs_tier}+qSponge-512",
            "signer_key_hash": signer_private_keyring.key_hash,
            "signer_name": signer_private_keyring.name,
            "signer_email": signer_private_keyring.email,
            "timestamp": timestamp,
            "attached_message_b64": _b64e(data),
            "message_qsponge_512": msg_digest,
            "hgc_signature_b64": _b64e(sig1),
            "qvs_signature_b64": _b64e(sig2),
        }
        metadata = {
            "Protocol": PROJECT_NAME,
            "Version": f"{PROTOCOL_VERSION} ({UNIVERSAL_VERSION_LABEL})",
            "Mode": "ATTACHED-SIGNATURE",
            "Suite": f"{qvs_tier}+qSponge-512",
            "Timestamp": timestamp,
        }
        return _armor_wrap("CALYX QPEP ATTACHED SIGNATURE", metadata, json.dumps(sig_obj).encode("utf-8"))

    @staticmethod
    def verify_signature(
        armored_attached_signature: str,
        signer_public_keyring: Optional[QPEPKeyRing] = None,
        keyring_pool: Optional[List[QPEPKeyRing]] = None,
    ) -> Tuple[bool, Optional[bytes], Optional[QPEPKeyRing]]:
        """
        Verifies an OpenQPEP Attached Signature packet (no separate detached message parameter).
        Extracts the embedded message from inside the signature packet, verifies the QVS + HGC-448
        signature against signer_public_keyring or across keyring_pool (Auto mode), and returns
        (is_valid, extracted_message_bytes, matched_keyring).
        """
        try:
            _, _, payload_bytes = _armor_unwrap(
                armored_attached_signature, expected_label="CALYX QPEP ATTACHED SIGNATURE"
            )
            sig_obj = json.loads(payload_bytes.decode("utf-8"))
            if "attached_message_b64" not in sig_obj:
                raise ValueError("Detached signatures are prohibited in OpenQPEP; message must be attached.")

            extracted_data = _b64d(sig_obj["attached_message_b64"])
            actual_digest = qsponge_512(extracted_data).hex().upper()
            if not hmac.compare_digest(actual_digest, sig_obj.get("message_qsponge_512", "")):
                return False, None, None

            target_hash = sig_obj.get("signer_key_hash")
            candidates = []
            if signer_public_keyring is not None:
                candidates = [signer_public_keyring]
            elif keyring_pool is not None:
                candidates = [kr for kr in keyring_pool if kr.key_hash == target_hash] or list(keyring_pool)

            for candidate in candidates:
                if candidate.key_hash != target_hash:
                    continue
                if not CalyxQPEPProtocol.verify_public_keyring_self_signature(candidate):
                    continue
                transcript = (
                    f"CALYX-QPEP-ATTACHED-SIG-v1|{candidate.key_hash}|{sig_obj['timestamp']}|{actual_digest}".encode("utf-8")
                )
                ed_pk = ed448.Ed448PublicKey.from_public_bytes(_b64d(candidate.public_bundle["hgc_sig_public_b64"]))
                ed_pk.verify(_b64d(sig_obj["hgc_signature_b64"]), transcript)
                qvs_pk = _b64d(candidate.public_bundle["qvs_public_b64"])
                if QVSEngine.verify(qvs_pk, transcript, _b64d(sig_obj["qvs_signature_b64"]), tier=candidate.qvs_tier):
                    return True, extracted_data, candidate
            return False, None, None
        except Exception:
            return False, None, None

    @staticmethod
    def sign_text(text: str, signer_private_keyring: QPEPKeyRing, passphrase: str) -> str:
        return CalyxQPEPProtocol.sign_bytes(text.encode("utf-8"), signer_private_keyring, passphrase)

    @staticmethod
    def verify_text_signature(
        armored_attached_signature: str,
        signer_public_keyring: Optional[QPEPKeyRing] = None,
        keyring_pool: Optional[List[QPEPKeyRing]] = None,
    ) -> Tuple[bool, Optional[str], Optional[QPEPKeyRing]]:
        ok, raw_bytes, kr = CalyxQPEPProtocol.verify_signature(
            armored_attached_signature,
            signer_public_keyring=signer_public_keyring,
            keyring_pool=keyring_pool,
        )
        return ok, (raw_bytes.decode("utf-8") if (ok and raw_bytes is not None) else None), kr


# Provide official alias OpenQPEPProtocol alongside CalyxQPEPProtocol
    @staticmethod
    def encrypt_multi_recipient(
        payload: bytes,
        recipient_keyrings,
        *,
        bucket_size: int = 4096,
        pad_slots_power_of_2: bool = True,
        min_slots: int = 4,
        use_blind_hint: bool = True,
    ) -> str:
        from .wire.multi_recipient import encrypt_multi_recipient as _enc_mr
        return _enc_mr(
            payload,
            recipient_keyrings,
            bucket_size=bucket_size,
            pad_slots_power_of_2=pad_slots_power_of_2,
            min_slots=min_slots,
            use_blind_hint=use_blind_hint,
        )

    @staticmethod
    def decrypt_multi_recipient(armored_packet: str, recipient_keyring: QPEPKeyRing, passphrase: str):
        from .wire.multi_recipient import decrypt_multi_recipient as _dec_mr
        return _dec_mr(armored_packet, recipient_keyring, passphrase)


    @staticmethod
    def get_keyring_suite_id(keyring: QPEPKeyRing) -> str:
        return str(keyring.public_bundle.get("suite_id") or keyring.public_bundle.get("qlx_tier") or "QLX-4096")

    @staticmethod
    def encrypt_beyond_lwe_packet(
        plaintext: bytes,
        recipient_keyring: QPEPKeyRing,
    ) -> str:
        """Encrypts bytes directly using the recipient .qpkrf key ring's native Beyond-LWE suite."""
        suite_id = OpenQPEPProtocol.get_keyring_suite_id(recipient_keyring)
        blwe_pub = recipient_keyring.public_bundle.get("beyond_lwe_public")
        if suite_id not in BEYOND_LWE_SUITES or not blwe_pub:
            raise ValueError(f"Key ring {recipient_keyring.key_hash[:12]} is not a Beyond-LWE suite ({suite_id}).")
        return encrypt_beyond_lwe(suite_id, plaintext, blwe_pub)

    @staticmethod
    def decrypt_beyond_lwe_packet(
        armored_packet: str,
        recipient_keyring: QPEPKeyRing,
        passphrase: str,
    ) -> bytes:
        """Unlocks the recipient .qpkrf private key ring via Argon2id+qSponge-512 and decrypts Beyond-LWE packet."""
        suite_id = OpenQPEPProtocol.get_keyring_suite_id(recipient_keyring)
        priv = OpenQPEPProtocol.unlock_private_keys(recipient_keyring, passphrase)
        blwe_priv = priv.get("beyond_lwe_private")
        if suite_id not in BEYOND_LWE_SUITES or not blwe_priv:
            raise ValueError(f"Key ring {recipient_keyring.key_hash[:12]} lacks Beyond-LWE private key material.")
        return decrypt_beyond_lwe(suite_id, armored_packet, blwe_priv)

    @staticmethod
    def sign_beyond_lwe_bytes(
        data: bytes,
        signer_private_keyring: QPEPKeyRing,
        passphrase: str,
    ) -> str:
        """Signs bytes directly using the signer .qpkrf key ring's native Beyond-LWE signature engine."""
        suite_id = OpenQPEPProtocol.get_keyring_suite_id(signer_private_keyring)
        blwe_pub = signer_private_keyring.public_bundle.get("beyond_lwe_public")
        priv = OpenQPEPProtocol.unlock_private_keys(signer_private_keyring, passphrase)
        blwe_priv = priv.get("beyond_lwe_private")
        if suite_id not in BEYOND_LWE_SUITES or not blwe_pub or not blwe_priv:
            raise ValueError(f"Key ring {signer_private_keyring.key_hash[:12]} lacks Beyond-LWE signing material.")
        return sign_beyond_lwe(suite_id, data, blwe_pub, blwe_priv)

    @staticmethod
    def verify_beyond_lwe_signature(
        armored_sig: str,
        signer_public_keyring: QPEPKeyRing,
    ) -> Tuple[bool, bytes]:
        """Verifies a native Beyond-LWE signature against the signer's .qpkrf public key ring."""
        suite_id = OpenQPEPProtocol.get_keyring_suite_id(signer_public_keyring)
        blwe_pub = signer_public_keyring.public_bundle.get("beyond_lwe_public")
        if suite_id not in BEYOND_LWE_SUITES or not blwe_pub:
            return False, b""
        return verify_beyond_lwe(suite_id, armored_sig, blwe_pub)


OpenQPEPProtocol = CalyxQPEPProtocol
