#!/usr/bin/env python3
"""
Calyx Labs Inc. Android APK ZipAlign + v1 / v2 / v3 Signer & Cryptographic Verifier (v1.1).

Produces 100% Android PackageManager-compliant APKs (API 29–37+ / Android 10–17+):
  1. Strict zipalign (-p 4, 4096 for .so): resources.arsc FIRST & STORED at 4-byte boundary,
     all STORED entries aligned via Local File Header extra-field zero-padding, zero data descriptors.
  2. Clean JAR v1 signature (META-INF/MANIFEST.MF, META-INF/CERT.SF with X-Android-APK-Signed: 2, 3,
     and clean DER PKCS#7 SignedData META-INF/CERT.RSA without bloated S/MIME signedAttributes).
  3. Full APK Signature Scheme v2 (0x7109871a) with 1 MiB chunked SHA-256 Merkle digest + RSA-PKCS1v15-SHA256.
  4. Full APK Signature Scheme v3 (0xf05368c0, minSdk=29, maxSdk=0x7fffffff) + RSA-PKCS1v15-SHA256.
  5. Verity page-alignment padding block (0x42726577) so APK Sig Block 42 is a multiple of 4096 bytes.
  6. Independent full cryptographic + structural verifier (ZIP, zipalign, AXML, v1, v2, v3).
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import io
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_SIG_SCHEME_V2_ID = 0x7109871A
APK_SIG_SCHEME_V3_ID = 0xF05368C0
VERITY_PADDING_BLOCK_ID = 0x42726577
SIG_ALG_RSA_PKCS1_V15_SHA256 = 0x0103
CHUNK_SIZE = 1024 * 1024

DEFAULT_KEY_DIR = Path("/home/ubuntu/OpenQPEP/.calyx_release_keys")
DEFAULT_KEY_PATH = DEFAULT_KEY_DIR / "calyx_apk_release_key.pem"
DEFAULT_CERT_PATH = DEFAULT_KEY_DIR / "calyx_apk_release_cert.pem"


# ---------------------------------------------------------------------------
# Minimal strict ASN.1 DER helpers (for clean PKCS#7 SignedData CERT.RSA)
# ---------------------------------------------------------------------------

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(val)) + val


def _der_seq(*items: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(items))


def _der_set(*items: bytes) -> bytes:
    # DER SET OF sorts elements lexicographically
    return _der_tlv(0x31, b"".join(sorted(items)))


def _der_int(n: int) -> bytes:
    if n == 0:
        b = b"\x00"
    else:
        b = n.to_bytes((n.bit_length() + 8) // 8, "big")
        if len(b) > 1 and b[0] == 0 and (b[1] & 0x80) == 0:
            b = b[1:]
    return _der_tlv(0x02, b)


def _der_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
        else:
            tmp = []
            while p:
                tmp.append(p & 0x7F)
                p >>= 7
            tmp.reverse()
            for i in range(len(tmp) - 1):
                out.append(tmp[i] | 0x80)
            out.append(tmp[-1])
    return _der_tlv(0x06, bytes(out))


def _der_null() -> bytes:
    return b"\x05\x00"


def _der_octet_string(b: bytes) -> bytes:
    return _der_tlv(0x04, b)


def build_pkcs7_cert_rsa(
    cert_sf_bytes: bytes,
    private_key: rsa.RSAPrivateKey,
    cert: x509.Certificate,
) -> bytes:
    """Build clean DER PKCS#7 SignedData (detached, no signedAttributes), matching apksigner."""
    oid_signed_data = _der_oid("1.2.840.113549.1.7.2")
    oid_data = _der_oid("1.2.840.113549.1.7.1")
    oid_sha256 = _der_oid("2.16.840.1.101.3.4.2.1")
    oid_rsa = _der_oid("1.2.840.113549.1.1.1")

    sha256_alg_id = _der_seq(oid_sha256)
    rsa_alg_id = _der_seq(oid_rsa, _der_null())

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    issuer_der = cert.issuer.public_bytes()
    serial_der = _der_int(cert.serial_number)

    sig_bytes = private_key.sign(cert_sf_bytes, asym_padding.PKCS1v15(), hashes.SHA256())

    signer_info = _der_seq(
        _der_int(1),
        _der_seq(issuer_der, serial_der),
        sha256_alg_id,
        rsa_alg_id,
        _der_octet_string(sig_bytes),
    )

    signed_data = _der_seq(
        _der_int(1),
        _der_set(sha256_alg_id),
        _der_seq(oid_data),
        _der_tlv(0xA0, cert_der),
        _der_set(signer_info),
    )

    return _der_seq(oid_signed_data, _der_tlv(0xA0, signed_data))


# ---------------------------------------------------------------------------
# Persistent Release Keypair Loader / Generator
# ---------------------------------------------------------------------------

def load_or_create_release_key(
    key_path: Path = DEFAULT_KEY_PATH,
    cert_path: Path = DEFAULT_CERT_PATH,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    if key_path.is_file() and cert_path.is_file():
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return private_key, cert

    key_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(key_path.parent, 0o700)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "OH"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Cleveland"),
        x509.NameAttribute(NameOID.POSTAL_CODE, "44105"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Calyx Labs Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Tristen Martinez (aka Calyxia)"),
    ])
    # Use 2025-01-01 UTC -> 2055-01-01 UTC so no Android device clock skew can ever trigger NotYetValid
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2055, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc))
        .sign(private_key, hashes.SHA256())
    )

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_pem)
    cert_path.write_bytes(cert_pem)
    os.chmod(cert_path, 0o644)
    return private_key, cert


# ---------------------------------------------------------------------------
# JAR v1 Manifest & Signature File Builders (72-byte line-length compliant)
# ---------------------------------------------------------------------------

def _jar_header(key: str, val: str) -> bytes:
    raw = f"{key}: {val}".encode("utf-8")
    if len(raw) <= 70:
        return raw + b"\r\n"
    out = bytearray(raw[:70]) + bytearray(b"\r\n")
    pos = 70
    while pos < len(raw):
        out.extend(b" ")
        out.extend(raw[pos : pos + 69])
        out.extend(b"\r\n")
        pos += 69
    return bytes(out)


def build_v1_signatures(
    content_entries: Sequence[Tuple[str, bytes]],
    private_key: rsa.RSAPrivateKey,
    cert: x509.Certificate,
) -> Tuple[bytes, bytes, bytes]:
    """Return (MANIFEST.MF, CERT.SF, CERT.RSA) bytes."""
    mf_main = (
        _jar_header("Manifest-Version", "1.0")
        + _jar_header("Created-By", "Calyx Labs Inc. APK Signer 1.1")
        + b"\r\n"
    )
    mf_sections: List[Tuple[str, bytes]] = []
    for name, raw in content_entries:
        dig = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")
        sec = _jar_header("Name", name) + _jar_header("SHA-256-Digest", dig) + b"\r\n"
        mf_sections.append((name, sec))

    manifest_bytes = mf_main + b"".join(sec for _, sec in mf_sections)

    mf_digest = base64.b64encode(hashlib.sha256(manifest_bytes).digest()).decode("ascii")
    sf_main = (
        _jar_header("Signature-Version", "1.0")
        + _jar_header("SHA-256-Digest-Manifest", mf_digest)
        + _jar_header("Created-By", "Calyx Labs Inc. APK Signer 1.1")
        + _jar_header("X-Android-APK-Signed", "2, 3")
        + b"\r\n"
    )
    sf_sections = []
    for name, sec in mf_sections:
        sec_dig = base64.b64encode(hashlib.sha256(sec).digest()).decode("ascii")
        sf_sections.append(_jar_header("Name", name) + _jar_header("SHA-256-Digest", sec_dig) + b"\r\n")

    cert_sf_bytes = sf_main + b"".join(sf_sections)
    cert_rsa_bytes = build_pkcs7_cert_rsa(cert_sf_bytes, private_key, cert)
    return manifest_bytes, cert_sf_bytes, cert_rsa_bytes


# ---------------------------------------------------------------------------
# Strict zipalign (-p 4 / 4096) ZIP Writer
# ---------------------------------------------------------------------------

def _dos_time_date(year: int = 2026, month: int = 11, day: int = 23, hour: int = 12, minute: int = 0, sec: int = 0) -> Tuple[int, int]:
    dos_time = ((hour & 0x1F) << 11) | ((minute & 0x3F) << 5) | ((sec // 2) & 0x1F)
    dos_date = (((year - 1980) & 0x7F) << 9) | ((month & 0x0F) << 5) | (day & 0x1F)
    return dos_time, dos_date


def _entry_sort_key(name: str, compress_type: int) -> Tuple[int, str]:
    if name == "resources.arsc":
        return (0, name)
    if compress_type == zipfile.ZIP_STORED and not name.startswith("META-INF/"):
        return (1, name)
    if name == "AndroidManifest.xml":
        return (2, name)
    if name.startswith("classes") and name.endswith(".dex"):
        return (3, name)
    if not name.startswith("META-INF/"):
        return (4, name)
    if name == "META-INF/MANIFEST.MF":
        return (5, name)
    if name == "META-INF/CERT.SF":
        return (6, name)
    if name == "META-INF/CERT.RSA":
        return (7, name)
    return (8, name)


def build_aligned_zip(entries: Sequence[Tuple[str, bytes, int]]) -> Tuple[bytes, bytes, bytes]:
    """
    Build a zipaligned ZIP32 archive without data descriptors.
    entries: sequence of (filename, raw_bytes, compress_type).
    Returns (sec1_local_entries, sec2_central_directory, sec3_eocd).
    """
    dos_time, dos_date = _dos_time_date()
    sec1 = bytearray()
    cd = bytearray()

    for name, raw, ctype in entries:
        name_b = name.encode("utf-8")
        crc = zlib.crc32(raw) & 0xFFFFFFFF
        usz = len(raw)

        if ctype == zipfile.ZIP_STORED:
            comp = raw
            align = 4096 if name.endswith(".so") else 4
            lh_off = len(sec1)
            data_off_unpadded = lh_off + 30 + len(name_b)
            pad = (align - (data_off_unpadded % align)) % align
            local_extra = b"\x00" * pad
        elif ctype == zipfile.ZIP_DEFLATED:
            co = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
            comp = co.compress(raw) + co.flush()
            lh_off = len(sec1)
            local_extra = b""
        else:
            raise ValueError(f"Unsupported compression type {ctype} for {name}")

        csz = len(comp)
        flags = 0  # No bit-3 data descriptor
        ver_needed = 20
        ver_made = 20

        local_hdr = struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            ver_needed,
            flags,
            ctype,
            dos_time,
            dos_date,
            crc,
            csz,
            usz,
            len(name_b),
            len(local_extra),
        )
        sec1.extend(local_hdr)
        sec1.extend(name_b)
        sec1.extend(local_extra)
        if ctype == zipfile.ZIP_STORED:
            assert len(sec1) % align == 0, f"Alignment failure on {name}: offset {len(sec1)}"
        sec1.extend(comp)

        cd_hdr = struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            ver_made,
            ver_needed,
            flags,
            ctype,
            dos_time,
            dos_date,
            crc,
            csz,
            usz,
            len(name_b),
            0,  # cd extra_len == 0 (zipalign convention)
            0,  # comment_len
            0,  # disk_start
            0,  # internal_attr
            0,  # external_attr
            lh_off,
        )
        cd.extend(cd_hdr)
        cd.extend(name_b)

    cd_off = len(sec1)
    cd_size = len(cd)
    n_entries = len(entries)
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        n_entries,
        n_entries,
        cd_size,
        cd_off,
        0,
    )
    return bytes(sec1), bytes(cd), eocd


# ---------------------------------------------------------------------------
# APK Signature Scheme v2 (0x7109871a) & v3 (0xf05368c0) + Verity Padding
# ---------------------------------------------------------------------------

def _lp(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def compute_chunked_sha256(sec1: bytes, sec2: bytes, sec3: bytes) -> bytes:
    """APK Signature Scheme v2/v3 1 MiB chunked SHA-256 Merkle digest."""
    chunk_digests: List[bytes] = []
    for sec in (sec1, sec2, sec3):
        mv = memoryview(sec)
        n = len(mv)
        for off in range(0, n, CHUNK_SIZE):
            c = mv[off : off + CHUNK_SIZE]
            h = hashlib.sha256()
            h.update(b"\xa5")
            h.update(struct.pack("<I", len(c)))
            h.update(c)
            chunk_digests.append(h.digest())
    top = hashlib.sha256()
    top.update(b"\x5a")
    top.update(struct.pack("<I", len(chunk_digests)))
    for d in chunk_digests:
        top.update(d)
    return top.digest()


def build_apk_signing_block(
    content_digest: bytes,
    private_key: rsa.RSAPrivateKey,
    cert: x509.Certificate,
    min_sdk: int = 29,
    max_sdk: int = 0x7FFFFFFF,
) -> bytes:
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    pub_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    digests = _lp(_lp(struct.pack("<I", SIG_ALG_RSA_PKCS1_V15_SHA256) + _lp(content_digest)))
    certs = _lp(_lp(cert_der))
    additional_attrs = _lp(b"")

    # Scheme v2 (0x7109871a)
    signed_data_v2 = digests + certs + additional_attrs
    sig_v2 = private_key.sign(signed_data_v2, asym_padding.PKCS1v15(), hashes.SHA256())
    sigs_v2 = _lp(_lp(struct.pack("<I", SIG_ALG_RSA_PKCS1_V15_SHA256) + _lp(sig_v2)))
    signer_v2 = _lp(signed_data_v2) + sigs_v2 + _lp(pub_der)
    v2_value = _lp(_lp(signer_v2))

    # Scheme v3 (0xf05368c0)
    sdk_range = struct.pack("<II", min_sdk, max_sdk)
    signed_data_v3 = digests + certs + sdk_range + additional_attrs
    sig_v3 = private_key.sign(signed_data_v3, asym_padding.PKCS1v15(), hashes.SHA256())
    sigs_v3 = _lp(_lp(struct.pack("<I", SIG_ALG_RSA_PKCS1_V15_SHA256) + _lp(sig_v3)))
    signer_v3 = _lp(signed_data_v3) + sdk_range + sigs_v3 + _lp(pub_der)
    v3_value = _lp(_lp(signer_v3))

    pairs: List[Tuple[int, bytes]] = [
        (APK_SIG_SCHEME_V2_ID, v2_value),
        (APK_SIG_SCHEME_V3_ID, v3_value),
    ]

    # Pad total APK Signing Block (8 + sum(12 + len(v)) + 8 + 16) to a multiple of 4096 bytes
    raw_total = 8 + sum(12 + len(v) for _, v in pairs) + 24
    rem = (4096 - (raw_total % 4096)) % 4096
    if rem > 0:
        if rem < 12:
            rem += 4096
        pairs.append((VERITY_PADDING_BLOCK_ID, b"\x00" * (rem - 12)))

    body = b"".join(struct.pack("<QI", 4 + len(v), pid) + v for pid, v in pairs)
    block_size = len(body) + 24  # pairs + uint64 size2 + 16-byte magic
    block = struct.pack("<Q", block_size) + body + struct.pack("<Q", block_size) + APK_SIG_BLOCK_MAGIC
    assert len(block) % 4096 == 0, f"APK Sig Block length {len(block)} not multiple of 4096"
    assert len(block) == block_size + 8
    return block


def build_and_sign_apk(
    content_entries: Sequence[Tuple[str, bytes, int]],
    private_key: rsa.RSAPrivateKey,
    cert: x509.Certificate,
    min_sdk: int = 29,
) -> bytes:
    """
    Build a zipaligned APK with v1 + v2 + v3 signatures from non-META-INF entries.
    content_entries: list of (filename, raw_bytes, compress_type).
    """
    # Filter out any stale META-INF signature files and ensure resources.arsc is STORED
    clean_entries: List[Tuple[str, bytes, int]] = []
    for name, raw, ctype in content_entries:
        if name.startswith("META-INF/"):
            continue
        if name == "resources.arsc":
            ctype = zipfile.ZIP_STORED
        clean_entries.append((name, raw, ctype))

    clean_entries.sort(key=lambda item: _entry_sort_key(item[0], item[2]))

    # 1. JAR v1 signature entries
    mf_bytes, sf_bytes, rsa_bytes = build_v1_signatures(
        [(n, r) for n, r, _ in clean_entries],
        private_key,
        cert,
    )
    all_entries = list(clean_entries) + [
        ("META-INF/MANIFEST.MF", mf_bytes, zipfile.ZIP_DEFLATED),
        ("META-INF/CERT.SF", sf_bytes, zipfile.ZIP_DEFLATED),
        ("META-INF/CERT.RSA", rsa_bytes, zipfile.ZIP_DEFLATED),
    ]

    # 2. Strict zipalign ZIP assembly
    sec1, sec2, orig_eocd = build_aligned_zip(all_entries)

    # 3. APK Signature Scheme v2 + v3 + Verity Padding Block
    content_digest = compute_chunked_sha256(sec1, sec2, orig_eocd)
    sig_block = build_apk_signing_block(content_digest, private_key, cert, min_sdk=min_sdk)

    # 4. Splice APK Signing Block before Central Directory and patch EOCD cd_offset
    final_eocd = bytearray(orig_eocd)
    new_cd_off = len(sec1) + len(sig_block)
    struct.pack_into("<I", final_eocd, 16, new_cd_off)

    return sec1 + sig_block + sec2 + bytes(final_eocd)


# ---------------------------------------------------------------------------
# Independent Full APK Verifier (ZIP, zipalign, AXML, v1, v2, v3)
# ---------------------------------------------------------------------------

def _read_lp(buf: bytes, pos: int) -> Tuple[bytes, int]:
    if pos + 4 > len(buf):
        raise ValueError("Truncated length-prefixed field")
    ln = struct.unpack("<I", buf[pos : pos + 4])[0]
    end = pos + 4 + ln
    if end > len(buf):
        raise ValueError(f"Length-prefixed field overflows buffer ({end} > {len(buf)})")
    return buf[pos + 4 : end], end


def verify_axml(axml: bytes, expected_vc: Optional[int] = None, expected_vn: Optional[str] = None) -> Dict[str, object]:
    if len(axml) < 36:
        raise ValueError("AXML too short")
    rtype, hsz, tsz = struct.unpack("<HHI", axml[:8])
    if rtype != 0x0003 or hsz != 8 or tsz != len(axml):
        raise ValueError(f"Invalid AXML header: type={hex(rtype)} hsz={hsz} tsz={tsz} actual={len(axml)}")

    sp_type, sp_hsz, sp_tsz, str_cnt, sty_cnt, sp_flags, str_start, sty_start = struct.unpack("<HHIIIIII", axml[8:36])
    if sp_type != 0x0001 or sp_hsz != 28 or sp_tsz % 4 != 0:
        raise ValueError(f"Invalid StringPool header: type={hex(sp_type)} hsz={sp_hsz} tsz={sp_tsz}")
    is_utf8 = bool(sp_flags & 0x100)
    is_sorted = bool(sp_flags & 0x01)
    offsets = struct.unpack(f"<{str_cnt}I", axml[8 + sp_hsz : 8 + sp_hsz + 4 * str_cnt])
    strings: List[str] = []
    base = 8 + str_start
    sp_end = 8 + sp_tsz
    for off in offsets:
        p = base + off
        if is_utf8:
            c1 = axml[p]; p += 1
            if c1 & 0x80: p += 1
            b1 = axml[p]; p += 1
            if b1 & 0x80:
                b1 = ((b1 & 0x7F) << 8) | axml[p]; p += 1
            s = axml[p : p + b1].decode("utf-8")
            if axml[p + b1] != 0:
                raise ValueError(f"Missing UTF-8 NUL terminator for {s!r}")
        else:
            u1 = struct.unpack("<H", axml[p : p + 2])[0]; p += 2
            if u1 & 0x8000:
                u2 = struct.unpack("<H", axml[p : p + 2])[0]; p += 2
                u1 = ((u1 & 0x7FFF) << 16) | u2
            if p + 2 * u1 + 2 > sp_end:
                raise ValueError("UTF-16 string overflows StringPool")
            s = axml[p : p + 2 * u1].decode("utf-16le")
            nul = struct.unpack("<H", axml[p + 2 * u1 : p + 2 * u1 + 2])[0]
            if nul != 0:
                raise ValueError(f"Missing UTF-16 NUL terminator for {s!r}")
        strings.append(s)

    if is_sorted and strings != sorted(strings):
        raise ValueError("AXML StringPool has SORTED_FLAG set but strings are not sorted")

    pos = sp_end
    info: Dict[str, object] = {}
    while pos < len(axml):
        if pos + 8 > len(axml):
            raise ValueError(f"Truncated AXML chunk at {pos}")
        ct, ch, cs = struct.unpack("<HHI", axml[pos : pos + 8])
        if cs < 8 or pos + cs > len(axml):
            raise ValueError(f"Corrupt AXML chunk size {cs} at {pos}")
        if ct == 0x0102:  # START_ELEMENT
            ns_i, name_i, attr_start, attr_size, attr_cnt, _, _, _ = struct.unpack("<iiHHHHHH", axml[pos + 16 : pos + 36])
            el = strings[name_i] if 0 <= name_i < len(strings) else ""
            if el in ("manifest", "uses-sdk"):
                apos = pos + 16 + attr_start
                for _ in range(attr_cnt):
                    _, a_name, a_raw, _, _, a_type, a_data = struct.unpack("<iiiHBBI", axml[apos : apos + 20])
                    an = strings[a_name] if 0 <= a_name < len(strings) else ""
                    if an == "versionCode":
                        info["versionCode"] = a_data
                    elif an == "versionName":
                        info["versionName"] = strings[a_raw] if 0 <= a_raw < len(strings) else strings[a_data]
                    elif an == "package":
                        info["package"] = strings[a_raw] if 0 <= a_raw < len(strings) else strings[a_data]
                    elif an in ("minSdkVersion", "targetSdkVersion", "compileSdkVersion"):
                        info[an] = a_data
                    apos += attr_size
        pos += cs
    if pos != len(axml):
        raise ValueError(f"AXML parse ended at {pos} != {len(axml)}")
    if expected_vc is not None and info.get("versionCode") != expected_vc:
        raise ValueError(f"AXML versionCode {info.get('versionCode')} != expected {expected_vc}")
    if expected_vn is not None and info.get("versionName") != expected_vn:
        raise ValueError(f"AXML versionName {info.get('versionName')!r} != expected {expected_vn!r}")
    return info


def verify_apk(
    apk_source: Path | bytes,
    expected_vc: Optional[int] = None,
    expected_vn: Optional[str] = None,
) -> Dict[str, object]:
    """
    Strictly verify ZIP structure, zipalign 4-byte alignment, AXML integrity,
    JAR v1 (MANIFEST.MF + CERT.SF + PKCS#7 CERT.RSA via OpenSSL CMS),
    APK Signature Scheme v2 (0x7109871a), APK Signature Scheme v3 (0xf05368c0),
    and 4096-byte Verity Padding (0x42726577).
    Raises ValueError / AssertionError on ANY defect.
    """
    data = apk_source.read_bytes() if isinstance(apk_source, Path) else apk_source

    # 1. EOCD & APK Signing Block 42
    eocd_off = data.rfind(b"PK\x05\x06")
    if eocd_off < 0:
        raise ValueError("Missing ZIP EOCD")
    _, disk, cd_disk, n_disk, n_tot, cd_size, cd_off, cmt_len = struct.unpack("<4sHHHHIIH", data[eocd_off : eocd_off + 22])
    if eocd_off + 22 + cmt_len != len(data):
        raise ValueError("Trailing bytes after EOCD")
    if disk != 0 or cd_disk != 0 or n_disk != n_tot:
        raise ValueError("Multi-disk ZIP not permitted in APK")
    if cd_off + cd_size != eocd_off:
        raise ValueError(f"Central Directory bounds invalid: {cd_off}+{cd_size} != {eocd_off}")

    if cd_off < 32 or data[cd_off - 16 : cd_off] != APK_SIG_BLOCK_MAGIC:
        raise ValueError("Missing APK Sig Block 42 (v2/v3 signatures required for targetSdkVersion >= 30)")
    sz2 = struct.unpack("<Q", data[cd_off - 24 : cd_off - 16])[0]
    sb_start = cd_off - sz2 - 8
    if sb_start < 0:
        raise ValueError("Invalid APK Signing Block start offset")
    sz1 = struct.unpack("<Q", data[sb_start : sb_start + 8])[0]
    if sz1 != sz2:
        raise ValueError(f"APK Signing Block size mismatch: sz1={sz1} != sz2={sz2}")
    sb_total = cd_off - sb_start
    if sb_total % 4096 != 0:
        raise ValueError(f"APK Signing Block total size {sb_total} is not a multiple of 4096")

    # 2. ZIP integrity, zipalign alignment, and AXML validation
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise ValueError(f"Corrupt ZIP entry: {bad}")
        infos = zf.infolist()
        if not infos or infos[0].filename != "resources.arsc":
            raise ValueError(f"resources.arsc must be first ZIP entry (found {infos[0].filename if infos else None})")

        non_meta_names: List[str] = []
        for zi in infos:
            lh_off = zi.header_offset
            sig, _, flags, ctype, _, _, _, _, _, fn_len, ex_len = struct.unpack("<4sHHHHHIIIHH", data[lh_off : lh_off + 30])
            if sig != b"PK\x03\x04":
                raise ValueError(f"Bad local header signature for {zi.filename}")
            if flags & 0x08:
                raise ValueError(f"ZIP entry {zi.filename} uses bit-3 data descriptor")
            data_off = lh_off + 30 + fn_len + ex_len
            if zi.filename == "resources.arsc":
                if ctype != zipfile.ZIP_STORED:
                    raise ValueError("resources.arsc MUST be uncompressed (STORED)")
                if data_off % 4 != 0:
                    raise ValueError(f"resources.arsc data_off={data_off} is not 4-byte aligned")
            elif ctype == zipfile.ZIP_STORED:
                align = 4096 if zi.filename.endswith(".so") else 4
                if data_off % align != 0:
                    raise ValueError(f"STORED entry {zi.filename} data_off={data_off} not {align}-byte aligned")
            if not zi.filename.startswith("META-INF/"):
                non_meta_names.append(zi.filename)

        axml_info = verify_axml(zf.read("AndroidManifest.xml"), expected_vc=expected_vc, expected_vn=expected_vn)
        min_sdk = int(axml_info.get("minSdkVersion", 29))

        # 3. Verify JAR v1 (MANIFEST.MF + CERT.SF + CERT.RSA)
        mf = zf.read("META-INF/MANIFEST.MF")
        sf = zf.read("META-INF/CERT.SF")
        rsa_der = zf.read("META-INF/CERT.RSA")

        for label, blob in (("MANIFEST.MF", mf), ("CERT.SF", sf)):
            for line in blob.split(b"\r\n"):
                if len(line) > 70:
                    raise ValueError(f"{label} exceeds 72-byte JAR line limit: {line!r}")

        mf_sha_b64 = base64.b64encode(hashlib.sha256(mf).digest()).decode("ascii")
        if f"SHA-256-Digest-Manifest: {mf_sha_b64}\r\n".encode("ascii") not in sf:
            raise ValueError("CERT.SF SHA-256-Digest-Manifest mismatch")
        if b"X-Android-APK-Signed: 2, 3\r\n" not in sf:
            raise ValueError("CERT.SF missing X-Android-APK-Signed: 2, 3 anti-stripping header")

        # Parse MANIFEST.MF sections & verify against ZIP payloads and CERT.SF
        mf_parts = mf.split(b"\r\n\r\n")
        sf_text = sf.decode("utf-8")
        mf_seen = set()
        for blk in mf_parts[1:]:
            if not blk.strip():
                continue
            raw_blk = blk + b"\r\n\r\n"
            lines = blk.decode("utf-8").replace("\r\n ", "").split("\r\n")
            name = lines[0].split("Name: ", 1)[1]
            dig = lines[1].split("SHA-256-Digest: ", 1)[1]
            actual = base64.b64encode(hashlib.sha256(zf.read(name)).digest()).decode("ascii")
            if dig != actual:
                raise ValueError(f"MANIFEST.MF SHA-256 mismatch for {name}")
            sec_dig = base64.b64encode(hashlib.sha256(raw_blk).digest()).decode("ascii")
            expected_sf_blk = (_jar_header("Name", name) + _jar_header("SHA-256-Digest", sec_dig)).decode("utf-8")
            if expected_sf_blk not in sf_text:
                raise ValueError(f"CERT.SF section digest mismatch for {name}")
            mf_seen.add(name)

        missing = set(non_meta_names) - mf_seen
        if missing:
            raise ValueError(f"ZIP entries missing from MANIFEST.MF: {sorted(missing)}")

        # OpenSSL CMS verification of CERT.RSA over CERT.SF
        with tempfile.NamedTemporaryFile() as f_rsa, tempfile.NamedTemporaryFile() as f_sf:
            f_rsa.write(rsa_der); f_rsa.flush()
            f_sf.write(sf); f_sf.flush()
            p = subprocess.run(
                ["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", f_rsa.name, "-content", f_sf.name, "-noverify", "-out", "/dev/null"],
                capture_output=True,
            )
            if p.returncode != 0:
                raise ValueError(f"OpenSSL CMS verification of CERT.RSA failed: {p.stderr.decode(errors='replace')}")
            p_cert = subprocess.run(
                ["openssl", "pkcs7", "-inform", "DER", "-in", f_rsa.name, "-print_certs"],
                capture_output=True,
            )
            if p_cert.returncode != 0:
                raise ValueError("Failed to extract cert from CERT.RSA")
            v1_cert = x509.load_pem_x509_certificate(p_cert.stdout)
            v1_cert_der = v1_cert.public_bytes(serialization.Encoding.DER)

    # 4. Verify APK Signature Scheme v2 (0x7109871a) & v3 (0xf05368c0)
    eocd_for_digest = bytearray(data[eocd_off:])
    struct.pack_into("<I", eocd_for_digest, 16, sb_start)
    expected_digest = compute_chunked_sha256(data[:sb_start], data[cd_off:eocd_off], bytes(eocd_for_digest))

    pos = sb_start + 8
    end = cd_off - 24
    seen_schemes = {}
    while pos < end:
        plen = struct.unpack("<Q", data[pos : pos + 8])[0]
        pid = struct.unpack("<I", data[pos + 8 : pos + 12])[0]
        pval = data[pos + 12 : pos + 8 + plen]
        pos += 8 + plen

        if pid == VERITY_PADDING_BLOCK_ID:
            if not all(b == 0 for b in pval):
                raise ValueError("Non-zero bytes in 0x42726577 Verity Padding block")
            seen_schemes[pid] = len(pval)
        elif pid in (APK_SIG_SCHEME_V2_ID, APK_SIG_SCHEME_V3_ID):
            signers_blob, _ = _read_lp(pval, 0)
            signer, s_end = _read_lp(signers_blob, 0)
            if s_end != len(signers_blob):
                raise ValueError(f"Trailing bytes in scheme {hex(pid)} signers")
            sp = 0
            signed_data, sp = _read_lp(signer, sp)
            outer_sdk = None
            if pid == APK_SIG_SCHEME_V3_ID:
                outer_sdk = struct.unpack("<II", signer[sp : sp + 8])
                sp += 8
            sigs_blob, sp = _read_lp(signer, sp)
            pub_der, sp = _read_lp(signer, sp)
            if sp != len(signer):
                raise ValueError(f"Trailing bytes in scheme {hex(pid)} signer")

            sdp = 0
            digs_blob, sdp = _read_lp(signed_data, sdp)
            certs_blob, sdp = _read_lp(signed_data, sdp)
            if pid == APK_SIG_SCHEME_V3_ID:
                inner_sdk = struct.unpack("<II", signed_data[sdp : sdp + 8])
                sdp += 8
                if inner_sdk != outer_sdk:
                    raise ValueError(f"v3 min/max SDK mismatch: inner={inner_sdk} outer={outer_sdk}")
                if inner_sdk[0] > min_sdk or inner_sdk[1] != 0x7FFFFFFF:
                    raise ValueError(f"v3 SDK range {inner_sdk} incompatible with minSdk={min_sdk}")
            _attrs, sdp = _read_lp(signed_data, sdp)
            if sdp != len(signed_data):
                raise ValueError(f"Trailing bytes in scheme {hex(pid)} signed_data")

            d_item, _ = _read_lp(digs_blob, 0)
            dalg = struct.unpack("<I", d_item[:4])[0]
            dval, _ = _read_lp(d_item, 4)
            if dalg != SIG_ALG_RSA_PKCS1_V15_SHA256 or dval != expected_digest:
                raise ValueError(f"Scheme {hex(pid)} content digest mismatch")

            c_item, _ = _read_lp(certs_blob, 0)
            if c_item != v1_cert_der:
                raise ValueError(f"Scheme {hex(pid)} certificate does not match JAR v1 CERT.RSA certificate")
            cert = x509.load_der_x509_certificate(c_item)
            expected_pub_der = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if pub_der != expected_pub_der:
                raise ValueError(f"Scheme {hex(pid)} SubjectPublicKeyInfo does not match certificate")

            s_item, _ = _read_lp(sigs_blob, 0)
            salg = struct.unpack("<I", s_item[:4])[0]
            sval, _ = _read_lp(s_item, 4)
            if salg != SIG_ALG_RSA_PKCS1_V15_SHA256:
                raise ValueError(f"Unexpected signature algorithm {hex(salg)} in scheme {hex(pid)}")
            cert.public_key().verify(sval, signed_data, asym_padding.PKCS1v15(), hashes.SHA256())
            seen_schemes[pid] = True

    if APK_SIG_SCHEME_V2_ID not in seen_schemes or APK_SIG_SCHEME_V3_ID not in seen_schemes:
        raise ValueError(f"Missing required v2/v3 schemes; found: {[hex(k) for k in seen_schemes]}")

    return {
        "size": len(data),
        "axml": axml_info,
        "v2_digest": expected_digest.hex(),
        "cert_sha256": hashlib.sha256(v1_cert_der).hexdigest(),
        "cert_subject": v1_cert.subject.rfc4514_string(),
        "cert_not_before": v1_cert.not_valid_before_utc.isoformat(),
        "cert_not_after": v1_cert.not_valid_after_utc.isoformat(),
        "sig_block_bytes": sb_total,
    }


def resign_apk_file(
    src_apk: Path,
    dst_apk: Path,
    key_path: Path = DEFAULT_KEY_PATH,
    cert_path: Path = DEFAULT_CERT_PATH,
    overrides: Optional[Dict[str, bytes]] = None,
) -> Dict[str, object]:
    """Re-pack, zipalign, and sign src_apk (with optional entry overrides) to dst_apk and verify."""
    overrides = overrides or {}
    private_key, cert = load_or_create_release_key(key_path, cert_path)
    entries: List[Tuple[str, bytes, int]] = []
    with zipfile.ZipFile(src_apk, "r") as zf:
        for zi in zf.infolist():
            if zi.filename.startswith("META-INF/"):
                continue
            raw = overrides[zi.filename] if zi.filename in overrides else zf.read(zi.filename)
            ctype = zipfile.ZIP_STORED if zi.filename == "resources.arsc" else zi.compress_type
            entries.append((zi.filename, raw, ctype))
    signed = build_and_sign_apk(entries, private_key, cert)
    dst_apk.write_bytes(signed)
    return verify_apk(signed)


def main() -> int:
    parser = argparse.ArgumentParser(description="Calyx Labs Inc. Android APK ZipAlign + v1/v2/v3 Signer & Verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sign = sub.add_parser("sign", help="ZipAlign and sign an APK with v1 + v2 + v3")
    p_sign.add_argument("input_apk", type=Path)
    p_sign.add_argument("output_apk", type=Path)
    p_sign.add_argument("--key", type=Path, default=DEFAULT_KEY_PATH)
    p_sign.add_argument("--cert", type=Path, default=DEFAULT_CERT_PATH)

    p_ver = sub.add_parser("verify", help="Verify APK zipalign, AXML, v1, v2, and v3 signatures")
    p_ver.add_argument("apk", type=Path)
    p_ver.add_argument("--version-code", type=int, default=None)
    p_ver.add_argument("--version-name", type=str, default=None)

    args = parser.parse_args()
    if args.cmd == "sign":
        res = resign_apk_file(args.input_apk, args.output_apk, args.key, args.cert)
        print(f"[SIGNED+VERIFIED] {args.output_apk} | size={res['size']}B | cert={res['cert_sha256'][:16]}... | axml={res['axml']}")
        return 0
    if args.cmd == "verify":
        res = verify_apk(args.apk, expected_vc=args.version_code, expected_vn=args.version_name)
        print(f"[PASS] {args.apk} | size={res['size']}B | v2+v3+v1+zipalign+AXML OK | cert={res['cert_sha256'][:16]}... | axml={res['axml']}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
