"""
OpenQPEP Official Release 1.0.0 (v1.0.0) — Universal Binary File Registry
(170+ Hardcoded File Extensions & Magic-Byte MIME Detector).
Standalone module with zero circular dependencies on calyx_qpep.protocol.
"""
from pathlib import Path
from typing import Dict, Optional, Tuple

SUPPORTED_FILE_EXTENSIONS: Dict[str, str] = {
    # Plain Text, Markup & Config
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".rst": "text/x-rst",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".log": "text/plain",
    ".rtf": "application/rtf",
    ".tex": "application/x-tex",
    ".html": "text/html",
    ".htm": "text/html",
    ".xhtml": "application/xhtml+xml",
    ".xml": "application/xml",
    ".xsd": "application/xml",
    ".xsl": "application/xml",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".geojson": "application/geo+json",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".toml": "application/toml",
    ".ini": "text/plain",
    ".cfg": "text/plain",
    ".conf": "text/plain",
    ".env": "text/plain",
    ".properties": "text/plain",
    ".ics": "text/calendar",
    ".vcf": "text/vcard",
    ".eml": "message/rfc822",
    ".mbox": "application/mbox",
    # Office & Publishing Documents
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".docm": "application/vnd.ms-word.document.macroEnabled.12",
    ".dotx": "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
    ".xlsb": "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".odg": "application/vnd.oasis.opendocument.graphics",
    ".pages": "application/vnd.apple.pages",
    ".numbers": "application/vnd.apple.numbers",
    ".key": "application/vnd.apple.keynote",
    ".epub": "application/epub+zip",
    ".mobi": "application/x-mobipocket-ebook",
    ".azw3": "application/vnd.amazon.ebook",
    ".djvu": "image/vnd.djvu",
    ".ps": "application/postscript",
    ".eps": "application/postscript",
    # Raster, Vector & RAW Images
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".jpe": "image/jpeg",
    ".jfif": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
    ".dib": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".ico": "image/x-icon",
    ".icns": "image/icns",
    ".heic": "image/heic",
    ".heif": "image/heif",
    ".avif": "image/avif",
    ".jxl": "image/jxl",
    ".jp2": "image/jp2",
    ".psd": "image/vnd.adobe.photoshop",
    ".ai": "application/postscript",
    ".xcf": "image/x-xcf",
    ".raw": "image/x-raw",
    ".dng": "image/x-adobe-dng",
    ".cr2": "image/x-canon-cr2",
    ".cr3": "image/x-canon-cr3",
    ".nef": "image/x-nikon-nef",
    ".arw": "image/x-sony-arw",
    ".orf": "image/x-olympus-orf",
    ".raf": "image/x-fuji-raf",
    ".tga": "image/x-tga",
    ".exr": "image/x-exr",
    ".hdr": "image/vnd.radiance",
    # Audio
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".flac": "audio/flac",
    ".ogg": "audio/ogg",
    ".oga": "audio/ogg",
    ".opus": "audio/opus",
    ".m4a": "audio/mp4",
    ".aac": "audio/aac",
    ".wma": "audio/x-ms-wma",
    ".aiff": "audio/aiff",
    ".aif": "audio/aiff",
    ".mid": "audio/midi",
    ".midi": "audio/midi",
    ".amr": "audio/amr",
    ".mka": "audio/x-matroska",
    # Video
    ".mp4": "video/mp4",
    ".m4v": "video/x-m4v",
    ".mov": "video/quicktime",
    ".mkv": "video/x-matroska",
    ".webm": "video/webm",
    ".avi": "video/x-msvideo",
    ".wmv": "video/x-ms-wmv",
    ".flv": "video/x-flv",
    ".mpeg": "video/mpeg",
    ".mpg": "video/mpeg",
    ".ts": "video/mp2t",
    ".m2ts": "video/mp2t",
    ".3gp": "video/3gpp",
    ".ogv": "video/ogg",
    # Archives, Disk Images & Packages
    ".zip": "application/zip",
    ".tar": "application/x-tar",
    ".gz": "application/gzip",
    ".tgz": "application/gzip",
    ".bz2": "application/x-bzip2",
    ".xz": "application/x-xz",
    ".zst": "application/zstd",
    ".lz4": "application/x-lz4",
    ".7z": "application/x-7z-compressed",
    ".rar": "application/vnd.rar",
    ".iso": "application/x-iso9660-image",
    ".dmg": "application/x-apple-diskimage",
    ".img": "application/octet-stream",
    ".vhd": "application/x-vhd",
    ".vmdk": "application/x-vmdk",
    ".apk": "application/vnd.android.package-archive",
    ".aab": "application/octet-stream",
    ".ipa": "application/octet-stream",
    ".deb": "application/vnd.debian.binary-package",
    ".rpm": "application/x-rpm",
    ".msi": "application/x-msi",
    ".exe": "application/vnd.microsoft.portable-executable",
    ".dll": "application/vnd.microsoft.portable-executable",
    ".so": "application/x-sharedlib",
    ".dylib": "application/x-mach-binary",
    ".wasm": "application/wasm",
    ".jar": "application/java-archive",
    ".whl": "application/zip",
    ".appimage": "application/octet-stream",
    # Source Code & Engineering
    ".py": "text/x-python",
    ".pyi": "text/x-python",
    ".c": "text/x-c",
    ".h": "text/x-c",
    ".cpp": "text/x-c++",
    ".hpp": "text/x-c++",
    ".cc": "text/x-c++",
    ".rs": "text/x-rust",
    ".go": "text/x-go",
    ".java": "text/x-java-source",
    ".kt": "text/x-kotlin",
    ".kts": "text/x-kotlin",
    ".swift": "text/x-swift",
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".cjs": "text/javascript",
    ".jsx": "text/jsx",
    ".tsx": "text/tsx",
    ".css": "text/css",
    ".scss": "text/x-scss",
    ".sh": "application/x-sh",
    ".bash": "application/x-sh",
    ".zsh": "application/x-sh",
    ".ps1": "application/x-powershell",
    ".bat": "application/x-bat",
    ".rb": "text/x-ruby",
    ".php": "application/x-httpd-php",
    ".pl": "text/x-perl",
    ".lua": "text/x-lua",
    ".r": "text/x-r",
    ".sql": "application/sql",
    ".proto": "text/plain",
    ".graphql": "application/graphql",
    ".dockerfile": "text/plain",
    ".cmake": "text/plain",
    ".mk": "text/plain",
    ".pv": "text/plain",
    ".spthy": "text/plain",
    ".cry": "text/plain",
    # Databases, Scientific, ML & 3D/CAD
    ".sqlite": "application/vnd.sqlite3",
    ".sqlite3": "application/vnd.sqlite3",
    ".db": "application/octet-stream",
    ".parquet": "application/vnd.apache.parquet",
    ".arrow": "application/vnd.apache.arrow.file",
    ".feather": "application/octet-stream",
    ".hdf5": "application/x-hdf5",
    ".h5": "application/x-hdf5",
    ".nc": "application/x-netcdf",
    ".fits": "application/fits",
    ".npy": "application/octet-stream",
    ".npz": "application/zip",
    ".pt": "application/octet-stream",
    ".onnx": "application/octet-stream",
    ".safetensors": "application/octet-stream",
    ".gguf": "application/octet-stream",
    ".stl": "model/stl",
    ".obj": "model/obj",
    ".gltf": "model/gltf+json",
    ".glb": "model/gltf-binary",
    ".fbx": "application/octet-stream",
    ".blend": "application/x-blender",
    ".step": "application/step",
    ".stp": "application/step",
    ".dwg": "image/vnd.dwg",
    ".dxf": "image/vnd.dxf",
    ".dcm": "application/dicom",
    # Fonts
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    # Cryptography, Security & OpenQPEP Native Formats
    ".qpkrf": "application/vnd.calyx.openqpep-keyring",
    ".qpep": "application/vnd.calyx.openqpep-packet",
    ".qrev": "application/vnd.calyx.openqpep-revocation",
    ".qshare": "application/vnd.calyx.openqpep-recovery-shard",
    ".qsig": "application/vnd.calyx.openqpep-signature",
    ".qts": "application/vnd.calyx.openqpep-timestamp",
    ".pem": "application/x-pem-file",
    ".crt": "application/x-x509-ca-cert",
    ".cer": "application/pkix-cert",
    ".der": "application/x-x509-ca-cert",
    ".p12": "application/x-pkcs12",
    ".pfx": "application/x-pkcs12",
    ".jks": "application/x-java-keystore",
    ".asc": "text/plain",
    ".gpg": "application/pgp-encrypted",
    ".pgp": "application/pgp-encrypted",
    ".sig": "application/octet-stream",
    ".bin": "application/octet-stream",
    ".dat": "application/octet-stream",
}

_MAGIC_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", ".png", "image/png"),
    (b"\xff\xd8\xff", ".jpg", "image/jpeg"),
    (b"GIF87a", ".gif", "image/gif"),
    (b"GIF89a", ".gif", "image/gif"),
    (b"%PDF-", ".pdf", "application/pdf"),
    (b"PK\x03\x04", ".zip", "application/zip"),
    (b"\x1f\x8b\x08", ".gz", "application/gzip"),
    (b"BZh", ".bz2", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", ".xz", "application/x-xz"),
    (b"7z\xbc\xaf\x27\x1c", ".7z", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", ".rar", "application/vnd.rar"),
    (b"\x28\xb5\x2f\xfd", ".zst", "application/zstd"),
    (b"SQLite format 3\x00", ".sqlite", "application/vnd.sqlite3"),
    (b"fLaC", ".flac", "audio/flac"),
    (b"OggS", ".ogg", "audio/ogg"),
    (b"ID3", ".mp3", "audio/mpeg"),
    (b"\x1a\x45\xdf\xa3", ".mkv", "video/x-matroska"),
    (b"\x00asm\x01\x00\x00\x00", ".wasm", "application/wasm"),
    (b"\x7fELF", ".so", "application/x-sharedlib"),
    (b"MZ", ".exe", "application/vnd.microsoft.portable-executable"),
    (b"BM", ".bmp", "image/bmp"),
    (b"II*\x00", ".tiff", "image/tiff"),
    (b"MM\x00*", ".tiff", "image/tiff"),
    (b"{\x5c\x72\x74\x66", ".rtf", "application/rtf"),
)


def detect_file_extension_and_mime(
    raw_bytes: bytes, filename: Optional[str] = None
) -> Tuple[str, str, str]:
    """
    Normalizes filename and detects canonical file extension and MIME type
    via explicit extension table (170+ formats) with magic-byte fallback.
    """
    clean_name = Path(filename).name if filename else ""
    if clean_name in ("", ".", ".."):
        clean_name = ""

    ext = Path(clean_name).suffix.lower() if clean_name else ""
    if ext and ext in SUPPORTED_FILE_EXTENSIONS:
        return clean_name, ext, SUPPORTED_FILE_EXTENSIONS[ext]

    # Magic-byte sniffing
    if raw_bytes.startswith(b"RIFF") and len(raw_bytes) >= 12:
        fourcc = raw_bytes[8:12]
        if fourcc == b"WEBP":
            return clean_name or "file.webp", ".webp", "image/webp"
        if fourcc == b"WAVE":
            return clean_name or "file.wav", ".wav", "audio/wav"
        if fourcc == b"AVI ":
            return clean_name or "file.avi", ".avi", "video/x-msvideo"
    if len(raw_bytes) >= 12 and raw_bytes[4:8] == b"ftyp":
        return clean_name or "file.mp4", ".mp4", "video/mp4"

    for magic, det_ext, det_mime in _MAGIC_SIGNATURES:
        if raw_bytes.startswith(magic):
            return clean_name or f"file{det_ext}", ext or det_ext, det_mime

    if ext:
        return clean_name, ext, "application/octet-stream"

    # UTF-8 text heuristic
    try:
        raw_bytes[:4096].decode("utf-8")
        if b"\x00" not in raw_bytes[:4096]:
            return clean_name or "message.txt", ".txt", "text/plain"
    except UnicodeDecodeError:
        pass
    return clean_name or "payload.bin", ".bin", "application/octet-stream"


__all__ = ["SUPPORTED_FILE_EXTENSIONS", "detect_file_extension_and_mime"]
