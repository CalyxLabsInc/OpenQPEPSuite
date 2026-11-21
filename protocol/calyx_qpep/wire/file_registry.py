# OpenQPEP Production Candidate 1.1.4 (v1.1.4-pc)
"""
OpenQPEP Universal Binary File Registry (165+ Hardcoded Extensions & Magic-Byte MIME Detector).
Re-exports the canonical registry for clean modular imports under calyx_qpep.wire.
"""
from ..protocol import SUPPORTED_FILE_EXTENSIONS, detect_file_extension_and_mime

__all__ = ["SUPPORTED_FILE_EXTENSIONS", "detect_file_extension_and_mime"]
