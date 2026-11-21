"""OpenQPEP v1.0.0-rc — Deterministic Reproducible Build Manifest & SPDX SBOM Generator."""
import hashlib
import json
from pathlib import Path
from typing import Any, Dict


def generate_spdx_sbom(repo_root: Path, version: str = "1.0.0-rc") -> Dict[str, Any]:
    files = []
    for p in sorted(repo_root.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        rel = str(p.relative_to(repo_root))
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        files.append({"fileName": rel, "checksums": [{"algorithm": "SHA256", "checksumValue": h}]})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CPOSLS-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"OpenQPEP-{version}",
        "documentNamespace": f"https://calyxlabsinc.org/spdx/openqpep-{version}",
        "creationInfo": {"creators": ["Organization: Calyx Labs Inc."]},
        "filesAnalyzed": len(files),
        "files": files,
    }
