#!/usr/bin/env python3
"""
OpenQPEP Suite Unified Verification Script (Official Release 1.1.0).
Validates version synchronization, Android native bridge registration, HTML cryptographic hygiene,
Android/iOS QPEP Client byte parity, unique Mail/Messenger icons, APK asset integrity, and CMS-signed .mobileconfig profiles.
"""
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

SUITE_ROOT = Path(__file__).resolve().parent
EXPECTED_VER = "1.1.0"


def main() -> int:
    errors = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            errors.append(msg)

    # 1. Core protocol version files
    pyproj = (SUITE_ROOT / "protocol/pyproject.toml").read_text(encoding="utf-8")
    cargo = (SUITE_ROOT / "protocol/rust/openqpep-core/Cargo.toml").read_text(encoding="utf-8")
    go_wire = (SUITE_ROOT / "protocol/go/openqpep/wire_v5.go").read_text(encoding="utf-8")
    check(f'version = "{EXPECTED_VER}"' in pyproj, "protocol/pyproject.toml version mismatch")
    check(f'version = "{EXPECTED_VER}"' in cargo, "rust/openqpep-core/Cargo.toml version mismatch")
    check(f'ProtocolVersion = "OpenQPEP/{EXPECTED_VER}"' in go_wire, "go/openqpep/wire_v5.go version mismatch")

    # 2. All 3 Android manifests, gradle files, MainActivity hardware bridge, and Desktop configs
    app_specs = [
        ("calyx-qpep-client", "229", "build.gradle.kts", "com/calyxlabs/qpepclient/MainActivity.java", "CalyxQPEPClient.apk", "CalyxQPEPClient.mobileconfig", "assets/calyx_qpep_app.html"),
        ("calyx-encrypted-messenger", "29", "build.gradle", "com/calyxlabs/qpem/MainActivity.java", "CalyxEncryptedMessenger.apk", "CalyxEncryptedMessenger.mobileconfig", "assets/calyx_v8.html"),
        ("calyx-encrypted-email", "13", "build.gradle", "com/calyxlabs/mail/MainActivity.java", "CalyxEncryptedEmail.apk", "CalyxEncryptedEmail.mobileconfig", "assets/calyx_mail.html"),
    ]
    for app_dir, vc, gradle_fn, java_rel, apk_fn, mc_fn, apk_html_entry in app_specs:
        base = SUITE_ROOT / "apps" / app_dir
        manifest = (base / "android/source/app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
        gradle = (base / "android/source/app" / gradle_fn).read_text(encoding="utf-8")
        java = (base / "android/source/app/src/main/java" / java_rel).read_text(encoding="utf-8")
        d_cargo = (base / "desktop/Cargo.toml").read_text(encoding="utf-8")
        d_tauri = json.loads((base / "desktop/tauri.conf.json").read_text(encoding="utf-8"))

        check(f'android:versionCode="{vc}"' in manifest, f"{app_dir} AndroidManifest versionCode != {vc}")
        check(f'android:versionName="{EXPECTED_VER}"' in manifest, f"{app_dir} AndroidManifest versionName != {EXPECTED_VER}")
        check(vc in gradle and EXPECTED_VER in gradle, f"{app_dir} {gradle_fn} version/vc mismatch")
        check("@JavascriptInterface" in java and '"CalyxHardwareBridge"' in java, f"{app_dir} MainActivity missing CalyxHardwareBridge @JavascriptInterface")
        check(f'version = "{EXPECTED_VER}"' in d_cargo, f"{app_dir} desktop/Cargo.toml version mismatch")
        check(d_tauri.get("version") == EXPECTED_VER, f"{app_dir} desktop/tauri.conf.json version mismatch")

        # Verify APK integrity + v1 signing files + clean HTML asset
        apk_path = base / "android" / apk_fn
        check(apk_path.is_file(), f"Missing APK: {apk_path}")
        if apk_path.is_file():
            with zipfile.ZipFile(apk_path, "r") as zf:
                names = set(zf.namelist())
                for req_entry in ("META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA", apk_html_entry):
                    check(req_entry in names, f"{apk_fn} missing {req_entry}")
                if apk_html_entry in names:
                    html = zf.read(apk_html_entry).decode("utf-8")
                    check(html.count("function detectDeviceRamInfo()") == 1, f"{apk_fn} {apk_html_entry} detectDeviceRamInfo count != 1")
                    check(f"OpenQPEP/{EXPECTED_VER}" in html or f"v{EXPECTED_VER}" in html, f"{apk_fn} {apk_html_entry} missing {EXPECTED_VER}")
                    check('OPENQPEP_WIRE_FORMAT = "v4' not in html, f"{apk_fn} still has stale Wire v4 assignment")
                    check("OPENQPEP_KDF_VERSION = 3" not in html, f"{apk_fn} still has stale kdf_version=3 assignment")
                    check("btoa(unescape(encodeURIComponent(outerPlaintext)))" not in html, f"{apk_fn} still has plaintext DeniableVault stub")
                    check("shard_payload: secretHex" not in html, f"{apk_fn} still has plaintext ThresholdKEM stub")
                    check("ct_b64: uint8ToBase64(slice)" not in html, f"{apk_fn} still has plaintext StreamingAttachment stub")
                    check("initOpenQPEPRC100" not in html and "v1.3.0-pc" not in html and "v1.4.0-pc" not in html, f"{apk_fn} still contains stale RC/PC function or comment markers")

        # Verify CMS-signed .mobileconfig
        mc_path = base / "ios" / mc_fn
        check(mc_path.is_file(), f"Missing mobileconfig: {mc_path}")
        if mc_path.is_file():
            p = subprocess.run(
                ["openssl", "cms", "-verify", "-inform", "DER", "-noverify"],
                input=mc_path.read_bytes(),
                capture_output=True,
            )
            check(p.returncode == 0, f"{mc_fn} failed OpenSSL CMS verify: {p.stderr.decode(errors='replace')}")
            inner = p.stdout.decode("utf-8", errors="replace")
            check(EXPECTED_VER in inner, f"{mc_fn} inner plist missing {EXPECTED_VER}")
            check("Production Candidate" not in inner and "PC 1." not in inner, f"{mc_fn} inner plist still contains stale PC text")

    # 3. Byte-for-byte parity between QPEP Client Android and iOS HTML
    c_and = SUITE_ROOT / "apps/calyx-qpep-client/android/source/app/src/main/assets/calyx_qpep_app.html"
    c_ios = SUITE_ROOT / "apps/calyx-qpep-client/ios/qpep-client-ios.html"
    check(
        hashlib.sha256(c_and.read_bytes()).hexdigest() == hashlib.sha256(c_ios.read_bytes()).hexdigest(),
        "calyx-qpep-client Android calyx_qpep_app.html and iOS qpep-client-ios.html are NOT byte-for-byte identical",
    )

    # 4. Unique Mail vs Messenger Android icon
    mail_ico = SUITE_ROOT / "apps/calyx-encrypted-email/android/source/app/src/main/res/drawable/ic_launcher.png"
    msg_ico = SUITE_ROOT / "apps/calyx-encrypted-messenger/android/source/app/src/main/res/drawable/ic_launcher.png"
    if mail_ico.is_file() and msg_ico.is_file():
        check(
            hashlib.sha256(mail_ico.read_bytes()).hexdigest() != hashlib.sha256(msg_ico.read_bytes()).hexdigest(),
            "Calyx Encrypted Email and Messenger icons must be unique",
        )

    if errors:
        print("[FAIL] OpenQPEP Suite verification failed:")
        for e in errors:
            print("  -", e)
        return 1
    print(f"[PASS] OpenQPEP Suite v{EXPECTED_VER} verification passed all checks (3 apps, 3 APKs, 3 CMS mobileconfigs, manifests, bridges, crypto hygiene).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
