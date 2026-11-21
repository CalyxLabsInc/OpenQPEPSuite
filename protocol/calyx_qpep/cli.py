#!/usr/bin/env python3
"""
OpenQPEP Interactive Blue-Text English-Command CLI (Production Candidate 1.1.4)
Project: OpenQPEP by Calyx Labs Inc. (Creator: Tristen Martinez)
Repository: https://github.com/CalyxLabsInc/OpenQPEP/
Directory: https://qpepkeys.calyxlabsinc.org

Supports both:
1. Interactive Blue-Themed English-Command Shell (default when invoked with no arguments
   or with `--interactive`), allowing users to run natural commands such as:
   - `Create Key`
   - `List Keys`
   - `Key Details <KeyName>`
   - `Export Public <KeyName>`
   - `Export Private <KeyName>`
   - `Import Key` / `Import Key <FilePath.qpkrf>`
   - `Delete Key <KeyName>`
   - `Encrypt Text` / `Decrypt Text`
   - `Encrypt File` / `Decrypt File`
   - `Create Signature` / `Verify Signature`
   - `Publish Key <KeyName>` / `Search Directory <Query>`
   - `Help` / `Exit`
2. Non-interactive flag subcommands (`check-passphrase`, `keygen`, `--version`) for CI/scripts.
"""
import os
import sys
import json
import getpass
import argparse
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List, Optional

from .protocol import (
    OpenQPEPProtocol,
    QPEPKeyRing,
    PROJECT_NAME,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    PROTOCOL_VERSION,
    QPKRF_EXTENSION,
)
from .passphrase import analyze_passphrase, QPEPPassphrasePolicyError

# ANSI Blue & Cyan styling for the interactive OpenQPEP terminal shell
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD_BLUE = "\033[1;94m"
BOLD_CYAN = "\033[1;96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

DEFAULT_KEYSTORE_PATH = Path(os.environ.get("OPENQPEP_KEYSTORE", str(Path.home() / ".openqpep" / "keyring.json")))
DIRECTORY_BASE_URL = os.environ.get("OPENQPEP_DIRECTORY_URL", "https://qpepkeys.calyxlabsinc.org")


def bprint(text: str = "") -> None:
    """Prints text in OpenQPEP signature blue."""
    print(f"{BLUE}{text}{RESET}")


def binput(prompt_text: str) -> str:
    """Prompts user with blue prompt text."""
    return input(f"{BOLD_CYAN}{prompt_text}{RESET} ").strip()


def bpass(prompt_text: str, use_stdin_if_piped: bool = True) -> str:
    """Prompts for passphrase (uses input() when stdin is piped in tests, getpass in TTY)."""
    if use_stdin_if_piped and not sys.stdin.isatty():
        return input(f"{BOLD_CYAN}{prompt_text}{RESET} ").strip()
    return getpass.getpass(f"{BOLD_CYAN}{prompt_text}{RESET} ").strip()


class OpenQPEPKeyStore:
    """Persistent local keyring manager for the OpenQPEP Interactive CLI."""

    def __init__(self, path: Path = DEFAULT_KEYSTORE_PATH):
        self.path = path
        self.keys: List[Dict[str, Any]] = []
        self.load()

    def load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self.keys = data
            except Exception:
                self.keys = []

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.keys, indent=2), encoding="utf-8")

    def add_or_update(self, kr: QPEPKeyRing, pub_armor: str, priv_armor: Optional[str]) -> None:
        entry = {
            "key_hash": kr.key_hash,
            "name": kr.name,
            "email": kr.email,
            "qlx_tier": kr.qlx_tier,
            "qvs_tier": kr.qvs_tier,
            "comment": kr.comment,
            "created_at": kr.created_at,
            "has_private": kr.has_private_key,
            "pub_armor": pub_armor,
            "priv_armor": priv_armor,
        }
        self.keys = [k for k in self.keys if k.get("key_hash") != kr.key_hash]
        self.keys.insert(0, entry)
        self.save()

    def find_key(self, query: str) -> Optional[Dict[str, Any]]:
        q = query.strip().lower()
        if not q:
            return None
        # Check 1-based numeric index first
        if q.isdigit():
            idx = int(q) - 1
            if 0 <= idx < len(self.keys):
                return self.keys[idx]
        # Exact name, email, or key_hash match
        for k in self.keys:
            if (
                k["name"].lower() == q
                or k["email"].lower() == q
                or k["key_hash"].lower().startswith(q)
            ):
                return k
        # Substring match
        for k in self.keys:
            if q in k["name"].lower() or q in k["email"].lower():
                return k
        return None


def print_banner(store: OpenQPEPKeyStore) -> None:
    bprint("================================================================================")
    print(f"{BOLD_CYAN}  OpenQPEP by Calyx Labs Inc. — Interactive Post-Quantum CLI ({UNIVERSAL_VERSION_LABEL}){RESET}")
    bprint("  Creator & Lead Architect: Tristen Martinez | https://github.com/CalyxLabsInc/OpenQPEP/")
    bprint("  Live Key Directory:       https://qpepkeys.calyxlabsinc.org")
    bprint(f"  Local Keyring Storage:    {store.path} ({len(store.keys)} key(s) loaded)")
    bprint("================================================================================")
    bprint("How to Use the OpenQPEP Interactive CLI (Type any English command below):")
    bprint("  • Create Key                      -> Guided step-by-step OpenQPEP key generation")
    bprint("  • List Keys                       -> View all keys in your local keyring")
    bprint("  • Key Details <KeyName>           -> Inspect Key Hash, status & .qpkrf public block")
    bprint("  • Export Public <KeyName>         -> Export a public .qpkrf key ring file")
    bprint("  • Export Private <KeyName>        -> Unlock & export a private .qpkrf key ring file")
    bprint("  • Import Key <FilePath.qpkrf>     -> Import a public or private .qpkrf file")
    bprint("  • Delete Key <KeyName>            -> Delete a key from your local keyring")
    bprint("  • Encrypt Text                    -> Encrypt a message using QLX + HGC-448 + CC-512")
    bprint("  • Decrypt Text                    -> Decrypt an OpenQPEP packet & verify sender")
    bprint("  • Encrypt File                    -> Encrypt any file into a .qpep packet")
    bprint("  • Decrypt File                    -> Decrypt a .qpep file packet")
    bprint("  • Create Signature                -> Create an Attached OpenQPEP Signature")
    bprint("  • Verify Signature                -> Verify an Attached Signature & extract message")
    bprint("  • Publish Key <KeyName>           -> Publish public key to qpepkeys.calyxlabsinc.org")
    bprint("  • Search Directory <Query>        -> Search qpepkeys.calyxlabsinc.org by name/email/hash")
    bprint("  • Help                            -> Show this command guide again")
    bprint("  • Exit                            -> Close the OpenQPEP CLI")
    bprint("--------------------------------------------------------------------------------")


def _prompt_valid_passphrase(prompt_label: str = "Set Key Passphrase", confirm: bool = True) -> str:
    while True:
        bprint(
            "  [Mandatory Passphrase Policy: 12+ chars, 2+ numbers, 4+ special chars, 2+ uppercase, 4+ lowercase]"
        )
        pw = bpass(f"{prompt_label}:")
        res = analyze_passphrase(pw)
        if not res.is_valid:
            print(f"{RED}  Passphrase Policy Violation: {' '.join(res.errors)}{RESET}")
            continue
        if confirm:
            pw2 = bpass("Confirm Key Passphrase:")
            if pw != pw2:
                print(f"{RED}  Passphrases do not match. Please try again.{RESET}")
                continue
        return pw


def _select_key_interactive(store: OpenQPEPKeyStore, prompt_title: str, require_private: bool = False) -> Optional[Dict[str, Any]]:
    candidates = [k for k in store.keys if (k.get("has_private") or not require_private)]
    if not candidates:
        kind = "personal (private)" if require_private else "keyring"
        print(f"{RED}No {kind} keys found in keyring. Run 'Create Key' or 'Import Key' first.{RESET}")
        return None
    bprint(f"\n{prompt_title}:")
    for idx, k in enumerate(candidates, start=1):
        tag = "Personal Key Pair" if k.get("has_private") else "Receiver Public Key"
        bprint(f"  {idx}. {k['name']} <{k['email']}> [{k['qlx_tier']} | {tag} | Hash: {k['key_hash'][:16]}...]")
    choice = binput("Choose key number or enter Key Name / Email / Hash (press Enter for 1):") or "1"
    if choice.isdigit() and 1 <= int(choice) <= len(candidates):
        return candidates[int(choice) - 1]
    for k in candidates:
        q = choice.lower()
        if q in k["name"].lower() or q in k["email"].lower() or k["key_hash"].lower().startswith(q):
            return k
    print(f"{RED}No matching key found for '{choice}'.{RESET}")
    return None


def _publish_entry_to_directory(entry: Dict[str, Any]) -> bool:
    url = f"{DIRECTORY_BASE_URL.rstrip('/')}/api/v1/keys/publish"
    payload = json.dumps(
        {
            "key_hash": entry["key_hash"],
            "name": entry["name"],
            "email": entry["email"],
            "suite": f"{entry['qlx_tier']} + {entry['qvs_tier']}",
            "public_qpkrf": entry["pub_armor"],
        }
    ).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            out = json.loads(resp.read().decode("utf-8"))
            print(f"{GREEN}Published to {DIRECTORY_BASE_URL}: {out.get('message', 'OK')}{RESET}")
            return True
    except Exception as exc:
        print(f"{YELLOW}Could not reach {DIRECTORY_BASE_URL} right now ({exc}). Your key is saved locally and can be published anytime with 'Publish Key {entry['name']}'.{RESET}")
        return False


def cmd_create_key(store: OpenQPEPKeyStore) -> None:
    bprint("\n--- OpenQPEP Guided Key Generation ---")
    bprint("Specify Key Type:")
    bprint("  1. Calyx Signature: QLX-4096 + QVS-256 (Default Recommended — 4096-Dim Quantum-Proof + HGC-448 + CC-512)")
    bprint("  2. Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold Tesseract — HIGH-TIER HARDWARE ONLY)")
    bprint("  3. QLX-2048 + QVS-128 Ultra-Grid (2048-Dim Hyper-Lattice + HGC-448 + CC-512)")
    bprint("  4. QLX-1024 + QVS-87 Sovereign Hybrid (1024-Dim Lattice + HGC-448 + CC-512)")
    bprint("  5. QLX-768 + QVS-65 Velocity (768-Dim High-Speed Lattice + HGC-448 + CC-512)")
    t_choice = binput("Enter option number (1-5, default 1):") or "1"
    tier_map = {
        "1": "QLX-4096",
        "2": "QLX-16384",
        "3": "QLX-2048",
        "4": "QLX-1024",
        "5": "QLX-768",
        "qlx-16384": "QLX-16384",
        "hyper-tesseract": "QLX-16384",
        "qlx-4096": "QLX-4096",
        "qlx-2048": "QLX-2048",
        "qlx-1024": "QLX-1024",
        "qlx-768": "QLX-768",
    }
    qlx_tier = tier_map.get(t_choice.lower(), "QLX-4096")
    if qlx_tier == "QLX-16384":
        bprint("  [!] HARDWARE NOTICE: Calyx Hyper-Tesseract (QLX-16384 + QVS-1024) is intended ONLY for high-tier")
        bprint("      flagship devices (e.g. Galaxy Z Fold 8 / high-RAM PCs). Low-tier devices may freeze or OOM.")

    name = ""
    while not name:
        name = binput("Set Key Name:")
    email = ""
    while not email:
        email = binput("Set Key Email:")
    comment = binput("Set Key Comment (optional, press Enter for 'OpenQPEP by Calyx Labs Inc.'):") or PROJECT_NAME
    passphrase = _prompt_valid_passphrase("Set Key Passphrase", confirm=True)

    bprint(f"Generating {qlx_tier} Module-LWE + Fiat-Shamir with Aborts + HGC-448 key pair...")
    kr = OpenQPEPProtocol.generate_keypair(
        name=name,
        email=email,
        passphrase=passphrase,
        qlx_tier=qlx_tier,
        comment=comment,
    )
    pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
    priv_armor = OpenQPEPProtocol.export_qpkrf(kr, passphrase=passphrase, include_private=True)
    store.add_or_update(kr, pub_armor, priv_armor)

    print(f"{GREEN}Successfully generated OpenQPEP Key Pair!{RESET}")
    bprint(f"  Owner:      {kr.name} <{kr.email}>")
    bprint(f"  Suite:      {kr.qlx_tier} + {kr.qvs_tier} + HGC-448 / CC-512")
    bprint(f"  Key Hash:   {kr.key_hash}")

    pub_ans = binput("Publish Public Key to OpenQPEP Directory (https://qpepkeys.calyxlabsinc.org)? (yes/no, default no):").lower()
    if pub_ans in ("y", "yes"):
        _publish_entry_to_directory(store.keys[0])


def cmd_list_keys(store: OpenQPEPKeyStore) -> None:
    if not store.keys:
        bprint("Your OpenQPEP keyring is currently empty. Type 'Create Key' or 'Import Key' to add a key.")
        return
    bprint(f"\n--- OpenQPEP Keyring ({len(store.keys)} key(s)) ---")
    for idx, k in enumerate(store.keys, start=1):
        kind = "Personal Key Pair (Public + Encrypted Private)" if k.get("has_private") else "Receiver Key (Public Only)"
        bprint(f"  [{idx}] {k['name']} <{k['email']}>")
        bprint(f"      Type:     {kind} | Suite: {k['qlx_tier']} + {k['qvs_tier']}")
        bprint(f"      Key Hash: {k['key_hash']}")


def cmd_key_details(store: OpenQPEPKeyStore, arg: str) -> None:
    entry = store.find_key(arg) if arg else _select_key_interactive(store, "Select Key to Inspect")
    if not entry:
        print(f"{RED}Key '{arg}' not found in keyring.{RESET}")
        return
    grouped_hash = " ".join(entry["key_hash"][i : i + 4] for i in range(0, len(entry["key_hash"]), 4))
    bprint("\n================================================================================")
    bprint(f"OpenQPEP Key Details — {entry['name']} <{entry['email']}>")
    bprint("================================================================================")
    bprint(f"  Protocol Version: {UNIVERSAL_VERSION_LABEL} ({PROJECT_NAME})")
    bprint(f"  Key Status:       Healthy (QPKD-Argon + CC-512 Protected)")
    bprint(f"  Key Suite:        {entry['qlx_tier']} + {entry['qvs_tier']} + HGC-448")
    bprint(f"  Created At:       {entry['created_at']}")
    bprint(f"  Private Key:      {'Present (Locked with QPKD-Argon + CC-512)' if entry.get('has_private') else 'Not Present (Public Key Only)'}")
    bprint(f"  Key Hash:         {grouped_hash}")
    bprint("\n--- QPKRF Public Key Block ---")
    bprint(entry["pub_armor"].strip())
    bprint("================================================================================")


def cmd_export_key(store: OpenQPEPKeyStore, is_private: bool, key_query: str) -> None:
    entry = store.find_key(key_query) if key_query else _select_key_interactive(
        store,
        f"Select Key to Export ({'Private' if is_private else 'Public'} .qpkrf)",
        require_private=is_private,
    )
    if not entry:
        print(f"{RED}Key '{key_query}' not found in keyring.{RESET}")
        return

    safe_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in entry["name"]).strip("_") or "openqpep_key"
    default_file = f"{safe_name}_{'private' if is_private else 'public'}.qpkrf"

    if is_private:
        if not entry.get("has_private") or not entry.get("priv_armor"):
            print(f"{RED}Key '{entry['name']}' is a public-only receiver key and has no private key to export.{RESET}")
            return
        pw = bpass(f"Enter Passphrase to Unlock and Export Private Key '{entry['name']}':")
        try:
            kr = OpenQPEPProtocol.import_qpkrf(entry["priv_armor"], passphrase=pw)
            out_path_str = binput(f"Output file path (press Enter for '{default_file}'):") or default_file
            if not out_path_str.lower().endswith(QPKRF_EXTENSION):
                out_path_str += QPKRF_EXTENSION
            OpenQPEPProtocol.export_qpkrf(kr, passphrase=pw, include_private=True, output_path=out_path_str)
            print(f"{GREEN}Exported Private Key Ring to {out_path_str}{RESET}")
        except Exception as exc:
            print(f"{RED}Private Key Export Failed: {exc}{RESET}")
    else:
        out_path_str = binput(f"Output file path (press Enter for '{default_file}'):") or default_file
        if not out_path_str.lower().endswith(QPKRF_EXTENSION):
            out_path_str += QPKRF_EXTENSION
        Path(out_path_str).write_text(entry["pub_armor"], encoding="utf-8")
        print(f"{GREEN}Exported Public Key Ring to {out_path_str}{RESET}")


def cmd_import_key(store: OpenQPEPKeyStore, path_arg: str) -> None:
    file_path = path_arg or binput("Enter path to .qpkrf file to import:")
    p = Path(file_path).expanduser()
    if not p.exists():
        print(f"{RED}File not found: {p}{RESET}")
        return
    raw_text = p.read_text(encoding="utf-8")
    is_priv = "PRIVATE KEY RING" in raw_text
    pw = None
    if is_priv:
        pw = bpass("Enter Mandatory Passphrase for this Private .qpkrf Key Ring:")
    try:
        kr = OpenQPEPProtocol.import_qpkrf(raw_text, passphrase=pw)
        pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
        priv_armor = raw_text if is_priv else None
        store.add_or_update(kr, pub_armor, priv_armor)
        kind = "Personal Key Pair" if is_priv else "Receiver Public Key"
        print(f"{GREEN}Imported {kind}: {kr.name} <{kr.email}> (Key Hash: {kr.key_hash}){RESET}")
    except Exception as exc:
        print(f"{RED}Import Failed: {exc}{RESET}")


def cmd_delete_key(store: OpenQPEPKeyStore, query: str) -> None:
    entry = store.find_key(query) if query else _select_key_interactive(store, "Select Key to Delete")
    if not entry:
        print(f"{RED}Key '{query}' not found.{RESET}")
        return
    confirm = binput(f"Delete key '{entry['name']} <{entry['email']}>' [{entry['key_hash'][:16]}...]? (yes/no):").lower()
    if confirm in ("y", "yes"):
        store.keys = [k for k in store.keys if k["key_hash"] != entry["key_hash"]]
        store.save()
        print(f"{GREEN}Deleted key '{entry['name']}'.{RESET}")


def cmd_encrypt_text(store: OpenQPEPKeyStore) -> None:
    sender_entry = _select_key_interactive(store, "Select Encrypting Key (Your Personal Key)", require_private=True)
    if not sender_entry:
        return
    recip_entry = _select_key_interactive(store, "Select Recipient Key (.qpkrf)", require_private=False)
    if not recip_entry:
        return
    pw = bpass(f"Enter Passphrase for Encrypting Key '{sender_entry['name']}':")
    msg = binput("Enter Plaintext Message to Encrypt:")
    try:
        sender_kr = OpenQPEPProtocol.import_qpkrf(sender_entry["priv_armor"], passphrase=pw)
        recip_kr = OpenQPEPProtocol.import_qpkrf(recip_entry["pub_armor"])
        pkt = OpenQPEPProtocol.encrypt_text(msg, recipient_keyring=recip_kr, encrypting_keyring=sender_kr, passphrase=pw)
        bprint("\n--- Armored OpenQPEP Encrypted Packet ---")
        bprint(pkt.strip())
        save_path = binput("Save encrypted packet to file? (Enter filename.qpep or press Enter to skip):")
        if save_path:
            Path(save_path).write_text(pkt, encoding="utf-8")
            print(f"{GREEN}Saved encrypted packet to {save_path}{RESET}")
    except Exception as exc:
        print(f"{RED}Encryption Failed: {exc}{RESET}")


def cmd_decrypt_text(store: OpenQPEPKeyStore) -> None:
    dec_entry = _select_key_interactive(store, "Select Decrypting Key (Your Personal Key)", require_private=True)
    if not dec_entry:
        return
    pw = bpass(f"Enter Passphrase for Decrypting Key '{dec_entry['name']}':")
    src = binput("Enter path to .qpep file OR paste first line of armored packet:")
    if Path(src).expanduser().exists():
        armored = Path(src).expanduser().read_text(encoding="utf-8")
    else:
        lines = [src]
        bprint("(Paste remaining lines of the armored packet, ending with -----END ...-----)")
        while not lines[-1].strip().startswith("-----END "):
            lines.append(input())
        armored = "\n".join(lines)
    try:
        dec_kr = OpenQPEPProtocol.import_qpkrf(dec_entry["priv_armor"], passphrase=pw)
        pt_bytes, meta = OpenQPEPProtocol.decrypt_packet(armored, recipient_private_keyring=dec_kr, passphrase=pw)
        print(f"{GREEN}\nDecryption & Integrity Verification Successful!{RESET}")
        bprint(f"  Encrypting Key Hash: {meta.get('encrypting_key_hash')}")
        bprint(f"  Plaintext qSponge:   {meta.get('plaintext_qsponge_512')[:32]}...")
        bprint("\n--- Decrypted Plaintext ---")
        bprint(pt_bytes.decode("utf-8", errors="replace"))
    except Exception as exc:
        print(f"{RED}Decryption Failed: {exc}{RESET}")


def cmd_encrypt_file(store: OpenQPEPKeyStore) -> None:
    sender_entry = _select_key_interactive(store, "Select Encrypting Key (Your Personal Key)", require_private=True)
    if not sender_entry:
        return
    recip_entry = _select_key_interactive(store, "Select Recipient Key (.qpkrf)", require_private=False)
    if not recip_entry:
        return
    in_path = Path(binput("Enter Input File Path to Encrypt:")).expanduser()
    if not in_path.exists():
        print(f"{RED}File not found: {in_path}{RESET}")
        return
    default_out = str(in_path) + ".qpep"
    out_path = Path(binput(f"Enter Output .qpep File Path (default '{default_out}'):") or default_out).expanduser()
    pw = bpass(f"Enter Passphrase for Encrypting Key '{sender_entry['name']}':")
    try:
        sender_kr = OpenQPEPProtocol.import_qpkrf(sender_entry["priv_armor"], passphrase=pw)
        recip_kr = OpenQPEPProtocol.import_qpkrf(recip_entry["pub_armor"])
        pkt = OpenQPEPProtocol.encrypt_bytes(
            in_path.read_bytes(),
            recipient_keyring=recip_kr,
            encrypting_keyring=sender_kr,
            passphrase=pw,
            filename=in_path.name,
        )
        out_path.write_text(pkt, encoding="utf-8")
        print(f"{GREEN}Encrypted '{in_path.name}' -> '{out_path}'{RESET}")
    except Exception as exc:
        print(f"{RED}File Encryption Failed: {exc}{RESET}")


def cmd_decrypt_file(store: OpenQPEPKeyStore) -> None:
    dec_entry = _select_key_interactive(store, "Select Decrypting Key (Your Personal Key)", require_private=True)
    if not dec_entry:
        return
    in_path = Path(binput("Enter .qpep File Path to Decrypt:")).expanduser()
    if not in_path.exists():
        print(f"{RED}File not found: {in_path}{RESET}")
        return
    pw = bpass(f"Enter Passphrase for Decrypting Key '{dec_entry['name']}':")
    try:
        dec_kr = OpenQPEPProtocol.import_qpkrf(dec_entry["priv_armor"], passphrase=pw)
        pt_bytes, meta = OpenQPEPProtocol.decrypt_packet(
            in_path.read_text(encoding="utf-8"),
            recipient_private_keyring=dec_kr,
            passphrase=pw,
        )
        default_out = meta.get("filename") or "decrypted_output.bin"
        out_path = Path(binput(f"Enter Output File Path (default '{default_out}'):") or default_out).expanduser()
        out_path.write_bytes(pt_bytes)
        print(f"{GREEN}Decrypted file saved to '{out_path}' ({len(pt_bytes)} bytes){RESET}")
    except Exception as exc:
        print(f"{RED}File Decryption Failed: {exc}{RESET}")


def cmd_create_signature(store: OpenQPEPKeyStore) -> None:
    signer_entry = _select_key_interactive(store, "Select Signing Key (Your Personal Key)", require_private=True)
    if not signer_entry:
        return
    pw = bpass(f"Enter Passphrase for Signing Key '{signer_entry['name']}':")
    msg = binput("Enter Message to Sign (Will Be Encapsulated Inside Attached Signature):")
    try:
        signer_kr = OpenQPEPProtocol.import_qpkrf(signer_entry["priv_armor"], passphrase=pw)
        sig_armor = OpenQPEPProtocol.sign_text(msg, signer_private_keyring=signer_kr, passphrase=pw)
        bprint("\n--- Armored OpenQPEP Attached Signature ---")
        bprint(sig_armor.strip())
    except Exception as exc:
        print(f"{RED}Signing Failed: {exc}{RESET}")


def cmd_verify_signature(store: OpenQPEPKeyStore) -> None:
    src = binput("Enter path to signature file OR paste first line of Attached Signature:")
    if Path(src).expanduser().exists():
        sig_armor = Path(src).expanduser().read_text(encoding="utf-8")
    else:
        lines = [src]
        bprint("(Paste remaining lines of the Attached Signature, ending with -----END ...-----)")
        while not lines[-1].strip().startswith("-----END "):
            lines.append(input())
        sig_armor = "\n".join(lines)

    pool = []
    for k in store.keys:
        try:
            pool.append(OpenQPEPProtocol.import_qpkrf(k["pub_armor"]))
        except Exception:
            pass
    ok, extracted_text, matched_kr = OpenQPEPProtocol.verify_text_signature(sig_armor, keyring_pool=pool)
    if ok and matched_kr is not None:
        print(f"{GREEN}\nVERIFIED: Authentic Attached OpenQPEP Signature!{RESET}")
        bprint(f"  Signer:   {matched_kr.name} <{matched_kr.email}>")
        bprint(f"  Key Hash: {matched_kr.key_hash}")
        bprint(f"  Message:  {extracted_text}")
    else:
        print(f"{RED}\nSignature Verification Failed: Signer key not in keyring or signature tampered.{RESET}")


def cmd_search_directory(query: str) -> None:
    q = query or binput("Enter Name, Email, or Key Hash to search on qpepkeys.calyxlabsinc.org:")
    url = f"{DIRECTORY_BASE_URL.rstrip('/')}/api/v1/keys/search?q={urllib.parse.quote(q)}"
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            keys = data.get("keys", [])
            if not keys:
                bprint(f"No matching keys found on {DIRECTORY_BASE_URL} for '{q}'.")
                return
            bprint(f"\nFound {len(keys)} key(s) on {DIRECTORY_BASE_URL}:")
            for idx, k in enumerate(keys, start=1):
                bprint(f"  [{idx}] {k['name']} <{k['email']}> ({k['suite']})")
                bprint(f"      Key Hash: {k['key_hash']}")
    except Exception as exc:
        print(f"{YELLOW}Directory search error ({DIRECTORY_BASE_URL}): {exc}{RESET}")




def cmd_verify_vectors(vectors_dir: str = "") -> int:
    from .vectors.kat_verifier import verify_all_kats
    target = Path(vectors_dir) if vectors_dir else (Path(__file__).resolve().parent.parent / "vectors")
    bprint(f"Verifying OpenQPEP Deterministic KAT Vectors in: {target}")
    ok, lines = verify_all_kats(target)
    for line in lines:
        print(f"{GREEN if line.startswith('[PASS]') else RED}{line}{RESET}")
    if ok:
        print(f"{GREEN}[OK] All {len(lines)} OpenQPEP Known Answer Test (KAT) suites verified bit-for-bit.{RESET}")
        return 0
    print(f"{RED}[FAIL] One or more OpenQPEP KAT suites failed verification.{RESET}")
    return 1

def interactive_shell(keystore_path: Path = DEFAULT_KEYSTORE_PATH) -> int:
    store = OpenQPEPKeyStore(keystore_path)
    print_banner(store)
    while True:
        try:
            raw_cmd = binput("\nOpenQPEP> ")
        except (EOFError, KeyboardInterrupt):
            bprint("\nExiting OpenQPEP CLI.")
            return 0

        if not raw_cmd:
            continue
        low = raw_cmd.lower().strip()

        if low in ("exit", "quit", "q"):
            bprint("Exiting OpenQPEP CLI.")
            return 0
        elif low in ("help", "?"):
            print_banner(store)
        elif low in ("create key", "generate key", "new key"):
            cmd_create_key(store)
        elif low in ("list keys", "show keys", "manage keys", "keys"):
            cmd_list_keys(store)
        elif low.startswith("key details") or low.startswith("inspect key"):
            arg = raw_cmd.split(None, 2)[2] if len(raw_cmd.split()) >= 3 else ""
            cmd_key_details(store, arg)
        elif low.startswith("export public"):
            arg = raw_cmd[len("export public") :].strip()
            cmd_export_key(store, is_private=False, key_query=arg)
        elif low.startswith("export private"):
            arg = raw_cmd[len("export private") :].strip()
            cmd_export_key(store, is_private=True, key_query=arg)
        elif low.startswith("export private/public"):
            arg = raw_cmd[len("export private/public") :].strip()
            which = binput("Export (1) Public Key or (2) Private Key? Enter 1 or 2:")
            cmd_export_key(store, is_private=(which == "2" or "priv" in which.lower()), key_query=arg)
        elif low.startswith("import key"):
            arg = raw_cmd[len("import key") :].strip()
            cmd_import_key(store, arg)
        elif low.startswith("delete key") or low.startswith("remove key"):
            arg = raw_cmd.split(None, 2)[2] if len(raw_cmd.split()) >= 3 else ""
            cmd_delete_key(store, arg)
        elif low in ("encrypt text", "encrypt message", "encrypt notepad"):
            cmd_encrypt_text(store)
        elif low in ("decrypt text", "decrypt message", "decrypt notepad"):
            cmd_decrypt_text(store)
        elif low == "encrypt file":
            cmd_encrypt_file(store)
        elif low == "decrypt file":
            cmd_decrypt_file(store)
        elif low in ("create signature", "sign text", "sign message", "sign"):
            cmd_create_signature(store)
        elif low in ("verify signature", "verify"):
            cmd_verify_signature(store)
        elif low.startswith("publish key"):
            arg = raw_cmd[len("publish key") :].strip()
            entry = store.find_key(arg) if arg else _select_key_interactive(store, "Select Key to Publish")
            if entry:
                _publish_entry_to_directory(entry)
        elif low.startswith("search directory"):
            arg = raw_cmd[len("search directory") :].strip()
            cmd_search_directory(arg)
        else:
            bprint(
                f"Unrecognized command '{raw_cmd}'. Type 'Create Key', 'List Keys', 'Export Public <KeyName>', "
                f"'Export Private <KeyName>', 'Encrypt Text', 'Decrypt Text', 'Create Signature', 'Verify Signature', or 'Help'."
            )


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv or argv == ["--interactive"] or argv == ["-i"]:
        return interactive_shell()

    parser = argparse.ArgumentParser(
        prog="openqpep",
        description=f"{PROJECT_NAME} ({UNIVERSAL_VERSION_LABEL}) — Quantum-Proof Encryption Protocol CLI",
    )
    parser.add_argument("--version", action="version", version=f"{PROJECT_NAME} {UNIVERSAL_VERSION_LABEL} ({PROTOCOL_VERSION})")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive blue-themed English command shell")
    sub = parser.add_subparsers(dest="cmd")

    p_chk = sub.add_parser("check-passphrase", help="Validate a passphrase against OpenQPEP QPKD-Argon policy")
    p_chk.add_argument("--passphrase", required=True)

    p_vv = sub.add_parser("verify-vectors", help="Verify OpenQPEP deterministic Known Answer Test (KAT) vectors")
    p_vv.add_argument("vectors_dir", nargs="?", default="", help="Optional path to vectors/ directory")
    p_kg = sub.add_parser("keygen", help="Generate a new OpenQPEP key pair and export .qpkrf files")
    p_kg.add_argument("--name", required=True)
    p_kg.add_argument("--email", required=True)
    p_kg.add_argument("--passphrase", required=True)
    p_kg.add_argument("--tier", default="QLX-4096", choices=["QLX-768", "QLX-1024", "QLX-2048", "QLX-4096", "QLX-16384"])
    p_kg.add_argument("--pub-out", required=True)
    p_kg.add_argument("--priv-out", required=True)

    args = parser.parse_args(argv)
    if args.interactive or not args.cmd:
        return interactive_shell()
    if args.cmd == "check-passphrase":
        res = analyze_passphrase(args.passphrase)
        bprint(f"Valid: {res.is_valid}")
        return 0 if res.is_valid else 1
    if args.cmd == "verify-vectors":
        return cmd_verify_vectors(args.vectors_dir)
    if args.cmd == "keygen":
        kr = OpenQPEPProtocol.generate_keypair(args.name, args.email, args.passphrase, qlx_tier=args.tier)
        OpenQPEPProtocol.export_qpkrf(kr, include_private=False, output_path=args.pub_out)
        OpenQPEPProtocol.export_qpkrf(kr, passphrase=args.passphrase, include_private=True, output_path=args.priv_out)
        bprint(f"Generated OpenQPEP Key Hash: {kr.key_hash}")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
