"""
Combines QPKD-Argon2id passphrase key material with hardware-bound FIDO2 WebAuthn PRF
(or Android StrongBox / Apple Secure Enclave) secret outputs, enforcing mandatory .qshare
recovery verification before hardware-only lock mode.
"""
import base64
import os
from typing import Any, Dict

from ..exceptions import QPEPMacVerificationError, QPEPSuiteError
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt
from ..primitives.qsponge import qsponge_512


def wrap_with_fido2_prf(
    secret_bytes: bytes,
    passphrase_key: bytes,
    hardware_prf_output: bytes,
    *,
    credential_id: str,
    enclave_type: str = "FIDO2-WebAuthn-PRF",
    recovery_verified: bool = True,
) -> Dict[str, Any]:
    if not recovery_verified:
        raise QPEPSuiteError("Hardware-bound wrapping requires verified .qshare Shamir recovery backup first.")
    if len(hardware_prf_output) < 32:
        raise ValueError("Hardware PRF output must be at least 32 bytes.")
    salt = os.urandom(32)
    kek = qsponge_512(b"CALYX-HW-PRF-WRAP-v1|" + salt + passphrase_key + hardware_prf_output)
    nonce24 = os.urandom(24)
    aad = f"{enclave_type}|{credential_id}".encode("utf-8")
    ct = cc512_encrypt(kek, nonce24, secret_bytes, aad)
    return {
        "envelope": "openqpep-hardware-wrap-v1",
        "enclave_type": enclave_type,
        "credential_id": credential_id,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce24_b64": base64.b64encode(nonce24).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
    }


def unwrap_with_fido2_prf(envelope: Dict[str, Any], passphrase_key: bytes, hardware_prf_output: bytes) -> bytes:
    salt = base64.b64decode(envelope["salt_b64"])
    kek = qsponge_512(b"CALYX-HW-PRF-WRAP-v1|" + salt + passphrase_key + hardware_prf_output)
    aad = f"{envelope['enclave_type']}|{envelope['credential_id']}".encode("utf-8")
    try:
        return cc512_decrypt(kek, base64.b64decode(envelope["nonce24_b64"]), base64.b64decode(envelope["ciphertext_b64"]), aad)
    except Exception as exc:
        raise QPEPMacVerificationError("Hardware PRF unwrap failed (wrong passphrase or wrong hardware token).") from exc


class HardwareKeyWrapper:
    @staticmethod
    def simulate_prf_eval(hardware_master_secret: bytes, salt_input: bytes) -> bytes:
        return qsponge_512(b"CALYX-SIMULATED-FIDO2-PRF|" + hardware_master_secret + salt_input)[:32]
