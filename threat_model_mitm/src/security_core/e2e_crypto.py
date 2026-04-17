from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# 32-byte shared secret for lab simulation only. In production, key material should
# be generated and stored in an HSM (e.g., EFR32MG24 Secure Vault or cloud HSM).
_SHARED_SECRET = b"snpgroup27cw2demokey000000000000"


def encrypt_payload(data_dict: dict[str, Any]) -> dict[str, str]:
    plaintext = json.dumps(data_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(_SHARED_SECRET).encrypt(nonce, plaintext, associated_data=None)
    return {
        "enc_v": "1",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_payload(encrypted_dict: dict[str, Any]) -> dict[str, Any]:
    try:
        nonce = base64.b64decode(str(encrypted_dict["nonce_b64"]), validate=True)
        ciphertext = base64.b64decode(str(encrypted_dict["ciphertext_b64"]), validate=True)
    except (KeyError, ValueError) as exc:
        raise ValueError("encrypted payload missing/corrupt fields") from exc
    plaintext = AESGCM(_SHARED_SECRET).decrypt(nonce, ciphertext, associated_data=None)
    decoded = json.loads(plaintext.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("decrypted payload must be a JSON object")
    return decoded
