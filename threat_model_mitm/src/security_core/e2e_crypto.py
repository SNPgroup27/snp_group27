from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _resolve_shared_secret() -> bytes:
    fallback = b"snpgroup27cw2demokey000000000000"
    env_value = os.environ.get("CGM_APP_SECRET_KEY")
    if not env_value:
        print(
            "[WARNING] CGM_APP_SECRET_KEY is not set. Falling back to insecure demo key."
        )
        return fallback
    raw = env_value.encode("utf-8")
    if len(raw) >= 32:
        return raw[:32]
    return raw.ljust(32, b"0")


def encrypt_payload(data_dict: dict[str, Any]) -> dict[str, str]:
    plaintext = json.dumps(data_dict, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    nonce = os.urandom(12)
    key = _resolve_shared_secret()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    return {
        "enc_v": "1",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_payload(encrypted_dict: dict[str, Any]) -> dict[str, Any]:
    try:
        nonce = base64.b64decode(str(encrypted_dict["nonce_b64"]), validate=True)
        ciphertext = base64.b64decode(
            str(encrypted_dict["ciphertext_b64"]), validate=True
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("encrypted payload missing/corrupt fields") from exc
    key = _resolve_shared_secret()
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
    decoded = json.loads(plaintext.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("decrypted payload must be a JSON object")
    return decoded
