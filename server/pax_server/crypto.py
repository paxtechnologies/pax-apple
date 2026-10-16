# SPDX-License-Identifier: GPL-3.0-only
"""Encryption at rest for escrowed removal passwords, and token hashing.

Removal passwords are encrypted with AES-256-GCM using a server key that lives
outside the database (env PAX_SERVER_KEY). The device ID is bound as associated
data, so a ciphertext copied onto another device row will not decrypt.
API tokens are stored only as SHA-256 hashes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION = b"\x01"


class KeyError_(ValueError):
    pass


def generate_key_b64() -> str:
    return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode()


class SecretBox:
    def __init__(self, key_b64: str):
        if not key_b64:
            raise KeyError_("PAX_SERVER_KEY is not set")
        try:
            key = base64.urlsafe_b64decode(key_b64.encode())
        except Exception as exc:  # noqa: BLE001
            raise KeyError_("PAX_SERVER_KEY is not valid base64") from exc
        if len(key) != 32:
            raise KeyError_("PAX_SERVER_KEY must decode to 32 bytes")
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: str, aad: str) -> bytes:
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, plaintext.encode(), aad.encode())
        return _VERSION + nonce + ct

    def decrypt(self, blob: bytes, aad: str) -> str:
        if not blob or blob[:1] != _VERSION:
            raise ValueError("unknown ciphertext version")
        nonce, ct = blob[1:13], blob[13:]
        return self._aead.decrypt(nonce, ct, aad.encode()).decode()


def new_token() -> str:
    return "pax_" + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def token_matches(token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), stored_hash)


if __name__ == "__main__":
    if "--generate-key" in sys.argv:
        print(generate_key_b64())
    else:
        print("usage: python3 -m pax_server.crypto --generate-key")
