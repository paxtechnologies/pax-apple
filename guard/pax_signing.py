# SPDX-License-Identifier: GPL-3.0-only
"""Signed JSON documents for Pax updates and filter lists (v0.8.0).

A signed document is
    {"payload": {...}, "signature": "<base64 Ed25519 signature>", "key_id": "<8 hex>"}
and the signature covers the payload's *canonical* JSON: UTF-8, keys sorted,
no whitespace (json.dumps(payload, sort_keys=True, separators=(",", ":"),
ensure_ascii=False)). The Swift side (PaxCore.UpdateManifest) builds the same
bytes the same way.

The public key is pinned below (and in PaxCore/Updates.swift). The private key
never enters the repo: it lives in the GitHub Actions secret
PAX_UPDATE_SIGNING_KEY (base64 of the 32-byte seed); see docs/UPDATES.md.
Rotating the key = add the new public key here, ship a release signed with the
old key, then sign with the new one.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json

import ed25519

# Pinned Ed25519 public keys (hex). Generated 2026-10-15 by
# scripts/sign-release.py keygen.
PUBLIC_KEYS_HEX = [
    "0ad387f103fcd5104604b968741da264cc6e97242aaf228b2e2f57d80f497204",
]


class SignatureError(Exception):
    """Unsigned, wrongly signed, or malformed document (PAX-UPDATE-002)."""


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def key_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:8]


def pinned_keys() -> list[bytes]:
    out = []
    for h in PUBLIC_KEYS_HEX:
        try:
            k = bytes.fromhex(h)
        except ValueError:
            continue
        if len(k) == 32:
            out.append(k)
    return out


def seed_from_text(text: str) -> bytes:
    """The private key as stored in the secret: base64 (or hex) of the 32-byte seed."""
    t = text.strip()
    try:
        raw = bytes.fromhex(t)
    except ValueError:
        try:
            raw = base64.b64decode(t, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("signing key must be base64 or hex of a 32-byte Ed25519 seed") from exc
    if len(raw) != 32:
        raise ValueError("signing key must be a 32-byte Ed25519 seed")
    return raw


def sign_document(payload: dict, seed: bytes) -> dict:
    pub = ed25519.public_key(seed)
    sig = ed25519.sign(seed, canonical(payload))
    return {"payload": payload, "signature": base64.b64encode(sig).decode(), "key_id": key_id(pub)}


def verify_document(doc, keys: list[bytes] | None = None) -> dict:
    """The payload of a correctly signed document, else SignatureError. Never
    accepts a document without a signature, whatever else it says."""
    if not isinstance(doc, dict) or not isinstance(doc.get("payload"), dict):
        raise SignatureError("not a signed Pax document")
    sig_b64 = doc.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        raise SignatureError("unsigned")
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (binascii.Error, ValueError):
        raise SignatureError("signature is not base64") from None
    keys = pinned_keys() if keys is None else keys
    if not keys:
        raise SignatureError("no public key pinned in this build")
    msg = canonical(doc["payload"])
    if any(ed25519.verify(k, msg, sig) for k in keys):
        return doc["payload"]
    raise SignatureError("bad signature")
