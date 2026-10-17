# SPDX-License-Identifier: GPL-3.0-only
"""Verified support release codes (v0.8.15). Standard library only.

When someone has a genuine emergency and Pax support has checked it, support can
issue a code that removes Pax from ONE device straight away, without the usual
wait. There is no universal code: every code names one device, works once, and
expires within 24 hours. A device whose owner turned "Allow verified support
release" off refuses every code.

A code is

    payload  = version (1 byte, = 1)
             | support ID of the device (10 bytes)
             | nonce (8 random bytes, single use)
             | issued_at (uint32, Unix seconds)
             | expires_at (uint32, Unix seconds, at most 24 h after issued_at)
    signature = Ed25519 over DOMAIN + payload, made with the support key
    code     = "PAXS-" + base32(payload + signature) in groups of five

The support key is a separate Ed25519 key from the update signing key, so a code
can never be confused with a signed update. Its private half never enters the
repo: support keeps it offline and runs tools/pax-support-release.py. The public
half is pinned below; pax-guard (a Mac's own escrow) and the Pax server (iPhone
and iPad escrow) both verify with this file. Used nonces are kept for good on
the device and on the server (they're 8 bytes each and codes are rare), so
moving a clock back can never make a used code work again.

The support ID is 10 random bytes shown as four groups of four base32 letters
(device page › Details › Support ID). It tells support which device a code is
for; it isn't a secret, and knowing it doesn't let anyone issue a code.
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import struct

import ed25519

# Pinned Ed25519 public key(s) of the support key (hex). Generated 2026-10-17 by
# tools/pax-support-release.py keygen. Rotating: add the new key, ship, then
# issue with it and drop the old one in a later release.
SUPPORT_PUBLIC_KEYS_HEX = [
    "395e61d87f6892eacf7bb917d4539c3d8d7f79431e1af6e4b8972b2a41698aac",
]

DOMAIN = b"pax-support-release/v1\x00"
VERSION = 1
PREFIX = "PAXS"
ID_BYTES = 10
NONCE_BYTES = 8
MAX_LIFETIME = 24 * 3600
CLOCK_SKEW = 300           # an issue time up to 5 minutes ahead of this device's clock is fine
_PAYLOAD = struct.Struct(">B10s8sII")
PAYLOAD_LEN = _PAYLOAD.size            # 27
SIG_LEN = 64
CODE_BYTES = PAYLOAD_LEN + SIG_LEN     # 91

# Support codes (common/pax_errors.py): one per way a code can fail.
MALFORMED = "PAX-ESCROW-012"
BAD_SIGNATURE = "PAX-ESCROW-013"
WRONG_DEVICE = "PAX-ESCROW-014"
EXPIRED = "PAX-ESCROW-015"
USED = "PAX-ESCROW-016"
TURNED_OFF = "PAX-ESCROW-017"
PARTNER_UNREACHABLE = "PAX-ESCROW-018"
TOO_MANY_TRIES = "PAX-ESCROW-019"


class SupportCodeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ------------------------------------------------------------------ support IDs
def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=")


def _clean(text: str) -> str:
    """Upper case, no separators; 0/1/8 typed for O/I/B are read as letters
    (base32 has no 0, 1, 8 or 9)."""
    t = re.sub(r"[\s\-_.:]", "", str(text or "")).upper()
    return t.translate(str.maketrans({"0": "O", "1": "I", "8": "B"}))


def format_support_id(raw: bytes) -> str:
    s = _b32(raw)
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def new_support_id() -> str:
    return format_support_id(secrets.token_bytes(ID_BYTES))


def support_id_bytes(support_id: str) -> bytes:
    t = _clean(support_id)
    if not re.fullmatch(r"[A-Z2-7]{16}", t):
        raise SupportCodeError(MALFORMED, "that isn't a Pax support ID")
    return base64.b32decode(t)


def normalise_support_id(support_id: str) -> str:
    return format_support_id(support_id_bytes(support_id))


# ------------------------------------------------------------------- the code
def pinned_keys() -> list[bytes]:
    out = []
    for h in SUPPORT_PUBLIC_KEYS_HEX:
        try:
            k = bytes.fromhex(h)
        except ValueError:
            continue
        if len(k) == 32:
            out.append(k)
    return out


def key_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:8]


def format_code(raw: bytes) -> str:
    s = _b32(raw)
    return PREFIX + "-" + "-".join(s[i:i + 5] for i in range(0, len(s), 5))


def issue(seed: bytes, support_id: str, now: int, lifetime: int = MAX_LIFETIME,
          nonce: bytes | None = None) -> str:
    """A code for one device. Used by tools/pax-support-release.py (and tests)."""
    if not 60 <= int(lifetime) <= MAX_LIFETIME:
        raise ValueError("a code lasts between 1 minute and 24 hours")
    nonce = nonce if nonce is not None else secrets.token_bytes(NONCE_BYTES)
    if len(nonce) != NONCE_BYTES:
        raise ValueError("nonce must be 8 bytes")
    payload = _PAYLOAD.pack(VERSION, support_id_bytes(support_id), nonce, int(now), int(now) + int(lifetime))
    return format_code(payload + ed25519.sign(seed, DOMAIN + payload))


def parse(code: str) -> dict:
    """Decode a code without checking anything but its shape."""
    t = _clean(code)
    if t.startswith(PREFIX):
        t = t[len(PREFIX):]
    if not t or len(t) > 200 or not re.fullmatch(r"[A-Z2-7]+", t):
        raise SupportCodeError(MALFORMED, "that isn't a complete Pax support code")
    try:
        raw = base64.b32decode(t + "=" * (-len(t) % 8))
    except (ValueError, TypeError):
        raise SupportCodeError(MALFORMED, "that isn't a complete Pax support code") from None
    if len(raw) != CODE_BYTES:
        raise SupportCodeError(MALFORMED, "that isn't a complete Pax support code")
    payload, sig = raw[:PAYLOAD_LEN], raw[PAYLOAD_LEN:]
    version, dev, nonce, issued_at, expires_at = _PAYLOAD.unpack(payload)
    if version != VERSION:
        raise SupportCodeError(MALFORMED, "this support code is for a different version of Pax")
    return {"payload": payload, "signature": sig, "support_id": format_support_id(dev),
            "nonce": nonce.hex(), "issued_at": issued_at, "expires_at": expires_at}


def verify(code: str, support_id: str, now: float, keys: list[bytes] | None = None,
           trusted_now: float | None = None) -> dict:
    """The checked contents of a code meant for `support_id`, else
    SupportCodeError. Checks the signature first (nothing in an unsigned code is
    believed), then the device, then the time (this device's clock and, when
    known, network time; either one saying it expired is enough). The caller
    still checks the device's switch and that the nonce wasn't used before."""
    c = parse(code)
    keys = pinned_keys() if keys is None else keys
    if not keys:
        raise SupportCodeError(BAD_SIGNATURE, "this copy of Pax can't check support codes")
    msg = DOMAIN + c["payload"]
    match = next((k for k in keys if ed25519.verify(k, msg, c["signature"])), None)
    if match is None:
        raise SupportCodeError(BAD_SIGNATURE, "that code wasn't issued by Pax support")
    if c["support_id"] != normalise_support_id(support_id):
        raise SupportCodeError(WRONG_DEVICE, "that code is for a different device")
    if c["expires_at"] <= c["issued_at"] or c["expires_at"] - c["issued_at"] > MAX_LIFETIME:
        raise SupportCodeError(EXPIRED, "that code's dates aren't valid")
    for t in (now, trusted_now):
        if t is None:
            continue
        if t >= c["expires_at"]:
            raise SupportCodeError(EXPIRED, "that code has expired")
        if c["issued_at"] > t + CLOCK_SKEW:
            raise SupportCodeError(EXPIRED, "that code isn't valid yet")
    c["key_id"] = key_id(match)
    del c["payload"], c["signature"]
    return c
