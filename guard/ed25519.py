# SPDX-License-Identifier: GPL-3.0-only
"""Ed25519 (RFC 8032) in pure Python, standard library only.

pax-guard runs on /usr/bin/python3 (Command Line Tools), which has no ed25519,
and Pax adds no third-party packages, so the signature check for updates and
filter lists lives here. It follows the RFC 8032 section 6 reference code
(public domain, "Python illustration"), with strict checks added for verify:
canonical S (< L), canonical point encodings, and a 64-byte signature.

Speed is irrelevant here (one check every few hours): verify takes ~10 ms.
Signing (scripts/sign-release.py) uses the same code, or the `cryptography`
package when it is installed. Tested against the RFC 8032 test vectors.
"""
from __future__ import annotations

import hashlib

__all__ = ["public_key", "sign", "verify", "BadSignature"]


class BadSignature(Exception):
    pass


P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _sha512_mod_l(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % L


# Points in extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z.
def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % P == 0


def _recover_x(y: int, sign: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)


def _compress(p) -> bytes:
    zinv = pow(p[2], P - 2, P)
    x = p[0] * zinv % P
    y = p[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("an Ed25519 private key (seed) is 32 bytes")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    a, _ = _secret_expand(secret)
    return _compress(_mul(a, G))


def sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = _secret_expand(secret)
    A = _compress(_mul(a, G))
    r = _sha512_mod_l(prefix + msg)
    R = _compress(_mul(r, G))
    h = _sha512_mod_l(R + A + msg)
    s = (r + h * a) % L
    return R + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """True only for a valid signature. Never raises on bad input."""
    try:
        if len(public) != 32 or len(signature) != 64:
            return False
        A = _decompress(public)
        if A is None:
            return False
        Rs = signature[:32]
        R = _decompress(Rs)
        if R is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        h = _sha512_mod_l(Rs + public + msg)
        sB = _mul(s, G)
        hA = _mul(h, A)
        return _equal(sB, _add(R, hA))
    except Exception:  # noqa: BLE001 - malformed input is just "not valid"
        return False
