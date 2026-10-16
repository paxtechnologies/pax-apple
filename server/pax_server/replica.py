# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.8: the replica feed a DoH-only second server reads from the primary.

GET /v1/replica/dns/changes?since=N  with  X-Pax-Replica-Key: <key>
answers the same change feed the primary's own resolver uses (token hashes,
each account's effective blocked sites and exceptions, categories and DNS
settings). It never carries a token, password, email or address.

Only keys whose SHA-256 is listed here (or in PAX_REPLICA_KEY_SHA256) are
accepted; anything else gets 404 so the endpoint isn't advertised. Publishing
a hash of a 256-bit random key reveals nothing about the key.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Iterable, Optional

# Pax's own second server (dns2, Hetzner hel1). Its key is in its /etc/pax/env
# only; rotate by adding a new hash here, releasing, then removing the old one.
REPLICA_KEY_SHA256 = (
    "62d8692a0ff90622b6f76b293da7460296b95f4c6f39fd7704f2cd7609097c67",
)


def key_allowed(key: Optional[str], extra: Iterable[str] = ()) -> bool:
    if not key or len(key) < 32 or len(key) > 256:
        return False
    digest = hashlib.sha256(key.strip().encode()).hexdigest()
    ok = False
    for h in tuple(REPLICA_KEY_SHA256) + tuple(extra):
        ok |= hmac.compare_digest(digest, str(h).strip().lower())
    return ok
