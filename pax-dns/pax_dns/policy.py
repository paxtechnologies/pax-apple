# SPDX-License-Identifier: GPL-3.0-only
"""Per-query decision and the in-memory store of users' effective lists.

Resolution order (README "pax-dns", v0.8.1):
  1. restricted, for everyone and whatever the user's exceptions say:
        the category list (restricted content, if one is loaded) and the
        "media_converters" sites, "media_converter_rule" and
        "remote_ai_browsers" sites (ChatGPT, Manus)            -> blocked answer
  2. the user's allow-list  -> forward to the allow upstream (the same filtered
                               upstream by default), unless the restricted-content
                               name rules match (then the exception is ignored)
  3. the user's blocklist   -> blocked answer
  4. built-in categories (v0.5), each blocked unless the user has it off:
        "bypass"          cloud PCs, browser isolation, web proxies (always on)
        "remote_desktop"  remote desktop / remote access (on by default; turning
                          it off waits like a removal, see the server)
  5. otherwise              -> forward to the upstream (the Family Filter in dev)
Each entry matches the domain and all of its subdomains. Unknown, malformed or
retired tokens get steps 1, 4 and 5: still filtered, never unfiltered (every
built-in category stays on for them).
"""
from __future__ import annotations

import enum
import hashlib
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional

from .domains import suffixes
from .lists import RESTRICTED_BUILTIN, CategoryList

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")


def hash_token(token: str) -> str:
    """Same hash the escrow server stores (pax_server.crypto.hash_token)."""
    return hashlib.sha256(token.encode()).hexdigest()


class Action(enum.Enum):
    ALLOW = "allow"                 # user exception: forward to the allow upstream (filtered)
    BLOCK_CUSTOM = "block_custom"   # user's blocklist
    BLOCK_CATEGORY = "block_category"
    FORWARD = "forward"             # upstream decides (Family Filter in dev)

    @property
    def blocked(self) -> bool:
        return self in (Action.BLOCK_CUSTOM, Action.BLOCK_CATEGORY)


# Built-in categories a user may switch off (after the wait). "bypass" is not
# here: it can't be switched off.
OPTIONAL_CATEGORIES = ("remote_desktop",)


@dataclass(frozen=True)
class UserLists:
    block: frozenset = frozenset()
    allow: frozenset = frozenset()
    # Built-in categories this user has switched off (wait already over).
    categories_off: frozenset = frozenset()


@dataclass(frozen=True)
class Decision:
    action: Action
    matched: Optional[str] = None
    category: Optional[str] = None


def _match(qname: str, domains) -> Optional[str]:
    for s in suffixes(qname):
        if s in domains:
            return s
    return None


_NEVER_EXCEPT = None


def never_except(qname: str) -> bool:
    """True when an exception must be ignored: the restricted-content name rule,
    top-level domains and hand list (common/pax_restricted.py)."""
    global _NEVER_EXCEPT
    if _NEVER_EXCEPT is None:
        from .lists import _restricted_module
        _NEVER_EXCEPT = _restricted_module().RestrictedCheck()
    return _NEVER_EXCEPT(qname)


def decide(qname: str, user: Optional[UserLists], category: Optional[CategoryList],
           builtin: Optional[Mapping[str, CategoryList]] = None) -> Decision:
    qname = qname.lower().rstrip(".")
    if category is not None:
        m = category.match(qname)
        if m:
            return Decision(Action.BLOCK_CATEGORY, m, "category")
    builtin = builtin or {}
    for name in RESTRICTED_BUILTIN:
        cl = builtin.get(name)
        m = cl.match(qname) if cl is not None else None
        if m:
            return Decision(Action.BLOCK_CATEGORY, m, name)
    if user is not None:
        m = _match(qname, user.allow)
        if m and not never_except(qname):
            return Decision(Action.ALLOW, m)
        m = _match(qname, user.block)
        if m:
            return Decision(Action.BLOCK_CUSTOM, m)
    for name, cl in builtin.items():
        if name in RESTRICTED_BUILTIN:
            continue
        if user is not None and name in OPTIONAL_CATEGORIES and name in user.categories_off:
            continue
        m = cl.match(qname)
        if m:
            return Decision(Action.BLOCK_CATEGORY, m, name)
    return Decision(Action.FORWARD)


@dataclass
class _Entry:
    lists: UserLists
    retire_at: Optional[int]
    account_id: str


@dataclass
class Store:
    """token hash -> effective lists. Updated by the syncer, read per query."""
    clock: Callable[[], float] = time.time
    _by_hash: dict = field(default_factory=dict)
    _by_account: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def lookup(self, token: Optional[str]) -> Optional[UserLists]:
        if not token or not TOKEN_RE.match(token):
            return None
        e = self._by_hash.get(hash_token(token))
        if e is None:
            return None
        if e.retire_at is not None and self.clock() >= e.retire_at:
            return None
        return e.lists

    def apply(self, feed: dict) -> None:
        """Apply a change feed (server /internal/v1/dns/changes shape)."""
        with self._lock:
            by_hash = {} if feed.get("full") else dict(self._by_hash)
            by_account = {} if feed.get("full") else dict(self._by_account)
            for acct in feed.get("accounts", []):
                aid = acct["account_id"]
                for h in by_account.pop(aid, ()):
                    by_hash.pop(h, None)
                off = frozenset(c for c in OPTIONAL_CATEGORIES
                                if acct.get("categories", {}).get(c, True) is False)
                lists = UserLists(frozenset(acct.get("block", ())), frozenset(acct.get("allow", ())),
                                  off)
                hashes = []
                for t in acct.get("tokens", []):
                    by_hash[t["hash"]] = _Entry(lists, t.get("retire_at"), aid)
                    hashes.append(t["hash"])
                by_account[aid] = hashes
            self._by_hash, self._by_account = by_hash, by_account

    def __len__(self) -> int:
        return len(self._by_account)
