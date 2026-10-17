# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.8: Pax's own DNS-over-HTTPS filter for iPhones and iPads.

Every iPhone/iPad set up with Pax's filter (the default from 0.8.8) points its
locked DNS settings at  https://dns.paxpeace.com/u/<token>/dns-query  (RFC 8484).
The token is the account's unguessable DNS token (192 bits, stored hashed); the
same token serves every device of the account, so a site added in Pax is
blocked on all of them within seconds, with no new profile.

Why this runs inside pax-server instead of the older stand-alone pax-dns: the
server self-updates (deploy/pax-server-update.py restarts pax-server only),
and Caddy already proxies /v1/* to it, so the resolver ships with every signed
release. And it runs the Mac's own engine (guard/dns_forwarder.py and
guard/filter_lists.py), so iPhones get exactly the lists and rules a Mac gets.

For each query, in this order (guard/dns_forwarder.py `Forwarder.decide`):
  1. the user's own blocked sites (not freed by an exception)
  2. SafeSearch rewrites (Google, Bing, DuckDuckGo, YouTube unless the user
     turned YouTube Restricted Mode off)
  3. restricted: Pax's v2 lists (pax-block, pax-nrd, the name rule), media
     converters, remote AI browsers, even when the user has an exception
  4. the user's exceptions (freed after the wait, never for a restricted site)
  5. Pax's categories: cloud PCs / proxies, X and Bluesky media (unless the
     user chose otherwise), remote desktop (unless switched off after the wait)
  6. overridable lists (DoH / VPN / proxy names)
  7. upstream (v0.8.18): Quad9 over DNS-over-TLS, then Cloudflare's security
     resolver (both filter malware only; every content decision is Pax's), then
     the family-filter chain, else SERVFAIL. The family-filter chain takes every
     lookup when the account turned on the extra family layer (Advanced), and
     for everyone, at once, when Pax's own filter fails a check: lists missing or
     failing their checks, the decision code throwing or slow, or the canary
     self-test failing (Forwarder.canary, run on start, after each list update and
     every few minutes). Never plain or unfiltered DNS (fail closed).
Reddit's and Imgur's media hosts are in pax-block (step 3), as on the Mac.

Roles: "all" (the primary, api.paxpeace.com) reads the account database
directly. "dns" (a second, DoH-only server) pulls the same effective lists from
the primary's replica feed (/v1/replica/dns/changes, shared key) and keeps a
copy on disk, so it keeps filtering with each user's last known list while the
primary is down. It never writes account state, so there is one source of
truth and no split brain.

Privacy: no query is logged. The uvicorn access log line for any /dns-query
path is dropped in-process (the path holds the token and a GET holds the name),
Caddy writes no access log, and nothing here records names or client addresses
except a per-address request counter for rate limiting, kept in memory only.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import random
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import OrderedDict
from pathlib import Path
from typing import Callable, Optional

_REPO = Path(__file__).resolve().parents[2]
for _d in (_REPO / "guard", _REPO / "common"):
    if str(_d) not in sys.path:
        sys.path.append(str(_d))

import dns_forwarder as dnsf  # noqa: E402  (guard/, standard library only)
import filter_lists as fl  # noqa: E402
import guard_config as gc  # noqa: E402
import pax_restricted as pr  # noqa: E402

log = logging.getLogger("pax.doh")

DOH_CT = "application/dns-message"
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
MAX_MESSAGE = 4096          # a single question; real queries are < 300 bytes


class BadQuery(ValueError):
    pass


def b64url_decode(s: str) -> bytes:
    """RFC 8484 4.1: base64url without padding (padding tolerated)."""
    if not s or len(s) > 2 * MAX_MESSAGE or "+" in s or "/" in s:
        raise BadQuery("missing, oversized or non-base64url dns parameter")
    s = s.rstrip("=")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise BadQuery("dns parameter is not valid base64url") from None


def hash_token(token: str) -> str:
    """Same as pax_server.crypto.hash_token (SHA-256 hex)."""
    return hashlib.sha256(token.encode()).hexdigest()


class DropDnsQueryLogs(logging.Filter):
    """Drop uvicorn access-log records for DoH paths (token + query name), the
    replica feed and /v1/stats (its key can be in the URL)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            text = record.getMessage()
        except Exception:  # noqa: BLE001
            return False
        # v0.8.24: /v1/stats may carry its key in the query string.
        return "dns-query" not in text and "/v1/replica/" not in text and "/v1/stats" not in text


def install_log_filter() -> None:
    f = DropDnsQueryLogs()
    for name in ("uvicorn.access", "uvicorn.error", "uvicorn"):
        lg = logging.getLogger(name)
        if not any(isinstance(x, DropDnsQueryLogs) for x in lg.filters):
            lg.addFilter(f)


# ----------------------------------------------------------- rate limits
class RateLimiter:
    """Token bucket per key (client address), in memory, bounded LRU."""

    def __init__(self, rate: float, burst: float, max_keys: int = 50_000,
                 clock: Callable[[], float] = time.monotonic):
        self.rate, self.burst, self.max_keys, self.clock = rate, burst, max_keys, clock
        self._b: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.rate <= 0:
            return True
        now = self.clock()
        with self._lock:
            tokens, last = self._b.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self._b[key] = (tokens - 1 if ok else tokens, now)
            self._b.move_to_end(key)
            while len(self._b) > self.max_keys:
                self._b.popitem(last=False)
            return ok


# --------------------------------------------------------- user policies
def _settings_of(acct: dict) -> dict:
    s = acct.get("settings") or {}
    # v0.8.13: X and Bluesky media are always blocked (see _base), whatever the feed says.
    return {"youtube_restricted": s.get("youtube_restricted", True) is not False}


class Policies:
    """token hash -> account; account -> dns_forwarder.Policy. Built from the
    change feed (Blocklist.changes shape plus "settings")."""

    def __init__(self, clock: Callable[[], float] = time.time, list_dirs=None):
        self.clock = clock
        self._lock = threading.Lock()
        self._tokens: dict = {}       # hash -> (account_id, retire_at)
        self._accounts: dict = {}     # account_id -> feed entry
        self._policies: dict = {}     # account_id -> Policy
        self.list_dirs = list_dirs
        self._shared: dict = {}
        self._base()
        self.default = self._build({})

    def _curated(self, cat: str) -> list:
        return gc.load_curated(cat, self.list_dirs)

    def _base(self) -> None:
        rule_path = gc.find_list("media_converter_rule", self.list_dirs)
        self._rule = pr.parse_rule_file(rule_path.read_text()) if rule_path else None
        restricted = []
        for cat in gc.RESTRICTED_CATEGORIES:
            restricted += self._curated(cat)
        if not restricted or self._rule is None:
            raise RuntimeError("PAX-DNS-008 Pax's curated lists are missing")
        # v0.8.13: X's and Bluesky's media servers are always blocked and no
        # exception frees them, so they sit with the restricted names.
        self._restricted = restricted + list(gc.ALWAYS_BLOCKED_MEDIA_NAMES)
        self._bypass = self._curated("bypass")
        self._remote_desktop = self._curated("remote_desktop")
        self._never_except = pr.RestrictedCheck()

    def _categories(self, s: dict, remote_desktop: bool, exceptions: list) -> list:
        cats = list(self._bypass)
        if remote_desktop:
            cats += self._remote_desktop
        return [c for c in cats if not any(c == e or c.endswith("." + e) for e in exceptions)]

    def _build(self, acct: dict) -> "dnsf.Policy":
        s = _settings_of(acct)
        rd = (acct.get("categories") or {}).get("remote_desktop", True) is not False
        fam = (acct.get("categories") or {}).get("family_layer") is True      # v0.8.18
        allow = [d for d in acct.get("allow", []) if isinstance(d, str)]
        block = [d for d in acct.get("block", []) if isinstance(d, str)]
        p = dnsf.Policy(blocked=block, exceptions=allow, youtube_restricted=s["youtube_restricted"],
                        never_except=self._never_except, family_layer=fam,
                        restricted_rules=[self._rule] if self._rule else [])
        # The big sets are shared between users (they only differ by switches).
        key = ("r",)
        if key not in self._shared:
            self._shared[key] = dnsf.Policy(restricted=self._restricted).restricted
        p.restricted = self._shared[key]
        ckey = ("c", rd)
        if allow:
            p.categories = dnsf.Policy(categories=self._categories(s, rd, allow)).categories
        else:
            if ckey not in self._shared:
                self._shared[ckey] = dnsf.Policy(categories=self._categories(s, rd, [])).categories
            p.categories = self._shared[ckey]
        return p

    def apply(self, feed: dict) -> None:
        built = {a["account_id"]: (a, self._build(a)) for a in feed.get("accounts", [])
                 if isinstance(a, dict) and a.get("account_id")}
        with self._lock:
            if feed.get("full"):
                self._tokens, self._accounts, self._policies = {}, {}, {}
            for aid, (acct, pol) in built.items():
                for h in [h for h, (a, _r) in self._tokens.items() if a == aid]:
                    del self._tokens[h]
                for t in acct.get("tokens", []):
                    if isinstance(t, dict) and isinstance(t.get("hash"), str):
                        self._tokens[t["hash"]] = (aid, t.get("retire_at"))
                self._accounts[aid] = acct
                self._policies[aid] = pol

    def lookup(self, token: Optional[str]) -> "dnsf.Policy":
        """The user's policy, or the default (everything on, no own lists) for
        an unknown or retired token: still filtered, never open."""
        if not token or not TOKEN_RE.match(token):
            return self.default
        with self._lock:
            hit = self._tokens.get(hash_token(token))
            if not hit:
                return self.default
            aid, retire_at = hit
            if retire_at is not None and self.clock() >= retire_at:
                return self.default
            return self._policies.get(aid, self.default)

    def snapshot(self) -> dict:
        with self._lock:
            return {"full": True, "accounts": list(self._accounts.values())}

    def __len__(self) -> int:
        return len(self._accounts)


# ------------------------------------------------------------- feeds
class LocalFeed:
    """Primary: the account database itself."""

    def __init__(self, blocklist):
        self.blocklist = blocklist

    def fetch(self, since: int) -> dict:
        return self.blocklist.changes(since)


class ReplicaFeed:
    """Second server: the primary's replica feed over HTTPS, with a copy on
    disk so a restart during a primary outage keeps every user's lists."""

    def __init__(self, primary_url: str, key: str, cache_path: Optional[str] = None,
                 opener: Optional[Callable] = None, timeout: float = 10.0):
        if not key:
            raise ValueError("PAX_REPLICA_KEY is required for the dns role")
        self.url = primary_url.rstrip("/") + "/v1/replica/dns/changes"
        self.key = key
        self.cache_path = cache_path
        self.opener = opener or (lambda req: urllib.request.urlopen(req, timeout=timeout))

    def fetch(self, since: int) -> dict:
        req = urllib.request.Request(f"{self.url}?since={int(since)}",
                                     headers={"X-Pax-Replica-Key": self.key,
                                              "User-Agent": "pax-dns-replica"})
        with self.opener(req) as r:
            return json.loads(r.read())

    def load_cache(self) -> Optional[dict]:
        if not self.cache_path:
            return None
        try:
            with open(self.cache_path) as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def save_cache(self, snapshot: dict) -> None:
        if not self.cache_path:
            return
        tmp = self.cache_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(snapshot, fh)
        os.replace(tmp, self.cache_path)


# ------------------------------------------------------------- service
class DohService:
    """The forwarder (Mac engine), the lists, the per-user policies and the
    background loops. `answer()` is thread-safe and blocking (call it from a
    worker thread)."""

    def __init__(self, feed, state_dir: str, role: str = "all", forwarder=None,
                 filter_store=None, rate: float = 25.0, burst: float = 400.0,
                 poll_seconds: float = 3.0, full_sync_seconds: float = 600.0,
                 clock: Callable[[], float] = time.time):
        self.role = role
        self.feed = feed
        self.state_dir = Path(state_dir)
        self.clock = clock
        self.policies = Policies(clock=clock)
        self.forwarder = forwarder or self._default_forwarder()
        self.filter_store = filter_store
        self.limiter = RateLimiter(rate, burst)
        self.poll_seconds = poll_seconds
        self.full_sync_seconds = full_sync_seconds
        self.seq = 0
        self.last_sync: Optional[float] = None
        self.last_full: float = 0.0
        self.sync_failures = 0
        self.lists_error: Optional[str] = None
        self.last_pack_report: Optional[dict] = None
        self._stop = threading.Event()
        self._threads: list = []
        self.stats = {"queries": 0, "rate_limited": 0, "bad": 0}

    @staticmethod
    def _default_forwarder():
        ups = dnsf.default_upstreams(timeout=2.5)
        return dnsf.Forwarder(ups, filters=None, log=lambda m: log.warning(m),
                              youtube_upstreams=dnsf.youtube_upstreams(ups, timeout=2.5),
                              cache_size=50_000, primary_upstreams=dnsf.primary_upstreams(timeout=2.5))

    # ------------------------------------------------------------ lists
    def load_lists(self) -> None:
        if self.filter_store is None:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            self.filter_store = fl.FilterStore(self.state_dir, plugin_dirs=[],
                                               log=lambda m: log.warning(m))
        try:
            self.forwarder.set_filters(self.filter_store.load())
            self.lists_error = None
        except Exception as exc:  # noqa: BLE001 - keep answering SERVFAIL, never open
            self.lists_error = f"{type(exc).__name__}: {exc}"[:200]
            log.error("PAX-DNS-006 filter lists failed to load: %s", self.lists_error)

    def update_lists(self) -> None:
        """v0.8.19: the signed filter pack, every ~6 hours (same checks as the Mac):
        the canary runs on the new lists before the swap, and a swapped-in pack that
        then fails the canary is rolled back at once and never taken again."""
        if self.filter_store is None:
            return
        def fetch(url):
            req = urllib.request.Request(url, headers={"User-Agent": "pax-server"})
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read(fl.MAX_DOWNLOAD + 1)
        try:
            report = self.filter_store.update(fetch, canary=dnsf.check_filterset)
        except Exception as exc:  # noqa: BLE001 - the lists in use stay
            log.warning("filter pack update skipped: %s", type(exc).__name__)
            return
        self.last_pack_report = {k: report.get(k) for k in ("version", "changed", "error", "ok", "checked_at")}
        if report.get("taken") and not report.get("changed"):
            self.forwarder.set_filters(self.filter_store.load())     # same lists, newer version
            log.warning("filter pack %s taken (no list changes)", report.get("version"))
            return
        if not report.get("changed"):
            if report.get("error"):
                log.warning("filter pack %s not taken: %s", report.get("version"), str(report["error"])[:200])
            return
        self.forwarder.set_filters(self.filter_store.load())
        result = dict(self.forwarder.last_canary or {})
        if not self.forwarder.primary_upstreams:
            fails = dnsf.check_filterset(self.forwarder.filters)
            result = {"ok": not fails, "failures": fails}
        if result.get("ok", True):
            log.warning("filter pack %s applied (%s)", report.get("version"), ", ".join(report["changed"]))
            return
        why = "; ".join(result.get("failures") or [])[:160] or "canary failed"
        self.filter_store.rollback_pack(why)
        self.forwarder.set_filters(self.filter_store.load())
        log.error("PAX-DNS-005 filter pack %s failed the canary after the swap (%s); rolled back",
                  report.get("version"), why)

    def _pack_status(self) -> Optional[dict]:
        if self.filter_store is None:
            return None
        try:
            return self.filter_store.pack_status()
        except Exception:  # noqa: BLE001 - informational
            return None

    # ------------------------------------------------------------- sync
    def sync_once(self) -> None:
        now = time.monotonic()
        since = self.seq
        if now - self.last_full >= self.full_sync_seconds:
            since = 0
        feed = self.feed.fetch(since)
        if since == 0:
            feed = dict(feed, full=True)
            self.last_full = now
        self.policies.apply(feed)
        self.seq = int(feed.get("seq", self.seq) or 0)
        self.last_sync = self.clock()
        if isinstance(self.feed, ReplicaFeed) and (feed.get("accounts") or since == 0):
            try:
                self.feed.save_cache(dict(self.policies.snapshot(), seq=self.seq))
            except OSError as exc:
                log.warning("replica cache not saved: %s", exc)

    def restore_cache(self) -> None:
        if isinstance(self.feed, ReplicaFeed):
            snap = self.feed.load_cache()
            if snap:
                self.policies.apply(dict(snap, full=True))
                log.info("restored %d accounts from the replica cache", len(self.policies))

    def _loop(self, fn, every: float, first_delay: float = 0.0) -> None:
        if self._stop.wait(first_delay):
            return
        while not self._stop.is_set():
            try:
                fn()
                if fn == self.sync_once:
                    self.sync_failures = 0
            except Exception as exc:  # noqa: BLE001 - keep the last good state
                if fn == self.sync_once:
                    self.sync_failures += 1
                    self.seq = 0
                    if self.sync_failures in (1, 10, 100, 1000):
                        log.warning("DNS list sync failed (%d in a row): %s", self.sync_failures,
                                    type(exc).__name__)
                else:
                    log.warning("%s failed: %s", getattr(fn, "__name__", "task"), type(exc).__name__)
            if self._stop.wait(every):
                return

    def start(self) -> None:
        self.restore_cache()
        def boot():
            self.load_lists()
        jobs = [
            (boot, 10 ** 9, 0.0),
            (self.sync_once, self.poll_seconds, 0.0),
            (self.forwarder.health_check, 60.0, 5.0),
            # v0.8.19: filter packs every 6 hours (first check 1-5 minutes after start)
            (self.update_lists, fl.UPDATE_INTERVAL, 60.0 + random.random() * 240.0),
        ]
        for fn, every, delay in jobs:
            t = threading.Thread(target=self._loop, args=(fn, every, delay), daemon=True,
                                 name=f"pax-doh-{getattr(fn, '__name__', 'job')}")
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()

    # ----------------------------------------------------------- answer
    def answer(self, wire: bytes, token: Optional[str], client: str) -> tuple[int, bytes, dict]:
        """(HTTP status, body, headers)."""
        if not self.limiter.allow(client):
            self.stats["rate_limited"] += 1
            return 429, b"slow down", {"Retry-After": "2", "Content-Type": "text/plain"}
        if not wire or len(wire) < 12 or len(wire) > MAX_MESSAGE:
            self.stats["bad"] += 1
            return 400, b"bad DNS message", {"Content-Type": "text/plain"}
        self.stats["queries"] += 1
        policy = self.policies.lookup(token)
        try:
            resp = self.forwarder.handle(wire, policy)
        except Exception:  # noqa: BLE001 - fail closed
            resp = None
            try:
                resp = dnsf.make_servfail(dnsf.Query(wire))
            except Exception:  # noqa: BLE001
                pass
        if resp is None:
            self.stats["bad"] += 1
            return 400, b"bad DNS message", {"Content-Type": "text/plain"}
        ttl = dnsf.cache_ttl(resp)
        return 200, resp, {"Content-Type": DOH_CT, "Cache-Control": f"max-age={max(0, min(ttl, 300))}"}

    def lists_restricted(self, domain: str) -> Optional[bool]:
        """v0.8.18, for the exception check: True when Pax's restricted lists or
        name rules block `domain` (or a parent), False when they don't, None when
        Pax's own filter can't answer (lists not loaded, or in its fallback)."""
        fwd = self.forwarder
        fs = fwd.filters
        if fs is None or not fwd.pax_filter_ok:
            return None
        d = domain.strip(".").lower()
        return bool(not fs.allowed(d) and fs.restricted_by(d))

    def status(self) -> dict:
        fs = self.forwarder.filters
        st = self.forwarder.status()
        return {
            "role": self.role,
            "ready": bool(self.forwarder.ready),
            "lists_error": self.lists_error,
            "list_entries": (fs.entries if fs is not None else 0),
            "lists_version": (fs.info.get("version") if fs is not None else None),
            "upstream": st.get("active"),
            "all_upstreams_down": st.get("all_down"),
            # v0.8.18: "pax" | "fallback" (Pax's filter failed a check) | "family"
            "filter_mode": st.get("filter_mode"),
            "fallback_reason": st.get("fallback_reason"),
            "canary": st.get("canary"),
            "filter_pack": self._pack_status(),             # v0.8.19
            "accounts": len(self.policies),
            "last_sync_age_seconds": (None if self.last_sync is None
                                      else round(self.clock() - self.last_sync, 1)),
            "sync_failures": self.sync_failures,
        }


def wire_from_request(method: str, query_dns: Optional[str], content_type: str,
                      body: Optional[bytes]) -> bytes:
    if method == "GET":
        return b64url_decode(query_dns or "")
    if content_type.split(";")[0].strip().lower() != DOH_CT:
        raise BadQuery(f"Content-Type must be {DOH_CT}")
    if body is None or len(body) > MAX_MESSAGE:
        raise BadQuery("DNS message too large")
    return body
