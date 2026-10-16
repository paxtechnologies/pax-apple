# SPDX-License-Identifier: GPL-3.0-only
"""Where pax-dns gets users' effective lists from, and the loop that keeps the
Store current (default every 2 s, so a newly blocked site applies within seconds).

  HttpSource    GET <server>/internal/v1/dns/changes?since=N  (X-Pax-Internal-Key)
  SqliteSource  reads the escrow server's SQLite file read-only (same host).
Both return the same feed shape:
  {"seq": int, "full": bool, "accounts": [{"account_id", "tokens": [{"hash",
   "retire_at"}], "block": [...], "allow": [...],
   "categories": {"remote_desktop": bool}}]}     (v0.5; missing = all on)
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

from .lists import CategoryList
from .policy import Store

log = logging.getLogger("pax.dns.sources")

# Must match pax_server/blocklist.py (a test checks it).
EFFECTIVE_BLOCK_SQL = """
SELECT e.domain FROM blocklist_entries e
WHERE e.account_id = :acct AND e.list = 'block'
  AND NOT EXISTS (SELECT 1 FROM blocklist_requests r
                  WHERE r.account_id = e.account_id AND r.action = 'unblock'
                    AND r.domain = e.domain AND r.status = 'pending'
                    AND r.effective_at <= :now)
"""
EFFECTIVE_ALLOW_SQL = """
SELECT domain FROM blocklist_entries WHERE account_id = :acct AND list = 'allow'
UNION
SELECT domain FROM blocklist_requests
WHERE account_id = :acct AND action = 'allow' AND status = 'pending' AND effective_at <= :now
"""
VALID_TOKENS_SQL = """
SELECT token_hash, retire_at FROM dns_tokens
WHERE account_id = :acct AND (retire_at IS NULL OR retire_at > :now)
"""
# v0.5: is the remote-desktop category on? Off only once a 'remote_desktop_off'
# request's wait has ended (or the server already applied it).
REMOTE_DESKTOP_SQL = """
SELECT CASE WHEN a.block_remote_desktop = 0 THEN 0
            WHEN EXISTS (SELECT 1 FROM blocklist_requests r
                         WHERE r.account_id = a.id AND r.action = 'remote_desktop_off'
                           AND r.status = 'pending' AND r.effective_at <= :now) THEN 0
            ELSE 1 END
FROM accounts a WHERE a.id = :acct
"""


def remote_desktop_on(conn, params: dict) -> bool:
    """Read REMOTE_DESKTOP_SQL; a database from before v0.5 has no column: on."""
    try:
        row = conn.execute(REMOTE_DESKTOP_SQL, params).fetchone()
    except sqlite3.OperationalError:
        return True
    return True if row is None else bool(row[0])


class HttpSource:
    def __init__(self, base_url: str, key: str, client: Optional[httpx.AsyncClient] = None):
        if not key:
            raise ValueError("PAX_INTERNAL_KEY is required for the HTTP source")
        self.url = base_url.rstrip("/") + "/internal/v1/dns/changes"
        self.key = key
        self.client = client or httpx.AsyncClient(timeout=10)

    async def fetch(self, since: int) -> dict:
        r = await self.client.get(self.url, params={"since": since},
                                  headers={"X-Pax-Internal-Key": self.key})
        r.raise_for_status()
        return r.json()


class SqliteSource:
    """Read-only view of the escrow DB. Computes effective lists from the
    timestamps, so changes whose wait has ended apply even if the server's
    sweeper hasn't run."""

    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        self.path = path
        self.clock = clock
        self._last_check: Optional[int] = None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def fetch_sync(self, since: int) -> dict:
        now = int(self.clock())
        conn = self._connect()
        try:
            seq = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM dns_changes").fetchone()[0]
            full = since <= 0 or self._last_check is None
            if full:
                ids = {r[0] for r in conn.execute("SELECT DISTINCT account_id FROM dns_tokens")}
            else:
                last = self._last_check
                ids = {r[0] for r in conn.execute(
                    "SELECT DISTINCT account_id FROM dns_changes WHERE seq > ?", (since,))}
                # Waits that ended since the last look (no seq bump needed).
                ids |= {r[0] for r in conn.execute(
                    "SELECT DISTINCT account_id FROM blocklist_requests WHERE status='pending' "
                    "AND effective_at > ? AND effective_at <= ?", (last, now))}
                ids |= {r[0] for r in conn.execute(
                    "SELECT DISTINCT account_id FROM dns_tokens WHERE retire_at > ? "
                    "AND retire_at <= ?", (last, now))}
            accounts = []
            for aid in sorted(ids):
                p = {"acct": aid, "now": now}
                accounts.append({
                    "account_id": aid,
                    "tokens": [{"hash": r[0], "retire_at": r[1]}
                               for r in conn.execute(VALID_TOKENS_SQL, p)],
                    "block": sorted(r[0] for r in conn.execute(EFFECTIVE_BLOCK_SQL, p)),
                    "allow": sorted(r[0] for r in conn.execute(EFFECTIVE_ALLOW_SQL, p)),
                    "categories": {"remote_desktop": remote_desktop_on(conn, p)},
                })
        finally:
            conn.close()
        self._last_check = now
        return {"seq": seq, "now": now, "full": full, "accounts": accounts}

    async def fetch(self, since: int) -> dict:
        return await asyncio.to_thread(self.fetch_sync, since)


def make_source(spec: str, internal_key: str = ""):
    if not spec:
        return None
    if spec.startswith("sqlite:///"):
        return SqliteSource(spec[len("sqlite:///"):])  # sqlite:////abs/path or sqlite:///rel
    if spec.startswith(("http://", "https://")):
        return HttpSource(spec, internal_key)
    raise ValueError(f"unknown PAX_DNS_SOURCE {spec!r} (use sqlite:///path or https://server)")


@dataclass
class Syncer:
    store: Store
    source: object = None
    category: CategoryList = field(default_factory=CategoryList)
    poll_seconds: float = 2.0
    # v0.5 built-in categories ({"bypass": ..., "remote_desktop": ...}).
    builtin: dict = field(default_factory=dict)
    seq: int = 0
    last_sync: Optional[float] = None
    failures: int = 0

    async def sync_once(self) -> None:
        if self.source is not None:
            feed = await self.source.fetch(self.seq)
            self.store.apply(feed)
            self.seq = feed.get("seq", self.seq)
            self.last_sync = time.time()
        try:
            self.category = self.category.reload_if_changed()
        except OSError:
            log.exception("category list reload failed; keeping the previous list")
        for name, cl in list(self.builtin.items()):
            try:
                self.builtin[name] = cl.reload_if_changed()
            except OSError:
                log.exception("%s list reload failed; keeping the previous list", name)

    async def run(self) -> None:
        while True:
            try:
                await self.sync_once()
                self.failures = 0
            except Exception:  # noqa: BLE001
                self.failures += 1
                # Keep serving the last good lists. Full resync after an error.
                if self.failures in (1, 10, 100):
                    log.exception("list sync failed (%d in a row)", self.failures)
                self.seq = 0
            await asyncio.sleep(self.poll_seconds)
