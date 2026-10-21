# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.24: private, aggregate-only usage numbers for whoever runs the server.

GET /v1/stats?key=<key>  (or header X-Pax-Stats-Key, or Authorization: Bearer)
answers totals only: how many accounts and devices there are, how many devices
were active, which app versions Macs run, how many DNS lookups were answered,
and one row of counts per day. It never returns an email, a name, an address,
a device ID, a token or a site. Without a valid key it answers 404, as if it
didn't exist.

Only keys whose SHA-256 is listed in STATS_KEY_SHA256 (or PAX_STATS_KEY_SHA256)
are accepted. Publishing the hash of a 256-bit random key reveals nothing about
the key; the key itself is kept by the operator and is never in the repo, the
server's environment or its logs (the access-log line for /v1/stats is dropped,
like DoH lines).

What "active" means. A device is active on a day (UTC) when, that day, it:
  * Mac: pax-guard synced blocked sites (/v1/sync) or fetched its settings
    (/v1/guard/config); or it was set up;
  * iPhone / iPad: its account's Pax DNS address answered a lookup on either
    Pax server, or it was set up. All of an account's iPhones and iPads share one
    DNS address, so the server can't tell them apart: when that address is used,
    each of the account's iPhones and iPads counts as active.
What is kept for this: one row per device with the platform, the last UTC day it
was active and (Macs on 0.8.24+) the app version it reported. No time of day,
no address, no lookup, no site. Plus one row of counts per UTC day.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

# The operator's key (Pax's own servers). The key is in the operator's keeper only;
# rotate by adding a new hash here, releasing, then removing the old one.
STATS_KEY_SHA256 = (
    "0696a33f05bfac3e00eb33e901339d1ccf0ee69048049d34ec93a855ceb14a38",
)

PLATFORMS = ("mac", "iphone", "ipad")
_PLATFORM = {"ios": "iphone", "ipados": "ipad", "mac": "mac", "macos": "mac"}
_VERSION_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEEP_ACTIVITY_DAYS = 35      # a device unseen this long drops out of the table
# v0.8.26: an iPhone/iPad is "not checking in" when its last day is this many UTC days
# back (so at least 48 hours with no Pax DNS traffic, at most 72).
QUIET_DAYS = 3
MAX_HISTORY_DAYS = 400
BACKFILL_DAYS = 90

SCHEMA = """
-- v0.8.24 aggregate usage numbers (pax_server/stats.py). No addresses, names,
-- times of day or sites: per device only the platform, the last UTC day it was
-- active and the app version it reported.
CREATE TABLE IF NOT EXISTS activity (
    subject      TEXT PRIMARY KEY,     -- 'device:<id>' | 'link:<id>' | 'dns-account:<id>'
    platform     TEXT NOT NULL,        -- 'mac' | 'iphone' | 'ipad' | 'account'
    last_day     TEXT NOT NULL,        -- 'YYYY-MM-DD' (UTC)
    app_version  TEXT
);
CREATE TABLE IF NOT EXISTS stats_daily (
    day            TEXT PRIMARY KEY,   -- 'YYYY-MM-DD' (UTC)
    accounts_total INTEGER,
    accounts_new   INTEGER,
    devices_total  INTEGER,
    devices_mac    INTEGER,
    devices_iphone INTEGER,
    devices_ipad   INTEGER,
    active         INTEGER NOT NULL DEFAULT 0,
    active_mac     INTEGER NOT NULL DEFAULT 0,
    active_iphone  INTEGER NOT NULL DEFAULT 0,
    active_ipad    INTEGER NOT NULL DEFAULT 0,
    dns_accounts   INTEGER NOT NULL DEFAULT 0,
    doh_queries    INTEGER NOT NULL DEFAULT 0,
    backfilled     INTEGER NOT NULL DEFAULT 0,   -- totals rebuilt from dates; no activity known
    updated_at     INTEGER
);
"""


def key_allowed(key: Optional[str], extra: Iterable[str] = ()) -> bool:
    if not key or len(key) < 32 or len(key) > 256:
        return False
    digest = hashlib.sha256(key.strip().encode()).hexdigest()
    ok = False
    for h in tuple(STATS_KEY_SHA256) + tuple(extra):
        ok |= hmac.compare_digest(digest, str(h).strip().lower())
    return ok


def utc_day(ts: float) -> str:
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d")


def _day_start(day: str) -> int:
    return int(datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp())


def _shift(day: str, n: int) -> str:
    return (datetime.strptime(day, "%Y-%m-%d") + timedelta(days=n)).strftime("%Y-%m-%d")


def platform_of(raw: str) -> str:
    return _PLATFORM.get((raw or "").lower(), "mac" if (raw or "").lower().startswith("mac") else "iphone")


class Stats:
    """Records activity (cheaply: one write per device per day) and answers the
    aggregate view. Thread-safe; `saw_dns` is called on the DoH hot path."""

    def __init__(self, db, clock, doh=None, role: str = "all", server: str = ""):
        self.db, self.clock, self.doh, self.role, self.server = db, clock, doh, role, server
        self._lock = threading.Lock()
        self._seen: dict = {}            # subject -> (day, version): skip repeat writes
        self._dns_pending: set = set()   # token hashes not yet resolved today
        self._dns_day: dict = {}         # token hash -> last day resolved
        self._doh_counted = 0            # this server's queries already added to a day
        self._last_flush = 0.0
        self._last_snapshot = 0.0
        self.started_at = int(self.clock.now())
        self.replicas: dict = {}         # server label -> {"since_restart", "started_at", "reported_at"}
        if db is not None:
            db._conn.executescript(SCHEMA)
            self._backfill()

    # ------------------------------------------------------------ recording
    def mark(self, subject: str, platform: str, version: Optional[str] = None) -> None:
        """`subject` is an internal ID (never shown); `platform` mac|iphone|ipad|account."""
        if self.db is None:
            return
        day = utc_day(self.clock.now())
        if version is not None and not _VERSION_RE.match(version.strip()):
            version = None
        version = version.strip() if version else None
        with self._lock:
            if self._seen.get(subject) == (day, version):
                return
            if len(self._seen) > 200_000:
                self._seen.clear()
            self._seen[subject] = (day, version)
        with self.db.transaction() as db:
            row = db.one("SELECT last_day, app_version FROM activity WHERE subject=?", (subject,))
            if row is None:
                db.execute("INSERT INTO activity(subject, platform, last_day, app_version) VALUES(?,?,?,?)",
                           (subject, platform, day, version))
                new_day = True
            else:
                new_day = row["last_day"] != day
                db.execute("UPDATE activity SET last_day=?, platform=?, app_version=COALESCE(?, app_version) "
                           "WHERE subject=?", (day, platform, version, subject))
            if new_day:
                self._ensure_day(db, day)
                if platform == "account":
                    db.execute("UPDATE stats_daily SET dns_accounts=dns_accounts+1 WHERE day=?", (day,))
                elif platform in PLATFORMS:
                    db.execute(f"UPDATE stats_daily SET active=active+1, active_{platform}=active_{platform}+1 "
                               "WHERE day=?", (day,))

    def forget(self, subjects=(), token_hashes=()) -> None:
        """v0.8.30: a deleted account's in-memory "already marked today" entries."""
        with self._lock:
            for sub in subjects:
                self._seen.pop(sub, None)
            for h in token_hashes:
                self._dns_day.pop(h, None)
                self._dns_pending.discard(h)

    def mark_device(self, device_row, version: Optional[str] = None) -> None:
        if device_row is not None:
            self.mark(f"device:{device_row['id']}", platform_of(device_row["platform"]), version)

    def mark_link(self, link_row, version: Optional[str] = None) -> None:
        if link_row is not None:
            self.mark(f"link:{link_row['id']}", "mac", version)

    def saw_dns(self, token_hash: str) -> None:
        """DoH hot path: remember the account's DNS address was used (resolved later)."""
        day = utc_day(self.clock.now())
        if self._dns_day.get(token_hash) == day:
            return
        with self._lock:
            if len(self._dns_pending) < 100_000:
                self._dns_pending.add(token_hash)
            if len(self._dns_day) > 200_000:
                self._dns_day.clear()
            self._dns_day[token_hash] = day

    def take_dns_pending(self) -> list:
        with self._lock:
            out = sorted(self._dns_pending)
            self._dns_pending.clear()
        return out

    def dns_hashes(self, hashes: Iterable[str]) -> int:
        """Primary: mark the iPhones/iPads (and the account) behind used DNS addresses."""
        if self.db is None:
            return 0
        n = 0
        for h in hashes:
            h = str(h).strip().lower()
            if not _HEX64.match(h):
                continue
            t = self.db.one("SELECT account_id FROM dns_tokens WHERE token_hash=?", (h,))
            if not t:
                continue
            n += 1
            self.mark(f"dns-account:{t['account_id']}", "account")
            for d in self.db.all("SELECT id, platform FROM devices WHERE account_id=? AND released_at IS NULL "
                                 "AND platform IN ('ios','ipados')", (t["account_id"],)):
                self.mark_device(d)
        return n

    def device_seen(self, device_row, account_id: str) -> dict:
        """v0.8.26, for the owner's own Mac only (GET /v1/devices): an iPhone's or iPad's
        last UTC day of Pax DNS traffic and whether it is still checking in. All of an
        account's iPhones and iPads share one DNS address, so this is "some phone on the
        account used it": a quiet phone shows only when all of them are quiet. checking_in
        is None (unknown) unless the account's address has been used since this was kept
        (a phone set up with another filter never looks quiet). No time of day, address
        or lookup is kept or returned."""
        out = {"last_seen": None, "checking_in": None}
        if (self.db is None or device_row["released_at"] is not None
                or platform_of(device_row["platform"]) not in ("iphone", "ipad")):
            return out
        row = self.db.one("SELECT last_day FROM activity WHERE subject=?", (f"device:{device_row['id']}",))
        if row is None:
            return out
        out["last_seen"] = row["last_day"]
        if self.db.one("SELECT 1 FROM activity WHERE subject=?", (f"dns-account:{account_id}",)) is None:
            return out
        today = datetime.strptime(utc_day(self.clock.now()), "%Y-%m-%d")
        gap = (today - datetime.strptime(row["last_day"], "%Y-%m-%d")).days
        out["checking_in"] = gap < QUIET_DAYS
        return out

    def add_queries(self, n: int) -> None:
        if self.db is None or n <= 0:
            return
        day = utc_day(self.clock.now())
        with self.db.transaction() as db:
            self._ensure_day(db, day)
            db.execute("UPDATE stats_daily SET doh_queries=doh_queries+? WHERE day=?", (int(n), day))

    def replica_report(self, server: str, hashes: list, delta: int, since_restart: int,
                       started_at: Optional[int]) -> dict:
        """Primary: a DoH-only server's report (used DNS addresses + lookup counts)."""
        resolved = self.dns_hashes(hashes[:100_000])
        self.add_queries(max(0, min(int(delta or 0), 10**9)))
        label = re.sub(r"[^a-z0-9.-]", "", (server or "replica").lower())[:40] or "replica"
        self.replicas[label] = {"since_restart": int(since_restart or 0), "started_at": started_at,
                                "reported_at": int(self.clock.now())}
        return {"ok": True, "resolved": resolved}

    def tick(self, force: bool = False) -> None:
        """From the server's sweep: resolve DNS use every minute, totals every 10."""
        now = time.monotonic()
        if force or now - self._last_flush >= 60:
            self._last_flush = now
            self.dns_hashes(self.take_dns_pending())
            q = self.doh_queries_since_restart()
            if q is not None and q > self._doh_counted:
                self.add_queries(q - self._doh_counted)
                self._doh_counted = q
        if force or now - self._last_snapshot >= 600:
            self._last_snapshot = now
            self.snapshot()

    def doh_queries_since_restart(self) -> Optional[int]:
        if self.doh is None:
            return None
        try:
            return int(self.doh.stats.get("queries", 0))
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------ totals
    def _ensure_day(self, db, day: str) -> None:
        db.execute("INSERT OR IGNORE INTO stats_daily(day, updated_at) VALUES(?, ?)",
                   (day, int(self.clock.now())))

    def totals_at(self, ts: int) -> dict:
        """Counts as of time `ts` (end of a day for history, now for today)."""
        db = self.db
        acc = db.one("SELECT COUNT(*) FROM accounts WHERE created_at <= ?", (ts,))[0]
        by = {p: 0 for p in PLATFORMS}
        for r in db.all("SELECT platform, COUNT(*) AS n FROM devices WHERE installed_at <= ? "
                        "AND (released_at IS NULL OR released_at > ?) GROUP BY platform", (ts, ts)):
            p = platform_of(r["platform"])
            by[p] = by.get(p, 0) + r["n"]
        links = db.one("SELECT COUNT(*) FROM sync_links WHERE created_at <= ? "
                       "AND (revoked_at IS NULL OR revoked_at > ?)", (ts, ts))[0]
        by["mac"] += links
        return {"accounts_total": acc, "devices_total": sum(by.values()), "by_platform": by}

    def snapshot(self) -> None:
        if self.db is None:
            return
        now = int(self.clock.now())
        day = utc_day(now)
        t = self.totals_at(now)
        new = self.db.one("SELECT COUNT(*) FROM accounts WHERE created_at >= ? AND created_at <= ?",
                          (_day_start(day), now))[0]
        with self.db.transaction() as db:
            self._ensure_day(db, day)
            db.execute("UPDATE stats_daily SET accounts_total=?, accounts_new=?, devices_total=?, devices_mac=?, "
                       "devices_iphone=?, devices_ipad=?, backfilled=0, updated_at=? WHERE day=?",
                       (t["accounts_total"], new, t["devices_total"], t["by_platform"]["mac"],
                        t["by_platform"]["iphone"], t["by_platform"]["ipad"], now, day))
            # Keep the table small: a device unseen for KEEP_ACTIVITY_DAYS is dropped.
            # v0.8.26: except an unreleased iPhone/iPad and its account's DNS row, so the
            # owner's "Not checking in · last seen" stays true for a phone gone quiet long ago.
            db.execute("DELETE FROM activity WHERE last_day < ? AND subject NOT IN ("
                       "SELECT 'device:' || id FROM devices WHERE released_at IS NULL "
                       "AND platform IN ('ios','ipados') UNION "
                       "SELECT 'dns-account:' || account_id FROM devices WHERE released_at IS NULL "
                       "AND platform IN ('ios','ipados'))", (_shift(day, -KEEP_ACTIVITY_DAYS),))

    def _backfill(self) -> None:
        """Once, on a database with no history: rebuild each past day's totals from
        the creation and release dates already stored (no activity: it wasn't kept)."""
        if self.db.one("SELECT COUNT(*) FROM stats_daily")[0]:
            return
        first = self.db.one("SELECT MIN(created_at) FROM accounts")[0]
        if first is None:
            return
        today = utc_day(self.clock.now())
        day = max(utc_day(first), _shift(today, -BACKFILL_DAYS))
        rows = []
        while day < today:
            end = _day_start(_shift(day, 1)) - 1
            t = self.totals_at(end)
            new = self.db.one("SELECT COUNT(*) FROM accounts WHERE created_at BETWEEN ? AND ?",
                              (_day_start(day), end))[0]
            rows.append((day, t["accounts_total"], new, t["devices_total"], t["by_platform"]["mac"],
                         t["by_platform"]["iphone"], t["by_platform"]["ipad"], int(self.clock.now())))
            day = _shift(day, 1)
        with self.db.transaction() as db:
            for r in rows:
                db.execute("INSERT OR IGNORE INTO stats_daily(day, accounts_total, accounts_new, devices_total, "
                           "devices_mac, devices_iphone, devices_ipad, backfilled, updated_at) "
                           "VALUES(?,?,?,?,?,?,?,1,?)", r)

    # ------------------------------------------------------------ the view
    def _active(self, since_day: str) -> dict:
        out = {p: 0 for p in PLATFORMS}
        for r in self.db.all("SELECT platform, COUNT(*) AS n FROM activity WHERE last_day >= ? "
                             "AND platform IN ('mac','iphone','ipad') GROUP BY platform", (since_day,)):
            out[r["platform"]] = r["n"]
        out["total"] = sum(out[p] for p in PLATFORMS)
        return out

    def history(self, days: int) -> list:
        days = max(0, min(int(days), MAX_HISTORY_DAYS))
        if days == 0:
            return []
        today = utc_day(self.clock.now())
        rows = self.db.all("SELECT * FROM stats_daily WHERE day >= ? ORDER BY day", (_shift(today, -(days - 1)),))
        out = []
        for r in rows:
            back = bool(r["backfilled"])
            act = None if back else {"total": r["active"], "mac": r["active_mac"],
                                     "iphone": r["active_iphone"], "ipad": r["active_ipad"]}
            out.append({
                "day": r["day"], "complete": r["day"] < today,
                "accounts_total": r["accounts_total"], "accounts_new": r["accounts_new"],
                "devices_total": r["devices_total"],
                "devices_by_platform": {"mac": r["devices_mac"], "iphone": r["devices_iphone"],
                                        "ipad": r["devices_ipad"]},
                "active_devices": act,
                "accounts_using_pax_dns": None if back else r["dns_accounts"],
                "doh_queries": None if back else r["doh_queries"],
                "rebuilt_from_dates": back,
            })
        return out

    def view(self, days: int = 7, version: str = "") -> dict:
        now = int(self.clock.now())
        gen = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if self.db is None:     # role "dns": no accounts here
            return {
                "generated_at": gen, "timezone": "UTC", "server": self.server, "role": self.role,
                "version": version, "authoritative": False,
                "note": "This server only answers DNS. Accounts, devices and history live on the primary "
                        "(api.paxpeace.com), which this server reports its DNS use to every few minutes.",
                "doh_queries": {"this_server_since_restart": self.doh_queries_since_restart(),
                                "this_server_started_at": _iso(self.started_at)},
            }
        self.tick(force=True)
        today = utc_day(now)
        t = self.totals_at(now)
        new_today = self.db.one("SELECT COUNT(*) FROM accounts WHERE created_at >= ?", (_day_start(today),))[0]
        new_7 = self.db.one("SELECT COUNT(*) FROM accounts WHERE created_at >= ?",
                            (_day_start(_shift(today, -6)),))[0]
        versions: dict = {}
        for r in self.db.all("SELECT COALESCE(app_version, 'unknown') AS v, COUNT(*) AS n FROM activity "
                             "WHERE platform='mac' AND last_day >= ? GROUP BY v", (_shift(today, -6),)):
            versions[r["v"]] = r["n"]
        dns_acc = lambda since: self.db.one(  # noqa: E731
            "SELECT COUNT(*) FROM activity WHERE platform='account' AND last_day >= ?", (since,))[0]
        row = self.db.one("SELECT doh_queries FROM stats_daily WHERE day=?", (today,))
        return {
            "generated_at": gen,
            "timezone": "UTC: 'today' and each history day run midnight to midnight UTC "
                        "(01:00 to 01:00 in London during British Summer Time)",
            "server": self.server, "role": self.role, "version": version, "authoritative": True,
            "accounts": {"total": t["accounts_total"], "new_today": new_today, "new_last_7_days": new_7},
            "devices": {
                "total": t["devices_total"], "by_platform": t["by_platform"],
                "note": "iPhones/iPads set up through Pax and not released, plus Macs linked to an account "
                        "(they sync blocked sites, on by default). A Mac that keeps its key to itself and "
                        "never syncs is invisible to the server.",
            },
            "active_devices": {
                "today": self._active(today),
                "today_or_yesterday": self._active(_shift(today, -1)),
                "last_7_days": self._active(_shift(today, -6)),
                "definition": "Active on a UTC day = a Mac synced blocked sites or fetched its settings, or an "
                              "iPhone/iPad's account DNS address answered a lookup (on either server), or the "
                              "device was set up that day. An account's iPhones and iPads share one DNS address, "
                              "so each of them counts when it is used. Only the last active day is kept, so "
                              "'today_or_yesterday' covers the last 24 hours and up to 48.",
                "since": "0.8.24 (activity before that wasn't recorded)",
            },
            "accounts_using_pax_dns": {"today": dns_acc(today), "last_7_days": dns_acc(_shift(today, -6))},
            "mac_app_versions": {
                "counts": dict(sorted(versions.items())),
                "window": "Macs active in the last 7 days. Macs report their version from 0.8.24; "
                          "older ones show as 'unknown'.",
            },
            "doh_queries": {
                "today_all_servers": row["doh_queries"] if row else 0,
                "this_server_since_restart": self.doh_queries_since_restart(),
                "this_server_started_at": _iso(self.started_at),
                "other_servers": {k: {"since_restart": v["since_restart"],
                                      "started_at": _iso(v["started_at"]) if v.get("started_at") else None,
                                      "reported_at": _iso(v["reported_at"])}
                                  for k, v in sorted(self.replicas.items())},
                "note": "Counts only, never names. 'today_all_servers' counts from 0.8.24's start; the "
                        "second server reports every few minutes.",
            },
            "history": self.history(days),
        }


def _iso(ts) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------ HTML
def render_html(v: dict) -> str:
    e = lambda x: html.escape("—" if x is None else str(x))  # noqa: E731
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<meta name='robots' content='noindex'><meta name='referrer' content='no-referrer'>",
        "<title>Pax · usage</title><style>",
        "body{font:15px/1.5 Georgia,serif;color:#1f2a24;background:#f7f5ef;margin:0;padding:24px;}",
        "main{max-width:820px;margin:auto}h1{font-weight:normal}h2{font-weight:normal;margin-top:28px}",
        "table{border-collapse:collapse;width:100%;background:#fff}td,th{padding:6px 10px;border-bottom:1px solid #e6e2d6;",
        "text-align:right}td:first-child,th:first-child{text-align:left}.m{color:#6b746e;font-size:13px}",
        "</style></head><body><main><h1>pax. usage</h1>",
        f"<p class='m'>Generated {e(v.get('generated_at'))} · {e(v.get('server'))} · version {e(v.get('version'))}"
        f" · {'authoritative' if v.get('authoritative') else 'DNS-only server'}</p>",
    ]
    if not v.get("authoritative"):
        dq = v.get("doh_queries") or {}
        parts.append(f"<p>{e(v.get('note'))}</p><p>DNS lookups since restart: {e(dq.get('this_server_since_restart'))}"
                     f" (since {e(dq.get('this_server_started_at'))})</p></main></body></html>")
        return "".join(parts)
    a, d, act = v["accounts"], v["devices"], v["active_devices"]
    bp = d["by_platform"]

    def row(label, *cells):
        return "<tr><td>" + e(label) + "</td>" + "".join(f"<td>{e(c)}</td>" for c in cells) + "</tr>"
    parts += [
        "<p class='m'>" + e(v["timezone"]) + "</p>",
        "<h2>Accounts</h2><table>", row("Total", a["total"]), row("New today", a["new_today"]),
        row("New in the last 7 days", a["new_last_7_days"]), "</table>",
        "<h2>Devices</h2><table><tr><th></th><th>Total</th><th>Mac</th><th>iPhone</th><th>iPad</th></tr>",
        row("Set up", d["total"], bp["mac"], bp["iphone"], bp["ipad"]),
    ]
    for key, label in (("today", "Active today"), ("today_or_yesterday", "Active today or yesterday"),
                       ("last_7_days", "Active in the last 7 days")):
        x = act[key]
        parts.append(row(label, x["total"], x["mac"], x["iphone"], x["ipad"]))
    parts += ["</table>", f"<p class='m'>{e(d['note'])}</p>", f"<p class='m'>{e(act['definition'])}</p>",
              "<h2>Mac app versions</h2><table>"]
    for ver, n in v["mac_app_versions"]["counts"].items():
        parts.append(row(ver, n))
    if not v["mac_app_versions"]["counts"]:
        parts.append(row("None yet", ""))
    dq = v["doh_queries"]
    parts += ["</table>", f"<p class='m'>{e(v['mac_app_versions']['window'])}</p>",
              "<h2>Pax DNS</h2><table>",
              row("Accounts using it today", v["accounts_using_pax_dns"]["today"]),
              row("Accounts using it, last 7 days", v["accounts_using_pax_dns"]["last_7_days"]),
              row("Lookups today, both servers", dq["today_all_servers"]),
              row(f"Lookups on this server since {dq['this_server_started_at']}", dq["this_server_since_restart"])]
    for k, o in dq["other_servers"].items():
        parts.append(row(f"Lookups on {k} since {o['started_at']} (reported {o['reported_at']})", o["since_restart"]))
    parts += ["</table>", "<h2>By day (UTC)</h2><table><tr><th>Day</th><th>Accounts</th><th>New</th>"
              "<th>Devices</th><th>Active</th><th>DNS lookups</th></tr>"]
    for h in reversed(v.get("history") or []):
        act_n = h["active_devices"]["total"] if h["active_devices"] else None
        label = h["day"] + ("" if h["complete"] else " (so far)")
        parts.append(row(label, h["accounts_total"], h["accounts_new"], h["devices_total"], act_n, h["doh_queries"]))
    parts.append("</table><p class='m'>Days before 0.8.24 are rebuilt from sign-up and set-up dates, so they "
                 "have no activity (—). Add ?days=90 for more.</p></main></body></html>")
    return "".join(parts)


# ------------------------------------------------------------ DoH-only server
class ReplicaReporter:
    """Role "dns": every few minutes tell the primary which DNS addresses were used
    (token hashes, which the primary already sends this server) and how many
    lookups were answered. Nothing else: no names, no client addresses."""

    def __init__(self, primary_url: str, key: str, stats: Stats, server: str = "dns2",
                 every: float = 300.0, opener=None, timeout: float = 15.0):
        import urllib.request
        self.url = primary_url.rstrip("/") + "/v1/replica/activity"
        self.key, self.stats, self.server, self.every = key, stats, server, every
        self.opener = opener or (lambda req: urllib.request.urlopen(req, timeout=timeout))
        self._unsent: set = set()
        self._sent_queries = 0
        self._stop = threading.Event()
        self.last_ok: Optional[int] = None

    def report_once(self) -> bool:
        import json
        import urllib.request
        self._unsent.update(self.stats.take_dns_pending())
        total = self.stats.doh_queries_since_restart() or 0
        body = {"server": self.server, "token_hashes": sorted(self._unsent)[:100_000],
                "queries": max(0, total - self._sent_queries), "since_restart": total,
                "started_at": self.stats.started_at}
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "X-Pax-Replica-Key": self.key,
                                              "User-Agent": "pax-dns-replica"})
        try:
            with self.opener(req) as r:
                r.read()
        except Exception:  # noqa: BLE001 - keep what wasn't sent, try again later
            if len(self._unsent) > 100_000:
                self._unsent.clear()
            return False
        self._unsent.clear()
        self._sent_queries = total
        self.last_ok = int(time.time())
        return True

    def _loop(self) -> None:
        while not self._stop.wait(self.every):
            self.report_once()

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True, name="pax-stats-report").start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.report_once()
        except Exception:  # noqa: BLE001
            pass
