# SPDX-License-Identifier: GPL-3.0-only
"""Custom blocklist and allow-list, synced to every device through pax-dns.

Rules (README "Blocked sites"):
  * Adding a site to the blocklist takes effect immediately (more protection is
    never delayed). It also drops an allow-list exception for the same domain and
    cancels a pending removal of it.
  * Removing a site, adding an allow-list exception (to reach something the Family
    Filter blocks) and rotating the DNS token are *requests*: they take effect
    after the delay (v0.8.9 `delay()`: the user's own wait by default), can be cancelled meanwhile, and
    the accountability partner is emailed, like a removal request.
  * Removing an allow-list exception is immediate (more protection).
  * v0.8.1: no exception for a site Pax always blocks (restricted content,
    media converters, or anything CleanBrowsing Family blocks): the request is
    refused with 422 `restricted_site` (PAX-DNS-010) before any wait or email
    (restricted.py). A waiting request that became restricted is refused when
    its wait ends, and the effective allow-list never carries one.
  * v0.5 categories: "bypass" (cloud PCs, browser isolation, web proxies) is
    always on. "remote_desktop" is on by default; switching it OFF is a request
    ('remote_desktop_off') with the same wait, cancel and partner email;
    switching it back ON is immediate and cancels a pending request.
  * Every entry covers the domain and all its subdomains.
  * pax-dns reads the *effective* lists: entries, minus removals whose wait has
    ended, plus exceptions whose wait has ended. `apply_due` writes those changes
    into the entries table and bumps the change feed; the effective view does not
    depend on it having run, so a stopped sweeper never delays anything.
"""
from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from .crypto import hash_token
from .domains import DomainError, display_domain, normalise_domain
from . import restricted
from .escrow import (Conflict, Escrow, EscrowError, MediaAlwaysBlocked, NotFound, Restricted,
                     fmt_duration)

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")


def new_dns_token() -> str:
    # URL-path safe, 192 bits. No prefix: it travels inside a DoH URL.
    return secrets.token_urlsafe(24)


class LimitReached(EscrowError):
    status, code = 422, "limit_reached"


def _id() -> str:
    return uuid.uuid4().hex


def doh_url(base: str, token: str) -> str:
    return f"{base.rstrip('/')}/u/{token}/dns-query"


# SQL for the effective lists at time :now. pax-dns's SQLite source uses the same
# statements (pax-dns/pax_dns/sources.py); a test checks they agree.
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
# v0.8.8: the account's DNS settings for Pax's own filter. YouTube Restricted
# Mode is instant both ways (project decision, 2026-10-16), like the Mac's switch.
# v0.8.13 (project decision): pictures and video on X and Bluesky are always
# blocked. They are still reported (always true) so older apps read them, but a
# request to turn either off is refused (422 media_always_blocked, PAX-DNS-016)
# before any request, wait or email. db.py forces old accounts back on and closes
# any waiting 'x_media_off' / 'bluesky_media_off' request.
ALWAYS_BLOCKED_MEDIA = ("x_media", "bluesky_media")
LEGACY_MEDIA_OFF_ACTIONS = ("x_media_off", "bluesky_media_off")
CATEGORIES = {
    "bypass": {"title": "Cloud PCs, remote browsers and web proxies",
               "can_turn_off": False},
    "remote_desktop": {"title": "Remote desktop and work virtual desktops",
                       "can_turn_off": True},
    # v0.8.18 (Advanced): after Pax's own filter, send lookups through a public
    # family filter too, instead of the malware-only resolver. Off by default; on is
    # immediate, off waits like a removal (it loosens the filter).
    "family_layer": {"title": "Extra family filter (Advanced)",
                     "can_turn_off": True},
}
# v0.8.18: the extra family layer, on until a 'family_layer_off' request's wait ends.
FAMILY_LAYER_SQL = """
SELECT CASE WHEN a.dns_family_layer = 0 THEN 0
            WHEN EXISTS (SELECT 1 FROM blocklist_requests r
                         WHERE r.account_id = a.id AND r.action = 'family_layer_off'
                           AND r.status = 'pending' AND r.effective_at <= :now) THEN 0
            ELSE 1 END
FROM accounts a WHERE a.id = :acct
"""
CATEGORY_OFF = {"remote_desktop": ("remote_desktop_off", "block_remote_desktop"),
                "family_layer": ("family_layer_off", "dns_family_layer")}


@dataclass
class Blocklist:
    escrow: Escrow
    # v0.8.18: Pax's own lists for the exception check (DohService.lists_restricted);
    # None = no in-process resolver, so the outside lookup decides as before.
    lists_check: Optional[Callable[[str], Optional[bool]]] = None

    @property
    def db(self):
        return self.escrow.db

    @property
    def settings(self):
        return self.escrow.settings

    def now(self) -> int:
        return self.escrow.clock.now()

    # ------------------------------------------------------------------ utils
    def _domain(self, raw: str) -> str:
        try:
            return normalise_domain(raw)
        except DomainError as exc:
            raise EscrowError(str(exc), field="domain") from None

    def _changed(self, account_id: str) -> None:
        self.db.execute("INSERT INTO dns_changes(account_id, at) VALUES (?,?)",
                        (account_id, self.now()))

    def _pending(self, account_id: str, action: str, domain: Optional[str]):
        if domain is None:
            return self.db.one(
                "SELECT * FROM blocklist_requests WHERE account_id=? AND action=? "
                "AND domain IS NULL AND status='pending'", (account_id, action))
        return self.db.one(
            "SELECT * FROM blocklist_requests WHERE account_id=? AND action=? AND domain=? "
            "AND status='pending'", (account_id, action, domain))

    def _entry(self, account_id: str, list_: str, domain: str):
        return self.db.one(
            "SELECT * FROM blocklist_entries WHERE account_id=? AND list=? AND domain=?",
            (account_id, list_, domain))

    def _request_view(self, r) -> dict:
        now = self.now()
        return {
            "request_id": r["id"],
            "action": r["action"],
            "domain": r["domain"],
            "display_domain": display_domain(r["domain"]) if r["domain"] else None,
            "status": r["status"],
            "created_at": r["created_at"],
            "effective_at": r["effective_at"],
            "seconds_remaining": max(0, r["effective_at"] - now),
        }

    def delay(self, acct) -> int:
        """v0.8.9: how long a loosening waits (removing a site, an exception, a
        category or setting off, a DNS address change). One setting for every
        device (Settings.blocklist_delay): "wait" (default) is the user's own wait,
        the longest of the account's and any linked Mac's; "fixed" is
        blocklist_delay_seconds (72 h, the server's rule before 0.8.9)."""
        if self.settings.blocklist_delay == "fixed":
            return int(self.settings.blocklist_delay_seconds)
        waits = [int(acct["wait_seconds"] or 0)]
        for r in self.db.all("SELECT wait_seconds FROM sync_links WHERE account_id=? AND revoked_at IS NULL "
                             "AND wait_seconds IS NOT NULL", (acct["id"],)):
            waits.append(int(r[0]))
        lo, hi = self.settings.min_wait_seconds, self.settings.max_wait_seconds
        return max(lo, min(hi, max(waits)))

    def link_partners(self, acct) -> list[str]:
        """v0.8.9: partners reported by Macs linked for sync, besides the account's own."""
        own = (acct["partner_email"] or "").strip().lower()
        out: list[str] = []
        for r in self.db.all("SELECT partner_email FROM sync_links WHERE account_id=? AND revoked_at IS NULL "
                             "AND partner_email IS NOT NULL AND partner_email != ''", (acct["id"],)):
            e = r[0].strip().lower()
            if e and e != own and e not in out:
                out.append(e)
        return out

    def _notify(self, acct, kind: str, subject: str, user_body: str, partner_body: str,
                required: bool = True) -> None:
        """v0.8.5: partner first; required=True fails closed (PartnerUnreachable),
        so call it before the change it announces. v0.8.9: a linked Mac's partner
        is told too (also before the change)."""
        for extra in self.link_partners(acct):
            self.escrow._mail_partner(extra, kind, f"[Pax partner] {subject}", partner_body, required=required)
        self.escrow._notify(acct, kind, subject, user_body, partner_body, required=required)

    # ------------------------------------------------------------ apply due
    def apply_due(self, account_id: Optional[str] = None) -> int:
        """Apply every pending request whose wait has ended. Returns how many."""
        now = self.now()
        sql = "SELECT * FROM blocklist_requests WHERE status='pending' AND effective_at<=?"
        params: tuple = (now,)
        if account_id:
            sql += " AND account_id=?"
            params = (now, account_id)
        applied = 0
        for r in self.db.all(sql + " ORDER BY effective_at", params):
            with self.db.transaction():
                still = self.db.one("SELECT status FROM blocklist_requests WHERE id=?", (r["id"],))
                if not still or still["status"] != "pending":
                    continue
                if r["action"] == "unblock":
                    self.db.execute(
                        "DELETE FROM blocklist_entries WHERE account_id=? AND list='block' "
                        "AND domain=?", (r["account_id"], r["domain"]))
                elif r["action"] == "allow" and restricted.is_restricted(r["domain"]):
                    self.db.execute("UPDATE blocklist_requests SET status='refused', closed_at=? WHERE id=?",
                                    (now, r["id"]))
                    continue
                elif r["action"] == "allow":
                    self.db.execute(
                        "INSERT OR IGNORE INTO blocklist_entries(account_id, list, domain, "
                        "created_at) VALUES (?,?,?,?)", (r["account_id"], "allow", r["domain"],
                                                         r["effective_at"]))
                elif r["action"] == "remote_desktop_off":
                    self.db.execute("UPDATE accounts SET block_remote_desktop=0 WHERE id=?",
                                    (r["account_id"],))
                elif r["action"] == "family_layer_off":
                    self.db.execute("UPDATE accounts SET dns_family_layer=0 WHERE id=?",
                                    (r["account_id"],))
                elif r["action"] in LEGACY_MEDIA_OFF_ACTIONS:
                    # v0.8.13: never applied (db.py refuses these at start-up too).
                    self.db.execute("UPDATE blocklist_requests SET status='refused', closed_at=? WHERE id=?",
                                    (now, r["id"]))
                    continue
                # rotate_token: retire_at was set when requested; nothing to write.
                self.db.execute(
                    "UPDATE blocklist_requests SET status='applied', closed_at=? WHERE id=?",
                    (now, r["id"]))
                self._changed(r["account_id"])
            acct = self.db.one("SELECT * FROM accounts WHERE id=?", (r["account_id"],))
            self.escrow._log(r["account_id"], f"blocklist_{r['action']}_applied",
                             detail=r["domain"])
            if acct:
                what = {
                    "unblock": f"{display_domain(r['domain'])} is no longer on your blocked list",
                    "allow": f"{display_domain(r['domain'])} is now allowed past the filter",
                    "rotate_token": "your old Pax DNS address has stopped working",
                    "remote_desktop_off": "remote desktop services are no longer blocked",
                    "family_layer_off": "the extra family filter is off (Pax's own filter still applies)",
                }[r["action"]]
                # The partner was told when it was requested; this is news only.
                self._notify(acct, f"blocklist_{r['action']}_applied", "Pax: change now in effect",
                             f"As you asked {fmt_duration(now - r['created_at'])} ago, {what}.",
                             f"For {acct['email']}: {what}.", required=False)
            applied += 1
        return applied

    # ------------------------------------------------------------- read
    def effective(self, account_id: str) -> tuple[list[str], list[str]]:
        p = {"acct": account_id, "now": self.now()}
        block = sorted(r[0] for r in self.db.all(EFFECTIVE_BLOCK_SQL, p))
        allow = sorted(r[0] for r in self.db.all(EFFECTIVE_ALLOW_SQL, p)
                       if not restricted.is_restricted(r[0]))
        return block, allow

    def view(self, acct) -> dict:
        self.apply_due(acct["id"])
        now = self.now()
        pending = self.db.all(
            "SELECT * FROM blocklist_requests WHERE account_id=? AND status='pending' "
            "ORDER BY effective_at", (acct["id"],))
        pending_unblock = {r["domain"]: r for r in pending if r["action"] == "unblock"}

        def entry(row, list_):
            d = row["domain"]
            out = {"domain": d, "display_domain": display_domain(d), "added_at": row["created_at"]}
            if list_ == "block":
                pr = pending_unblock.get(d)
                out["pending_removal"] = self._request_view(pr) if pr else None
            return out

        blocked = [entry(r, "block") for r in self.db.all(
            "SELECT * FROM blocklist_entries WHERE account_id=? AND list='block' "
            "ORDER BY domain", (acct["id"],))]
        allowed = [entry(r, "allow") for r in self.db.all(
            "SELECT * FROM blocklist_entries WHERE account_id=? AND list='allow' "
            "ORDER BY domain", (acct["id"],))]
        return {
            "now": now,
            "blocked": blocked,
            "allowed": allowed,
            "pending": [self._request_view(r) for r in pending],
            "limits": {
                "max_blocked": self.settings.blocklist_max_entries,
                "max_allowed": self.settings.allowlist_max_entries,
                "delay_seconds": self.delay(acct),
            },
        }

    # ------------------------------------------------------------ block list
    def add_block(self, acct, raw: str) -> dict:
        domain = self._domain(raw)
        aid = acct["id"]
        self.apply_due(aid)
        now = self.now()
        created = False
        with self.db.transaction():
            # Re-adding a site you asked to unblock simply cancels that request.
            pr = self._pending(aid, "unblock", domain)
            if pr:
                self.db.execute("UPDATE blocklist_requests SET status='cancelled', closed_at=? "
                                "WHERE id=?", (now, pr["id"]))
            # Blocking beats a pending or existing exception for the same domain.
            pa = self._pending(aid, "allow", domain)
            if pa:
                self.db.execute("UPDATE blocklist_requests SET status='cancelled', closed_at=? "
                                "WHERE id=?", (now, pa["id"]))
            self.db.execute("DELETE FROM blocklist_entries WHERE account_id=? AND list='allow' "
                            "AND domain=?", (aid, domain))
            if not self._entry(aid, "block", domain):
                count = self.db.one("SELECT COUNT(*) FROM blocklist_entries WHERE account_id=? "
                                    "AND list='block'", (aid,))[0]
                if count >= self.settings.blocklist_max_entries:
                    raise LimitReached(
                        f"your blocked list is full ({self.settings.blocklist_max_entries} sites)")
                self.db.execute(
                    "INSERT INTO blocklist_entries(account_id, list, domain, created_at) "
                    "VALUES (?,?,?,?)", (aid, "block", domain, now))
                created = True
            self._changed(aid)
        self.escrow._log(aid, "blocklist_added", detail=domain)
        return {"domain": domain, "display_domain": display_domain(domain), "created": created,
                "effective_at": now, "list": self.view(acct)}

    def request_unblock(self, acct, raw: str) -> dict:
        domain = self._domain(raw)
        aid = acct["id"]
        self.apply_due(aid)
        if not self._entry(aid, "block", domain):
            raise NotFound(f"{display_domain(domain)} isn't on your blocked list")
        existing = self._pending(aid, "unblock", domain)
        if existing:
            raise Conflict("a removal for this site is already waiting",
                           request=self._request_view(existing))
        return self._new_request(acct, "unblock", domain)

    # ------------------------------------------------------------ allow list
    def request_allow(self, acct, raw: str) -> dict:
        domain = self._domain(raw)
        aid = acct["id"]
        self.apply_due(aid)
        if self._entry(aid, "block", domain):
            raise Conflict(f"{display_domain(domain)} is on your blocked list; "
                           "remove it from there instead")
        if self._entry(aid, "allow", domain):
            raise Conflict(f"{display_domain(domain)} is already allowed")
        try:
            restricted.check(domain, self.settings.restricted_probe_url, lists_check=self.lists_check,
                             family_layer=self.family_layer(aid))
        except restricted.pr.RestrictedSite:
            raise Restricted(restricted.RESTRICTED_MESSAGE, domain=domain) from None
        existing = self._pending(aid, "allow", domain)
        if existing:
            raise Conflict("an exception for this site is already waiting",
                           request=self._request_view(existing))
        count = self.db.one(
            "SELECT (SELECT COUNT(*) FROM blocklist_entries WHERE account_id=? AND list='allow')"
            " + (SELECT COUNT(*) FROM blocklist_requests WHERE account_id=? AND action='allow' "
            "AND status='pending')", (aid, aid))[0]
        if count >= self.settings.allowlist_max_entries:
            raise LimitReached(
                f"your allowed list is full ({self.settings.allowlist_max_entries} sites)")
        return self._new_request(acct, "allow", domain)

    def remove_allow(self, acct, raw: str) -> dict:
        """Dropping an exception is more protection, so it is immediate."""
        domain = self._domain(raw)
        aid = acct["id"]
        self.apply_due(aid)
        now = self.now()
        with self.db.transaction():
            pa = self._pending(aid, "allow", domain)
            entry = self._entry(aid, "allow", domain)
            if not pa and not entry:
                raise NotFound(f"{display_domain(domain)} isn't on your allowed list")
            if pa:
                self.db.execute("UPDATE blocklist_requests SET status='cancelled', closed_at=? "
                                "WHERE id=?", (now, pa["id"]))
            self.db.execute("DELETE FROM blocklist_entries WHERE account_id=? AND list='allow' "
                            "AND domain=?", (aid, domain))
            self._changed(aid)
        self.escrow._log(aid, "allowlist_removed", detail=domain)
        return self.view(acct)

    # -------------------------------------------------------------- requests
    def _new_request(self, acct, action: str, domain: Optional[str],
                     effective_at: Optional[int] = None, announced: bool = False) -> dict:
        now = self.now()
        delay = self.delay(acct)
        effective_at = effective_at if effective_at is not None else now + delay
        if not announced:
            # Partner first (fail closed): no email, no countdown.
            self._announce(acct, action, domain)
        rid = _id()
        self.db.execute(
            "INSERT INTO blocklist_requests(id, account_id, action, domain, status, created_at, "
            "effective_at) VALUES (?,?,?,?,?,?,?)",
            (rid, acct["id"], action, domain, "pending", now, effective_at))
        self.escrow._log(acct["id"], f"blocklist_{action}_requested", detail=domain)
        row = self.db.one("SELECT * FROM blocklist_requests WHERE id=?", (rid,))
        return {"request": self._request_view(row), "list": self.view(acct)}

    def _announce(self, acct, action: str, domain: Optional[str]) -> None:
        delay = self.delay(acct)
        shown = display_domain(domain) if domain else ""
        what_user = {
            "unblock": f"remove {shown} from your blocked list",
            "allow": f"allow {shown} past the filter",
            "rotate_token": "change your Pax DNS address",
            "remote_desktop_off": "stop blocking remote desktop services",
            "family_layer_off": "turn off the extra family filter",
        }[action]
        what_partner = {
            "unblock": f"unblock {shown}",
            "allow": f"allow {shown} past the Pax filter",
            "rotate_token": "change their Pax DNS address (devices still using the old one "
                            "lose their custom blocks)",
            "remote_desktop_off": "stop blocking remote desktop and remote-access services "
                                  "(another computer isn't filtered by Pax)",
            "family_layer_off": "turn off the extra family filter (Pax's own filter stays on)",
        }[action]
        self._notify(
            acct, f"blocklist_{action}_requested", "Pax: change requested",
            f"You asked to {what_user}. It takes effect in {fmt_duration(delay)} and you can "
            "cancel it any time before then.",
            f"{acct['email']} asked to {what_partner}. It takes effect in "
            f"{fmt_duration(delay)}. You might want to check in with them.",
        )

    def cancel_request(self, acct, request_id: str) -> dict:
        r = self.db.one("SELECT * FROM blocklist_requests WHERE id=? AND account_id=?",
                        (request_id, acct["id"]))
        if not r:
            raise NotFound("request not found")
        self.apply_due(acct["id"])
        r = self.db.one("SELECT * FROM blocklist_requests WHERE id=?", (request_id,))
        if r["status"] != "pending":
            raise Conflict(f"this request is already {r['status']}")
        now = self.now()
        self.db.execute("UPDATE blocklist_requests SET status='cancelled', closed_at=? WHERE id=?",
                        (now, request_id))
        if r["action"] == "rotate_token":
            # Keep the old token: the new one stays valid too.
            self.db.execute("UPDATE dns_tokens SET retire_at=NULL WHERE account_id=? AND "
                            "retire_at=?", (acct["id"], r["effective_at"]))
            self._changed(acct["id"])
        self.escrow._log(acct["id"], f"blocklist_{r['action']}_cancelled", detail=r["domain"])
        shown = (display_domain(r["domain"]) if r["domain"] else
                 {"rotate_token": "the DNS address change",
                  "remote_desktop_off": "turning off remote desktop blocking",
                  "family_layer_off": "turning off the extra family filter"}.get(
                     r["action"], r["action"]))
        self._notify(acct, f"blocklist_{r['action']}_cancelled", "Pax: change cancelled",
                     f"You cancelled the pending change for {shown}. Well done.",
                     f"{acct['email']} cancelled their pending change for {shown}.",
                     required=False)
        return self.view(acct)

    # ------------------------------------------------------------ categories
    def remote_desktop_blocked(self, account_id: str) -> bool:
        row = self.db.one(REMOTE_DESKTOP_SQL, {"acct": account_id, "now": self.now()})
        return True if row is None else bool(row[0])

    def family_layer(self, account_id: str) -> bool:
        """v0.8.18: is the extra family-filter layer on?"""
        row = self.db.one(FAMILY_LAYER_SQL, {"acct": account_id, "now": self.now()})
        return False if row is None else bool(row[0])

    def category_enabled(self, account_id: str, category: str) -> bool:
        if category == "family_layer":
            return self.family_layer(account_id)
        if category == "remote_desktop":
            return self.remote_desktop_blocked(account_id)
        return True

    def categories(self, acct) -> dict:
        aid = acct["id"]
        self.apply_due(aid)
        pending = self._pending(aid, "remote_desktop_off", None)
        rd = self.remote_desktop_blocked(aid)
        fpending = self._pending(aid, "family_layer_off", None)
        return {
            "now": self.now(),
            "categories": [
                {"id": "bypass", **CATEGORIES["bypass"], "enabled": True, "pending": None},
                {"id": "remote_desktop", **CATEGORIES["remote_desktop"], "enabled": rd,
                 "pending": self._request_view(pending) if pending else None},
                {"id": "family_layer", **CATEGORIES["family_layer"], "enabled": self.family_layer(aid),
                 "pending": self._request_view(fpending) if fpending else None},
            ],
            "delay_seconds": self.delay(acct),
        }

    def set_category(self, acct, category: str, enabled: bool) -> tuple[int, dict]:
        """(HTTP status, body). On is immediate (more protection); off is a
        request that waits like a removal."""
        if category not in CATEGORIES:
            raise NotFound(f"unknown category {category!r}")
        if not CATEGORIES[category]["can_turn_off"]:
            if enabled:
                return 200, self.categories(acct)
            raise Conflict("this category can't be turned off")
        aid = acct["id"]
        self.apply_due(aid)
        action, column = CATEGORY_OFF[category]
        pending = self._pending(aid, action, None)
        if enabled:
            now = self.now()
            with self.db.transaction():
                if pending:
                    self.db.execute("UPDATE blocklist_requests SET status='cancelled', "
                                    "closed_at=? WHERE id=?", (now, pending["id"]))
                self.db.execute(f"UPDATE accounts SET {column}=1 WHERE id=?", (aid,))
                self._changed(aid)
            self.escrow._log(aid, f"{category}_on")
            return 200, self.categories(acct)
        if not self.category_enabled(aid, category):
            return 200, self.categories(acct)
        if pending:
            raise Conflict("turning this off is already waiting",
                           request=self._request_view(pending))
        out = self._new_request(acct, action, None)
        # A category change is invisible to DNS until the wait ends; bump the
        # feed anyway so devices refresh their view of the request.
        self._changed(aid)
        return 202, {"request": out["request"], **self.categories(acct)}

    # ------------------------------------------------------- DNS settings
    def dns_settings_values(self, account_id: str) -> dict:
        row = self.db.one("SELECT dns_youtube_restricted FROM accounts WHERE id=?", (account_id,))
        # v0.8.13: X and Bluesky media are always blocked (reported for older apps).
        return {"x_media": True, "bluesky_media": True,
                "youtube_restricted": True if row is None else bool(row[0])}

    def dns_settings(self, acct) -> dict:
        aid = acct["id"]
        self.apply_due(aid)
        return {"now": self.now(), "settings": self.dns_settings_values(aid),
                "pending": {k: None for k in ALWAYS_BLOCKED_MEDIA},
                "always_blocked": list(ALWAYS_BLOCKED_MEDIA),
                "delay_seconds": self.delay(acct)}

    def set_dns_settings(self, acct, values: dict) -> tuple[int, dict]:
        """YouTube Restricted Mode is immediate both ways. v0.8.13: pictures and
        video on X and Bluesky are always blocked; asking to turn either off is
        refused before anything changes (no request, no wait, no email), and
        asking to keep them on is accepted and changes nothing."""
        aid = acct["id"]
        off = [k for k in ALWAYS_BLOCKED_MEDIA if values.get(k) is False]
        if off:
            self.escrow._log(aid, "dns_settings_refused", detail=",".join(f"{k}=False" for k in off))
            raise MediaAlwaysBlocked("pictures and video on X and Bluesky are always off; posts stay readable",
                                     settings=off)
        self.apply_due(aid)
        with self.db.transaction():
            if "youtube_restricted" in values and values["youtube_restricted"] is not None:
                self.db.execute("UPDATE accounts SET dns_youtube_restricted=? WHERE id=?",
                                (1 if values["youtube_restricted"] else 0, aid))
            self._changed(aid)
        self.escrow._log(aid, "dns_settings", detail=",".join(f"{k}={v}" for k, v in sorted(values.items())
                                                               if v is not None))
        return 200, self.dns_settings(acct)

    # ------------------------------------------------------------ DNS token
    def _issue_token(self, account_id: str) -> str:
        token = new_dns_token()
        self.db.execute(
            "INSERT INTO dns_tokens(token_hash, account_id, token_ct, created_at, retire_at) "
            "VALUES (?,?,?,?,NULL)",
            (hash_token(token), account_id,
             self.escrow.box.encrypt(token, aad=f"dns:{account_id}"), self.now()))
        self._changed(account_id)
        return token

    def dns_info(self, acct) -> dict:
        """The account's per-user DoH URL (creating the token on first use)."""
        aid = acct["id"]
        self.apply_due(aid)
        cur = self.db.one("SELECT * FROM dns_tokens WHERE account_id=? AND retire_at IS NULL "
                          "ORDER BY created_at DESC LIMIT 1", (aid,))
        if cur:
            token = self.escrow.box.decrypt(cur["token_ct"], aad=f"dns:{aid}")
            created = cur["created_at"]
        else:
            token = self._issue_token(aid)
            created = self.now()
        retiring = self.db.all("SELECT created_at, retire_at FROM dns_tokens WHERE account_id=? "
                               "AND retire_at IS NOT NULL AND retire_at > ? ORDER BY retire_at",
                               (aid, self.now()))
        return {
            "doh_url": doh_url(self.settings.dns_base_url, token),
            "token": token,
            "created_at": created,
            "retiring": [{"created_at": r["created_at"], "retire_at": r["retire_at"]}
                         for r in retiring],
        }

    def rotate_token(self, acct) -> dict:
        """New token now; the old one keeps working until the wait ends (rotating is
        not a way round the wait: devices on the old URL lose their custom blocks)."""
        aid = acct["id"]
        self.apply_due(aid)
        if self._pending(aid, "rotate_token", None):
            raise Conflict("a DNS address change is already waiting")
        cur = self.db.all("SELECT token_hash FROM dns_tokens WHERE account_id=? AND "
                          "retire_at IS NULL", (aid,))
        if not cur:
            return self.dns_info(acct)
        retire_at = self.now() + self.delay(acct)
        self._announce(acct, "rotate_token", None)   # partner first: no email, no change
        with self.db.transaction():
            for r in cur:
                self.db.execute("UPDATE dns_tokens SET retire_at=? WHERE token_hash=?",
                                (retire_at, r["token_hash"]))
            self._issue_token(aid)
        self._new_request(acct, "rotate_token", None, effective_at=retire_at, announced=True)
        return self.dns_info(acct)

    # ------------------------------------------------------- pax-dns feed
    def changes(self, since: int) -> dict:
        """Change feed for pax-dns. `since=0` returns every account with a token."""
        self.apply_due()
        now = self.now()
        seq = self.db.one("SELECT COALESCE(MAX(seq), 0) FROM dns_changes")[0]
        if since <= 0:
            ids = [r[0] for r in self.db.all("SELECT DISTINCT account_id FROM dns_tokens")]
        elif since >= seq:
            ids = []
        else:
            ids = [r[0] for r in self.db.all(
                "SELECT DISTINCT account_id FROM dns_changes WHERE seq > ?", (since,))]
        accounts = []
        for aid in ids:
            tokens = self.db.all(VALID_TOKENS_SQL, {"acct": aid, "now": now})
            block, allow = self.effective(aid)
            accounts.append({
                "account_id": aid,
                "tokens": [{"hash": t["token_hash"], "retire_at": t["retire_at"]} for t in tokens],
                "block": block,
                "allow": allow,
                "categories": {"remote_desktop": self.remote_desktop_blocked(aid),
                               "family_layer": self.family_layer(aid)},     # v0.8.18
                "settings": self.dns_settings_values(aid),   # v0.8.8
            })
        return {"seq": seq, "now": now, "full": since <= 0, "accounts": accounts}
