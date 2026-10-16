# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.5: abuse limits for a public Pax server.

* Sign-up rate limit per client IP. POST /v1/accounts needs no token and sends a
  welcome email, so without a limit anyone could use the server to email
  strangers or use up the mail provider's daily quota.
* A global daily budget for outbound email, kept under the provider's quota
  (Resend's free tier allows 100 a day). Two tiers:
    - "account": emails to the account holder (welcome, copies of their own
      requests). Best-effort; they stop first, at PAX_ACCOUNT_MAIL_DAILY_CAP.
    - "partner": emails to an accountability partner. They may use the whole
      budget (PAX_MAIL_DAILY_CAP), and they fail closed: when one can't be
      sent, the action that needed it doesn't start (escrow.PartnerUnreachable).
* At most one welcome email per address per day.

The client IP comes from X-Forwarded-For only when the connection itself comes
from this machine (Caddy on localhost); anyone else could forge the header.
Addresses and IPs are stored as SHA-256 hashes, and rows older than two days
are pruned.
"""
from __future__ import annotations

import hashlib
import ipaddress
from typing import Optional

DAY = 86400
HOUR = 3600
ACCOUNT, PARTNER = "account", "partner"


def _h(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


def is_loopback(host: Optional[str]) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def client_ip(peer: Optional[str], forwarded_for: Optional[str]) -> str:
    """The address to rate-limit. X-Forwarded-For is trusted only from a
    loopback peer (the local reverse proxy). Caddy appends the address it saw
    as the last entry, so the last valid entry is the one to use; anything a
    client put in front of it is ignored."""
    peer = (peer or "").strip() or "unknown"
    if forwarded_for and is_loopback(peer):
        for part in reversed(forwarded_for.split(",")):
            cand = part.strip().strip('"')
            if cand.startswith("[") and "]" in cand:          # [v6]:port
                cand = cand[1:cand.index("]")]
            elif cand.count(":") == 1:                       # v4:port
                cand = cand.split(":", 1)[0]
            try:
                return str(ipaddress.ip_address(cand))
            except ValueError:
                continue
    return peer


class Limits:
    """Sign-up limits and the outbound mail budget, stored in the server's
    SQLite database so they survive restarts."""

    def __init__(self, db, settings, clock):
        self.db, self.settings, self.clock = db, settings, clock

    # ---------------------------------------------------------------- sign-up
    def check_signup(self, ip: str) -> Optional[str]:
        """Record a sign-up attempt from `ip`. Returns None if allowed, or a
        message saying why not (the caller answers 429)."""
        s = self.settings
        now = self.clock.now()
        key = _h(ip)
        with self.db.transaction():
            self.db.execute("DELETE FROM signup_attempts WHERE at<?", (now - 2 * DAY,))
            hour = self.db.one("SELECT COUNT(*) FROM signup_attempts WHERE ip_hash=? AND at>?",
                               (key, now - HOUR))[0]
            day = self.db.one("SELECT COUNT(*) FROM signup_attempts WHERE ip_hash=? AND at>?",
                              (key, now - DAY))[0]
            if s.signup_per_ip_hour > 0 and hour >= s.signup_per_ip_hour:
                return "too many new accounts from your network in the last hour; try again later"
            if s.signup_per_ip_day > 0 and day >= s.signup_per_ip_day:
                return "too many new accounts from your network today; try again tomorrow"
            self.db.execute("INSERT INTO signup_attempts(ip_hash, at) VALUES (?,?)", (key, now))
        return None

    # ------------------------------------------------------------ mail budget
    def sent_today(self) -> int:
        """Emails handed to the provider in the last 24 hours (sent or failed:
        a failed attempt may still count against the provider's quota). A
        rolling day is never fewer than the provider's calendar day."""
        now = self.clock.now()
        return self.db.one("SELECT COUNT(*) FROM mail_log WHERE at>? AND status IN "
                           "('sending','sent','failed')", (now - DAY,))[0]

    def reserve(self, to: str, kind: str, tier: str) -> tuple[Optional[int], str]:
        """(row id, "") when this email may go out, or (None, why) when it must
        be dropped. The row counts against the budget at once, so two requests
        can't both take the last slot."""
        s = self.settings
        now = self.clock.now()
        with self.db.transaction():
            self.db.execute("DELETE FROM mail_log WHERE at<?", (now - 2 * DAY,))
            used = self.sent_today()
            cap = s.mail_daily_cap if tier == PARTNER else min(s.account_mail_daily_cap, s.mail_daily_cap)
            why = ""
            if cap >= 0 and used >= cap:
                why = "daily email limit reached"
            elif kind == "welcome" and self.db.one(
                    "SELECT 1 FROM mail_log WHERE to_hash=? AND kind='welcome' AND at>? AND status IN "
                    "('sending','sent')", (_h(to), now - DAY)):
                why = "welcome already sent to this address today"
            cur = self.db.execute(
                "INSERT INTO mail_log(at, kind, tier, to_hash, status) VALUES (?,?,?,?,?)",
                (now, kind, tier, _h(to), "dropped" if why else "sending"))
            return (None, why) if why else (cur.lastrowid, "")

    def finish(self, row_id: int, ok: bool) -> None:
        self.db.execute("UPDATE mail_log SET status=? WHERE id=?", ("sent" if ok else "failed", row_id))
