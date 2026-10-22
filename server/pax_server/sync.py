# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.9: one blocked-sites list per account, shared by every device.

iPhones and iPads read the account's list through Pax's DoH filter (0.8.8). A
Mac on local escrow (pax-guard holds its own key) keeps a copy of the list and
syncs it here with a *sync token* (`POST /v1/sync/links`, made by the Pax app
with the account's sign-in and handed to pax-guard over its socket).

What a sync token can do, and nothing more:
  * read the account's blocked sites, the removals waiting, and the removals
    that took effect since a given time (`POST /v1/sync`);
  * add sites (instant: more protection is never delayed);
  * ask to remove a site, or cancel such a request. That goes through the one
    removal rule (Blocklist.request_unblock): the partner is emailed first
    (fail closed), then the wait (Blocklist.delay), cancellable meanwhile.
It can't reveal a password, change the wait or the partner, or touch exceptions.

Linking without extra steps: the Pax app holds the account's sign-in (made when
an iPhone is set up from this Mac, or when partner emails go through Pax's
server). Whenever the app has one and this Mac's pax-guard isn't linked yet, it
links it. A Mac or iPhone set up elsewhere with the same email signs in to that
account with a one-time code sent to the email (`/v1/accounts/signin/*`).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import uuid
from typing import Optional

from .crypto import hash_token, token_matches
from .domains import DomainError, display_domain, normalise_domain
from .escrow import Conflict, EscrowError, NotFound, RateLimited, Unauthorized

SYNC_TOKEN_PREFIX = "pxs_"
MAX_LINKS = 20
MAX_ADD_PER_SYNC = 2000
CODE_TTL = 15 * 60
CODE_MAX_ATTEMPTS = 5
CODES_PER_HOUR = 5


def new_sync_token() -> str:
    return SYNC_TOKEN_PREFIX + secrets.token_urlsafe(32)


def _id() -> str:
    return uuid.uuid4().hex


def _code_hash(account_id: str, code: str) -> str:
    return hashlib.sha256(f"{account_id}:{code}".encode()).hexdigest()


def _signup_email_hash(email: str) -> str:
    """v0.8.31: how signup_codes knows an address without storing it."""
    return hashlib.sha256(f"pax-signup:{email.strip().lower()}".encode()).hexdigest()


class ListSync:
    def __init__(self, blocklist):
        self.blocklist = blocklist

    @property
    def escrow(self):
        return self.blocklist.escrow

    @property
    def db(self):
        return self.blocklist.db

    def now(self) -> int:
        return self.blocklist.now()

    # ------------------------------------------------------------- links
    def create_link(self, acct, device_name: str, platform: str = "macos") -> dict:
        n = self.db.one("SELECT COUNT(*) FROM sync_links WHERE account_id=? AND revoked_at IS NULL",
                        (acct["id"],))[0]
        if n >= MAX_LINKS:
            raise Conflict(f"this account already has {MAX_LINKS} linked Macs")
        token, lid, now = new_sync_token(), _id(), self.now()
        self.db.execute(
            "INSERT INTO sync_links(id, account_id, token_hash, device_name, platform, created_at) "
            "VALUES (?,?,?,?,?,?)", (lid, acct["id"], hash_token(token), device_name[:100], platform, now))
        self.escrow._log(acct["id"], "sync_linked", detail=device_name[:100])
        return {"link_id": lid, "sync_token": token, "created_at": now, "account_email": acct["email"]}

    def links(self, acct) -> list[dict]:
        return [{"link_id": r["id"], "device_name": r["device_name"], "platform": r["platform"],
                 "created_at": r["created_at"], "last_seen": r["last_seen"]}
                for r in self.db.all("SELECT * FROM sync_links WHERE account_id=? AND revoked_at IS NULL "
                                     "ORDER BY created_at", (acct["id"],))]

    def authenticate(self, token: Optional[str]):
        """(account, link) for a sync token, else 401."""
        if not token or not token.startswith(SYNC_TOKEN_PREFIX):
            raise Unauthorized("invalid sync token")
        link = self.db.one("SELECT * FROM sync_links WHERE token_hash=?", (hash_token(token),))
        if not link or link["revoked_at"] is not None or not token_matches(token, link["token_hash"]):
            raise Unauthorized("invalid sync token")
        acct = self.db.one("SELECT * FROM accounts WHERE id=?", (link["account_id"],))
        if not acct:
            raise Unauthorized("invalid sync token")
        return self.escrow._materialize(acct), link

    # -------------------------------------------------------------- sync
    def sync(self, acct, link, add: list, since: int = 0, wait_seconds: Optional[int] = None,
             partner_email: Optional[str] = None) -> dict:
        """Add what the Mac added (instant), record its wait and partner, and
        return the account's list. `removed` lists removals that took effect
        (after their wait) at or after `since` and after the link was made: the
        only thing that may take a site off a Mac's copy."""
        s = self.escrow.settings
        now = self.now()
        wait = None
        if isinstance(wait_seconds, int) and wait_seconds > 0:
            wait = max(s.min_wait_seconds, min(s.max_wait_seconds, wait_seconds))
        partner = (partner_email or "").strip().lower()[:254] or None
        if partner and ("@" not in partner or any(c in partner for c in " \r\n,;")):
            partner = None
        self.db.execute("UPDATE sync_links SET last_seen=?, wait_seconds=COALESCE(?, wait_seconds), "
                        "partner_email=? WHERE id=?", (now, wait, partner, link["id"]))
        added, rejected = self._add_many(acct, add[:MAX_ADD_PER_SYNC])
        self.blocklist.apply_due(acct["id"])
        return self.state(acct, link, since, added=added, rejected=rejected)

    def _add_many(self, acct, raw: list) -> tuple[list[str], list[dict]]:
        aid, now = acct["id"], self.now()
        added: list[str] = []
        rejected: list[dict] = []
        wanted: list[str] = []
        for r in raw:
            try:
                d = normalise_domain(str(r))
            except DomainError as exc:
                rejected.append({"domain": str(r)[:255], "reason": str(exc)})
                continue
            if d not in wanted:
                wanted.append(d)
        if not wanted:
            return added, rejected
        limit = self.escrow.settings.blocklist_max_entries
        with self.db.transaction():
            have = {r[0] for r in self.db.all("SELECT domain FROM blocklist_entries WHERE account_id=? "
                                              "AND list='block'", (aid,))}
            for d in wanted:
                # Adding cancels a waiting removal of it and beats an exception.
                self.db.execute("UPDATE blocklist_requests SET status='cancelled', closed_at=? WHERE "
                                "account_id=? AND domain=? AND action IN ('unblock','allow') AND "
                                "status='pending'", (now, aid, d))
                self.db.execute("DELETE FROM blocklist_entries WHERE account_id=? AND list='allow' AND "
                                "domain=?", (aid, d))
                if d in have:
                    continue
                if len(have) >= limit:
                    rejected.append({"domain": d, "reason": f"your blocked list is full ({limit} sites)"})
                    continue
                self.db.execute("INSERT INTO blocklist_entries(account_id, list, domain, created_at) "
                                "VALUES (?,?,?,?)", (aid, "block", d, now))
                have.add(d)
                added.append(d)
            self.blocklist._changed(aid)
        if added:
            self.escrow._log(aid, "sync_added", detail=",".join(added[:20]))
        return added, rejected

    def state(self, acct, link, since: int = 0, added=(), rejected=()) -> dict:
        aid = acct["id"]
        block, _allow = self.blocklist.effective(aid)
        pending = self.db.all("SELECT * FROM blocklist_requests WHERE account_id=? AND action='unblock' "
                              "AND status='pending' ORDER BY effective_at", (aid,))
        removed = [{"domain": r["domain"], "applied_at": r["closed_at"]} for r in self.db.all(
            "SELECT domain, closed_at FROM blocklist_requests WHERE account_id=? AND action='unblock' "
            "AND status='applied' AND closed_at >= ? AND closed_at > ? ORDER BY closed_at",
            (aid, int(since or 0), int(link["created_at"])))
            if r["domain"] not in block]
        return {"now": self.now(), "blocked": block,
                "pending": [self.blocklist._request_view(r) for r in pending],
                "removed": removed, "added": list(added), "rejected": list(rejected),
                "delay_seconds": self.blocklist.delay(acct),
                "max_blocked": self.escrow.settings.blocklist_max_entries,
                "account_email": acct["email"], "link_id": link["id"]}

    def request_unblock(self, acct, link, raw: str) -> dict:
        out = self.blocklist.request_unblock(acct, raw)
        self.escrow._log(acct["id"], "sync_unblock_requested", detail=link["device_name"])
        return {"request": out["request"], "state": self.state(acct, link)}

    def cancel(self, acct, link, request_id: str) -> dict:
        self.blocklist.cancel_request(acct, request_id)
        return {"state": self.state(acct, link)}

    # ------------------------------------------------- sign in with a code
    def signin_start(self, email: str) -> None:
        """Email a one-time code to an existing account. Always looks the same
        to the caller (no hint whether the address has an account)."""
        email = (email or "").strip().lower()
        acct = self.db.one("SELECT * FROM accounts WHERE email=?", (email,))
        if not acct:
            return
        now = self.now()
        recent = self.db.one("SELECT COUNT(*) FROM signin_codes WHERE account_id=? AND created_at>?",
                             (acct["id"], now - 3600))[0]
        if recent >= CODES_PER_HOUR:
            raise RateLimited("too many codes; try again in an hour")
        code = f"{secrets.randbelow(1_000_000):06d}"
        self.db.execute("INSERT INTO signin_codes(id, account_id, code_hash, created_at, expires_at) "
                        "VALUES (?,?,?,?,?)", (_id(), acct["id"], _code_hash(acct["id"], code), now, now + CODE_TTL))
        self.escrow._log(acct["id"], "signin_code_sent")
        self.escrow._mail(email, "signin_code", "Your Pax sign-in code",
                          f"Your Pax code is {code}. It works for 15 minutes. If you didn't ask for it, "
                          "you can ignore this email: nothing changes without the code.")

    def signin_finish(self, email: str, code: str, label: str = "") -> dict:
        email = (email or "").strip().lower()
        code = (code or "").strip()
        acct = self.db.one("SELECT * FROM accounts WHERE email=?", (email,))
        if not acct:
            raise Unauthorized("that code isn't right or has expired")
        now = self.now()
        row = self.db.one("SELECT * FROM signin_codes WHERE account_id=? AND used_at IS NULL AND expires_at>? "
                          "ORDER BY created_at DESC LIMIT 1", (acct["id"], now))
        if not row or row["attempts"] >= CODE_MAX_ATTEMPTS:
            raise Unauthorized("that code isn't right or has expired")
        if not hmac.compare_digest(row["code_hash"], _code_hash(acct["id"], code)):
            self.db.execute("UPDATE signin_codes SET attempts=attempts+1 WHERE id=?", (row["id"],))
            raise Unauthorized("that code isn't right or has expired")
        return self._issue_signin(acct, email, label, "signin_codes", row["id"])

    def _issue_signin(self, acct, email: str, label: str, code_table: str, code_id: str) -> dict:
        """A new sign-in token for an existing account whose email a one-time code
        has just proved: the code is used up in the same transaction (a second use
        finds it gone: 401), and the email counts as verified (v0.8.31)."""
        assert code_table in ("signin_codes", "signup_codes")
        from .crypto import new_token
        token = new_token()
        now = self.now()
        with self.db.transaction():
            cur = self.db.execute(f"UPDATE {code_table} SET used_at=? WHERE id=? AND used_at IS NULL", (now, code_id))
            if cur.rowcount != 1:
                raise Unauthorized("that code isn't right or has expired")
            self.db.execute("INSERT INTO account_tokens(token_hash, account_id, created_at, label) VALUES (?,?,?,?)",
                            (hash_token(token), acct["id"], now, label[:100] or None))
            self.db.execute("UPDATE accounts SET email_verified_at=? WHERE id=?", (now, acct["id"]))
        self.escrow._log(acct["id"], "signed_in", detail=label[:100] or None)
        self.escrow._mail(email, "signed_in", "Pax: a new device signed in",
                          "A device just signed in to your Pax account with a code sent to this address. "
                          "Signing in only lets it share your blocked sites; unblocking still waits and your "
                          "partner is told.")
        return {"account_id": acct["id"], "token": token}

    # ------------------------------- v0.8.31: one email-code flow, new or existing
    def email_start(self, email: str) -> None:
        """POST /v1/accounts/email/start: a 6-digit code to `email`, whether or not it
        has an account yet, so the caller learns nothing about which. An address with
        an account gets today's sign-in code (signin_codes); a new address gets a code
        in signup_codes (hashes only) and no account is made until it comes back.
        Same rules for both: 15 minutes, 5 tries a code, 5 codes an hour an address."""
        email = (email or "").strip().lower()
        if self.db.one("SELECT 1 FROM accounts WHERE email=?", (email,)):
            self.signin_start(email)
            return
        now = self.now()
        eh = _signup_email_hash(email)
        with self.db.transaction():
            self.db.execute("DELETE FROM signup_codes WHERE expires_at<?", (now - 86400,))
            recent = self.db.one("SELECT COUNT(*) FROM signup_codes WHERE email_hash=? AND created_at>?",
                                 (eh, now - 3600))[0]
            if recent >= CODES_PER_HOUR:
                raise RateLimited("too many codes; try again in an hour")
            code = f"{secrets.randbelow(1_000_000):06d}"
            self.db.execute("INSERT INTO signup_codes(id, email_hash, code_hash, created_at, expires_at) "
                            "VALUES (?,?,?,?,?)", (_id(), eh, _code_hash("signup:" + eh, code), now, now + CODE_TTL))
        self.escrow._mail(email, "signup_code", "Your Pax code",
                          f"Your Pax code is {code}. It works for 15 minutes. If you didn't ask for it, "
                          "you can ignore this email: no account is made without the code.")

    def _signup_code(self, email: str, code: str):
        """The open signup code for `email` when `code` matches it, else None (a
        wrong guess uses up one of its 5 tries)."""
        eh = _signup_email_hash(email)
        row = self.db.one("SELECT * FROM signup_codes WHERE email_hash=? AND used_at IS NULL AND expires_at>? "
                          "ORDER BY created_at DESC LIMIT 1", (eh, self.now()))
        if not row or row["attempts"] >= CODE_MAX_ATTEMPTS:
            return None
        if not hmac.compare_digest(row["code_hash"], _code_hash("signup:" + eh, code)):
            self.db.execute("UPDATE signup_codes SET attempts=attempts+1 WHERE id=?", (row["id"],))
            return None
        return row

    def email_verify(self, email: str, code: str, label: str = "") -> tuple[dict, bool]:
        """POST /v1/accounts/email/verify: ({account_id, token, created}, created).
        Existing account: a new sign-in (exactly as POST /v1/accounts/signin).
        New address: the account is made now, with its email already verified.
        A wrong, used or expired code is 401 and nothing is made (fail closed)."""
        email = (email or "").strip().lower()
        code = (code or "").strip()
        acct = self.db.one("SELECT * FROM accounts WHERE email=?", (email,))
        if acct:
            try:
                return {**self.signin_finish(email, code, label), "created": False}, False
            except Unauthorized:
                # A code sent while the address had no account yet (someone made it
                # in between) still proves the address: sign in with it.
                row = self._signup_code(email, code)
                if not row:
                    raise
                return {**self._issue_signin(acct, email, label, "signup_codes", row["id"]), "created": False}, False
        row = self._signup_code(email, code)
        if not row:
            raise Unauthorized("that code isn't right or has expired")
        from .crypto import new_token
        account_id, token = _id(), new_token()
        now = self.now()
        try:
            with self.db.transaction():
                cur = self.db.execute("UPDATE signup_codes SET used_at=? WHERE id=? AND used_at IS NULL",
                                      (now, row["id"]))
                if cur.rowcount != 1:
                    raise Unauthorized("that code isn't right or has expired")
                self.db.execute(
                    "INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds, email_verified_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (account_id, email, hash_token(token), now, self.escrow.settings.default_wait_seconds, now))
        except sqlite3.IntegrityError:
            # The address got an account a moment ago (UNIQUE email): sign in to it.
            acct = self.db.one("SELECT * FROM accounts WHERE email=?", (email,))
            if not acct:
                raise
            return {**self._issue_signin(acct, email, label, "signup_codes", row["id"]), "created": False}, False
        self.escrow._log(account_id, "account_registered", detail="email verified")
        return {"account_id": account_id, "token": token, "created": True}, True


def view_domain(d: str) -> str:
    return display_domain(d)


__all__ = ["ListSync", "new_sync_token", "EscrowError", "NotFound"]
