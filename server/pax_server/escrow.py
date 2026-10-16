# SPDX-License-Identifier: GPL-3.0-only
"""Escrow rules. Pure business logic, no HTTP. Fully automated: no step needs a
human at Pax to approve anything.

Rules (see README "How removal works"):
  * Wait time: increases apply immediately; decreases take effect only after the
    *current* wait time has elapsed.
  * Removal request: starts a timer equal to the effective wait time (none during
    the 1-hour grace period after a device is registered). After it expires the
    user confirms and the password is revealed. Unconfirmed requests lapse after
    the reveal window.
  * Partner: adding the first partner is immediate. Changing or removing a partner
    waits the current wait time. The partner is emailed about every removal,
    cancellation, reveal, emergency, wait decrease and partner change.
  * Emergency release: logged, short cooling-off, rate-limited, auto-reply with
    crisis lines.
  * Email (v0.8.5): a partner alert that starts a countdown or releases a
    password is sent FIRST; if it can't be sent (provider error or the daily
    email budget) the action doesn't happen (PartnerUnreachable, HTTP 503,
    PAX-ESCROW-010). Emails to the account holder are best-effort: dropped first
    when the budget runs low, and a failure never undoes or blocks an action.
  * Grace requests (v0.8.5): a no-wait request made in the grace period can only
    be confirmed until the grace period ends; then it lapses. Requests past their
    window are lapsed by the sweep too, not only when someone looks.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from .config import Settings
from .crypto import SecretBox, hash_token, new_token, token_matches
from .db import Database
from .limits import ACCOUNT, PARTNER, Limits
from .notify import CRISIS_LINES, Email, EmailSender, crisis_text

log = logging.getLogger("pax.escrow")


class Clock:
    def now(self) -> int:
        return int(time.time())


class EscrowError(Exception):
    status = 400
    code = "bad_request"

    def __init__(self, message: str, **extra):
        super().__init__(message)
        self.message = message
        self.extra = extra


class NotFound(EscrowError):
    status, code = 404, "not_found"


class Conflict(EscrowError):
    status, code = 409, "conflict"


class Restricted(EscrowError):
    """v0.8.1: an exception for a site Pax always blocks (PAX-DNS-010)."""
    status, code = 422, "restricted_site"


class MediaAlwaysBlocked(EscrowError):
    """v0.8.13: pictures and video on X and Bluesky are always blocked; a request
    to turn them off is refused before anything changes (PAX-DNS-016)."""
    status, code = 422, "media_always_blocked"


class TooEarly(EscrowError):
    status, code = 425, "too_early"


class Gone(EscrowError):
    status, code = 410, "gone"


class RateLimited(EscrowError):
    status, code = 429, "rate_limited"


class Unauthorized(EscrowError):
    status, code = 401, "unauthorized"


class PartnerUnreachable(EscrowError):
    """v0.8.5: the partner alert an action needs couldn't be sent, so the action
    didn't start (fail closed). Support code PAX-ESCROW-010."""
    status, code = 503, "partner_unreachable"


def _id() -> str:
    return uuid.uuid4().hex


def fmt_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m and not d:
        parts.append(f"{m}m")
    return " ".join(parts) or "0m"


@dataclass
class Escrow:
    db: Database
    settings: Settings
    clock: Clock
    sender: EmailSender

    def __post_init__(self):
        self.box = SecretBox(self.settings.server_key_b64)
        self.limits = Limits(self.db, self.settings, self.clock)

    # ------------------------------------------------------------------ utils
    def _log(self, account_id: str, kind: str, device_id: Optional[str] = None,
             detail: Optional[str] = None) -> None:
        self.db.execute(
            "INSERT INTO events(account_id, device_id, at, kind, detail) VALUES (?,?,?,?,?)",
            (account_id, device_id, self.clock.now(), kind, detail),
        )

    def _send(self, to: str, kind: str, subject: str, body: str, tier: str) -> bool:
        """Send one email within the daily budget. True if it went out. Never
        raises: callers decide what a failure means."""
        row, why = self.limits.reserve(to, kind, tier)
        if row is None:
            log.warning("email[%s] (%s) not sent: %s", kind, tier, why)
            return False
        try:
            self.sender.send(Email(to=to, subject=subject, body=body, kind=kind))
        except Exception as exc:  # noqa: BLE001 - any provider failure
            log.warning("email[%s] (%s) failed: %s", kind, tier, type(exc).__name__)
            self.limits.finish(row, False)
            return False
        self.limits.finish(row, True)
        return True

    def _mail(self, to: Optional[str], kind: str, subject: str, body: str) -> bool:
        """An email to the account holder: best-effort, dropped first."""
        return bool(to) and self._send(to, kind, subject, body, ACCOUNT)

    def _mail_partner(self, to: Optional[str], kind: str, subject: str, body: str,
                      required: bool = True) -> bool:
        """An email to an accountability partner. required=True (the default)
        raises PartnerUnreachable when it can't be sent, so call it BEFORE the
        action it announces; required=False is for news that makes Pax
        stricter (a cancellation) or adds a partner, which never waits on email."""
        if not to:
            return False
        ok = self._send(to, kind, subject, body, PARTNER)
        if not ok and required:
            raise PartnerUnreachable(
                "Pax couldn't email your partner just now, so nothing has started. Try again later.")
        return ok

    def _notify(self, acct, kind: str, subject: str, user_body: str,
                partner_body: Optional[str] = None, required: bool = True) -> None:
        """Partner first (fail closed when required), then the account holder's
        copy (best-effort)."""
        if acct["partner_email"]:
            self._mail_partner(acct["partner_email"], kind, f"[Pax partner] {subject}",
                               partner_body or user_body, required=required)
        self._mail(acct["email"], kind, subject, user_body)

    # --------------------------------------------------------------- accounts
    def register_account(self, email: str) -> tuple[str, str]:
        email = email.strip().lower()
        if self.db.one("SELECT 1 FROM accounts WHERE email=?", (email,)):
            raise Conflict("an account with this email already exists", sign_in=True)
        account_id, token = _id(), new_token()
        self.db.execute(
            "INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) "
            "VALUES (?,?,?,?,?)",
            (account_id, email, hash_token(token), self.clock.now(),
             self.settings.default_wait_seconds),
        )
        self._log(account_id, "account_registered")
        # v0.8.5: best-effort. The account exists either way (201); a failed or
        # dropped welcome (daily budget, one per address per day) changes nothing.
        if not self._mail(email, "welcome", "Welcome to Pax",
                          "Your Pax account is set up. Keep your Pax app sign-in safe."):
            self._log(account_id, "welcome_not_sent")
        return account_id, token

    def authenticate(self, token: Optional[str]):
        if not token:
            raise Unauthorized("missing bearer token")
        h = hash_token(token)
        row = self.db.one("SELECT * FROM accounts WHERE token_hash=?", (h,))
        if row and token_matches(token, row["token_hash"]):
            return self._materialize(row)
        # v0.8.9: another sign-in to the same account (email + one-time code).
        extra = self.db.one("SELECT account_id, token_hash FROM account_tokens WHERE token_hash=?", (h,))
        if extra and token_matches(token, extra["token_hash"]):
            row = self.db.one("SELECT * FROM accounts WHERE id=?", (extra["account_id"],))
            if row:
                return self._materialize(row)
        raise Unauthorized("invalid token")

    def _materialize(self, acct):
        """Apply any pending wait/partner change whose time has come."""
        now = self.clock.now()
        changed = False
        if acct["pending_wait_effective"] is not None and now >= acct["pending_wait_effective"]:
            self.db.execute(
                "UPDATE accounts SET wait_seconds=?, pending_wait_seconds=NULL, "
                "pending_wait_effective=NULL WHERE id=?",
                (acct["pending_wait_seconds"], acct["id"]),
            )
            self._log(acct["id"], "wait_decrease_applied",
                      detail=str(acct["pending_wait_seconds"]))
            changed = True
        if (acct["pending_partner_effective"] is not None
                and now >= acct["pending_partner_effective"]):
            new = acct["pending_partner_email"] or None
            self.db.execute(
                "UPDATE accounts SET partner_email=?, pending_partner_email=NULL, "
                "pending_partner_effective=NULL WHERE id=?",
                (new, acct["id"]),
            )
            self._log(acct["id"], "partner_change_applied", detail=new or "(removed)")
            if new:
                self._mail_partner(new, "partner_added", "You are now a Pax accountability partner",
                                   f"{acct['email']} has made you their Pax accountability partner. "
                                   "You will be told when they ask to remove their blocker.",
                                   required=False)
            changed = True
        if changed:
            acct = self.db.one("SELECT * FROM accounts WHERE id=?", (acct["id"],))
        return acct

    def account_status(self, acct) -> dict:
        return {
            "account_id": acct["id"],
            "email": acct["email"],
            "wait_seconds": acct["wait_seconds"],
            "pending_wait_seconds": acct["pending_wait_seconds"],
            "pending_wait_effective_at": acct["pending_wait_effective"],
            "partner_email": acct["partner_email"],
            "adblock": bool(acct["adblock"]),
            "block_remote_desktop": bool(acct["block_remote_desktop"]),
            "pending_partner_email": (
                None if acct["pending_partner_effective"] is None
                else (acct["pending_partner_email"] or "")
            ),
            "pending_partner_effective_at": acct["pending_partner_effective"],
            "limits": {
                "min_wait_seconds": self.settings.min_wait_seconds,
                "max_wait_seconds": self.settings.max_wait_seconds,
            },
        }

    # -------------------------------------------------------------- wait time
    def set_wait(self, acct, wait_seconds: int) -> dict:
        s = self.settings
        if not (s.min_wait_seconds <= wait_seconds <= s.max_wait_seconds):
            raise EscrowError(
                f"wait time must be between {fmt_duration(s.min_wait_seconds)} "
                f"and {fmt_duration(s.max_wait_seconds)}"
            )
        now = self.clock.now()
        current = acct["wait_seconds"]
        if wait_seconds >= current:
            # Increase (or same): immediate, and cancels any pending decrease.
            self.db.execute(
                "UPDATE accounts SET wait_seconds=?, pending_wait_seconds=NULL, "
                "pending_wait_effective=NULL WHERE id=?",
                (wait_seconds, acct["id"]),
            )
            self._log(acct["id"], "wait_increased", detail=str(wait_seconds))
        else:
            effective = now + current
            # Partner first: no email, no countdown.
            self._notify(
                acct, "wait_decrease_requested", "Wait time decrease requested",
                f"Your wait time will drop from {fmt_duration(current)} to "
                f"{fmt_duration(wait_seconds)} in {fmt_duration(current)}.",
                f"{acct['email']} asked to shorten their Pax wait time from "
                f"{fmt_duration(current)} to {fmt_duration(wait_seconds)}. It takes "
                f"effect in {fmt_duration(current)}.",
            )
            self.db.execute(
                "UPDATE accounts SET pending_wait_seconds=?, pending_wait_effective=? WHERE id=?",
                (wait_seconds, effective, acct["id"]),
            )
            self._log(acct["id"], "wait_decrease_requested", detail=str(wait_seconds))
        return self.account_status(self.db.one("SELECT * FROM accounts WHERE id=?", (acct["id"],)))

    # ----------------------------------------------------------- notify relay
    RELAY_PER_DAY = 50

    def relay_notify(self, acct, kind: str, subject: str, body: str,
                     partner_email: Optional[str], partner_body: Optional[str]) -> dict:
        """v0.8.0: email a Mac's partner (and the account holder) on behalf of
        pax-guard's local escrow. The Mac decides who its partner is; the server
        only relays, at most RELAY_PER_DAY a day per account, and logs it."""
        import re as _re
        since = self.clock.now() - 86400
        row = self.db.one("SELECT COUNT(*) AS n FROM events WHERE account_id=? AND kind='notify_relayed' "
                          "AND at>=?", (acct["id"], since))
        if row and row["n"] >= self.RELAY_PER_DAY:
            raise RateLimited("too many notifications today; try again tomorrow")
        partner = (partner_email or "").strip().lower() or None
        if partner and not _re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}\.[a-z]{2,63}", partner):
            raise EscrowError("partner_email is not an email address")
        # v0.8.5: the partner's copy first and fail closed (503, PAX-ESCROW-010):
        # pax-guard keeps the action queued and retries. The account holder's copy
        # is best-effort and dropped first when the daily budget runs low.
        if partner:
            self._mail_partner(partner, kind, f"[Pax partner] {subject}", partner_body or body)
        self._mail(acct["email"], kind, subject, body)
        self._log(acct["id"], "notify_relayed", detail=f"{kind} partner={'yes' if partner else 'no'}")
        return {"relayed": True, "to_partner": bool(partner)}

    # ---------------------------------------------------------------- partner
    def set_partner(self, acct, partner_email: Optional[str]) -> dict:
        new = (partner_email or "").strip().lower() or None
        if new and new == acct["email"]:
            raise EscrowError("you cannot be your own accountability partner")
        current = acct["partner_email"]
        now = self.clock.now()
        if new == current:
            # Re-asserting the current partner cancels any pending change.
            self.db.execute(
                "UPDATE accounts SET pending_partner_email=NULL, pending_partner_effective=NULL "
                "WHERE id=?", (acct["id"],))
            self._log(acct["id"], "partner_change_cancelled")
        elif current is None:
            # Adding accountability is never delayed.
            self.db.execute(
                "UPDATE accounts SET partner_email=?, pending_partner_email=NULL, "
                "pending_partner_effective=NULL WHERE id=?", (new, acct["id"]))
            self._log(acct["id"], "partner_added", detail=new)
            # Adding accountability never waits on email.
            self._mail_partner(new, "partner_added", "You are now a Pax accountability partner",
                               f"{acct['email']} has made you their Pax accountability partner. "
                               "You will be told when they ask to remove their blocker. You "
                               "never need to approve anything; Pax is fully automatic.",
                               required=False)
        else:
            effective = now + acct["wait_seconds"]
            what = f"change your partner to {new}" if new else "remove your partner"
            # The current partner is told first: no email, no countdown.
            self._notify(
                acct, "partner_change_requested", "Partner change requested",
                f"You asked to {what}. This takes effect in {fmt_duration(acct['wait_seconds'])}.",
                f"{acct['email']} asked to "
                + (f"replace you with {new}" if new else "remove you")
                + f" as their Pax accountability partner. This takes effect in "
                  f"{fmt_duration(acct['wait_seconds'])}.",
            )
            self.db.execute(
                "UPDATE accounts SET pending_partner_email=?, pending_partner_effective=? "
                "WHERE id=?", (new or "", effective, acct["id"]))
            self._log(acct["id"], "partner_change_requested", detail=new or "(remove)")
        return self.account_status(self.db.one("SELECT * FROM accounts WHERE id=?", (acct["id"],)))

    # ------------------------------------------------------------ pax-guard
    def issue_guard_token(self, acct, device_id: str) -> str:
        d = self._device(acct, device_id)
        if d["platform"] != "mac":
            raise EscrowError("guard tokens are for self-locked Macs (platform 'mac')")
        token = new_token()
        self.db.execute("INSERT INTO guard_tokens(token_hash, device_id, created_at) VALUES (?,?,?)",
                        (hash_token(token), d["id"], self.clock.now()))
        self._log(acct["id"], "guard_token_issued", d["id"])
        return token

    def guard_device(self, token: Optional[str]):
        """(account, device) for a guard token, or Unauthorized."""
        if not token:
            raise Unauthorized("missing guard token")
        row = self.db.one("SELECT * FROM guard_tokens WHERE token_hash=?", (hash_token(token),))
        if not row:
            raise Unauthorized("invalid guard token")
        d = self.db.one("SELECT * FROM devices WHERE id=?", (row["device_id"],))
        acct = self._materialize(self.db.one("SELECT * FROM accounts WHERE id=?", (d["account_id"],)))
        return acct, d

    # ---------------------------------------------------------------- adblock
    def set_adblock(self, acct, enabled: bool) -> dict:
        """Ad/tracker blocking on self-locked Macs (pax-guard reads it). Not a
        protection against unwanted content, so both directions are immediate."""
        self.db.execute("UPDATE accounts SET adblock=? WHERE id=?", (1 if enabled else 0, acct["id"]))
        self._log(acct["id"], "adblock_on" if enabled else "adblock_off")
        return self.account_status(self.db.one("SELECT * FROM accounts WHERE id=?", (acct["id"],)))

    # ---------------------------------------------------------------- devices
    def register_device(self, acct, name: str, platform: str, profile_identifier: str,
                        removal_password: str) -> dict:
        # "mac" (v0.4) = a self-locked Mac: the escrowed secret is the hidden
        # paxadmin account's password, not a profile removal password.
        if platform not in ("ios", "ipados", "macos", "mac"):
            raise EscrowError("platform must be ios, ipados, macos or mac")
        if len(removal_password) < 20:
            raise EscrowError("removal password too short")
        device_id = _id()
        now = self.clock.now()
        ct = self.box.encrypt(removal_password, aad=device_id)
        self.db.execute(
            "INSERT INTO devices(id, account_id, name, platform, profile_identifier, "
            "password_ct, installed_at) VALUES (?,?,?,?,?,?,?)",
            (device_id, acct["id"], name, platform, profile_identifier, ct, now),
        )
        self._log(acct["id"], "device_registered", device_id, name)
        return self.device_status(acct, device_id)

    def _device(self, acct, device_id: str):
        row = self.db.one("SELECT * FROM devices WHERE id=? AND account_id=?",
                          (device_id, acct["id"]))
        if not row:
            raise NotFound("device not found")
        return row

    def _window_over(self, rr, installed_at: int, now: int) -> bool:
        """Has this request's window passed? Every request lapses once its
        reveal window ends. A pending grace request (no wait, made in the grace
        period) also lapses when the grace period ends (v0.8.5): otherwise a
        request made in the first hour stays a standing unlock for days. This
        covers requests made under an older, longer grace period too."""
        if now > rr["expires_at"]:
            return True
        return (rr["status"] == "pending" and rr["kind"] == "grace"
                and now >= installed_at + self.settings.grace_seconds)

    def _lapse(self, rr, account_id: str, now: int) -> None:
        self.db.execute(
            "UPDATE removal_requests SET status='lapsed', closed_at=? WHERE id=? AND status='pending'",
            (now, rr["id"]))
        self._log(account_id, "removal_lapsed", rr["device_id"], rr["kind"])

    def _active_request(self, device_id: str):
        """The open request for a device, lapsing it first if its window passed."""
        row = self.db.one(
            "SELECT rr.*, d.installed_at AS device_installed_at, d.account_id AS account_id "
            "FROM removal_requests rr JOIN devices d ON d.id=rr.device_id "
            "WHERE rr.device_id=? AND rr.status IN ('pending','revealed') "
            "ORDER BY rr.created_at DESC LIMIT 1", (device_id,))
        now = self.clock.now()
        if row and self._window_over(row, row["device_installed_at"], now):
            if row["status"] == "pending":
                self._lapse(row, row["account_id"], now)
            return None
        return row

    def lapse_due(self) -> int:
        """v0.8.5: lapse every pending request whose window has passed, so a
        stale request never sits as "pending" until someone looks. Called by the
        server's sweep. Returns how many lapsed."""
        now = self.clock.now()
        rows = self.db.all(
            "SELECT rr.*, d.installed_at AS device_installed_at, d.account_id AS account_id "
            "FROM removal_requests rr JOIN devices d ON d.id=rr.device_id "
            "WHERE rr.status='pending' AND (rr.expires_at<? OR (rr.kind='grace' AND d.installed_at+?<=?))",
            (now, self.settings.grace_seconds, now))
        n = 0
        for r in rows:
            if self._window_over(r, r["device_installed_at"], now):
                self._lapse(r, r["account_id"], now)
                n += 1
        return n

    def _request_view(self, rr) -> Optional[dict]:
        if not rr:
            return None
        now = self.clock.now()
        return {
            "request_id": rr["id"],
            "kind": rr["kind"],
            "status": rr["status"],
            "created_at": rr["created_at"],
            "unlock_at": rr["unlock_at"],
            "expires_at": rr["expires_at"],
            "seconds_remaining": max(0, rr["unlock_at"] - now),
            "can_reveal": rr["status"] in ("pending", "revealed") and now >= rr["unlock_at"],
        }

    def device_status(self, acct, device_id: str) -> dict:
        d = self._device(acct, device_id)
        now = self.clock.now()
        grace_until = d["installed_at"] + self.settings.grace_seconds
        return {
            "device_id": d["id"],
            "name": d["name"],
            "platform": d["platform"],
            "profile_identifier": d["profile_identifier"],
            "installed_at": d["installed_at"],
            "grace_until": grace_until,
            "in_grace_period": now < grace_until,
            "released_at": d["released_at"],
            "removal_request": self._request_view(self._active_request(d["id"])),
        }

    def list_devices(self, acct) -> list[dict]:
        rows = self.db.all("SELECT id FROM devices WHERE account_id=? ORDER BY installed_at",
                           (acct["id"],))
        return [self.device_status(acct, r["id"]) for r in rows]

    # ---------------------------------------------------------------- removal
    def request_removal(self, acct, device_id: str) -> dict:
        d = self._device(acct, device_id)
        if d["released_at"]:
            raise Conflict("this device's password has already been released")
        existing = self._active_request(device_id)
        if existing:
            raise Conflict("a removal request is already open",
                           removal_request=self._request_view(existing))
        now = self.clock.now()
        grace_until = d["installed_at"] + self.settings.grace_seconds
        in_grace = now < grace_until
        wait = 0 if in_grace else acct["wait_seconds"]
        kind = "grace" if in_grace else "standard"
        unlock_at = now + wait
        # A grace request can only be confirmed while the grace period lasts.
        expires_at = grace_until if in_grace else unlock_at + self.settings.reveal_window_seconds
        when = "now (grace period)" if in_grace else f"in {fmt_duration(wait)}"
        # Partner first (fail closed): if they can't be told, no countdown starts.
        self._notify(
            acct, "removal_requested", f"Removal requested for {d['name']}",
            f"You asked to remove Pax from {d['name']}. The password can be revealed {when}. "
            "You can cancel at any time before then.",
            f"{acct['email']} asked to remove Pax from {d['name']}. The password can be "
            f"revealed {when}. You might want to check in with them.",
        )
        rid = _id()
        self.db.execute(
            "INSERT INTO removal_requests(id, device_id, kind, status, created_at, unlock_at, "
            "expires_at) VALUES (?,?,?,?,?,?,?)",
            (rid, device_id, kind, "pending", now, unlock_at, expires_at))
        self._log(acct["id"], "removal_requested", device_id, kind)
        return self.device_status(acct, device_id)

    def cancel_removal(self, acct, device_id: str) -> dict:
        d = self._device(acct, device_id)
        rr = self._active_request(device_id)
        if not rr or rr["status"] != "pending":
            raise NotFound("no pending removal request")
        self.db.execute("UPDATE removal_requests SET status='cancelled', closed_at=? WHERE id=?",
                        (self.clock.now(), rr["id"]))
        self._log(acct["id"], "removal_cancelled", device_id)
        self._notify(acct, "removal_cancelled", f"Removal cancelled for {d['name']}",
                     f"You cancelled the removal request for {d['name']}. Well done.",
                     f"{acct['email']} cancelled their request to remove Pax from {d['name']}.",
                     required=False)
        return self.device_status(acct, device_id)

    def confirm_and_reveal(self, acct, device_id: str) -> dict:
        d = self._device(acct, device_id)
        rr = self._active_request(device_id)
        if not rr:
            lapsed = self.db.one(
                "SELECT 1 FROM removal_requests WHERE device_id=? AND status='lapsed'",
                (device_id,))
            if lapsed:
                raise Gone("the reveal window passed; make a new removal request")
            raise NotFound("no removal request; request removal first")
        now = self.clock.now()
        if now < rr["unlock_at"]:
            raise TooEarly(
                f"the wait has {fmt_duration(rr['unlock_at'] - now)} left",
                removal_request=self._request_view(rr))
        password = self.box.decrypt(d["password_ct"], aad=d["id"])
        if rr["status"] == "pending":
            # Partner first (fail closed): no email, no password.
            self._notify(acct, "password_revealed", f"Removal password released for {d['name']}",
                         f"The removal password for {d['name']} was revealed in the Pax app.",
                         f"{acct['email']} has been given the password to remove Pax from "
                         f"{d['name']}.")
            self.db.execute(
                "UPDATE removal_requests SET status='revealed', closed_at=? WHERE id=?",
                (now, rr["id"]))
            self.db.execute("UPDATE devices SET released_at=? WHERE id=?", (now, d["id"]))
            self._log(acct["id"], "password_revealed", device_id, rr["kind"])
        return {
            "device_id": d["id"],
            "profile_identifier": d["profile_identifier"],
            "removal_password": password,
            "revealed_at": now,
        }

    # -------------------------------------------------------------- emergency
    def emergency_release(self, acct, device_id: str, reason: str) -> dict:
        d = self._device(acct, device_id)
        reason = (reason or "").strip()
        if len(reason) < 10:
            raise EscrowError("please describe the emergency (at least 10 characters)",
                              crisis_lines=CRISIS_LINES)
        if d["released_at"]:
            raise Conflict("this device's password has already been released")
        now = self.clock.now()
        last = acct["last_emergency_at"]
        if last is not None and now - last < self.settings.emergency_min_interval_seconds:
            next_ok = last + self.settings.emergency_min_interval_seconds
            self._log(acct["id"], "emergency_refused_rate_limit", device_id, reason[:500])
            raise RateLimited(
                f"emergency release was used recently; next available in "
                f"{fmt_duration(next_ok - now)}. A normal removal request still works.",
                crisis_lines=CRISIS_LINES)
        grace_until = d["installed_at"] + self.settings.grace_seconds
        in_grace = now < grace_until
        cooloff = 0 if in_grace else self.settings.emergency_cooloff_seconds
        target_unlock = now + cooloff
        rr = self._active_request(device_id)
        unlock_at = min(rr["unlock_at"], target_unlock) if rr and rr["status"] == "pending" \
            else target_unlock
        # A no-wait emergency in the grace period closes with the grace period.
        expires_at = grace_until if in_grace else unlock_at + self.settings.reveal_window_seconds
        # Partner first (fail closed): if they can't be told, the cooling-off
        # doesn't start and the 90-day allowance isn't used up.
        if acct["partner_email"]:
            self._mail_partner(
                acct["partner_email"], "emergency_requested",
                "[Pax partner] Emergency release requested",
                f"{acct['email']} requested an emergency release of Pax on {d['name']}. It "
                f"unlocks in {fmt_duration(unlock_at - now)}. Please check in with them."
                f"\n\n{crisis_text()}",
            )
        if rr and rr["status"] == "pending":
            self.db.execute(
                "UPDATE removal_requests SET kind='emergency', reason=?, unlock_at=?, expires_at=? "
                "WHERE id=?", (reason[:2000], unlock_at, expires_at, rr["id"]))
        else:
            self.db.execute(
                "INSERT INTO removal_requests(id, device_id, kind, status, reason, created_at, "
                "unlock_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                (_id(), device_id, "emergency", "pending", reason[:2000], now, unlock_at,
                 expires_at))
        self.db.execute("UPDATE accounts SET last_emergency_at=? WHERE id=?", (now, acct["id"]))
        self._log(acct["id"], "emergency_requested", device_id, reason[:2000])
        # Best-effort; the crisis lines are in the response too.
        self._mail(
            acct["email"], "emergency_auto_reply", "Pax emergency release: we got your request",
            f"Your emergency release for {d['name']} will unlock in {fmt_duration(unlock_at - now)}."
            f"\n\n{crisis_text()}",
        )
        status = self.device_status(acct, device_id)
        status["crisis_lines"] = CRISIS_LINES
        status["message"] = crisis_text()
        return status
