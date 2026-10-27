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
  * Verified support release (v0.8.15, guard/support_code.py): a one-time code
    from Pax support, signed with the support key, for ONE device (its support
    ID), expiring within 24 hours. Checked: the device's switch, the signature,
    the device, the expiry, the nonce never used before. Then the partner is
    emailed FIRST (no email, no release) and the password is released to the
    owner at once, as confirming a finished request does. The switch is per
    device: on by default for new set-ups (the app sends the choice), off for
    devices registered before 0.8.15 (never turned on by a migration), off at
    once, on only after the account's wait with the partner told first.
  * Trial day (v0.8.18): a genuinely new set-up (the app asks for it and sends a
    hashed hardware ID) gets trial_seconds (24 h) in which turning Pax off needs no
    wait; the partner is still emailed first (fail closed). It replaces the 1-hour
    grace for that device. The day is counted from the FIRST trial start of the
    account and of the hardware (trial_hardware, kept for good), so setting up
    again, a new account on the same phone or reinstalling only ever gets what is
    left of that first day. Turning on verified support release is instant in the
    trial day (partner first). "Start my wait now" ends it early and lapses any
    no-wait request. Devices registered before 0.8.18 never have one.
"""
from __future__ import annotations

import logging
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, Optional

from .config import Settings
from .crypto import SecretBox, hash_token, new_token, token_matches
from .db import Database
from .limits import ACCOUNT, PARTNER, Limits
from .notify import CRISIS_LINES, Email, EmailSender, crisis_text

log = logging.getLogger("pax.escrow")

_GUARD = Path(__file__).resolve().parents[2] / "guard"
if str(_GUARD) not in sys.path:
    sys.path.append(str(_GUARD))   # support_code.py + ed25519.py (standard library only)


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


class AppUpdateRequired(EscrowError):
    """v0.8.32: POST /v1/accounts (account without a verified email) is retired for
    new accounts; the app must use /v1/accounts/email/*. Support code PAX-ESCROW-020."""
    status, code = 410, "app_update_required"


APP_UPDATE_REQUIRED_MESSAGE = (
    "This version of Pax can't make new accounts any more. Download the latest Pax from "
    "paxpeace.com (it checks your email with a 6-digit code), then set up again.")


class ChildWaitFixed(EscrowError):
    """v0.8.32: a child account's turn-off wait can't go below the child minimum
    (30 days by default). Support code PAX-ESCROW-021."""
    status, code = 403, "child_wait_fixed"


class ChildLimit(EscrowError):
    """v0.8.32: this parent address already looks after the most child accounts
    (5 by default). Support code PAX-ESCROW-022."""
    status, code = 429, "child_limit"


# v0.8.32 child accounts: accounts.email of a child row is a unique placeholder that
# can never receive mail (.invalid is reserved, RFC 2606) and never leaves the server.
CHILD_EMAIL_DOMAIN = "accounts.paxpeace.invalid"


def child_placeholder_email(account_id: str) -> str:
    return f"child.{account_id}@{CHILD_EMAIL_DOMAIN}"


def is_child(acct) -> bool:
    keys = acct.keys() if hasattr(acct, "keys") else ()
    return "kind" in keys and acct["kind"] == "child"


def holder_email(acct) -> Optional[str]:
    """Where an account's own mail goes: the parent for a child account, else its email."""
    if is_child(acct):
        return acct["parent_email"]
    return acct["email"]


class RateLimited(EscrowError):
    status, code = 429, "rate_limited"


class Unauthorized(EscrowError):
    status, code = 401, "unauthorized"


class DevicesStillProtected(Conflict):
    """v0.8.30: DELETE /v1/accounts/me while Pax still holds a device's key, or a
    turn-off wait / emergency release / other removal request is open (fail closed:
    deleting an account never skips the wait or the trusted person's email)."""
    status, code = 409, "devices_still_protected"


class PartnerUnreachable(EscrowError):
    """v0.8.5: the partner alert an action needs couldn't be sent, so the action
    didn't start (fail closed). Support code PAX-ESCROW-010."""
    status, code = 503, "partner_unreachable"


class SupportRefused(EscrowError):
    """v0.8.15: a verified support code that can't be used. `code` is the API
    error name; pax_errors.escrow_code maps it to PAX-ESCROW-012..019."""

    def __init__(self, pax_code: str, message: str):
        self.code, self.status = SUPPORT_ERRORS[pax_code]
        super().__init__(message)


# support_code.py's PAX code -> (API error name, HTTP status)
SUPPORT_ERRORS = {
    "PAX-ESCROW-012": ("support_code_malformed", 400),
    "PAX-ESCROW-013": ("support_code_unverified", 403),
    "PAX-ESCROW-014": ("support_code_wrong_device", 403),
    "PAX-ESCROW-015": ("support_code_expired", 410),
    "PAX-ESCROW-016": ("support_code_used", 409),
    "PAX-ESCROW-017": ("support_release_off", 403),
    "PAX-ESCROW-018": ("support_partner_unreachable", 503),
    "PAX-ESCROW-019": ("support_rate_limited", 429),
}
SUPPORT_TRIES_PER_HOUR = 10


def _id() -> str:
    return uuid.uuid4().hex


DISPLAY_NAME_MAX = 40


def clean_display_name(value: Optional[str], limit: int = DISPLAY_NAME_MAX) -> Optional[str]:
    """v0.8.31: a holder's first name for emails, or None when it isn't one. One
    line, stripped, at most `limit` characters, no control or format characters
    (that includes newlines and bidi overrides) and no links. main.py refuses a bad
    from_name with 422 before it gets here; this is the second line of defence for
    stored values."""
    import unicodedata
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return ""
    if len(v) > limit or any(unicodedata.category(c)[0] in ("C", "Z") and c != " " for c in v):
        return None
    low = v.lower()
    if "://" in low or "www." in low:
        return None
    return v


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
    # v0.8.26: (device row, account id) -> {"last_seen", "checking_in"} for iPhones and
    # iPads (pax_server/stats.py Stats.device_seen); None: not known on this server.
    seen: Optional[Callable] = None

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
        copy (best-effort). v0.8.32: on a child account the holder is the parent,
        who is told FIRST and, when required, fail closed like a partner."""
        if is_child(acct):
            # The trusted-person wording (it names the child), else the holder's.
            self._tell_parent(acct, kind, subject, partner_body or user_body, required=required)
        if acct["partner_email"]:
            self._mail_partner(acct["partner_email"], kind, f"[Pax partner] {subject}",
                               partner_body or user_body, required=required)
        if not is_child(acct):
            self._mail(acct["email"], kind, subject, user_body)

    def _tell_parent(self, acct, kind: str, subject: str, body: str, required: bool = True) -> bool:
        """v0.8.32: mail about a child account to its parent, before the action it
        announces; required=True raises PartnerUnreachable when it can't be sent."""
        if not is_child(acct):
            return False
        label = acct["label"] or "your child's device"
        return self._mail_partner(acct["parent_email"], kind, f"[Pax, {label}] {subject}", body, required=required)

    # v0.8.31: how emails to a trusted person name the account holder.
    ANONYMOUS_HOLDER = "Someone using Pax"

    @classmethod
    def who(cls, acct, mid: bool = False) -> str:
        """The account holder as emails to their trusted person name them: the first
        name they gave (display_name), else their email. Every account has an email
        (accounts.email is NOT NULL), so "Someone using Pax" is only a defensive
        fallback for a row without one; no email can ever say "None"."""
        keys = acct.keys() if hasattr(acct, "keys") else ()
        name = (acct["display_name"] if "display_name" in keys else None) or ""
        name = clean_display_name(name) or ""
        if name:
            return name
        if is_child(acct):          # v0.8.32: never the placeholder address
            return (acct["label"] or "").strip() or ("your child" if mid else "Your child")
        email = (acct["email"] if "email" in keys else None) or ""
        if email.strip():
            return email.strip()
        return "someone using Pax" if mid else cls.ANONYMOUS_HOLDER   # mid-sentence

    # --------------------------------------------------------------- accounts
    def refuse_unverified_signup(self, email: str) -> None:
        """v0.8.32: POST /v1/accounts no longer makes accounts. Nothing here writes an
        account row: the only creator is ListSync.email_verify (a code to the email)."""
        email = email.strip().lower()
        if self.db.one("SELECT 1 FROM accounts WHERE email=?", (email,)):
            raise Conflict("an account with this email already exists", sign_in=True)
        raise AppUpdateRequired(APP_UPDATE_REQUIRED_MESSAGE)

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
                                   f"{self.who(acct)} has made you their Pax accountability partner. "
                                   "You will be told when they ask to remove their blocker.",
                                   required=False)
            changed = True
        if changed:
            acct = self.db.one("SELECT * FROM accounts WHERE id=?", (acct["id"],))
        return acct

    def account_status(self, acct) -> dict:
        return {
            "account_id": acct["id"],
            "email": holder_email(acct),                    # v0.8.32: the parent's, for a child
            "kind": acct["kind"] if "kind" in acct.keys() else "adult",
            "label": acct["label"] if "label" in acct.keys() else None,
            "parent_email": acct["parent_email"] if "parent_email" in acct.keys() else None,
            "email_verified": acct["email_verified_at"] is not None,   # v0.8.31: a code to it has worked
            "display_name": acct["display_name"],        # v0.8.31: null unless given (from_name)
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
        # v0.8.32: a child account's wait never goes below the child minimum (30 days),
        # whatever the app asks for. Longer is allowed.
        if is_child(acct) and wait_seconds < s.child_wait_seconds:
            raise ChildWaitFixed(f"a child account's turn-off wait stays at least "
                                 f"{fmt_duration(s.child_wait_seconds)}")
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
                acct, "wait_decrease_requested", "Turn-off wait shortening requested",
                f"You asked to shorten your turn-off wait (how long turning Pax off takes after you ask) "
                f"from {fmt_duration(current)} to {fmt_duration(wait_seconds)}. It takes effect in "
                f"{fmt_duration(current)}.",
                f"{self.who(acct)} asked to shorten their Pax turn-off wait (how long turning Pax off "
                f"takes after they ask) from {fmt_duration(current)} to {fmt_duration(wait_seconds)}. "
                f"It takes effect in {fmt_duration(current)}.",
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
        self._mail(holder_email(acct), kind, subject, body)
        self._log(acct["id"], "notify_relayed", detail=f"{kind} partner={'yes' if partner else 'no'}")
        return {"relayed": True, "to_partner": bool(partner)}

    # ---------------------------------------------------------------- partner
    def set_partner(self, acct, partner_email: Optional[str], from_name: Optional[str] = None) -> dict:
        """from_name (v0.8.31, optional): the first name the trusted person's emails
        use for the holder (accounts.display_name, via who()). None leaves it as it
        is; "" clears it. Stored before any email below goes out."""
        new = (partner_email or "").strip().lower() or None
        if new and new == (holder_email(acct) or "").strip().lower():
            if is_child(acct):
                raise EscrowError("the parent already gets every email about this account; "
                                  "choose someone else or no one")
            raise EscrowError("you cannot be your own accountability partner")
        if from_name is not None:
            name = clean_display_name(from_name)
            if (name or None) != (acct["display_name"] or None):
                self.db.execute("UPDATE accounts SET display_name=? WHERE id=?", (name or None, acct["id"]))
                self._log(acct["id"], "display_name_set" if name else "display_name_cleared")
                acct = self.db.one("SELECT * FROM accounts WHERE id=?", (acct["id"],))
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
                               f"{self.who(acct)} has made you their Pax accountability partner. "
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
                f"{self.who(acct)} asked to "
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
                        removal_password: str, support_release: bool = False,
                        trial: bool = False, hardware_id: Optional[str] = None) -> dict:
        # "mac" (v0.4) = a self-locked Mac: the escrowed secret is the hidden
        # paxadmin account's password, not a profile removal password.
        if platform not in ("ios", "ipados", "macos", "mac"):
            raise EscrowError("platform must be ios, ipados, macos or mac")
        if len(removal_password) < 20:
            raise EscrowError("removal password too short")
        device_id = _id()
        now = self.clock.now()
        ct = self.box.encrypt(removal_password, aad=device_id)
        if is_child(acct):
            trial = False          # v0.8.32: no trial day (no turn-off without the wait) on a child account
        trial_until = self._trial_for_new_device(acct, now, hardware_id) if trial else None
        self.db.execute(
            "INSERT INTO devices(id, account_id, name, platform, profile_identifier, "
            "password_ct, installed_at, support_id, support_release, trial_until) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (device_id, acct["id"], name, platform, profile_identifier, ct, now,
             self._new_support_id(), 1 if support_release else 0, trial_until),
        )
        self._log(acct["id"], "device_registered", device_id, name)
        if trial:
            self._log(acct["id"], "trial_day", device_id,
                      f"until {trial_until}" if trial_until else "none (already had one)")
        self._log(acct["id"], "support_release_setting", device_id,
                  f"setup {'on' if support_release else 'off'}")
        return self.device_status(acct, device_id)

    def _device(self, acct, device_id: str):
        row = self.db.one("SELECT * FROM devices WHERE id=? AND account_id=? AND retired_at IS NULL",
                          (device_id, acct["id"]))
        if not row:
            raise NotFound("device not found")
        return self._support_materialize(acct, row)

    # ------------------------------------------------------ v0.8.18 trial day
    def _trial_for_new_device(self, acct, now: int, hardware_id: Optional[str]) -> Optional[int]:
        """The end of a new device's trial day, or None. Counted from the earliest
        of: this account's first trial start, this account's first device (an
        account from before 0.8.18 has long had its day) and this hardware's first
        trial start. Needs the hashed hardware ID, so a crafted or older client
        never gets one. Records both starts either way."""
        import hashlib
        if self.settings.trial_seconds <= 0:
            return None
        hw = (hardware_id or "").strip().lower()
        if not (16 <= len(hw) <= 128) or not all(c in "0123456789abcdef" for c in hw):
            return None
        starts = [now]
        if acct["trial_started_at"] is not None:
            starts.append(acct["trial_started_at"])
        first_dev = self.db.one("SELECT MIN(installed_at) AS t FROM devices WHERE account_id=?", (acct["id"],))
        if first_dev and first_dev["t"] is not None:
            starts.append(first_dev["t"])
        hw_hash = hashlib.sha256(("pax-trial-hw:" + hw).encode()).hexdigest()
        row = self.db.one("SELECT first_at FROM trial_hardware WHERE hw_hash=?", (hw_hash,))
        if row:
            starts.append(row["first_at"])
        else:
            self.db.execute("INSERT OR IGNORE INTO trial_hardware(hw_hash, first_at) VALUES (?,?)", (hw_hash, now))
        start = min(starts)
        if acct["trial_started_at"] is None:
            self.db.execute("UPDATE accounts SET trial_started_at=? WHERE id=? AND trial_started_at IS NULL",
                            (start, acct["id"]))
        until = start + self.settings.trial_seconds
        return until if until > now else None

    def _free_until(self, d) -> int:
        """Until when a removal on this device needs no wait: its trial day (or when
        it was ended early), else the first hour after registration."""
        grace_until = d["installed_at"] + self.settings.grace_seconds
        if d["trial_until"]:
            if d["trial_ended_at"]:
                return d["trial_ended_at"]
            return max(d["trial_until"], grace_until)
        return grace_until

    def _in_trial(self, d, now: int) -> bool:
        return bool(d["trial_until"]) and not d["trial_ended_at"] and now < d["trial_until"]

    def _trial_view(self, d, now: int) -> Optional[dict]:
        if not d["trial_until"]:
            return None
        return {"active": self._in_trial(d, now), "until": d["trial_until"], "ended_at": d["trial_ended_at"]}

    def end_trial(self, acct, device_id: str) -> dict:
        """"Start my wait now": the trial day ends at once and a no-wait request made
        in it lapses. Stricter, so it never waits on email."""
        d = self._device(acct, device_id)
        now = self.clock.now()
        if self._in_trial(d, now):
            self.db.execute("UPDATE devices SET trial_ended_at=? WHERE id=?", (now, d["id"]))
            rows = self.db.all("SELECT * FROM removal_requests WHERE device_id=? AND status='pending' "
                               "AND (kind IN ('trial','grace') OR expires_at<=?)", (d["id"], d["trial_until"]))
            for r in rows:
                self._lapse(r, acct["id"], now)
            self._log(acct["id"], "trial_ended_early", d["id"], f"{d['trial_until'] - now}s left")
        return self.device_status(acct, device_id)

    # ------------------------------------------------ v0.8.15 support release
    @staticmethod
    def _new_support_id() -> str:
        import support_code as sc
        return sc.new_support_id()

    def _support_materialize(self, acct, d):
        """Give an older device its support ID (the switch stays as it is: off for
        devices registered before 0.8.15), and apply a requested "on" whose wait is over."""
        changed = False
        if not d["support_id"]:
            self.db.execute("UPDATE devices SET support_id=? WHERE id=? AND support_id IS NULL",
                            (self._new_support_id(), d["id"]))
            changed = True
        if d["support_pending_on"] is not None and self.clock.now() >= d["support_pending_on"]:
            self.db.execute("UPDATE devices SET support_release=1, support_pending_on=NULL WHERE id=?", (d["id"],))
            self._log(acct["id"], "support_release_setting", d["id"], "on (applied after the wait)")
            changed = True
        return self.db.one("SELECT * FROM devices WHERE id=?", (d["id"],)) if changed else d

    def set_support_release(self, acct, device_id: str, allowed: bool) -> dict:
        """Off: at once. On: after the account's current wait, partner told first
        (fail closed, PAX-ESCROW-010), like shortening the wait. Only the device's
        owner can change it; nothing turns it on without the wait."""
        d = self._device(acct, device_id)
        if not allowed:
            self.db.execute("UPDATE devices SET support_release=0, support_pending_on=NULL WHERE id=?", (d["id"],))
            self._log(acct["id"], "support_release_setting", d["id"], "off")
            return self.device_status(acct, device_id)
        if d["support_release"] or d["support_pending_on"] is not None:
            return self.device_status(acct, device_id)
        if self._in_trial(d, self.clock.now()):
            # v0.8.18: in the trial day Pax can be turned off with no wait, so this is
            # instant too. The partner is still told first (no email, no change).
            self._notify(
                acct, "support_release_on", f"Verified support release turned on for {d['name']}",
                f"You turned on verified support release on {d['name']} (it's still your trial day).",
                f"{self.who(acct)} turned on verified support release on {d['name']}: in a genuine "
                "emergency that Pax support has checked, a one-time code could remove Pax from that device "
                "without the wait. You'd be emailed first.",
            )
            self.db.execute("UPDATE devices SET support_release=1, support_pending_on=NULL WHERE id=?", (d["id"],))
            self._log(acct["id"], "support_release_setting", d["id"], "on (trial day, instant)")
            return self.device_status(acct, device_id)
        wait = acct["wait_seconds"]
        self._notify(
            acct, "support_release_on_requested", f"Verified support release requested for {d['name']}",
            f"You asked to allow verified support release on {d['name']}. It takes effect in "
            f"{fmt_duration(wait)}.",
            f"{self.who(acct)} asked to allow verified support release on {d['name']}: in a genuine "
            "emergency that Pax support has checked, a one-time code could remove Pax from that device "
            f"without the wait. You'd be emailed first. This takes effect in {fmt_duration(wait)}.",
        )
        self.db.execute("UPDATE devices SET support_pending_on=? WHERE id=?", (self.clock.now() + wait, d["id"]))
        self._log(acct["id"], "support_release_setting", d["id"], f"on requested (after {wait}s)")
        return self.device_status(acct, device_id)

    def redeem_support(self, acct, device_id: str, code: str) -> dict:
        """A verified support code for this device: check everything, email the
        partner first (no email, no release), then release the password to the
        owner at once. Every refusal is logged on the server."""
        import support_code as sc
        d = self._device(acct, device_id)
        now = self.clock.now()

        def refuse(pax_code: str, message: str, detail: str = ""):
            self._log(acct["id"], "support_code_refused", d["id"], f"{pax_code} {detail}".strip())
            raise SupportRefused(pax_code, message)

        tries = self.db.one("SELECT COUNT(*) AS n FROM events WHERE device_id=? AND kind='support_code_refused' "
                            "AND at>=?", (d["id"], now - 3600))
        if tries and tries["n"] >= SUPPORT_TRIES_PER_HOUR:
            refuse(sc.TOO_MANY_TRIES, "too many support code tries; wait an hour")
        if not d["support_release"]:
            refuse(sc.TURNED_OFF, "verified support release is off on this device")
        try:
            c = sc.verify(code, d["support_id"], now)
        except sc.SupportCodeError as exc:
            refuse(exc.code, exc.message)
        if self.db.one("SELECT 1 FROM support_nonces WHERE nonce=?", (c["nonce"],)):
            refuse(sc.USED, "that code has already been used", c["nonce"])
        if d["released_at"]:
            raise Conflict("this device's password has already been released")
        try:
            self.db.execute("INSERT INTO support_nonces(nonce, device_id, used_at, expires_at, key_id) "
                            "VALUES (?,?,?,?,?)", (c["nonce"], d["id"], now, c["expires_at"], c["key_id"]))
        except sqlite3.IntegrityError:
            refuse(sc.USED, "that code has already been used", c["nonce"])
        try:
            self._tell_parent(acct, "support_release_used", f"Verified support release used for {d['name']}",
                              f"Pax support issued a one-time code for {d['name']} and it has just been used, "
                              "so the password to remove Pax from it is being released now.")
            if acct["partner_email"]:
                self._mail_partner(
                    acct["partner_email"], "support_release_used",
                    f"[Pax partner] Verified support release used for {d['name']}",
                    f"Pax support checked an emergency with {self.who(acct, mid=True)} and issued a one-time code for "
                    f"{d['name']}. It has just been used, so the password to remove Pax from {d['name']} is "
                    "being released now. You might want to check in with them.")
        except PartnerUnreachable:
            self.db.execute("DELETE FROM support_nonces WHERE nonce=?", (c["nonce"],))   # the code still works
            refuse(sc.PARTNER_UNREACHABLE, "Pax couldn't email your partner just now, so nothing was released. "
                   "The code still works until it expires; try again shortly.", c["nonce"])
        password = self.box.decrypt(d["password_ct"], aad=d["id"])
        self.db.execute("UPDATE removal_requests SET status='cancelled', closed_at=? "
                        "WHERE device_id=? AND status='pending'", (now, d["id"]))
        self.db.execute(
            "INSERT INTO removal_requests(id, device_id, kind, status, reason, created_at, unlock_at, "
            "expires_at, closed_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (_id(), d["id"], "support", "revealed", "verified support code", now, now,
             now + self.settings.reveal_window_seconds, now))
        self.db.execute("UPDATE devices SET released_at=? WHERE id=?", (now, d["id"]))
        self._log(acct["id"], "support_release_used", d["id"], f"nonce={c['nonce']} key={c['key_id']}")
        self._mail(holder_email(acct), "support_release_used", f"Verified support release used for {d['name']}",
                   f"You used a one-time code from Pax support. The password to remove Pax from {d['name']} "
                   "was released in the Pax app.")
        return {
            "device_id": d["id"],
            "profile_identifier": d["profile_identifier"],
            "removal_password": password,
            "revealed_at": now,
            "support_release": True,
        }

    def _window_over(self, rr, installed_at: int, now: int) -> bool:
        """Has this request's window passed? Every request lapses once its
        reveal window ends. A pending grace request (no wait, made in the grace
        period) also lapses when the grace period ends (v0.8.5): otherwise a
        request made in the first hour stays a standing unlock for days. This
        covers requests made under an older, longer grace period too."""
        if now > rr["expires_at"]:
            return True
        if rr["status"] == "pending" and rr["kind"] == "trial":
            return now >= rr["expires_at"]          # expires_at is the end of the trial day
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
            "WHERE rr.status='pending' AND (rr.expires_at<=? OR (rr.kind='grace' AND d.installed_at+?<=?))",
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
        grace_until = self._free_until(d)
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
            # v0.8.15: Details › Support ID, and the "Allow verified support release" switch.
            "support_id": d["support_id"],
            "support_release": {"allowed": bool(d["support_release"]),
                                "pending_on_at": d["support_pending_on"]},
            # v0.8.16: the account's turn-off wait, for the app's "Turn-off wait: 7 days" row.
            "wait_seconds": acct["wait_seconds"],
            # v0.8.18: {"active", "until", "ended_at"}, or None (no trial day).
            "trial": self._trial_view(d, now),
            # v0.8.21: the emergency release cooling-off, for "turns off after 24 hours".
            "emergency_cooloff_seconds": self.settings.emergency_cooloff_seconds,
            # v0.8.26: plainly whether the password was released (by a finished turn-off
            # wait, an emergency or trial-day turn-off, or a support code), so the app
            # never shows "Protected" for a device Pax no longer holds.
            "released": d["released_at"] is not None,
            # v0.8.26 (iPhone/iPad, owner only): the last UTC day the account's Pax DNS
            # address was used, and whether it has been used in the last 48 hours or so
            # (None: Pax can't tell). Day granularity; no time, address or lookup.
            **self._seen_view(d),
        }

    def _seen_view(self, d) -> dict:
        out = {"last_seen": None, "checking_in": None}
        if self.seen is None:
            return out
        try:
            got = self.seen(d, d["account_id"]) or {}
        except Exception:  # noqa: BLE001 - a status read never fails on this
            log.exception("last-seen lookup failed")
            return out
        out["last_seen"] = got.get("last_seen")
        out["checking_in"] = got.get("checking_in")
        return out

    def list_devices(self, acct) -> list[dict]:
        rows = self.db.all("SELECT id FROM devices WHERE account_id=? AND retired_at IS NULL "
                           "ORDER BY installed_at", (acct["id"],))
        return [self.device_status(acct, r["id"]) for r in rows]

    def retire_device(self, acct, device_id: str) -> dict:
        """v0.8.26 "Remove from list" for a device Pax is already off on: the owner's
        list forgets it. Allowed ONLY when the device's password was already released,
        so it can never turn protection off or shorten a wait. Logged either way; the
        row stays (retired_at) for the event history."""
        row = self.db.one("SELECT * FROM devices WHERE id=? AND account_id=?", (device_id, acct["id"]))
        if not row:
            raise NotFound("device not found")
        if row["retired_at"] is not None:
            return {"device_id": row["id"], "retired": True, "retired_at": row["retired_at"]}
        if row["released_at"] is None:
            self._log(acct["id"], "device_retire_refused", device_id, "not released")
            raise Conflict("Pax is still on this device, so it stays on your account. "
                           "Use the turn-off wait first.")
        now = self.clock.now()
        cur = self.db.execute("UPDATE devices SET retired_at=? WHERE id=? AND account_id=? "
                              "AND released_at IS NOT NULL AND retired_at IS NULL",
                              (now, device_id, acct["id"]))
        if cur.rowcount != 1:
            raise Conflict("this device changed; try again")
        try:   # its last-seen day goes too (v0.8.24 activity table, when this server keeps one)
            self.db.execute("DELETE FROM activity WHERE subject=?", (f"device:{device_id}",))
        except sqlite3.OperationalError:
            pass
        self._log(acct["id"], "device_retired", device_id)
        return {"device_id": device_id, "retired": True, "retired_at": now}

    # ------------------------------------------------ v0.8.30 delete account
    DELETE_TRIES_PER_HOUR = 10
    # A deleted account leaves one dns_changes row (its random ID, a sequence number
    # and a time; nothing else) so the DNS servers drop it at their next 3-second
    # poll instead of the next 10-minute full sync. Pruned after this long.
    DELETED_TOMBSTONE_SECONDS = 3600
    # Every table holding one account's rows, children first (no ON DELETE CASCADE,
    # PRAGMA foreign_keys=ON). activity (stats.py) is keyed by subject.
    _DELETE_SQL = (
        ("guard_tokens", "DELETE FROM guard_tokens WHERE device_id IN (SELECT id FROM devices WHERE account_id=:a)"),
        ("removal_requests", "DELETE FROM removal_requests WHERE device_id IN "
                             "(SELECT id FROM devices WHERE account_id=:a)"),
        ("activity", "DELETE FROM activity WHERE subject IN (SELECT 'device:' || id FROM devices WHERE account_id=:a) "
                     "OR subject IN (SELECT 'link:' || id FROM sync_links WHERE account_id=:a) "
                     "OR subject = 'dns-account:' || :a"),
        ("devices", "DELETE FROM devices WHERE account_id=:a"),
        ("blocklist_entries", "DELETE FROM blocklist_entries WHERE account_id=:a"),
        ("blocklist_requests", "DELETE FROM blocklist_requests WHERE account_id=:a"),
        ("dns_tokens", "DELETE FROM dns_tokens WHERE account_id=:a"),
        ("dns_changes", "DELETE FROM dns_changes WHERE account_id=:a"),
        ("sync_links", "DELETE FROM sync_links WHERE account_id=:a"),
        ("account_tokens", "DELETE FROM account_tokens WHERE account_id=:a"),
        ("signin_codes", "DELETE FROM signin_codes WHERE account_id=:a"),
        ("events", "DELETE FROM events WHERE account_id=:a"),
        ("accounts", "DELETE FROM accounts WHERE id=:a"),
    )

    def _still_protected(self, account_id: str) -> list[dict]:
        """Devices that stop an account being deleted. The same rule as
        work/v0830 delete_check.sql (released_at IS NULL: Pax still holds the key,
        whether or not the phone is checking in), plus any open removal request
        (a turn-off wait, an emergency release, a trial/grace/support request).
        Released and retired devices are safe."""
        out = []
        for d in self.db.all("SELECT * FROM devices WHERE account_id=? ORDER BY installed_at", (account_id,)):
            rr = self.db.one("SELECT kind FROM removal_requests WHERE device_id=? AND status='pending' "
                             "ORDER BY created_at DESC LIMIT 1", (d["id"],))
            if d["released_at"] is None:
                reason = ("emergency_release" if rr and rr["kind"] == "emergency"
                          else "turn_off_wait" if rr else "pax_on")
            elif rr:
                reason = "pending_request"          # shouldn't happen; fail closed anyway
            else:
                continue
            item = {"device_id": d["id"], "name": d["name"], "platform": d["platform"],
                    "reason": reason, "removal_request": rr["kind"] if rr else None,
                    "checking_in": None}
            if d["released_at"] is None:
                item["checking_in"] = self._seen_view(d)["checking_in"]
            out.append(item)
        return out

    def delete_account(self, acct) -> dict:
        """v0.8.30 DELETE /v1/accounts/me. Refuses (409 devices_still_protected) while
        any device is still protected; otherwise deletes every row of the account in
        one transaction, then emails the holder a confirmation (best-effort: a failed
        email never undoes it). The trusted person is not emailed. Returns what the
        caller needs to forget in memory (stats subjects, DNS token hashes)."""
        aid = acct["id"]
        now = self.clock.now()
        tries = self.db.one("SELECT COUNT(*) FROM events WHERE account_id=? AND kind='account_delete_refused' "
                            "AND at>?", (aid, now - 3600))[0]
        if tries >= self.DELETE_TRIES_PER_HOUR:
            raise RateLimited("too many tries to delete this account in the last hour; try again later")
        # Lapse requests whose window has passed first, so a stale "pending" row
        # doesn't block a device that was really turned off long ago.
        for rr in self.db.all("SELECT rr.*, d.installed_at AS device_installed_at FROM removal_requests rr "
                              "JOIN devices d ON d.id=rr.device_id WHERE d.account_id=? AND rr.status='pending'",
                              (aid,)):
            if self._window_over(rr, rr["device_installed_at"], now):
                self._lapse(rr, aid, now)
        blocked: list[dict] = []
        gone: dict = {}
        with self.db.transaction():
            row = self.db.one("SELECT * FROM accounts WHERE id=?", (aid,))
            if row is None:
                raise Unauthorized("invalid token")
            blocked = self._still_protected(aid)
            if not blocked:
                email = holder_email(row)          # v0.8.32: the parent, for a child account
                gone = {
                    "subjects": [f"device:{r[0]}" for r in self.db.all(
                        "SELECT id FROM devices WHERE account_id=?", (aid,))]
                    + [f"link:{r[0]}" for r in self.db.all("SELECT id FROM sync_links WHERE account_id=?", (aid,))]
                    + [f"dns-account:{aid}"],
                    "dns_hashes": [r[0] for r in self.db.all(
                        "SELECT token_hash FROM dns_tokens WHERE account_id=?", (aid,))],
                    "devices": self.db.one("SELECT COUNT(*) FROM devices WHERE account_id=?", (aid,))[0],
                }
                for table, sql in self._DELETE_SQL:
                    try:
                        self.db.execute(sql, {"a": aid})
                    except sqlite3.OperationalError:
                        if table != "activity":     # only stats.py's table can be absent
                            raise
                # Tombstone for the DNS feeds (see DELETED_TOMBSTONE_SECONDS).
                self.db.execute("INSERT INTO dns_changes(account_id, at) VALUES (?,?)", (aid, now))
        if blocked:
            n = len(blocked)
            self._log(aid, "account_delete_refused", detail=f"{n} device(s) still protected")
            raise DevicesStillProtected(
                f"Pax is still on {n} device{'s' if n != 1 else ''} on this account. Turn Pax off on "
                "every device first (your turn-off wait and the email to your trusted person apply as "
                "usual), then delete your account.",
                count=n, devices=blocked)
        log.info("account deleted (%d device(s))", gone["devices"])
        sent = self._mail(email, "account_deleted", "Your Pax account has been deleted",
                          "Your Pax account has been deleted, as you asked. Your devices, blocked "
                          "sites, history and sign-ins have been removed from Pax's server, and the "
                          "app's sign-in no longer works.\n\n"
                          "If you didn't ask for this, or you'd like to use Pax again, you can set up "
                          "a new account at any time. Reply to this email if you have any questions."
                          "\n\nPax")
        if not sent:
            log.warning("email[account_deleted] confirmation not sent (the account is deleted)")
        self.prune_deleted()
        return gone

    def prune_deleted(self, force: bool = False) -> int:
        """Drop deleted accounts' DNS-feed tombstones once they're old (at most
        every 10 minutes from the sweep; the scan is over dns_changes)."""
        now = self.clock.now()
        last = getattr(self, "_last_prune", None)
        if not force and last is not None and now - last < 600:
            return 0
        self._last_prune = now
        cur = self.db.execute("DELETE FROM dns_changes WHERE at<? AND account_id NOT IN (SELECT id FROM accounts)",
                              (now - self.DELETED_TOMBSTONE_SECONDS,))
        return cur.rowcount or 0

    # ------------------------------------------------ v0.8.31 replace escrow
    def replace_escrow(self, acct, device_id: str, removal_password: str) -> dict:
        """v0.8.31 PUT /v1/devices/{id}/escrow: replace the secret Pax holds for one of
        the account's devices (the iPhone app adds the Screen Time passcode from Home
        after one-tap set-up). Re-encrypted with aad=device_id like registration.
        It never loosens anything: the secret is only ever revealed when a finished
        wait (or emergency / support release) releases it. Refused (409) once the
        device is released or retired, or while a removal request or emergency
        release is open, so a request in flight always reveals the secret it was
        made for. Logged as escrow_replaced (never the secret)."""
        if len(removal_password or "") < 20 or len(removal_password) > 256:
            raise EscrowError("removal password must be 20 to 256 characters")
        refusal = None          # (log detail, Conflict) raised after the transaction, so the log stays
        with self.db.transaction():
            row = self.db.one("SELECT * FROM devices WHERE id=? AND account_id=?", (device_id, acct["id"]))
            if not row:
                raise NotFound("device not found")
            if row["retired_at"] is not None:
                refusal = ("retired", Conflict("this device was removed from your list", reason="retired"))
            elif row["released_at"] is not None:
                refusal = ("released", Conflict("this device's password has already been released",
                                                reason="released"))
            else:
                rr = self._active_request(device_id)
                if rr:
                    why = "emergency_open" if rr["kind"] == "emergency" else "removal_request_open"
                    refusal = (why, Conflict(
                        "a turn-off request is open on this device; cancel it (or let it finish) first",
                        reason=why, removal_request=self._request_view(rr)))
            if refusal is None:
                ct = self.box.encrypt(removal_password, aad=row["id"])
                cur = self.db.execute("UPDATE devices SET password_ct=? WHERE id=? AND account_id=? "
                                      "AND released_at IS NULL AND retired_at IS NULL",
                                      (ct, row["id"], acct["id"]))
                if cur.rowcount != 1:
                    refusal = ("changed", Conflict("this device changed; try again", reason="changed"))
                else:
                    self._log(acct["id"], "escrow_replaced", row["id"])
        if refusal is not None:
            self._log(acct["id"], "escrow_replace_refused", device_id, refusal[0])
            raise refusal[1]
        return self.device_status(acct, device_id)

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
        grace_until = self._free_until(d)
        in_grace = now < grace_until
        in_trial = self._in_trial(d, now)
        wait = 0 if in_grace else acct["wait_seconds"]
        kind = "trial" if in_trial else "grace" if in_grace else "standard"
        unlock_at = now + wait
        # A grace request can only be confirmed while the grace period lasts.
        expires_at = grace_until if in_grace else unlock_at + self.settings.reveal_window_seconds
        # v0.8.16: plain words for the wait (new users found "the wait" confusing).
        when = ("straight away (it's still the trial day after set-up)" if in_trial
                else "straight away (it's still the first hour after set-up)" if in_grace
                else f"in {fmt_duration(wait)}, when the turn-off wait ends")
        # Partner first (fail closed): if they can't be told, no countdown starts.
        self._notify(
            acct, "removal_requested", f"Removal requested for {d['name']}",
            f"You asked to turn Pax off on {d['name']}. It can be turned off {when}. "
            "You can cancel any time during the wait.",
            f"{self.who(acct)} asked to turn Pax off on {d['name']}. It can be turned off "
            f"{when}. You might want to check in with them.",
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
                     f"{self.who(acct)} cancelled their request to remove Pax from {d['name']}.",
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
                         f"{self.who(acct)} has been given the password to remove Pax from "
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
        grace_until = self._free_until(d)
        in_grace = now < grace_until
        cooloff = 0 if in_grace else self.settings.emergency_cooloff_seconds
        target_unlock = now + cooloff
        rr = self._active_request(device_id)
        unlock_at = min(rr["unlock_at"], target_unlock) if rr and rr["status"] == "pending" \
            else target_unlock
        # A no-wait emergency in the grace period closes with the grace period.
        expires_at = grace_until if in_grace else unlock_at + self.settings.reveal_window_seconds
        # Partner first (fail closed): if they can't be told, the cooling-off
        # doesn't start and the 90-day allowance isn't used up. v0.8.32: a child
        # account's parent is told first, the same way.
        self._tell_parent(acct, "emergency_requested", "Emergency release requested",
                          f"An emergency release of Pax was requested on {d['name']}. It unlocks in "
                          f"{fmt_duration(unlock_at - now)}. Please check in with your child.\n\n{crisis_text()}")
        if acct["partner_email"]:
            self._mail_partner(
                acct["partner_email"], "emergency_requested",
                "[Pax partner] Emergency release requested",
                f"{self.who(acct)} requested an emergency release of Pax on {d['name']}. It "
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
        if not is_child(acct):          # v0.8.32: the parent already got the email above
            self._mail(
                acct["email"], "emergency_auto_reply", "Pax emergency release: we got your request",
                f"Your emergency release for {d['name']} will unlock in {fmt_duration(unlock_at - now)}."
                f"\n\n{crisis_text()}",
            )
        status = self.device_status(acct, device_id)
        status["crisis_lines"] = CRISIS_LINES
        status["message"] = crisis_text()
        return status
