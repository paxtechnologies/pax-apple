# SPDX-License-Identifier: GPL-3.0-only
"""The user's own blocked sites, kept by pax-guard when the Mac uses local
escrow (v0.8.0), so the Mac needs no server.

Same rules as the server (server/pax_server/blocklist.py): adding a site is
instant; removing one, or adding an exception (a site Pax's lists block that
you want back), waits as long as the removal wait and can be cancelled. The
JSON it returns has the server's shape (`BlocklistView` in PaxCore), so the
app shows either the same way.

v0.8.1: an exception can't be asked for a site in a category Pax always
blocks (restricted content, media converters, or anything CleanBrowsing
Family blocks): `request_allow` refuses it with PAX-DNS-010 before any wait
starts or any partner email goes out. pax-guard passes the check in as
`restricted_check` (raises) and `restricted_static` (no network, used again
when a wait ends).

v0.8.7: the same file keeps the user's blocked Mac apps ("apps", keyed by bundle
ID; pax_guard.py enforces them). Adding one is instant; unblocking one is a
loosening, so it goes through exactly the path an unblocked site does: your wait,
your partner told first (fail closed), cancellable (action "unblock_app").

v0.8.12: Pax Max (the image blur chosen at set-up) can be switched after set-up.
Turning it on is instant. Turning it off is a loosening, so it goes through the
same path: your partner told first (fail closed), cancellable, applied only when
its time is up. Its wait is a fixed hour (PAX_MAX_OFF_SECONDS, the project's rule,
2026-10-16), not your own wait (action "pax_max_off", key "pax-max").

Stored in /Library/PaxGuard/state/blocklist.json (root 0600; the state folder
is root 0700). Pending changes apply when the wall clock is past their time
and, if network time is known, that agrees too.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

MAX_BLOCKED = 2000
MAX_ALLOWED = 200
MAX_APPS = 200          # v0.8.7 (guard_config.MAX_BLOCKED_APPS)
SITE_ACTIONS = ("unblock", "allow")
PAX_MAX_KEY = "pax-max"           # v0.8.12: the "domain" of a pax_max_off request
PAX_MAX_OFF_SECONDS = 3600        # v0.8.12: turning Pax Max off waits a fixed hour
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$")


RESTRICTED_CODE = "PAX-DNS-010"
RESTRICTED_MESSAGE = "This site is in a category Pax always blocks, so it can't be allowed."


class BlocklistError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def normalise(raw: str) -> str:
    s = (raw or "").strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = re.split(r"[/?#]", s, 1)[0].split("@")[-1].split(":")[0].strip(".")
    if s.startswith("*."):
        s = s[2:]
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise BlocklistError("PAX-DNS-009", "that isn't a website address") from None
    if not _DOMAIN.match(s) or all(p.isdigit() for p in s.split(".")):
        raise BlocklistError("PAX-DNS-009", "that isn't a website address")
    return s


class LocalBlocklist:
    def __init__(self, path: Path, wait_seconds=lambda: 72 * 3600, clock=time.time,
                 trusted_time=lambda: None, partner=None, restricted_check=None, restricted_static=None,
                 on_applied=None):
        self.path = Path(path)
        self.wait_seconds = wait_seconds
        self.clock = clock
        self.trusted_time = trusted_time
        self.partner = partner          # partner.PartnerNotifier (v0.8 accountability emails) or None
        # v0.8.1: callable(domain) raising for a site Pax always blocks (may look
        # the name up upstream), and callable(domain) -> bool without the network.
        self.restricted_check = restricted_check
        self.restricted_static = restricted_static
        self._lock = threading.RLock()
        # v0.8.12: callable(request) after a waited change took effect (tamper log).
        self.on_applied = on_applied

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text())
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {"blocked": {}, "allowed": {}, "pending": []}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(data, sort_keys=True).encode())
        finally:
            os.close(fd)
        os.replace(tmp, self.path)

    def _due(self, effective_at: int) -> bool:
        now = self.clock()
        if now < effective_at:
            return False
        trusted = self.trusted_time()
        return trusted is None or trusted + 300 >= effective_at

    def apply_due(self) -> list[str]:
        """Carry out waits that are over. Returns what changed."""
        with self._lock:
            data = self._load()
            done, keep = [], []
            applied = []
            changed_only = False
            for r in data["pending"]:
                if r["status"] == "notifying":
                    keep.append(r)
                elif r["status"] == "pending" and self._due(r["effective_at"]):
                    if (r["action"] == "allow" and self.restricted_static is not None
                            and self.restricted_static(r["domain"])):
                        r["status"] = "refused"      # became restricted during the wait
                        changed_only = True
                        continue
                    if r["action"] == "unblock":
                        data["blocked"].pop(r["domain"], None)
                    elif r["action"] == "unblock_app":
                        data.setdefault("apps", {}).pop(r["domain"], None)
                        done.append(f"unblock the app {r.get('label') or r['domain']}")
                        continue
                    elif r["action"] == "pax_max_off":
                        data["pax_max"] = False
                        done.append("turn off Pax Max")
                        applied.append(r)
                        continue
                    elif r["action"] == "allow":
                        data["allowed"][r["domain"]] = {"added_at": int(self.clock())}
                    done.append(f"{r['action']} {r['domain']}")
                elif r["status"] == "pending":
                    keep.append(r)
            if done or changed_only:
                data["pending"] = keep
                self._save(data)
        for r in applied:
            if self.on_applied is not None:
                try:
                    self.on_applied(r)
                except Exception:  # noqa: BLE001 - the change itself is saved
                    pass
        if done and self.partner and self.partner.partner():
            self.partner.notify("blocklist_change_applied", "Pax: change now in effect",
                                "Your change is now in effect: " + ", ".join(done) + ".",
                                "Your Pax partner's change is now in effect: " + ", ".join(done) + ".")
        return done

    def entries(self) -> dict:
        """v0.8.9: blocked sites with when each was added here (for sync)."""
        return dict(self._load()["blocked"])

    def add_synced(self, d: str) -> None:
        """v0.8.9: a site from the account's synced list: blocked here at once."""
        self.add(d)

    def remove_synced(self, d: str) -> None:
        """v0.8.9: the account's removal of this site took effect (after the wait,
        with the partner told first, on the server). Only list_sync calls this."""
        with self._lock:
            data = self._load()
            data["blocked"].pop(d, None)
            for r in data["pending"]:
                if r["domain"] == d and r["action"] == "unblock" and r["status"] in ("pending", "notifying"):
                    r["status"] = "applied_by_sync"
            self._save(data)

    def blocked(self) -> list[str]:
        return sorted(self._load()["blocked"])

    def allowed(self) -> list[str]:
        return sorted(self._load()["allowed"])

    # ------------------------------------------------------------- the view
    def view(self) -> dict:
        self.apply_due()
        with self._lock:
            data = self._load()
            now = int(self.clock())
            pending = [self._req_view(r, now) for r in data["pending"]
                       if r["status"] in ("pending", "notifying") and r["action"] in SITE_ACTIONS]
            by_domain = {p["domain"]: p for p in pending if p["action"] == "unblock"}
            return {
                "now": now,
                "blocked": [{"domain": d, "display_domain": d, "added_at": v.get("added_at", 0),
                             "pending_removal": by_domain.get(d)} for d, v in sorted(data["blocked"].items())],
                "allowed": [{"domain": d, "display_domain": d, "added_at": v.get("added_at", 0)}
                            for d, v in sorted(data["allowed"].items())],
                "pending": pending,
                "limits": {"max_blocked": MAX_BLOCKED, "max_allowed": MAX_ALLOWED,
                           "delay_seconds": int(self.wait_seconds())},
            }

    @staticmethod
    def _req_view(r: dict, now: int) -> dict:
        return {"request_id": r["id"], "action": r["action"], "domain": r["domain"],
                "display_domain": r.get("label") or r["domain"], "status": r["status"],
                "created_at": r["created_at"],
                "effective_at": r["effective_at"], "seconds_remaining": max(0, r["effective_at"] - now)}

    # ------------------------------------------------------ v0.8.7 Mac apps
    def apps(self) -> dict:
        self.apply_due()
        return dict(self._load().get("apps", {}))

    def apps_view(self) -> dict:
        self.apply_due()
        with self._lock:
            data = self._load()
            now = int(self.clock())
            pending = [self._req_view(r, now) for r in data["pending"]
                       if r["status"] in ("pending", "notifying") and r["action"] == "unblock_app"]
            by_id = {p["domain"]: p for p in pending}
            apps = [{"bundle_id": b, "name": v.get("name") or b, "team_id": v.get("team_id", ""),
                     "added_at": v.get("added_at", 0), "pending_removal": by_id.get(b)}
                    for b, v in sorted(data.get("apps", {}).items(), key=lambda kv: (kv[1].get("name") or kv[0]).lower())]
            return {"now": now, "apps": apps, "pending": pending,
                    "limits": {"max_apps": MAX_APPS, "delay_seconds": int(self.wait_seconds())}}

    def add_app(self, entry: dict) -> dict:
        """Instant (it makes Pax stricter). Blocking it again cancels a pending unblock."""
        bid = str(entry.get("bundle_id") or "")
        if not bid:
            raise BlocklistError("PAX-MAC-017", "Pax couldn't read that app")
        with self._lock:
            data = self._load()
            apps = data.setdefault("apps", {})
            created = bid not in apps
            if created and len(apps) >= MAX_APPS:
                raise BlocklistError("PAX-MAC-017", f"your list is full ({MAX_APPS} apps)")
            apps[bid] = {k: v for k, v in entry.items() if k != "bundle_id"} if created else apps[bid]
            for r in data["pending"]:
                if r["domain"] == bid and r["action"] == "unblock_app" and r["status"] == "pending":
                    r["status"] = "cancelled"
            self._save(data)
        return {"bundle_id": bid, "created": created, "apps": self.apps_view()}

    def request_unblock_app(self, bundle_id: str) -> dict:
        apps = self._load().get("apps", {})
        if bundle_id not in apps:
            raise BlocklistError("PAX-MAC-017", "that app isn't on your list")
        out = self._request("unblock_app", bundle_id, label=apps[bundle_id].get("name") or bundle_id)
        return {"request": out["request"], "apps": self.apps_view()}

    # -------------------------------------------------------------- actions
    def add(self, raw: str) -> dict:
        d = normalise(raw)
        with self._lock:
            data = self._load()
            created = d not in data["blocked"]
            if created:
                if len(data["blocked"]) >= MAX_BLOCKED:
                    raise BlocklistError("PAX-DNS-009", f"your list is full ({MAX_BLOCKED} sites)")
                data["blocked"][d] = {"added_at": int(self.clock())}
                # Blocking a site again cancels a pending unblock of it.
                for r in data["pending"]:
                    if r["domain"] == d and r["action"] == "unblock" and r["status"] == "pending":
                        r["status"] = "cancelled"
                self._save(data)
        return {"domain": d, "created": created, "list": self.view()}

    # ---------------------------------------------------- v0.8.12 Pax Max
    def pax_max(self, default: bool) -> bool:
        """Pax Max in effect: the last switch here, else the set-up choice."""
        self.apply_due()
        v = self._load().get("pax_max")
        return v if isinstance(v, bool) else bool(default)

    def pax_max_pending(self) -> dict | None:
        """The waiting (or partner-notifying) request to turn Pax Max off, if any."""
        self.apply_due()
        now = int(self.clock())
        for r in self._load()["pending"]:
            if r["action"] == "pax_max_off" and r["status"] in ("pending", "notifying"):
                return self._req_view(r, now)
        return None

    def pax_max_on(self) -> bool:
        """Instant (it makes Pax stricter). Also cancels a waiting request to turn it
        off (no partner email needed: nothing is loosened). Returns True if it was off."""
        with self._lock:
            data = self._load()
            was = data.get("pax_max")
            data["pax_max"] = True
            gates = []
            for r in data["pending"]:
                if r["action"] == "pax_max_off" and r["status"] in ("pending", "notifying"):
                    if r["status"] == "notifying":
                        gates.append(r["id"])
                    r["status"] = "cancelled"
            self._save(data)
        for rid in gates:
            if self.partner:
                self.partner.drop_gate({"type": "blocklist", "id": rid})
        return was is not True

    def request_pax_max_off(self) -> dict:
        """A loosening: the partner first (fail closed), then a fixed hour."""
        out = self._request("pax_max_off", PAX_MAX_KEY, label="Pax Max", delay=PAX_MAX_OFF_SECONDS)
        return {"request": out["request"]}

    def _request(self, action: str, d: str, label: str | None = None, delay: int | None = None) -> dict:
        with self._lock:
            data = self._load()
            for r in data["pending"]:
                if r["domain"] == d and r["action"] == action and r["status"] == "pending":
                    return {"request": self._req_view(r, int(self.clock())), "list": self.view()}
            now = int(self.clock())
            has_partner = bool(self.partner and self.partner.partner())
            wait = int(delay) if delay else int(self.wait_seconds())
            r = {"id": secrets.token_hex(8), "action": action, "domain": d,
                 "status": "notifying" if has_partner else "pending",
                 "created_at": now, "effective_at": now + wait}
            if label:
                r["label"] = label
            if delay:
                r["delay"] = int(delay)
            data["pending"].append(r)
            self._save(data)
        if has_partner:
            what = {"unblock": f"unblock {d}", "unblock_app": f"unblock the app {label or d}",
                    "pax_max_off": "turn off Pax Max (the image blur)"}.get(
                action, f"allow {d} (a site Pax blocks)")
            when_you = "in 1 hour" if action == "pax_max_off" else "after your turn-off wait"
            when_they = "in 1 hour" if action == "pax_max_off" else "after their turn-off wait"
            ok = self.partner.notify(
                f"blocklist_{action}_requested", "Pax: change requested",
                f"You asked to {what}. It takes effect {when_you}; you can cancel before then.",
                f"Your Pax partner asked to {what}. It takes effect {when_they}.",
                gate={"type": "blocklist", "id": r["id"]})
            if not ok:
                raise BlocklistError("PAX-ESCROW-010", "We couldn't tell your partner yet, so this change's wait "
                                     "hasn't started. Pax keeps trying.")
            self.activate(r["id"])
        with self._lock:
            data = self._load()
            r = next(x for x in data["pending"] if x["id"] == r["id"])
            return {"request": self._req_view(r, int(self.clock())), "list": self.view()}

    def activate(self, request_id: str) -> bool:
        """The partner was told: the wait starts now."""
        with self._lock:
            data = self._load()
            for r in data["pending"]:
                if r["id"] == request_id and r["status"] == "notifying":
                    now = int(self.clock())
                    wait = int(r.get("delay") or self.wait_seconds())
                    r.update({"status": "pending", "created_at": now, "effective_at": now + wait})
                    self._save(data)
                    return True
        return False

    def request_unblock(self, raw: str) -> dict:
        d = normalise(raw)
        if d not in self._load()["blocked"]:
            raise BlocklistError("PAX-DNS-009", f"{d} isn't on your list")
        return self._request("unblock", d)

    def check_allowable(self, d: str) -> None:
        """Raise PAX-DNS-010 for a site in a category Pax always blocks."""
        if self.restricted_static is not None and self.restricted_static(d):
            raise BlocklistError(RESTRICTED_CODE, RESTRICTED_MESSAGE)
        if self.restricted_check is not None:
            try:
                self.restricted_check(d)
            except BlocklistError:
                raise
            except Exception:  # noqa: BLE001 - pax_restricted.RestrictedSite or a failed lookup: refuse
                raise BlocklistError(RESTRICTED_CODE, RESTRICTED_MESSAGE) from None

    def request_allow(self, raw: str) -> dict:
        d = normalise(raw)
        self.check_allowable(d)     # before any wait or partner email
        if len(self._load()["allowed"]) >= MAX_ALLOWED:
            raise BlocklistError("PAX-DNS-009", "too many exceptions")
        return self._request("allow", d)

    def remove_allow(self, raw: str) -> dict:
        """Ending an exception is instant (it makes Pax stricter)."""
        d = normalise(raw)
        with self._lock:
            data = self._load()
            data["allowed"].pop(d, None)
            self._save(data)
        return self.view()

    def cancel(self, request_id: str) -> dict:
        with self._lock:
            data = self._load()
            for r in data["pending"]:
                if r["id"] == request_id and r["status"] in ("pending", "notifying"):
                    was = r["status"]
                    r["status"] = "cancelled"
                    self._save(data)
                    if self.partner and was == "notifying":
                        self.partner.drop_gate({"type": "blocklist", "id": request_id})
                    elif self.partner and self.partner.partner():
                        what = r.get("label") or r["domain"]
                        self.partner.notify("blocklist_change_cancelled", "Pax: change cancelled",
                                            f"You cancelled the change to {what}.",
                                            f"Your Pax partner cancelled their change to {what}.")
                    return self.view()
        raise BlocklistError("PAX-ESCROW-005", "no such waiting change")
