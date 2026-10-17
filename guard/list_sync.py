# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.9: "Sync blocked sites across devices" for a Mac on local escrow.

One list per Pax account lives on the Pax server; iPhones and iPads read it
through Pax's DoH filter. This Mac keeps its own copy (LocalBlocklist, which
pax-guard enforces) and syncs it with the account through a narrow *sync
token* the app hands over (`sync.link`, see server/pax_server/sync.py).

Rules (on by default; one switch in Settings):
  * Adding a site here is blocked here at once and pushed within seconds.
    A site added on another device is pulled within SYNC_INTERVAL seconds.
  * Removing a site from the synced list goes through the account's one
    removal rule on the server: the partner is emailed first (fail closed),
    then the wait (by default the user's own wait; the longer of this Mac's
    and the account's), cancellable. If the server can't be reached, nothing
    starts (PAX-DNS-013); the site stays blocked.
  * A site leaves this Mac's copy ONLY when the server reports that its
    removal took effect (`removed`, after the wait) since sync was last
    switched on, and the site wasn't added here again. A site that is simply
    missing from the server's answer (a new account, a reset, an outage) is
    pushed back instead. So an outage or a wiped server never unblocks anything.
  * Offline: this Mac enforces its last list plus anything added here; the
    additions wait in a queue and go out when the server answers.
  * Switching sync OFF never removes a block: this Mac keeps its copy and the
    lists diverge from there. Switching it ON merges as a union (this Mac's
    sites go to the account, the account's come here; nothing is removed).
  * The switch is instant both ways, with no partner email (it can't loosen
    anything), and is written to the tamper log, like the other settings.

State: /Library/PaxGuard/state/sync.json (root 0600). It holds the sync token,
which is a secret: never logged, never returned to the app.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import local_blocklist as lb

SYNC_INTERVAL = 15          # seconds between pulls (plus an immediate push after a local add)
TOKEN_PREFIX = "pxs_"
# v0.8.24: this Mac's Pax version, sent as X-Pax-Version so the server can count
# how many Macs run each version (it keeps the version and the day, nothing else).
APP_VERSION = ""
UNREACHABLE = ("PAX-DNS-013", "Pax couldn't reach your Pax account, so nothing changed and the site stays "
                               "blocked. Try again when you're online.")


class HTTPFailure(Exception):
    def __init__(self, status: int, body: dict):
        super().__init__(f"HTTP {status}")
        self.status, self.body = status, body


def post_json(url: str, headers: dict, body: dict, timeout: int = 20) -> dict:
    """POST JSON, return JSON. HTTPFailure for an HTTP error answer, OSError when
    unreachable. Falls back to /usr/bin/curl (macOS trust store) on a TLS
    problem; headers and body go through stdin / a 0600 file, never argv."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (the app's server)
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
        except ValueError:
            payload = {}
        raise HTTPFailure(exc.code, payload if isinstance(payload, dict) else {}) from None
    except urllib.error.URLError as exc:
        if "CERTIFICATE" not in str(exc).upper() or not os.path.exists("/usr/bin/curl"):
            raise OSError(str(exc)) from None
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix="pax-sync-")
    try:
        os.write(fd, data)
        os.close(fd)
        hdrs = "\n".join(f"{k}: {v}" for k, v in {"Content-Type": "application/json", **headers}.items())
        p = subprocess.run(["/usr/bin/curl", "-sS", "--max-time", str(timeout), "-H", "@-", "-X", "POST",
                            "--data-binary", f"@{tmp}", "-w", "\n%{http_code}", url],
                           input=hdrs, capture_output=True, text=True, timeout=timeout + 5)
        if p.returncode != 0:
            raise OSError(f"curl {p.returncode}")
        text, _, code = p.stdout.rpartition("\n")
        payload = json.loads(text or "{}")
        if not 200 <= int(code) < 300:
            raise HTTPFailure(int(code), payload if isinstance(payload, dict) else {})
        return payload
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def valid_server_url(url: str) -> bool:
    u = (url or "").strip()
    if u.startswith("https://") and len(u) > 9:
        return True
    host = u[len("http://"):].split("/")[0].split(":")[0] if u.startswith("http://") else ""
    return host in ("localhost", "127.0.0.1", "[::1]")


class ListSync:
    def __init__(self, path: Path, blocklist: "lb.LocalBlocklist", *, clock=time.time,
                 wait_seconds=lambda: None, partner_email=lambda: None, tamper=None, log=print,
                 http=post_json, on_change=None):
        self.path = Path(path)
        self.blocklist = blocklist
        self.clock = clock
        self.wait_seconds = wait_seconds
        self.partner_email = partner_email
        self.tamper = tamper or (lambda kind, detail: None)
        self.log = log
        self.http = http
        self.on_change = on_change or (lambda: None)
        self._lock = threading.RLock()
        self._kick = threading.Event()

    # ------------------------------------------------------------ state
    def _load(self) -> dict:
        try:
            d = json.loads(self.path.read_text())
            if isinstance(d, dict):
                return d
        except (OSError, ValueError):
            pass
        return {}

    def _save(self, d: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(d, sort_keys=True).encode())
        finally:
            os.close(fd)
        os.replace(tmp, self.path)

    def enabled(self) -> bool:
        v = self._load().get("enabled")
        return True if v is None else bool(v)      # default ON

    def linked(self) -> bool:
        d = self._load()
        return bool(d.get("token")) and bool(d.get("server_url"))

    def active(self) -> bool:
        return self.enabled() and self.linked()

    def status(self) -> dict:
        """What the app shows. Never the token."""
        d = self._load()
        srv = d.get("server") or {}
        return {"enabled": self.enabled(), "linked": self.linked(),
                "account_email": d.get("account_email"), "server_url": d.get("server_url"),
                "linked_at": d.get("linked_at"), "enabled_at": d.get("enabled_at"),
                "last_ok": d.get("last_ok"), "last_error": d.get("last_error"),
                "queued": len(d.get("queued") or {}), "pending": len(srv.get("pending") or []),
                "delay_seconds": srv.get("delay_seconds"), "interval": SYNC_INTERVAL}

    # ------------------------------------------------------------ set-up
    def link(self, server_url: str, token: str, account_email: str | None = None, uid=None) -> dict:
        server_url = (server_url or "").strip()
        token = (token or "").strip()
        if not valid_server_url(server_url):
            raise lb.BlocklistError("PAX-DNS-014", "that server address isn't usable")
        if not token.startswith(TOKEN_PREFIX) or len(token) < 20:
            raise lb.BlocklistError("PAX-DNS-014", "that sync sign-in isn't valid")
        with self._lock:
            d = self._load()
            now = int(self.clock())
            same = d.get("server_url") == server_url.rstrip("/") + "/" and d.get("token") == token
            d.update({"server_url": server_url.rstrip("/") + "/", "token": token,
                      "account_email": (account_email or "")[:254] or None, "linked_at": now})
            if not same:
                # A new link merges as a union: everything here goes to the account.
                d["enabled_at"] = now
                d.pop("server", None)
                q = d.setdefault("queued", {})
                for dom in self.blocklist.blocked():
                    q.setdefault(dom, now)
            d.setdefault("enabled_at", now)
            self._save(d)
        if not same:
            self.tamper("sync:linked", {"account": account_email or "", "uid": uid})
            self.log(f"blocked-sites sync linked to an account (uid {uid})")
        self.kick()
        return self.status()

    def set_enabled(self, on, uid=None) -> dict:
        if not isinstance(on, bool):
            raise ValueError("enabled must be true or false")
        with self._lock:
            d = self._load()
            before = self.enabled()
            d["enabled"] = on
            d["changed_at"] = int(self.clock())
            if on and not before:
                # Union on: push this Mac's sites; only removals from now on count.
                now = int(self.clock())
                d["enabled_at"] = now
                q = d.setdefault("queued", {})
                for dom in self.blocklist.blocked():
                    q.setdefault(dom, now)
            self._save(d)
        if before != on:
            self.tamper("setting:sync_blocked_sites", {"from": before, "to": on, "uid": uid})
            self.log(f"blocked-sites sync {'on' if on else 'off'} (uid {uid})")
        if on:
            self.kick()
        return self.status()

    # ----------------------------------------------------------- events
    def note_added(self, domain: str) -> None:
        """A site added on this Mac: queue it for the account (kept while offline)."""
        with self._lock:
            d = self._load()
            if not self.enabled():
                return
            d.setdefault("queued", {})[domain] = int(self.clock())
            self._save(d)
        self.kick()

    def kick(self) -> None:
        self._kick.set()

    def wait_for_kick(self, timeout: float) -> None:
        self._kick.wait(timeout)
        self._kick.clear()

    # ------------------------------------------------------------- sync
    def _headers(self, d: dict) -> dict:
        h = {"X-Pax-Sync-Token": d["token"]}
        if APP_VERSION:
            h["X-Pax-Version"] = APP_VERSION
        return h

    def sync_once(self) -> dict:
        """Push the queue, pull the account's list, apply it under the rules
        above. Returns what changed here. Never raises for network trouble."""
        changed = {"added": [], "removed": [], "pushed": []}
        if not self.active():
            return changed
        for _ in range(2):      # a second round pushes what the union found
            with self._lock:
                d = self._load()
                queued = dict(d.get("queued") or {})
                body = {"add": sorted(queued), "since": int(d.get("enabled_at") or 0)}
                wait = self._safe(self.wait_seconds)
                if isinstance(wait, int) and wait > 0:
                    body["wait_seconds"] = wait
                partner = self._safe(self.partner_email)
                if partner:
                    body["partner_email"] = partner
                url, headers = d["server_url"] + "v1/sync", self._headers(d)
            try:
                resp = self.http(url, headers, body)
            except HTTPFailure as exc:
                self._error(f"HTTP {exc.status}")
                if exc.status == 401:
                    self.log("PAX-DNS-015 the account no longer knows this Mac's sync sign-in; "
                             "keeping this Mac's list")
                return changed
            except Exception as exc:  # noqa: BLE001 - offline / server down: keep everything
                self._error(type(exc).__name__)
                return changed
            more = self._apply(resp, queued, changed)
            if not more:
                break
        if changed["added"] or changed["removed"]:
            try:
                self.on_change()
            except Exception as exc:  # noqa: BLE001
                self.log(f"sync: enforcing the new list failed ({type(exc).__name__}); next check retries")
        return changed

    @staticmethod
    def _safe(fn):
        try:
            return fn()
        except Exception:  # noqa: BLE001
            return None

    def _error(self, what: str) -> None:
        with self._lock:
            d = self._load()
            d["last_error"] = {"at": int(self.clock()), "error": what}
            d["last_try"] = int(self.clock())
            self._save(d)

    def _apply(self, resp: dict, sent: dict, changed: dict) -> bool:
        if not isinstance(resp, dict) or not isinstance(resp.get("blocked"), list):
            self._error("bad answer")
            return False
        server = {str(x) for x in resp["blocked"]}
        rejected = {str(r.get("domain")) for r in resp.get("rejected") or [] if isinstance(r, dict)}
        with self._lock:
            d = self._load()
            queued = d.setdefault("queued", {})
            # Pushed: what we sent and the server now has (or refused) leaves the queue,
            # unless it was added here again while we were talking.
            for dom, at in sent.items():
                if (dom in server or dom in rejected) and queued.get(dom) == at:
                    queued.pop(dom, None)
                    if dom in server:
                        changed["pushed"].append(dom)
            entries = self.blocklist.entries()
            # Pull: the account's sites are blocked here at once.
            for dom in sorted(server - set(entries)):
                try:
                    self.blocklist.add_synced(dom)
                    changed["added"].append(dom)
                except lb.BlocklistError as exc:
                    self.log(f"sync: couldn't add a site from the account ({exc.code})")
            # Removals: only a removal the server says took effect (after its wait),
            # since sync was switched on, for a site not added here again since.
            for r in resp.get("removed") or []:
                if not isinstance(r, dict):
                    continue
                dom, applied = str(r.get("domain") or ""), int(r.get("applied_at") or 0)
                if not dom or dom in server or dom in queued or applied < int(d.get("enabled_at") or 0):
                    continue
                e = entries.get(dom)
                if e is not None and int(e.get("added_at", 0)) <= applied:
                    self.blocklist.remove_synced(dom)
                    changed["removed"].append(dom)
            # Union: a site here that the account doesn't have (and didn't remove) goes up.
            removed_now = set(changed["removed"])
            more = False
            for dom in self.blocklist.blocked():
                if dom not in server and dom not in queued and dom not in rejected \
                        and dom not in removed_now:
                    queued[dom] = int(self.clock())
                    more = True
            d["server"] = {"blocked": sorted(server), "pending": resp.get("pending") or [],
                           "delay_seconds": resp.get("delay_seconds"), "at": int(self.clock())}
            if resp.get("account_email"):
                d["account_email"] = resp["account_email"]
            d["last_ok"] = int(self.clock())
            d["last_try"] = d["last_ok"]
            d["last_error"] = None
            self._save(d)
        if changed["removed"]:
            self.tamper("sync:removed", {"sites": changed["removed"][:20]})
        return more

    def loop(self, stop: threading.Event | None = None) -> None:
        while stop is None or not stop.is_set():
            try:
                self.sync_once()
            except Exception as exc:  # noqa: BLE001 - never stop syncing
                self.log(f"sync error: {type(exc).__name__}")
            self.wait_for_kick(SYNC_INTERVAL)

    # ------------------------------------------------- removal and cancel
    def request_unblock(self, raw: str) -> dict:
        """The one removal rule, on the server. Nothing starts if it can't be reached."""
        dom = lb.normalise(raw)
        if dom not in self.blocklist.entries():
            raise lb.BlocklistError("PAX-DNS-009", f"{dom} isn't on your list")
        if dom in (self._load().get("queued") or {}):
            self.sync_once()            # the account must have it before it can be removed
            if dom in (self._load().get("queued") or {}):
                raise lb.BlocklistError(*UNREACHABLE)
        d = self._load()
        try:
            resp = self.http(d["server_url"] + "v1/sync/unblock", self._headers(d), {"domain": dom})
        except HTTPFailure as exc:
            raise self._server_error(exc) from None
        except Exception:  # noqa: BLE001
            raise lb.BlocklistError(*UNREACHABLE) from None
        self._store_state(resp.get("state"))
        return {"request": resp.get("request"), "list": self.decorate(self.blocklist.view())}

    def owns_request(self, request_id: str) -> bool:
        srv = self._load().get("server") or {}
        return any(p.get("request_id") == request_id for p in srv.get("pending") or [])

    def cancel(self, request_id: str) -> dict:
        d = self._load()
        try:
            resp = self.http(d["server_url"] + f"v1/sync/requests/{request_id}/cancel", self._headers(d), {})
        except HTTPFailure as exc:
            raise self._server_error(exc) from None
        except Exception:  # noqa: BLE001
            raise lb.BlocklistError("PAX-DNS-013", "Pax couldn't reach your Pax account to cancel. "
                                                    "The site stays blocked meanwhile; try again shortly.") from None
        self._store_state(resp.get("state"))
        return self.decorate(self.blocklist.view())

    @staticmethod
    def _server_error(exc: HTTPFailure) -> lb.BlocklistError:
        b = exc.body or {}
        if exc.status == 503:
            return lb.BlocklistError("PAX-ESCROW-010", "We couldn't tell your partner yet, so this change's "
                                                       "wait hasn't started.")
        if exc.status == 401:
            return lb.BlocklistError("PAX-DNS-015", "Your Pax account doesn't know this Mac any more. "
                                                     "Open Pax to link it again.")
        code = b.get("pax_code") or ("PAX-ESCROW-005" if exc.status >= 400 else "PAX-DNS-013")
        return lb.BlocklistError(code, str(b.get("message") or f"the server said no (HTTP {exc.status})"))

    def _store_state(self, state) -> None:
        if not isinstance(state, dict) or not isinstance(state.get("blocked"), list):
            return
        with self._lock:
            d = self._load()
            srv = d.get("server") or {}
            srv.update({"pending": state.get("pending") or [], "delay_seconds": state.get("delay_seconds"),
                        "at": int(self.clock())})
            d["server"] = srv
            self._save(d)

    # ------------------------------------------------------------- view
    def decorate(self, view: dict) -> dict:
        """The local view, with the account's waiting removals (the one rule) when
        sync is on. Exceptions stay this Mac's own."""
        view = dict(view)
        view["sync"] = self.status()
        if not self.active():
            return view
        srv = self._load().get("server") or {}
        pend = [p for p in srv.get("pending") or [] if isinstance(p, dict) and p.get("action") == "unblock"]
        now = int(self.clock())
        for p in pend:
            p["seconds_remaining"] = max(0, int(p.get("effective_at", now)) - now)
        by = {p.get("domain"): p for p in pend}
        view["blocked"] = [dict(b, pending_removal=by.get(b["domain"]) or b.get("pending_removal"))
                           for b in view.get("blocked", [])]
        local_other = [p for p in view.get("pending", []) if p.get("action") != "unblock"]
        local_unblock = [p for p in view.get("pending", []) if p.get("action") == "unblock"
                         and p.get("domain") not in by]
        view["pending"] = pend + local_unblock + local_other
        if srv.get("delay_seconds"):
            lim = dict(view.get("limits") or {})
            lim["delay_seconds"] = int(srv["delay_seconds"])
            view["limits"] = lim
        return view
