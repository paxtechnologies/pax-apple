# SPDX-License-Identifier: GPL-3.0-only
"""Local escrow inside pax-guard (v0.8.0): no server needed for the Mac.

pax-guard (root) keeps the secrets that undo Pax and releases them only after
the wait:
  * paxadmin's password (the only administrator on a protected Mac),
  * the FileVault personal recovery key, after pax-guard rotated it,
  * on Intel Macs, the firmware password pax-guard set.

Where: /Library/PaxGuard/escrow/ (root:wheel 0700) holding secrets.json,
state.json and hmac.key (each root:wheel 0600). The everyday Standard account
cannot read any of it. Every load checks owner and mode of the folder and the
files and an HMAC over each file; a failed check is logged as tamper and
blocks every release until fixed. (Root can always forge these files: the
checks catch corruption and clumsy edits, not a determined administrator, and
on a protected Mac only paxadmin is an administrator.)

Why files and not the System keychain: the `security` tool takes the secret as
a command-line argument (visible in `ps` while it runs), and a root-only file
is no weaker against root than a System keychain item.

The timer: a removal request unlocks after the wait (24 hours, 72 hours by
default, 7 days, or any number of days up to 365). Time is counted three ways
and the strictest wins:
  * credited time: every heartbeat adds the wall-clock step, but never more
    than the continuous monotonic clock moved (+2 min), so setting the clock
    forward while the Mac runs gains nothing;
  * the wall clock must be past unlock_at;
  * when the DNS upstreams' TLS-protected Date header is known (last 24 h), it
    must be past unlock_at too.
The clock going backwards is logged and puts a hold on the request: release
then also needs that network time to confirm the wait is over.

Like the server: a 1-hour grace period after set-up (removal needs no wait),
emergency release (24-hour cooling-off, once per 90 days), a 7-day window to
reveal after unlock, and a shorter wait itself takes the current wait.

Stale requests lapse on their own (v0.8.5), checked at every heartbeat, status
and reveal: a request made in the grace period can only be used until the grace
period ends (measured by the wall clock, by time credited since the request and
by network time, so moving the clock back doesn't keep it alive), and any
request lapses once its 7-day reveal window has passed.

Verified support release (v0.8.15, support_code.py): in a genuine emergency that
Pax support has checked, support can issue a one-time code for THIS Mac (its
support ID). redeem_support() checks the switch, the signature, the device, the
expiry and that the nonce was never used, emails the partner FIRST (not queued:
if it can't be sent, nothing happens), then releases straight away exactly as a
finished removal request does. The switch ("Allow verified support release")
lives here, in state.json, and nothing outside this Mac can change it: set-up
chooses it (on by default), Macs set up before 0.8.15 start with it off (they
never agreed to it), turning it off is immediate, and turning it on waits the
full wait with the partner told first, like shortening the wait.

Trial day (v0.8.18): on a genuinely new set-up, the first 24 hours are a trial
day. Turning Pax off (and an emergency release) needs no wait in that day; the
partner, if there is one, is still told first, fail closed as always. Turning
on verified support release is also instant in the trial day. After 24 hours
the chosen turn-off wait applies by itself. "Start my wait now" (end_trial)
ends it early and closes any no-wait request. It replaces the 1-hour grace on
the set-ups that get it; a set-up without it still gets the 1-hour grace.
"Genuinely new" is anchored OUTSIDE the escrow folder, in a marker that
removing Pax leaves behind (/private/var/db/PaxPeace/trial.json, root 0700/
0600): the first set-up on a Mac writes it, every later set-up (or a re-set-up
after an unfinished one) reads its start time, so reinstalling only ever gets
the rest of the first day. pax-guard writes the marker for Macs set up before
0.8.18 at its first heartbeat (start = their install time), so they never get
one. An unreadable marker counts as "trial used" (fail closed).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as _secrets
import stat
import threading
import time
from pathlib import Path

HOUR, DAY = 3600, 86400
WAIT_CHOICES = (24 * HOUR, 72 * HOUR, 7 * DAY)
DEFAULT_WAIT = 72 * HOUR
MIN_WAIT = 24 * HOUR
MAX_WAIT = 365 * DAY
GRACE = 1 * HOUR   # first hour after set-up only (2026-10-16: a week was long enough to relapse)
TRIAL = 24 * HOUR  # v0.8.18: trial day on a genuinely new set-up (turn off with no wait)
REVEAL_WINDOW = 7 * DAY
EMERGENCY_COOLOFF = 24 * HOUR
EMERGENCY_MIN_INTERVAL = 90 * DAY
SLACK = 120                      # seconds of wall/monotonic disagreement tolerated per beat
SECRET_NAMES = ("paxadmin", "recovery_key", "firmware")
# What each kind of request releases.
RELEASES = {"remove": ("paxadmin", "recovery_key", "firmware"),
            "locked_out": ("recovery_key", "firmware")}
DEFAULT_DIR = Path("/Library/PaxGuard/escrow")
# v0.8.18: outlives Pax's removal on purpose (the uninstallers only remove /Library/PaxGuard).
TRIAL_MARKER = Path("/private/var/db/PaxPeace/trial.json")


class EscrowError(Exception):
    def __init__(self, code: str, message: str, **extra):
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = extra


class TamperError(EscrowError):
    pass


def _now() -> float:
    return time.time()


def _mono() -> float:
    from dns_forwarder import monotonic_continuous
    return monotonic_continuous()


def _boot_time() -> int:
    """kern.boottime seconds (changes at every boot)."""
    try:
        import subprocess
        out = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.boottime"], capture_output=True,
                             text=True, timeout=5).stdout
        return int(out.split("sec =", 1)[1].split(",", 1)[0])
    except Exception:  # noqa: BLE001
        return 0


class LocalEscrow:
    def __init__(self, base: Path = DEFAULT_DIR, *, clock=_now, mono=_mono, boot_time=_boot_time,
                 trusted_time=lambda: None, tamper_log=None, require_root: bool | None = None,
                 senders=None, log=print, trial_marker: Path | None = None):
        self.base = Path(base)
        # The real escrow folder uses the system marker; any other folder (tests,
        # a guard running from a temporary state dir) keeps its marker beside it.
        if trial_marker is None:
            trial_marker = TRIAL_MARKER if self.base == DEFAULT_DIR else self.base.parent / "trial-marker.json"
        self.trial_marker = Path(trial_marker)
        self.clock = clock
        self.mono = mono
        self.boot_time = boot_time
        self.trusted_time = trusted_time
        self.tamper_log = tamper_log or (lambda kind, detail: None)
        self.require_root = (os.geteuid() == 0) if require_root is None else require_root
        self._lock = threading.RLock()
        from partner import PartnerNotifier
        self.partner = PartnerNotifier(self._read_opt, self._write_locked, clock=clock, log=log, senders=senders)

    # ------------------------------------------------------------ storage
    def _read_opt(self, name: str, default):
        with self._lock:
            if not (self.base / name).exists():
                return default
            return self._read(name)

    def _write_locked(self, name: str, data: dict) -> None:
        with self._lock:
            self._write(name, data)
    @property
    def _key_path(self) -> Path:
        return self.base / "hmac.key"

    def exists(self) -> bool:
        return (self.base / "secrets.json").exists()

    def _check_perms(self, path: Path, mode: int) -> None:
        try:
            st = path.lstat()
        except FileNotFoundError:
            raise TamperError("PAX-GUARD-010", f"{path.name} is missing") from None
        if stat.S_ISLNK(st.st_mode):
            raise TamperError("PAX-GUARD-010", f"{path.name} is a symbolic link")
        if stat.S_IMODE(st.st_mode) & ~mode:
            raise TamperError("PAX-GUARD-010", f"{path.name} has mode {oct(stat.S_IMODE(st.st_mode))}")
        if self.require_root and st.st_uid != 0:
            raise TamperError("PAX-GUARD-010", f"{path.name} is not owned by root")

    def _key(self) -> bytes:
        self._check_perms(self._key_path, 0o600)
        key = self._key_path.read_bytes()
        if len(key) != 32:
            raise TamperError("PAX-GUARD-010", "hmac.key is damaged")
        return key

    def _mac(self, body: bytes) -> str:
        return hmac.new(self._key(), body, hashlib.sha256).hexdigest()

    def _read(self, name: str) -> dict:
        self._check_perms(self.base, 0o700)
        path = self.base / name
        self._check_perms(path, 0o600)
        try:
            doc = json.loads(path.read_text())
            body = json.dumps(doc["data"], sort_keys=True).encode()
        except (ValueError, KeyError, TypeError):
            raise TamperError("PAX-GUARD-010", f"{name} is not readable") from None
        if not hmac.compare_digest(self._mac(body), str(doc.get("mac", ""))):
            raise TamperError("PAX-GUARD-010", f"{name} failed its integrity check")
        return doc["data"]

    def _write(self, name: str, data: dict) -> None:
        body = json.dumps(data, sort_keys=True).encode()
        doc = json.dumps({"data": data, "mac": self._mac(body)}, sort_keys=True)
        path = self.base / name
        tmp = self.base / f".{name}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, doc.encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp, 0o600)
        if self.require_root:
            os.chown(tmp, 0, 0)
        os.replace(tmp, path)

    def _init_dir(self) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        os.chmod(self.base, 0o700)
        if self.require_root:
            os.chown(self.base, 0, 0)
        if not self._key_path.exists():
            fd = os.open(self._key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, _secrets.token_bytes(32))
            finally:
                os.close(fd)
            if self.require_root:
                os.chown(self._key_path, 0, 0)

    # ------------------------------------------------------------ deposit
    def deposit(self, name: str, secret: str, wait_seconds: int | None = None,
                replace: bool = False, support_release: bool = False, trial: bool = False) -> str:
        """Store a secret. paxadmin can be stored only once (set-up); the recovery
        key and firmware password are replaced by pax-guard when it rotates them.
        Returns the SHA-256 of the stored value so the caller can confirm it."""
        if name not in SECRET_NAMES:
            raise EscrowError("PAX-ESCROW-008", f"unknown secret {name}")
        if not secret or len(secret) > 512 or "\x00" in secret:
            raise EscrowError("PAX-ESCROW-008", "empty or invalid secret")
        with self._lock:
            first = not self.exists()
            if first:
                if name != "paxadmin":
                    raise EscrowError("PAX-ESCROW-008", "the paxadmin password must be stored first")
                self._init_dir()
                wait = validate_wait(wait_seconds if wait_seconds is not None else DEFAULT_WAIT)
                now = int(self.clock())
                trial_state = self._new_trial(now) if trial else None
                self._write("secrets.json", {"paxadmin": secret})
                self._write("state.json", {
                    "schema": 1, "installed_at": now, "wait_seconds": wait, "pending_wait": None,
                    "request": None, "released_at": None, "last_emergency_at": None,
                    "wall_last": now, "mono_last": self.mono(), "boot": self.boot_time(),
                    "holds": {}, "support": _new_support(bool(support_release), "setup"),
                    "trial": trial_state})
            else:
                sec = self._read("secrets.json")
                if name in sec and not (replace and name != "paxadmin"):
                    raise EscrowError("PAX-ESCROW-008", f"{name} is already stored")
                sec[name] = secret
                self._write("secrets.json", sec)
            return hashlib.sha256(secret.encode()).hexdigest()

    def holds(self) -> list[str]:
        with self._lock:
            return sorted(self._read("secrets.json"))

    def secret_for_guard(self, name: str) -> str | None:
        """Internal use by pax-guard only (e.g. paxadmin's password to rotate the
        recovery key). Never reachable over the app socket."""
        with self._lock:
            return self._read("secrets.json").get(name)

    def forget(self, name: str) -> None:
        with self._lock:
            sec = self._read("secrets.json")
            if name != "paxadmin" and sec.pop(name, None) is not None:
                self._write("secrets.json", sec)

    # --------------------------------------------------- v0.8.18 trial day
    def _marker_first_at(self) -> int | None:
        """When this Mac's first Pax set-up started its trial day (None: never set
        up). A marker that exists but can't be read counts as long ago (no trial)."""
        p = self.trial_marker
        try:
            if p.is_symlink():
                return 0
            if not p.exists():
                return None
            first = int(json.loads(p.read_text())["first_at"])
            return first if first > 0 else 0
        except (OSError, ValueError, KeyError, TypeError):
            return 0

    def _write_marker(self, first_at: int) -> None:
        """Record the first set-up on this Mac (never overwritten)."""
        p = self.trial_marker
        if p.exists() or p.is_symlink():
            return
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(p.parent, 0o700)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, json.dumps({"schema": 1, "first_at": int(first_at)}).encode())
            finally:
                os.close(fd)
            if self.require_root:
                os.chown(p.parent, 0, 0)
                os.chown(p, 0, 0)
        except FileExistsError:
            pass

    def _new_trial(self, now: int) -> dict | None:
        """A trial day for a set-up asking for one: only the rest of the day that
        started at this Mac's first set-up. Marks the Mac either way."""
        first = self._marker_first_at()
        if first is None:
            first = now
        self._write_marker(first)
        until = first + TRIAL
        if until <= now:
            return None
        return {"started_at": first, "until": until, "ended_at": None}

    @staticmethod
    def _free_until(st: dict) -> int:
        """Until when a removal needs no wait: the trial day (ended early or not),
        else the first hour after set-up."""
        tr = st.get("trial")
        if isinstance(tr, dict) and tr.get("until"):
            if tr.get("ended_at"):
                return int(tr["ended_at"])
            return max(int(tr["until"]), int(st["installed_at"]) + GRACE)
        return int(st["installed_at"]) + GRACE

    @staticmethod
    def _in_trial(st: dict, now: float) -> bool:
        tr = st.get("trial")
        return (isinstance(tr, dict) and bool(tr.get("until")) and not tr.get("ended_at")
                and now < tr["until"])

    def _trial_view(self, st: dict, now: float) -> dict | None:
        tr = st.get("trial")
        if not isinstance(tr, dict) or not tr.get("until"):
            return None
        return {"active": self._in_trial(st, now), "until": int(tr["until"]),
                "ended_at": tr.get("ended_at"), "started_at": tr.get("started_at")}

    def end_trial(self) -> dict:
        """"Start my wait now": the trial day ends at once, and a no-wait request
        made in it lapses (a new one takes the full wait). Stricter, so no email
        is needed; logged to the tamper log."""
        with self._lock:
            st = self._read("state.json")
            now = int(self.clock())
            if self._in_trial(st, now):
                st["trial"]["ended_at"] = now
                self._lapse_if_stale(st, now)
                self._write("state.json", st)
                self.tamper_log("trial_ended_early", {"left_seconds": int(st["trial"]["until"] - now)})
        return self.status()

    # --------------------------------------------------------------- time
    def heartbeat(self) -> dict:
        """Called every guard cycle: credits elapsed time to an open request and
        notices the clock being moved. Returns what it saw."""
        with self._lock:
            st = self._read("state.json")
            now, mono, boot = self.clock(), self.mono(), self.boot_time()
            dw = now - st["wall_last"]
            same_boot = boot == st.get("boot") and mono >= st.get("mono_last", 0)
            seen = {"dw": dw, "same_boot": same_boot}
            if same_boot:
                dm = mono - st["mono_last"]
                credit = max(0.0, min(dw, dm + SLACK))
                if dw < -SLACK:
                    seen["clock"] = "backwards"
                    self.tamper_log("clock_backwards", {"seconds": int(-dw)})
                    if st.get("request") and st["request"]["status"] == "pending":
                        st["request"]["clock_hold"] = True
                elif dw > dm + SLACK:
                    seen["clock"] = "forward"
                    self.tamper_log("clock_forward", {"seconds": int(dw - dm)})
            else:
                credit = max(0.0, dw)
                if dw < -SLACK:
                    seen["clock"] = "backwards"
                    self.tamper_log("clock_backwards", {"seconds": int(-dw), "across_restart": True})
                    if st.get("request") and st["request"]["status"] == "pending":
                        st["request"]["clock_hold"] = True
            rr = st.get("request")
            if rr and rr["status"] == "pending":
                rr["credited"] = rr.get("credited", 0) + credit
            if self._lapse_if_stale(st, now):
                seen["lapsed"] = True
            if st.get("pending_wait") and now >= st["pending_wait"]["effective_at"]:
                st["wait_seconds"] = st["pending_wait"]["seconds"]
                st["pending_wait"] = None
            sup = self._support(st)
            if sup.get("pending_on") and now >= sup["pending_on"]["effective_at"]:
                sup["allowed"], sup["pending_on"] = True, None
                self.tamper_log("support_release_setting", {"allowed": True, "applied": True})
            # A wall clock that went backwards is not trusted as the new baseline
            # for "now >= unlock_at"; credited time already ignores the jump.
            st["wall_last"], st["mono_last"], st["boot"] = now, mono, boot
            self._write("state.json", st)
            # v0.8.18: a Mac set up before the trial day existed is marked as having
            # had its first set-up, so removing and setting up again gives no trial.
            try:
                self._write_marker(int(st["installed_at"]))
            except OSError:
                pass
        if self.apply_partner_change():
            seen["partner_changed"] = True
        return seen

    def _grace_over(self, st: dict, rr: dict, now: float) -> bool:
        """Has the grace period a no-wait request relied on ended? Any one of
        three clocks saying so is enough: the wall clock, the time credited
        since the request was made (immune to moving the clock back), and the
        network time when known."""
        grace_until = self._free_until(st)
        if now >= grace_until:
            return True
        if rr.get("status") == "pending" and rr["created_at"] + rr.get("credited", 0) >= grace_until:
            return True
        trusted = self.trusted_time()
        return trusted is not None and trusted >= grace_until

    def _reveal_window_over(self, rr: dict) -> bool:
        """7 days past the unlock, counted in credited time (moving the clock
        forward doesn't end it early, moving it back doesn't stretch it) or by
        network time when known."""
        if rr.get("credited", 0) >= rr["wait"] + REVEAL_WINDOW:
            return True
        trusted = self.trusted_time()
        return trusted is not None and trusted > rr["unlock_at"] + REVEAL_WINDOW + 300

    def _lapse_if_stale(self, st: dict, now: float) -> bool:
        """v0.8.5: lapse the open request if its window has passed. Returns True
        when it did (the caller writes state.json). A grace request (or an
        emergency made in the grace period, which also had no wait) lapses when
        the grace period ends, even if it is still "telling your partner"; any
        pending request lapses 7 days after it unlocked (_reveal_window_over)."""
        rr = st.get("request")
        if not rr or rr["status"] not in ("pending", "notifying"):
            return False
        stale = False
        if (rr["kind"] in ("grace", "trial") or rr.get("grace_window")) and self._grace_over(st, rr, now):
            stale = True
        elif rr["status"] == "pending" and self._reveal_window_over(rr):
            stale = True
        if not stale:
            return False
        was = rr["status"]
        rr["status"] = "lapsed"
        rr["lapsed_at"] = int(now)
        if was == "notifying":
            self.partner.drop_gate({"type": "removal", "id": rr["id"]})
        return True

    def _release_ok(self, rr: dict, now: float) -> tuple[bool, str]:
        if rr["status"] not in ("pending", "revealed"):
            return False, rr["status"]
        if rr["status"] == "revealed":
            return True, ""
        need = rr["wait"]
        if rr.get("credited", 0) + 1 < need:
            return False, "wait"
        if now < rr["unlock_at"]:
            return False, "wait"
        trusted = self.trusted_time()
        if trusted is not None and trusted + 300 < rr["unlock_at"]:
            return False, "network time says the wait isn't over"
        if rr.get("clock_hold") and trusted is None:
            return False, "the clock was moved back; waiting for network time to confirm"
        return True, ""

    # ------------------------------------------------------------- status
    def status(self) -> dict:
        with self._lock:
            st = self._read("state.json")
            now = self.clock()
            grace_until = self._free_until(st)
            rr = st.get("request")
            view = None
            if rr:
                if self._lapse_if_stale(st, now):
                    self._write("state.json", st)
                ok, why = self._release_ok(rr, now)
                left_credit = max(0, rr["wait"] - int(rr.get("credited", 0)))
                left_wall = max(0, int(rr["unlock_at"] - now))
                view = {"request_id": rr["id"], "kind": rr["kind"], "reason": rr.get("reason", "remove"),
                        "status": rr["status"], "created_at": rr["created_at"], "unlock_at": rr["unlock_at"],
                        "seconds_remaining": 0 if rr["status"] != "pending" else max(left_credit, left_wall),
                        "can_reveal": ok, "blocked_because": "" if ok else why,
                        "clock_hold": bool(rr.get("clock_hold"))}
                if rr["status"] == "notifying":
                    view["seconds_remaining"] = rr["wait"]
                    view["can_reveal"] = False
                    view["blocked_because"] = "telling your partner first"
                if rr["status"] in ("cancelled", "lapsed"):
                    view = None
            return {
                "device_id": "local", "name": "This Mac", "platform": "mac", "escrow": "local",
                "installed_at": st["installed_at"], "grace_until": grace_until,
                "in_grace_period": now < grace_until, "released_at": st.get("released_at"),
                "removal_request": view, "wait_seconds": st["wait_seconds"],
                "pending_wait": st.get("pending_wait"), "holds": self.holds(),
                "last_emergency_at": st.get("last_emergency_at"),
                "partner": self.partner.public_view(),
                # v0.8.18: {"active", "until", "ended_at", "started_at"} or None (no trial day).
                "trial": self._trial_view(st, now),
                **self._support_view(st),
            }

    # ------------------------------------------------------------ actions
    def request_removal(self, reason: str = "remove") -> dict:
        if reason not in RELEASES:
            raise EscrowError("PAX-ESCROW-008", "unknown reason")
        with self._lock:
            st = self._read("state.json")
            if st.get("released_at") and reason == "remove":
                raise EscrowError("PAX-ESCROW-005", "already released")
            rr = st.get("request")
            if rr and rr["status"] == "pending":
                raise EscrowError("PAX-ESCROW-005", "a request is already open")
            now = int(self.clock())
            in_grace = now < self._free_until(st)
            in_trial = self._in_trial(st, now)
            wait = 0 if in_grace else st["wait_seconds"]
            rid = _secrets.token_hex(8)
            partner = self.partner.partner()
            st["request"] = {"id": rid, "kind": "trial" if in_trial else "grace" if in_grace else "standard",
                             "reason": reason, "status": "notifying" if partner else "pending",
                             "created_at": now, "unlock_at": now + wait, "wait": wait, "credited": 0}
            self._write("state.json", st)
            if partner:
                what = "remove Pax from this Mac" if reason == "remove" else "get back into this Mac (locked out)"
                # v0.8.16: plain words for the wait.
                when = ("straight away (it's still the trial day after set-up)" if in_trial
                        else "straight away (it's still the first hour after set-up)" if in_grace
                        else f"in {_fmt(wait)}, when the turn-off wait ends")
                ok = self.partner.notify(
                    "removal_requested", "Removal requested for this Mac",
                    f"You asked to {what}. It unlocks {when}. You can cancel any time during the wait.",
                    f"Your Pax partner asked to {what}. It unlocks {when}. You might want to check in with them.",
                    gate={"type": "removal", "id": rid})
                if not ok:
                    raise EscrowError("PAX-ESCROW-010", "We couldn't tell your partner yet, so your turn-off wait hasn't "
                                      "started. Pax keeps trying and starts it once they're told.")
                self._activate_removal(rid)
        return self.status()

    def _activate_removal(self, rid: str) -> bool:
        with self._lock:
            st = self._read("state.json")
            rr = st.get("request")
            if not rr or rr["id"] != rid or rr["status"] != "notifying":
                return False
            now = int(self.clock())
            if self._lapse_if_stale(st, now):
                # The partner was told only after the grace period ended: the
                # no-wait request is gone; a new one takes the full wait.
                self._write("state.json", st)
                return True
            rr.update({"status": "pending", "created_at": now, "unlock_at": now + rr["wait"], "credited": 0})
            self._write("state.json", st)
            return True

    def activate(self, gate: dict) -> bool:
        """A queued partner email went out: start what was waiting on it."""
        t = gate.get("type")
        if t == "removal":
            return self._activate_removal(gate.get("id", ""))
        with self._lock:
            st = self._read("state.json")
            now = int(self.clock())
            if t == "reveal":
                rr = st.get("request")
                if rr and rr["id"] == gate.get("id"):
                    rr["reveal_notified"] = True
            elif t == "emergency" and st.get("pending_emergency"):
                self._apply_emergency(st, now)
            elif t == "wait" and st.get("wait_notifying") == gate.get("seconds"):
                st["pending_wait"] = {"seconds": gate["seconds"], "effective_at": now + st["wait_seconds"]}
                st["wait_notifying"] = None
            elif t == "partner":
                self.partner.set_pending_partner({"email": gate.get("email") or None,
                                                  "effective_at": now + st["wait_seconds"]})
            elif t == "support_on":
                sup = self._support(st)
                if not sup.get("notifying_on"):
                    return False
                sup["notifying_on"] = False
                sup["pending_on"] = {"effective_at": now + st["wait_seconds"], "requested_at": now}
            else:
                return False
            self._write("state.json", st)
            return True

    def cancel(self) -> dict:
        with self._lock:
            st = self._read("state.json")
            rr = st.get("request")
            if not rr or rr["status"] not in ("pending", "notifying"):
                raise EscrowError("PAX-ESCROW-005", "no pending request")
            was = rr["status"]
            rr["status"] = "cancelled"
            self._write("state.json", st)
        if was == "notifying":
            self.partner.drop_gate({"type": "removal", "id": rr["id"]})   # they never heard of it
        else:
            # Cancelling makes Pax stricter: never held up by email; queued if it fails.
            self.partner.notify("removal_cancelled", "Removal cancelled for this Mac",
                                "You cancelled your request to remove Pax. Well done.",
                                "Your Pax partner cancelled their request to remove Pax from their Mac.")
        return self.status()

    def emergency(self, reason_text: str) -> dict:
        reason_text = (reason_text or "").strip()
        if len(reason_text) < 10:
            raise EscrowError("PAX-ESCROW-008", "please describe the emergency (at least 10 characters)")
        with self._lock:
            st = self._read("state.json")
            now = int(self.clock())
            last = st.get("last_emergency_at")
            if last is not None and now - last < EMERGENCY_MIN_INTERVAL:
                raise EscrowError("PAX-ESCROW-006", "emergency release was used recently",
                                  next_at=last + EMERGENCY_MIN_INTERVAL)
            st["last_emergency_at"] = now
            st["pending_emergency"] = {"at": now}
            self._write("state.json", st)
            partner = self.partner.partner()
            if partner:
                in_grace = now < self._free_until(st)
                cool = 0 if in_grace else EMERGENCY_COOLOFF
                ok = self.partner.notify(
                    "emergency_requested", "Pax emergency release requested",
                    f"Your emergency release for this Mac unlocks in {_fmt(cool)}.",
                    f"Your Pax partner requested an emergency release of Pax on their Mac. It unlocks in "
                    f"{_fmt(cool)}. Please check in with them.", gate={"type": "emergency"})
                if not ok:
                    raise EscrowError("PAX-ESCROW-010", "We couldn't tell your partner yet, so the emergency "
                                      "cooling-off hasn't started. Pax keeps trying.")
            st = self._read("state.json")
            self._apply_emergency(st, now)
            self._write("state.json", st)
        return self.status()

    def _apply_emergency(self, st: dict, now: int) -> None:
        if not st.get("pending_emergency"):
            return
        st["pending_emergency"] = None
        in_grace = now < self._free_until(st)
        cool = 0 if in_grace else EMERGENCY_COOLOFF
        rr = st.get("request")
        if rr and rr["status"] in ("pending", "notifying"):
            if in_grace:
                rr["grace_window"] = True      # no wait: closes with the grace period (v0.8.5)
            rr["unlock_at"] = min(rr["unlock_at"], now + cool) if rr["status"] == "pending" else now + cool
            rr["wait"] = min(rr["wait"], int(rr.get("credited", 0)) + cool) if rr["status"] == "pending" else cool
            rr["kind"] = "emergency"
            if rr["status"] == "notifying":
                rr.update({"status": "pending", "created_at": now, "credited": 0})
        else:
            st["request"] = {"id": _secrets.token_hex(8), "kind": "emergency", "reason": "remove",
                             "status": "pending", "created_at": now, "unlock_at": now + cool,
                             "wait": cool, "credited": 0}
            if in_grace:
                st["request"]["grace_window"] = True

    def reveal(self) -> dict:
        """The released secrets, once the wait is over. Marks the request revealed."""
        with self._lock:
            st = self._read("state.json")
            if self._lapse_if_stale(st, self.clock()):
                self._write("state.json", st)
                raise EscrowError("PAX-ESCROW-005", "this request has lapsed; start a new one (it takes "
                                  "your full wait)")
            rr = st.get("request")
            if rr and rr["status"] == "notifying":
                raise EscrowError("PAX-ESCROW-010", "Your wait starts once your partner has been told.")
            if not rr or rr["status"] not in ("pending", "revealed"):
                raise EscrowError("PAX-ESCROW-005", "no removal request; start your wait first")
            ok, why = self._release_ok(rr, self.clock())
            if not ok:
                raise EscrowError("PAX-ESCROW-007", f"not yet: {why}",
                                  seconds_remaining=max(0, int(rr["unlock_at"] - self.clock())))
            if rr["status"] == "pending" and self.partner.partner() and not rr.get("reveal_notified"):
                queued = any(m.get("gate") == {"type": "reveal", "id": rr["id"]}
                             for m in self.partner.config()["outbox"])
                if not queued:
                    ok = self.partner.notify(
                        "password_revealed", "Removal password released for this Mac",
                        "The password to remove Pax from this Mac was shown in the Pax app.",
                        "Your Pax partner has been given the password to remove Pax from their Mac.",
                        gate={"type": "reveal", "id": rr["id"]})
                    if ok:
                        rr["reveal_notified"] = True
                        self._write("state.json", st)
                if not rr.get("reveal_notified"):
                    raise EscrowError("PAX-ESCROW-010", "Your wait is over, but Pax couldn't tell your partner "
                                      "yet. It keeps trying; try again in a few minutes.")
            sec = self._read("secrets.json")
            if rr["status"] == "pending":
                rr["status"] = "revealed"
                if rr.get("reason", "remove") == "remove":
                    st["released_at"] = int(self.clock())
                self._write("state.json", st)
            out = {"device_id": "local", "reason": rr.get("reason", "remove")}
            for name in RELEASES[rr.get("reason", "remove")]:
                if name in sec:
                    out[{"paxadmin": "removal_password", "recovery_key": "recovery_key",
                         "firmware": "firmware_password"}[name]] = sec[name]
            return out

    def released(self) -> bool:
        with self._lock:
            return bool(self._read("state.json").get("released_at"))

    def set_wait(self, seconds: int) -> dict:
        seconds = validate_wait(seconds)
        with self._lock:
            st = self._read("state.json")
            now = int(self.clock())
            if seconds >= st["wait_seconds"]:
                st["wait_seconds"], st["pending_wait"] = seconds, None
                self._write("state.json", st)
            elif self.partner.partner():
                st["wait_notifying"] = seconds
                self._write("state.json", st)
                ok = self.partner.notify(
                    "wait_decrease_requested", "Turn-off wait shortening requested",
                    f"You asked to shorten your turn-off wait (how long turning Pax off takes after you ask) "
                    f"to {_fmt(seconds)}. That takes {_fmt(st['wait_seconds'])}.",
                    f"Your Pax partner asked to shorten their turn-off wait (how long turning Pax off takes "
                    f"after they ask) from {_fmt(st['wait_seconds'])} to {_fmt(seconds)}. "
                    f"That takes {_fmt(st['wait_seconds'])}.",
                    gate={"type": "wait", "seconds": seconds})
                if not ok:
                    raise EscrowError("PAX-ESCROW-010", "We couldn't tell your partner yet, so the change "
                                      "hasn't started. Pax keeps trying.")
                self.activate({"type": "wait", "seconds": seconds})
            else:
                st["pending_wait"] = {"seconds": seconds, "effective_at": now + st["wait_seconds"]}
                self._write("state.json", st)
        return self.status()

    # ------------------------------------------- v0.8.15 verified support release
    def _support(self, st: dict) -> dict:
        """The support-release state, created on first use. A Mac set up before
        0.8.15 has none: it gets a support ID and the switch OFF (it never agreed
        to support release). The caller writes state.json."""
        sup = st.get("support")
        if not isinstance(sup, dict) or not sup.get("id"):
            sup = _new_support(False, "migrated")
            st["support"] = sup
        sup.setdefault("used_nonces", {})
        sup.setdefault("pending_on", None)
        sup.setdefault("notifying_on", False)
        return sup

    def _support_view(self, st: dict) -> dict:
        had = isinstance(st.get("support"), dict) and st["support"].get("id")
        sup = self._support(st)
        if not had:
            self._write("state.json", st)          # keep the new support ID
        pend = sup.get("pending_on")
        return {"support_id": sup["id"],
                "support_release": {"allowed": bool(sup.get("allowed")),
                                    "pending_on_at": pend["effective_at"] if pend else None,
                                    "telling_partner": bool(sup.get("notifying_on")),
                                    "since": sup.get("since")}}

    def set_support_release(self, allowed) -> dict:
        """Off: at once (stricter). On: after the current wait, partner told
        first (fail closed, PAX-ESCROW-010), like shortening the wait."""
        if not isinstance(allowed, bool):
            raise EscrowError("PAX-ESCROW-008", "allowed must be true or false")
        with self._lock:
            st = self._read("state.json")
            sup = self._support(st)
            now = int(self.clock())
            if not allowed:
                was_notifying = sup.get("notifying_on")
                sup.update({"allowed": False, "pending_on": None, "notifying_on": False})
                self._write("state.json", st)
                self.tamper_log("support_release_setting", {"allowed": False})
                if was_notifying:
                    self.partner.drop_gate({"type": "support_on"})
                return self.status()
            if sup.get("allowed") or sup.get("pending_on") or sup.get("notifying_on"):
                self._write("state.json", st)
                return self.status()
            if self._in_trial(st, now):
                # v0.8.18: in the trial day Pax can be turned off with no wait, so turning
                # this on is instant too. The partner is still told first (no email, no change).
                ok = self.partner.notify(
                    "support_release_on", "Verified support release turned on",
                    "You turned on verified support release on this Mac (it's still your trial day).",
                    "Your Pax partner turned on verified support release on their Mac: in a genuine "
                    "emergency that Pax support has checked, a one-time code could remove Pax from that Mac "
                    "without the wait. You'd be emailed first.", queue=False)
                if not ok:
                    raise EscrowError("PAX-ESCROW-010", "We couldn't tell your partner just now, so nothing "
                                      "changed. Try again in a few minutes.")
                sup.update({"allowed": True, "pending_on": None, "notifying_on": False})
                self._write("state.json", st)
                self.tamper_log("support_release_setting", {"allowed": True, "trial_day": True})
                return self.status()
            wait = st["wait_seconds"]
            if self.partner.partner():
                sup["notifying_on"] = True
                self._write("state.json", st)
                ok = self.partner.notify(
                    "support_release_on_requested", "Verified support release requested",
                    f"You asked to allow verified support release on this Mac. It takes {_fmt(wait)}.",
                    "Your Pax partner asked to allow verified support release on their Mac: in a genuine "
                    "emergency that Pax support has checked, a one-time code could remove Pax from that Mac "
                    f"without the wait. You'd be emailed first. This takes effect in {_fmt(wait)}.",
                    gate={"type": "support_on"})
                if not ok:
                    raise EscrowError("PAX-ESCROW-010", "We couldn't tell your partner yet, so the change "
                                      "hasn't started. Pax keeps trying.")
                self.activate({"type": "support_on"})
            else:
                sup["pending_on"] = {"effective_at": now + wait, "requested_at": now}
                self._write("state.json", st)
            self.tamper_log("support_release_setting", {"allowed": True, "after_seconds": wait})
        return self.status()

    def redeem_support(self, code: str) -> dict:
        """A verified support code for this Mac: check it, email the partner first
        (never queued: no email, no release), then release at once, exactly as
        confirming a finished removal request does. Every refusal is logged."""
        import support_code as sc
        with self._lock:
            st = self._read("state.json")
            sup = self._support(st)
            self._write("state.json", st)
            try:
                if not sup.get("allowed"):
                    raise sc.SupportCodeError(sc.TURNED_OFF, "verified support release is off on this Mac")
                c = sc.verify(code, sup["id"], self.clock(), trusted_now=self.trusted_time())
                if c["nonce"] in sup["used_nonces"]:
                    raise sc.SupportCodeError(sc.USED, "that code has already been used")
            except sc.SupportCodeError as exc:
                self.tamper_log("support_code_refused", {"code": exc.code})
                raise EscrowError(exc.code, exc.message) from None
            if st.get("released_at"):
                raise EscrowError("PAX-ESCROW-005", "Pax has already released this Mac")
            ok = self.partner.notify(
                "support_release_used", "Verified support release used on this Mac",
                "You used a one-time code from Pax support. Pax is releasing this Mac now.",
                "Pax support checked an emergency with your Pax partner and issued a one-time code for "
                "their Mac. It has just been used, so Pax is releasing that Mac now. You might want to "
                "check in with them.", queue=False)
            if not ok:
                self.tamper_log("support_code_refused", {"code": sc.PARTNER_UNREACHABLE, "nonce": c["nonce"]})
                raise EscrowError(sc.PARTNER_UNREACHABLE, "Pax couldn't email your partner just now, so nothing "
                                  "was released. The code still works until it expires; try again shortly.")
            now = int(self.clock())
            sup["used_nonces"][c["nonce"]] = c["expires_at"]
            old = st.get("request")
            if old and old.get("status") == "notifying":
                self.partner.drop_gate({"type": "removal", "id": old["id"]})
            st["request"] = {"id": _secrets.token_hex(8), "kind": "support", "reason": "remove",
                             "status": "pending", "created_at": now, "unlock_at": now, "wait": 0,
                             "credited": 0, "reveal_notified": True, "support_nonce": c["nonce"]}
            self._write("state.json", st)
            self.tamper_log("support_release_used", {"nonce": c["nonce"], "key_id": c["key_id"],
                                                     "expires_at": c["expires_at"]})
            return self.reveal()

    # ------------------------------------------------------------ partner
    def set_partner(self, email: str | None) -> dict:
        """Adding the first partner is immediate; changing or removing one waits
        the current wait (and the current partner is told first), as on the server."""
        from partner import valid_email
        new = (email or "").strip().lower() or None
        if new and not valid_email(new):
            raise EscrowError("PAX-ESCROW-011", "that isn't an email address")
        with self._lock:
            st = self._read("state.json")
            current = self.partner.partner()
            if new == current:
                self.partner.set_pending_partner(None)
                return self.status()
            if current is None:
                if not self.partner.config().get("transport"):
                    raise EscrowError("PAX-ESCROW-011", "set up how Pax sends email first (Settings › Accountability partner email)")
                self.partner.set_partner_now(new)
                self.partner.notify("partner_added", "You are now a Pax accountability partner",
                                    "Your partner was added.",
                                    "Someone you know has made you their Pax accountability partner. You'll be "
                                    "told when they ask to remove their blocker. You never need to approve "
                                    "anything; Pax is fully automatic.", to=new)
                return self.status()
            what = f"replace you with {new}" if new else "remove you"
            ok = self.partner.notify(
                "partner_change_requested", "Partner change requested",
                f"You asked to {'change your partner to ' + new if new else 'remove your partner'}. "
                f"It takes {_fmt(st['wait_seconds'])}.",
                f"Your Pax partner asked to {what} as their accountability partner. This takes effect in "
                f"{_fmt(st['wait_seconds'])}.", gate={"type": "partner", "email": new or ""})
            if not ok:
                raise EscrowError("PAX-ESCROW-010", "We couldn't tell your partner yet, so the change hasn't "
                                  "started. Pax keeps trying.")
            self.activate({"type": "partner", "email": new or ""})
        return self.status()

    def apply_partner_change(self) -> bool:
        """From the heartbeat: a partner change whose wait is over takes effect."""
        pend = self.partner.config().get("pending_partner")
        if not pend or self.clock() < pend.get("effective_at", 0):
            return False
        new = pend.get("email")
        self.partner.set_partner_now(new)
        if new:
            self.partner.notify("partner_added", "You are now a Pax accountability partner",
                                "Your new partner was added.",
                                "Someone you know has made you their Pax accountability partner.", to=new)
        return True


def _new_support(allowed: bool, since: str) -> dict:
    import support_code as sc
    return {"id": sc.new_support_id(), "allowed": bool(allowed), "pending_on": None,
            "notifying_on": False, "used_nonces": {}, "since": since}


def _fmt(seconds: int) -> str:
    seconds = int(seconds)
    if seconds <= 0:
        return "no time"
    if seconds % DAY == 0:
        d = seconds // DAY
        return f"{d} day{'s' if d != 1 else ''}"
    h = round(seconds / HOUR)
    return f"{h} hour{'s' if h != 1 else ''}"


def validate_wait(seconds) -> int:
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        raise EscrowError("PAX-ESCROW-002", "the wait must be a number of seconds") from None
    if not MIN_WAIT <= seconds <= MAX_WAIT:
        raise EscrowError("PAX-ESCROW-002", "the wait must be between 24 hours and 365 days")
    return seconds


def main(argv: list[str] | None = None) -> int:
    """Root-only CLI used once, by the app's set-up step (through the admin prompt):
      local_escrow.py deposit --secret-file F --wait-seconds N [--dir D] [--reset]
    reads the secret from F (then deletes F), stores it, prints its SHA-256."""
    import argparse
    import sys
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("deposit")
    d.add_argument("--secret-file", required=True)
    d.add_argument("--wait-seconds", type=int, default=DEFAULT_WAIT)
    d.add_argument("--dir", default=str(DEFAULT_DIR))
    d.add_argument("--name", default="paxadmin", choices=["paxadmin"])
    d.add_argument("--support-release", choices=["on", "off"], default="off",
                   help="v0.8.15: allow verified support release (the app sends its set-up choice, on by default)")
    d.add_argument("--trial", choices=["on", "off"], default="off",
                   help="v0.8.18: a new set-up asks for a trial day (granted only on this Mac's first day)")
    d.add_argument("--reset", action="store_true",
                   help="set-up only: discard an escrow left by an earlier, unfinished set-up")
    sub.add_parser("status").add_argument("--dir", default=str(DEFAULT_DIR))
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("PAX-ESCROW-008: must run as root", file=sys.stderr)
        return 1
    esc = LocalEscrow(Path(a.dir))
    try:
        if a.cmd == "deposit":
            if a.reset and Path(a.dir).exists():
                import shutil
                shutil.rmtree(a.dir)
            p = Path(a.secret_file)
            secret = p.read_text().strip("\n")
            try:
                p.unlink()
            except OSError:
                pass
            digest = esc.deposit(a.name, secret, wait_seconds=a.wait_seconds,
                                 support_release=a.support_release == "on", trial=a.trial == "on")
            receipt = {"stored": a.name, "sha256": digest}
            if a.trial == "on":
                trial = esc.status().get("trial")
                receipt["trial_until"] = trial["until"] if trial and trial["active"] else None
            print(json.dumps(receipt))
        else:
            print(json.dumps({k: v for k, v in esc.status().items()}))
    except EscrowError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
