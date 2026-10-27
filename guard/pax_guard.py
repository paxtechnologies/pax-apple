#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""pax-guard: the root enforcement daemon on a Mac protected by "Protect this Mac".

Runs as a LaunchDaemon (root, KeepAlive) from /Library/PaxGuard. Every ~30 s,
and soon after a network change, it:

  1. checks the Pax profile is still installed (alerts + logs if not; it cannot
     reinstall a profile silently, macOS needs a person for that)
  2. keeps the managed block in /etc/hosts: your blocked sites, DoH resolver
     names, and (if ad blocking is on) ad/tracker domains (HaGeZi Light, daily).
     v0.8.7: the "Ads and trackers" switch works live on local escrow
     (state/settings.json, like YouTube Restricted Mode), and the ad-list names
     that are also restricted content stay blocked with ads off
  3. keeps the pf anchor blocking DoT, public DoH resolvers and VPN ports
  4. kills and quarantines VPN clients, Tor, unmanageable browsers and (v0.5)
     virtual-machine apps
  5. polls the Pax server with a read-only guard token for list changes
  6. (v0.8.7) keeps the user's own Blocked apps closed: a watcher checks running
     programs every 2 s by bundle ID and code signature, kills a match and moves
     its app into the root-only quarantine, wherever it was copied and whatever
     it was renamed to
  7. (v0.8.33) installs and updates ordinary apps for the Standard account when
     they pass its checks (app_installs.py): same bundle ID and Team ID for an
     update, Developer ID signed and notarised, not a blocked kind of app; .pkg
     installers only when Apple signed them; Apple's own software updates on request
v0.5 adds the "bypass" (always on) and "remote desktop" (server-controlled,
on by default) categories to the hosts block, HaGeZi's DoH/VPN/Tor/Proxy bypass
list, and remote-desktop ports to pf while that category is on.

v0.8.0 makes the Mac independent of any server:
  * local escrow (local_escrow.py): pax-guard itself holds paxadmin's password
    (and the rotated FileVault recovery key / Intel firmware password) and
    releases them after the wait; the app talks to it over /var/run/pax-guard.sock
  * a local DNS forwarder on 127.0.0.1:53 (dns_forwarder.py) with Pax's own
    lists (filter_lists.py), SafeSearch rewrites, then CleanBrowsing Family DoH,
    then AdGuard Family DoH, else SERVFAIL; every network service's DNS points
    at 127.0.0.1 and pf lets only the forwarder reach the upstreams
  * daily signed list updates, 6-hourly signed app updates (pax_update.py)
  * tamper evidence (tamper.py) and the Recovery-mode cheap wins (recovery_guard.py)
The server path (escrow_mode "server") still works, for iPhone set-ups and
anyone who wants it.

Config: /Library/PaxGuard/config.json (root:wheel 0600: it holds the guard token).
State and caches: /Library/PaxGuard/state/ (root 0700). Log: /var/log/pax-guard.log.

Only the standard library is needed (Python 3.9+). Since v0.8.6 pax-guard runs on
its own copy of the signed CPython that ships in Pax.app, /Library/PaxGuard/runtime
(guard_runtime.py), started by bin/pax-guard-launch.sh; /usr/bin/python3 (Command
Line Tools) is only a fallback. The system layer (`System`) is a class so tests can
replace it; tests never touch the real Mac.

Usage:
  pax_guard.py run            # the daemon loop (LaunchDaemon)
  pax_guard.py once           # one cycle, then exit (install and tests)
  pax_guard.py uninstall      # remove hosts block + pf anchor + restore quarantined apps
                              # (only the unlock flow calls this, as root)
  pax_guard.py status         # JSON summary
  pax_guard.py selftest       # imports, bundled lists and config parse (used by updates)
  pax_guard.py ask '<json>'   # send one request to the running guard's socket
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# pax_restricted.py ships next to this file; in the repo it lives in common/.
sys.path.append(str(Path(__file__).resolve().parent.parent / "common"))
import guard_config as gc  # noqa: E402
import guard_runtime as grt  # noqa: E402
import pax_restricted as pr  # noqa: E402

grt.ssl_env()   # v0.8.6: the bundled CPython trusts macOS's /etc/ssl/cert.pem, like /usr/bin/python3

VERSION = "0.8.32"


# v0.8.23: a short backup-filter episode (pax-guard restarting after an update starts on
# the backup until its lists load and the self-check passes) is still written to the
# tamper log, but isn't sent to the app as a recent notice: it isn't a security change.
BRIEF_FALLBACK_SECONDS = 600


def _shown_tamper_events(events: list[dict]) -> list[dict]:
    out: list[dict] = []
    start: dict | None = None
    for e in events:
        k = e.get("kind")
        if k == "dns:fallback_on":
            if start is None:
                start = e
            continue
        if k == "dns:fallback_off":
            if start is not None and int(e.get("ts", 0)) - int(start.get("ts", 0)) >= BRIEF_FALLBACK_SECONDS:
                out += [start, e]
            start = None
            continue
        out.append(e)
    if start is not None:
        out.append(start)          # still on the backup: the app decides when it's worth showing
    return out
BASE = Path("/Library/PaxGuard")
CONFIG_PATH = BASE / "config.json"
STATE_DIR = BASE / "state"
QUARANTINE_DIR = BASE / "quarantine"
LOG_PATH = Path("/var/log/pax-guard.log")
LABEL = "org.paxpeace.pax-guard"
PLIST_PATH = Path(f"/Library/LaunchDaemons/{LABEL}.plist")
INTERVAL = 30
SHORT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")   # v0.8.10, as MacLockdown.isSafeShortName
RUNTIME_CHECK_INTERVAL = 600     # v0.8.6: re-hash /Library/PaxGuard/runtime
APP_DIRS = ["/Applications", "/Applications/Utilities"]


@dataclass
class GuardConfig:
    # v0.8.5: the production Pax server by default; set-up writes the server
    # the app uses (Settings > Advanced), so a self-hosted one still works.
    server_url: str = "https://api.paxpeace.com/"
    guard_token: str = ""
    profile_identifier: str = ""
    user: str = ""                    # the everyday (demoted) account
    resolver_host: str = "doh.cleanbrowsing.org"
    # The set-up choice. v0.8.7: on local escrow the Home switch (state/settings.json)
    # wins once used; on server escrow the server's account setting does.
    adblock_default: bool = True
    # v0.8.13: pictures and video on X and Bluesky are always blocked. The old
    # x_media_default / bluesky_media_default set-up keys (v0.7.0-v0.8.12) are no
    # longer read, so a Mac set up with either off has it back on after updating
    # (see GuardConfig.load and media_forced_on).
    media_forced_on = False   # not a field: set by load() only (v0.8.13)
    ads_allow: list[str] = field(default_factory=list)   # extra local allow-list
    interval: int = INTERVAL
    # v0.8.0. "local": pax-guard holds the secrets (no server); "server": the
    # Pax escrow server does (v0.4-v0.7 behaviour); "auto": server if a guard
    # token is set, else local.
    escrow_mode: str = "auto"
    # "local": the 127.0.0.1 forwarder; "profile": v0.7's DoH profile only.
    dns_mode: str = "local"
    rotate_recovery_key: bool = True      # FileVault PRK rotated + escrowed
    firmware_password: bool = True        # Intel only
    mdm_managed: bool = False             # set-up found another organisation's MDM
    testing_allow_extra_admins: bool = False
    updates: bool = True                  # can't be switched off in the app
    # v0.8.6: YouTube Restricted Mode, chosen at set-up (on by default). The
    # switch in Settings (state/settings.json) wins once used.
    youtube_restricted_default: bool = True
    # v0.8.10: other administrators made standard at set-up (with the user's OK).
    # pax-guard keeps them standard; the uninstaller makes them admins again.
    demoted_admins: list[str] = field(default_factory=list)
    # v0.8.12 Pax Max after set-up. pax_max_switchable: the profile installs Pax
    # Image Blur in Firefox whatever was chosen, so pax-guard can turn it on and off
    # (0.8.12+ set-ups). pax_max_default: the set-up choice (None before 0.8.12).
    pax_max_switchable: bool = False
    pax_max_default: "bool | None" = None

    @property
    def local_escrow(self) -> bool:
        if self.escrow_mode == "auto":
            return not self.guard_token
        return self.escrow_mode == "local"

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> "GuardConfig":
        data = json.loads(path.read_text())
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        cfg = cls(**known)
        # v0.8.13 migration: a set-up that turned X or Bluesky media off is forced
        # back on (the keys are ignored); remembered only for one calm log line.
        cfg.media_forced_on = any(data.get(k) is False for k in LEGACY_MEDIA_KEYS)
        return cfg


# v0.8.13: set-up keys that used to switch X / Bluesky media off. Ignored now.
LEGACY_MEDIA_KEYS = ("x_media_default", "bluesky_media_default")


class RateLimited(OSError):
    """HTTP 429 or 5xx from an update source (v0.8.0): back off, don't retry now."""

    def __init__(self, status: int, retry_after: str | None = None):
        super().__init__(f"HTTP {status}")
        self.status = status
        try:
            self.retry_after = int(retry_after) if retry_after else None
        except ValueError:
            self.retry_after = None


def log(msg: str) -> None:
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    print(line, flush=True)


class System:
    """Everything that touches the Mac. Replaced by a fake in tests."""

    def read(self, path: str) -> str:
        try:
            return Path(path).read_text()
        except FileNotFoundError:
            return ""

    def write_atomic(self, path: str, text: str, mode: int = 0o644) -> None:
        p = Path(path)
        tmp = p.with_name(f".{p.name}.pax-tmp")
        tmp.write_text(text)
        os.chmod(tmp, mode)
        try:
            os.chown(tmp, 0, 0)
        except PermissionError:
            pass
        os.replace(tmp, p)

    def run(self, args: list[str], stdin: str | None = None, timeout: int = 30) -> tuple[int, str]:
        try:
            r = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=timeout)
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, str(exc)

    def run_split(self, args: list[str], stdin: str | None = None,
                  timeout: int = 30) -> tuple[int, str, str]:
        """Like run, but stdout and stderr apart (fdesetup prints a plist on stdout)."""
        try:
            r = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout or "", r.stderr or ""
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, "", str(exc)

    def fetch(self, url: str, headers: dict | None = None, timeout: int = 20) -> bytes:
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed URLs)
                return resp.read()
        except urllib.error.HTTPError as exc:
            # v0.8.0: GitHub/jsDelivr said "slow down" or are failing: don't hit
            # them again through curl; the caller backs off.
            if exc.code == 429 or exc.code >= 500:
                raise RateLimited(exc.code, exc.headers.get("Retry-After") if exc.headers else None) from None
            raise
        except Exception as first:  # noqa: BLE001
            # Fallback: /usr/bin/curl uses the macOS trust store, whatever Python's
            # OpenSSL thinks. Headers go on stdin (-H @-) so tokens stay out of argv.
            args = ["/usr/bin/curl", "-fsSL", "--max-time", str(timeout), "-H", "@-", url]
            hdrs = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
            try:
                r = subprocess.run(args, input=hdrs.encode(), capture_output=True, timeout=timeout + 5)
            except (OSError, subprocess.TimeoutExpired):
                raise first from None
            if r.returncode != 0:
                raise first
            return r.stdout

    def resolve(self, host: str) -> list[str]:
        try:
            return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
        except OSError:
            return []

    def list_apps(self, dirs: list[str]) -> list[str]:
        out: list[str] = []
        for d in dirs:
            try:
                for name in os.listdir(d):
                    if name.lower().endswith(".app"):
                        out.append(os.path.join(d, name))
            except OSError:
                continue
        return out

    def bundle_id(self, app_path: str) -> str | None:
        try:
            with open(os.path.join(app_path, "Contents", "Info.plist"), "rb") as fh:
                return plistlib.load(fh).get("CFBundleIdentifier")
        except (OSError, plistlib.InvalidFileException, ValueError):
            return None

    def app_plist(self, app_path: str) -> dict:
        """v0.8.7: the app's Info.plist (name, executable), {} if unreadable."""
        try:
            with open(os.path.join(app_path, "Contents", "Info.plist"), "rb") as fh:
                data = plistlib.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, plistlib.InvalidFileException, ValueError):
            return {}

    def processes(self) -> list[tuple[int, str]]:
        code, out = self.run(["/bin/ps", "-axo", "pid=,comm="])
        procs = []
        if code == 0:
            for line in out.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0].isdigit():
                    procs.append((int(parts[0]), parts[1]))
        return procs

    def kill(self, pid: int) -> None:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    def move(self, src: str, dst: str) -> None:
        Path(dst).parent.mkdir(parents=True, exist_ok=True)
        shutil.move(src, dst)
        os.chmod(dst, 0o700)

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def home_of(self, user: str) -> str | None:
        if not user:
            return None
        p = f"/Users/{user}"
        return p if os.path.isdir(p) else None

    def now(self) -> int:
        return int(time.time())


class Guard:
    def __init__(self, cfg: GuardConfig, system: System | None = None,
                 state_dir: Path = STATE_DIR, quarantine_dir: Path = QUARANTINE_DIR,
                 list_dirs: list[Path] | None = None):
        self.cfg = cfg
        self.list_dirs = list_dirs
        self.sys = system or System()
        self.state_dir = state_dir
        self.quarantine_dir = quarantine_dir
        self.remote: dict = {}
        self.released = False
        # v0.8.0 components. The escrow and blocklist live next to state/ so tests
        # (state_dir in a temp folder) never touch /Library.
        import local_escrow as le
        import local_blocklist as lb
        import tamper as tp
        self.base_dir = state_dir.parent
        self.forwarder = None          # dns_forwarder.Forwarder once run_forever starts it
        self.tamper_log = tp.TamperLog(state_dir / "tamper.jsonl", clock=self.sys.now)
        self.escrow = le.LocalEscrow(self.base_dir / "escrow", clock=self.sys.now,
                                     trusted_time=self.trusted_time,
                                     tamper_log=self.tamper_log.append)
        self.blocklist = lb.LocalBlocklist(state_dir / "blocklist.json", wait_seconds=self._wait_seconds,
                                           clock=self.sys.now, trusted_time=self.trusted_time,
                                           partner=self.escrow.partner if self.escrow.exists() else None,
                                           restricted_check=self.restricted_upstream_check,
                                           restricted_static=self.restricted_static,
                                           on_applied=self._waited_change_applied)
        # v0.8.9: "Sync blocked sites across devices" (local escrow; on by default).
        import list_sync as lsync
        lsync.APP_VERSION = VERSION      # v0.8.24: sent with each sync, for the server's version count
        self.list_sync = lsync.ListSync(state_dir / "sync.json", self.blocklist, clock=self.sys.now,
                                        wait_seconds=self._wait_seconds_or_none,
                                        partner_email=self._partner_email,
                                        tamper=self.tamper_log.append, log=log,
                                        on_change=self._refresh_after_list_change)
        self.updater = None
        self.filter_store = None
        self._update_rate = None
        self._bg: dict = {}
        self._runtime_checked = 0
        self._runtime_note = ""
        # v0.8.7: the app socket (its own thread) and the loop both rewrite
        # /etc/hosts and the lists now; one at a time.
        self._hosts_lock = threading.RLock()
        self._lists_lock = threading.Lock()
        # v0.8.7 Blocked apps: app path -> (read at, AppIdentity); one enforcer at a time.
        self._ident_cache: dict = {}
        self._apps_lock = threading.RLock()
        # v0.8.33 Pax-approved installs and updates (app_installs.py); made on first use.
        self._installer = None
        self._install_rate = None

    # ---------------------------------------------------------------- state
    def _state_file(self, name: str) -> Path:
        return self.state_dir / name

    def _load_json(self, name: str, default):
        try:
            return json.loads(self.sys.read(str(self._state_file(name))) or "null") or default
        except ValueError:
            return default

    def _save_json(self, name: str, value) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.sys.write_atomic(str(self._state_file(name)), json.dumps(value), 0o600)

    # --------------------------------------------------------------- server
    def sync_remote(self) -> dict:
        """Fetch /v1/guard/config. On failure keep the last good copy, so a
        network outage never unblocks anything."""
        cached = self._load_json("remote.json", {})
        if self.cfg.local_escrow:
            self.remote = self.local_remote()
            return self.remote
        if not self.cfg.guard_token:
            self.remote = cached
            return cached
        url = self.cfg.server_url.rstrip("/") + "/v1/guard/config"
        try:
            data = json.loads(self.sys.fetch(url, {"X-Pax-Guard-Token": self.cfg.guard_token,
                                                   "X-Pax-Version": VERSION}))  # v0.8.24: version count only
            if isinstance(data, dict) and isinstance(data.get("blocked"), list):
                self._save_json("remote.json", data)
                self.remote = data
                return data
        except Exception as exc:  # noqa: BLE001 - any failure keeps the cache
            log(f"PAX-GUARD-007 server sync failed ({type(exc).__name__}); using cached lists")
        self.remote = cached
        return cached

    # ---------------------------------------------------------- v0.8 local
    def trusted_time(self) -> float | None:
        return self.forwarder.trusted_now() if self.forwarder is not None else None

    def _wait_seconds(self) -> int:
        try:
            return int(self.escrow.status()["wait_seconds"])
        except Exception:  # noqa: BLE001 - no escrow yet: the default wait
            return 72 * 3600

    def _wait_seconds_or_none(self):
        """v0.8.9: this Mac's own wait, reported to the account so a synced removal
        waits at least this long (None before the key is held)."""
        if not (self.cfg.local_escrow and self.escrow.exists()):
            return None
        return int(self.escrow.status()["wait_seconds"])

    def _partner_email(self):
        if not (self.cfg.local_escrow and self.escrow.exists()):
            return None
        return self.escrow.partner.partner()

    def flush_partner(self) -> list[dict]:
        """Retry queued partner emails; start whatever was waiting on them."""
        if self.blocklist.partner is None:
            self.blocklist.partner = self.escrow.partner
        gates = self.escrow.partner.flush()
        for g in gates:
            if g.get("type") == "blocklist":
                self.blocklist.activate(g.get("id", ""))
            else:
                self.escrow.activate(g)
        return gates

    def local_remote(self) -> dict:
        """The same shape as the server's /v1/guard/config, from local state."""
        self.blocklist.apply_due()
        released = False
        try:
            released = self.escrow.exists() and self.escrow.released()
        except Exception as exc:  # noqa: BLE001 - tamper: never treated as released
            log(f"PAX-GUARD-010 escrow check failed: {exc}")
        return {"blocked": self.blocklist.blocked(), "allowed": self.blocklist.allowed(),
                "adblock": self.local_adblock, "released": released}

    @property
    def adblock(self) -> bool:
        """Ads and trackers in effect: on local escrow the Home switch (v0.8.7),
        on server escrow the server's account setting (last good copy)."""
        if self.cfg.local_escrow:
            return self.local_adblock
        return bool(self.remote.get("adblock", self.cfg.adblock_default))

    @property
    def x_media_blocked(self) -> bool:
        """v0.8.13: X's image/video servers are always blocked (no switch; neither the
        old set-up key nor a server value can turn this off)."""
        return True

    @property
    def bluesky_media_blocked(self) -> bool:
        """v0.8.13: Bluesky's image/video/GIF servers are always blocked."""
        return True

    # ------------------------------------------------ v0.8.6 user settings
    @property
    def youtube_restricted(self) -> bool:
        """YouTube Restricted Mode: on unless the user switched it off in Settings
        (or chose off at set-up). Kept in state/, so updates never reset it."""
        st = self._load_json("settings.json", {})
        if isinstance(st, dict) and isinstance(st.get("youtube_restricted"), bool):
            return st["youtube_restricted"]
        return bool(self.cfg.youtube_restricted_default)

    @property
    def family_layer(self) -> bool:
        """v0.8.18 Advanced: the extra family-filter layer after Pax's own filter.
        Local escrow keeps it with the waited changes; server escrow reads the
        account's category. Off by default."""
        if self.cfg.local_escrow:
            try:
                return self.blocklist.family_layer()
            except Exception:  # noqa: BLE001 - unreadable state: the stricter choice
                return True
        cats = self.remote.get("categories") or {}
        return cats.get("family_layer") is True

    @property
    def local_adblock(self) -> bool:
        """v0.8.7: "Ads and trackers" on local escrow: the Home switch once used
        (state/settings.json, so updates and restarts keep it), else the set-up choice."""
        st = self._load_json("settings.json", {})
        if isinstance(st, dict) and isinstance(st.get("adblock"), bool):
            return st["adblock"]
        return bool(self.cfg.adblock_default)

    def settings_view(self) -> dict:
        st = self._load_json("settings.json", {})
        local = self.cfg.local_escrow
        return {"youtube_restricted": self.youtube_restricted,
                "youtube_available": self.cfg.dns_mode == "local",
                # v0.8.7: ads. adblock_local false = the Pax server holds the setting
                # (server escrow), so the app switches it there.
                "adblock": self.local_adblock if local else self.adblock,
                "adblock_local": local,
                # v0.8.12: Pax Max after set-up (see handle_pax_max).
                "pax_max": self.pax_max_view(),
                # v0.8.18 Advanced: the extra family filter. family_layer_local false =
                # the Pax server holds it (an account category with the same wait).
                "family_layer": self.family_layer,
                "family_layer_local": local,
                "family_layer_pending": self.blocklist.family_layer_pending() if local else None,
                "changed_at": st.get("changed_at") if isinstance(st, dict) else None}

    def _save_setting(self, key: str, value: bool) -> None:
        st = self._load_json("settings.json", {})
        st = st if isinstance(st, dict) else {}
        st.update({key: value, "changed_at": self.sys.now()})
        self._save_json("settings.json", st)

    def set_adblock(self, on, uid=None) -> dict:
        """v0.8.7: "Ads and trackers" on local escrow. A convenience filter, not
        restricted-content protection, so both directions take effect at once with
        no wait and no partner email, like YouTube Restricted Mode; the change is
        written to the tamper log. Off removes only ad names: restricted content
        (including the ad-list names that are restricted, see restricted_ad_names)
        stays blocked in /etc/hosts and in the forwarder."""
        if not isinstance(on, bool):
            raise ValueError("adblock must be true or false")
        before = self.local_adblock
        self._save_setting("adblock", on)
        if before != on:
            self.tamper_log.append("setting:adblock", {"from": before, "to": on, "uid": uid})
            log(f"ads and trackers {'on' if on else 'off'} (uid {uid})")
        self.sync_remote()
        if on and self.ads_stale():
            # No copy yet (set up with ads off) or an old one: whatever copy there is
            # goes in now, and a fresh one is fetched without holding up the app.
            def fetch_then_apply():
                self.refresh_lists(force=True, ads_only=True)
                self._enforce_hosts_quietly()
            self._background("ads", fetch_then_apply)
        self._enforce_hosts_quietly()
        return self.settings_view()

    def _enforce_hosts_quietly(self) -> None:
        try:
            self.enforce_hosts()
        except OSError as exc:
            log(f"hosts update deferred to the next check ({exc})")

    def set_youtube_restricted(self, on, uid=None) -> dict:
        """The project's rule: both directions take effect at once, with no
        wait and no partner email. The change is written to the tamper log."""
        if not isinstance(on, bool):
            raise ValueError("youtube_restricted must be true or false")
        before = self.youtube_restricted
        self._save_setting("youtube_restricted", on)
        if before != on:
            self.tamper_log.append("setting:youtube_restricted", {"from": before, "to": on, "uid": uid})
            log(f"YouTube Restricted Mode {'on' if on else 'off'} (uid {uid})")
        self.update_forwarder_policy()
        return self.settings_view()

    @property
    def remote_desktop_blocked(self) -> bool:
        """On unless the server says the user switched it off (after the wait).
        An older server, or no server yet, means on."""
        cats = self.remote.get("categories") or {}
        return cats.get("remote_desktop", True) is not False

    # ------------------------------------------------------------ ad lists
    def ads_stale(self) -> bool:
        """v0.8.7: no ad list yet, or one older than a day."""
        meta = self._load_json("lists-meta.json", {})
        return (not self._load_json("ads.json", []) or
                self.sys.now() - int(meta.get("ads_fetched_at", 0)) >= gc.ADS_REFRESH_SECONDS)

    def refresh_lists(self, force: bool = False, ads_only: bool = False) -> None:
        """Download HaGeZi Light (hosts) + DoH names + DoH IPs, at most daily.

        v0.8.7: the ad list has its own clock (ads_fetched_at), so switching ads
        on after days off fetches a fresh copy at once instead of up to a day
        later; a failed ad download is retried hourly. Only one refresh runs at a
        time (the loop, or the app's switch in the background)."""
        if not self._lists_lock.acquire(blocking=False):
            return
        try:
            self._refresh_lists(force, ads_only)
        finally:
            self._lists_lock.release()

    def _refresh_lists(self, force: bool, ads_only: bool) -> None:
        meta = self._load_json("lists-meta.json", {})
        now = self.sys.now()
        lists_due = not ads_only and (force or now - int(meta.get("fetched_at", 0)) >= gc.ADS_REFRESH_SECONDS)
        ads_due = self.adblock and (force or (
            now - int(meta.get("ads_fetched_at", 0)) >= gc.ADS_REFRESH_SECONDS
            and now - int(meta.get("ads_tried_at", 0)) >= gc.ADS_RETRY_SECONDS))
        if not (lists_due or ads_due):
            return
        if ads_due:
            meta["ads_tried_at"] = now
            for url in (gc.ADS_LIST_URL, gc.ADS_LIST_MIRROR):
                try:
                    domains = gc.parse_domain_list(self.sys.fetch(url, timeout=60).decode("utf-8", "replace"))
                except Exception:  # noqa: BLE001
                    continue
                if len(domains) >= gc.ADS_MIN_ENTRIES:
                    self._save_json("ads.json", domains)
                    meta["ads_fetched_at"] = now
                    break
                log(f"PAX-DNS-002 ad list from {url} too small ({len(domains)}); keeping the old copy")
        if lists_due:
            for url in (gc.BYPASS_LIST_URL, gc.BYPASS_LIST_MIRROR):
                try:
                    names = gc.parse_domain_list(self.sys.fetch(url, timeout=60).decode("utf-8", "replace"))
                except Exception:  # noqa: BLE001
                    continue
                if len(names) >= gc.BYPASS_MIN_ENTRIES:
                    self._save_json("bypass.json", names)
                    break
                log(f"PAX-DNS-002 bypass list from {url} too small ({len(names)}); keeping the old copy")
            try:
                names = gc.parse_domain_list(self.sys.fetch(gc.DOH_NAMES_URL).decode("utf-8", "replace"))
                if len(names) > 500:
                    self._save_json("doh-names.json", names)
            except Exception:  # noqa: BLE001
                pass
            try:
                ips = [l.strip() for l in self.sys.fetch(gc.DOH_IPS_URL).decode().splitlines()]
                ips = [i for i in ips if i and not i.startswith("#")]
                if len(ips) > 100:
                    self._save_json("doh-ips.json", ips)
            except Exception:  # noqa: BLE001
                pass
            meta["fetched_at"] = now
        self._save_json("lists-meta.json", meta)

    # ----------------------------------------- v0.8.7 restricted ad names
    def restricted_ad_names(self, ads_raw: str | None = None) -> list[str]:
        """Names in the last downloaded ad list that are also restricted content
        (Pax's name rule, top-level domains and hand list, the restricted
        categories, and, once loaded, the forwarder's restricted lists such as
        pax-block). HaGeZi Light carried 1,221 of them (2026-10-16), mostly
        adult ad servers. They go in /etc/hosts at restricted priority whether ads
        are on or off, so switching ads off never unblocks one, even on a Mac
        whose DNS doesn't go through the forwarder. Kept in
        state/ads-restricted.json, recomputed when the ad list or the forwarder's
        lists change (in the background while the daemon runs)."""
        if ads_raw is None:
            ads_raw = self.sys.read(str(self._state_file("ads.json")))
        if not ads_raw.strip():
            saved = self._load_json("ads-restricted.json", {})
            return list(saved.get("names", [])) if isinstance(saved, dict) else []
        fs = self.forwarder.filters if self.forwarder is not None else None
        version = str((fs.info or {}).get("version", "loaded")) if fs is not None else "none"
        key = hashlib.sha256(ads_raw.encode()).hexdigest()[:32] + "|" + version
        saved = self._load_json("ads-restricted.json", {})
        saved = saved if isinstance(saved, dict) else {}
        if saved.get("key") == key:
            return list(saved.get("names", []))
        if self.forwarder is None:
            return self._compute_restricted_ads(ads_raw, key, fs)       # once / tests: right away
        # The daemon: the previous answer stands while the new one is worked out.
        self._background("ads-restricted", lambda: self._compute_restricted_ads(ads_raw, key, fs))
        return list(saved.get("names", []))

    def _compute_restricted_ads(self, ads_raw: str, key: str, fs) -> list[str]:
        try:
            ads = json.loads(ads_raw)
        except ValueError:
            return []
        rule = self.media_converter_rule()
        chk = pr.RestrictedCheck(sets=[set(self.restricted_sites())], rules=[rule] if rule else [])
        names = []
        for d in ads if isinstance(ads, list) else []:
            if not isinstance(d, str):
                continue
            if chk(d) or (fs is not None and not fs.allowed(d) and fs.restricted_by(d)):
                names.append(d)
        prev = self._load_json("ads-restricted.json", {})
        prev = prev if isinstance(prev, dict) else {}
        prev_names = [n for n in prev.get("names", []) if isinstance(n, str)]
        if fs is None and str(prev.get("key", "")).split("|")[0] == key.split("|")[0]:
            # Same ad list, lists not loaded yet (just restarted): keep what the
            # full check found last time as well.
            have = set(names)
            names += [n for n in prev_names if n not in have]
        self._save_json("ads-restricted.json", {"key": key, "names": names, "at": self.sys.now()})
        if self.forwarder is not None and set(names) != set(prev_names):
            log(f"{len(names)} ad-list names are restricted content; they stay blocked with ads off")
        return names

    # ---------------------------------------------------------------- hosts
    def desired_hosts_domains(self) -> list[str]:
        blocked = list(self.remote.get("blocked", []))
        allowed = list(self.remote.get("allowed", [])) + list(self.cfg.ads_allow)
        ads_raw = self.sys.read(str(self._state_file("ads.json")))
        try:
            ads = (json.loads(ads_raw or "null") or []) if self.adblock else []
        except ValueError:
            ads = []
        protected = [self.cfg.resolver_host]
        host = (self.cfg.server_url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0])
        if host:
            protected.append(host)
        # v0.8.13: X and Bluesky media are in restricted_sites() (always, no exception).
        categories = self.curated("bypass")
        if self.remote_desktop_blocked:
            categories += self.curated("remote_desktop")
        return gc.hosts_domains(blocked, ads=ads, allowlist=gc.ADS_ALLOWLIST + allowed,
                                bypass_names=self._load_json("doh-names.json", []),
                                protected=protected, categories=categories,
                                bypass_list=self._load_json("bypass.json", []),
                                exceptions=list(self.remote.get("allowed", [])),
                                restricted=self.restricted_sites(),
                                restricted_exact=self.restricted_ad_names(ads_raw))

    def curated(self, category: str) -> list[str]:
        names = gc.load_curated(category, self.list_dirs)
        if not names:
            log(f"PAX-GUARD-008 curated list '{category}' is missing; reinstall pax-guard")
        return names

    def enforce_hosts(self) -> bool:
        with self._hosts_lock:
            return self._enforce_hosts()

    def _enforce_hosts(self) -> bool:
        current = self.sys.read(gc.HOSTS_PATH)
        new = gc.render_hosts(current, self.desired_hosts_domains(), self.hosts_extra())
        if new == current:
            return False
        self.sys.write_atomic(gc.HOSTS_PATH, new, 0o644)
        self.sys.run(["/usr/bin/dscacheutil", "-flushcache"])
        self.sys.run(["/usr/bin/killall", "-HUP", "mDNSResponder"])
        log("hosts block updated")
        return True

    # ------------------------------------------------------------------- pf
    def desired_pf(self, root_only_upstream: bool = True) -> str:
        extra = gc.merge_doh_ips(self._load_json("doh-ips.json", []), base=[])
        if self.cfg.dns_mode == "local":
            fwd = self.forwarder
            pinned = fwd.family_ips() if fwd is not None else []
            primary = fwd.primary_ips() if fwd is not None else []
            allow = sorted(set(gc.CLEANBROWSING_FAMILY_IPS + gc.ADGUARD_FAMILY_IPS + pinned))
            return gc.pf_rules(allow_ips=allow, doh_ips=gc.PUBLIC_DOH_IPS, dns_only_ips=extra,
                               remote_desktop=self.remote_desktop_blocked, local_dns=True,
                               root_only_upstream=root_only_upstream, primary_ips=primary)
        allow = sorted(set(gc.CLEANBROWSING_FAMILY_IPS + self.sys.resolve(self.cfg.resolver_host)))
        code, out = self.sys.run(["/usr/sbin/scutil", "--dns"], timeout=5)
        system_dns = gc.parse_scutil_dns(out) if code == 0 else []
        return gc.pf_rules(allow_ips=allow, doh_ips=gc.PUBLIC_DOH_IPS, dns_only_ips=extra,
                           system_dns=system_dns, remote_desktop=self.remote_desktop_blocked)

    def ensure_pf_enabled(self) -> None:
        """pf is off by default on macOS. `pfctl -E` takes a reference that keeps
        it on; only ask when it's actually disabled so references don't pile up."""
        code, out = self.sys.run(["/sbin/pfctl", "-s", "info"])
        if code != 0 or "Status: Enabled" not in out:
            self.sys.run(["/sbin/pfctl", "-E"])

    def enforce_pf(self) -> bool:
        root_only = not self._load_json("pf.json", {}).get("no_user_match")
        rules = self.desired_pf(root_only_upstream=root_only)
        digest = hashlib.sha256(rules.encode()).hexdigest()
        code, out = self.sys.run(["/sbin/pfctl", "-a", gc.PF_ANCHOR, "-sr"])
        loaded = code == 0 and "block drop out" in out
        if loaded and self._load_json("pf.json", {}).get("digest") == digest:
            self.ensure_pf_enabled()
            return False
        code, out = self.sys.run(["/sbin/pfctl", "-a", gc.PF_ANCHOR, "-f", "-"], stdin=rules)
        no_user = not root_only
        if code != 0 and root_only and self.cfg.dns_mode == "local":
            # A pf that won't match by user: still only the filtered upstreams.
            log(f"PAX-GUARD-009 pf refused the root-only rule ({out.strip()[:120]}); loading without it")
            rules = self.desired_pf(root_only_upstream=False)
            digest = hashlib.sha256(rules.encode()).hexdigest()
            code, out = self.sys.run(["/sbin/pfctl", "-a", gc.PF_ANCHOR, "-f", "-"], stdin=rules)
            no_user = True
        if code != 0:
            log(f"PAX-GUARD-009 pfctl load failed: {out.strip()[:200]}")
            return False
        self.ensure_pf_enabled()
        self._save_json("pf.json", {"digest": digest, "no_user_match": no_user})
        log("pf anchor loaded")
        return True

    # ------------------------------------------------------- v0.8 DNS settings
    NETWORKSETUP = "/usr/sbin/networksetup"

    def enforce_dns_settings(self) -> list[str]:
        """Point every enabled network service's DNS at 127.0.0.1 (the forwarder).
        The first time, the previous servers are saved so removal restores them."""
        if self.cfg.dns_mode != "local":
            return []
        code, out = self.sys.run([self.NETWORKSETUP, "-listallnetworkservices"], timeout=15)
        if code != 0:
            return []
        saved = self._load_json("dns-saved.json", {})
        changed = []
        for svc in gc.parse_network_services(out):
            c, cur = self.sys.run([self.NETWORKSETUP, "-getdnsservers", svc], timeout=10)
            servers = gc.parse_dns_servers(cur) if c == 0 else []
            if servers == [gc.LOCAL_DNS]:
                continue
            if svc not in saved:
                saved[svc] = servers
            self.sys.run([self.NETWORKSETUP, "-setdnsservers", svc, gc.LOCAL_DNS], timeout=15)
            changed.append(svc)
        if changed:
            self._save_json("dns-saved.json", saved)
            self.sys.run(["/usr/bin/dscacheutil", "-flushcache"])
            self.sys.run(["/usr/bin/killall", "-HUP", "mDNSResponder"])
            log(f"DNS for {', '.join(changed)} now goes to Pax (127.0.0.1)")
        return changed

    def restore_dns_settings(self) -> list[str]:
        saved = self._load_json("dns-saved.json", {})
        done = []
        for svc, servers in saved.items():
            self.sys.run([self.NETWORKSETUP, "-setdnsservers", svc] + (servers or ["Empty"]), timeout=15)
            done.append(svc)
        return done

    def forwarder_policy(self):
        import dns_forwarder as dnsf
        cats = self.curated("bypass")   # v0.8.13: X/Bluesky media are in restricted_sites()
        if self.remote_desktop_blocked:
            cats += self.curated("remote_desktop")
        exceptions = list(self.remote.get("allowed", []))
        cats = [c for c in cats if not any(c == e or c.endswith("." + e) for e in exceptions)]
        rule = self.media_converter_rule()
        return dnsf.Policy(blocked=list(self.remote.get("blocked", [])), exceptions=exceptions,
                           categories=cats, restricted=self.restricted_sites(),
                           restricted_rules=[rule] if rule else [], never_except=pr.RestrictedCheck(),
                           youtube_restricted=self.youtube_restricted, family_layer=self.family_layer)

    # ------------------------------------------- v0.8.1 restricted categories
    def restricted_sites(self) -> list[str]:
        """Always-on sites no exception frees: the media converters, the
        remote AI browsers and (v0.8.13) X's and Bluesky's media servers."""
        out: list[str] = []
        for cat in gc.RESTRICTED_CATEGORIES:
            out += self.curated(cat)
        return out + list(gc.ALWAYS_BLOCKED_MEDIA_NAMES)

    def media_converter_rule(self):
        path = gc.find_list("media_converter_rule", self.list_dirs)
        if path is None:
            log("PAX-GUARD-008 curated list 'media_converter_rule' is missing; reinstall pax-guard")
            return None
        return pr.parse_rule_file(path.read_text())

    def restricted_static(self, domain: str) -> bool:
        """True for a site Pax always blocks, without the network: restricted
        content (name rule, top-level domains, hand list, pax-block, pax-nrd,
        restricted plug-ins), the media converters and the remote AI browsers."""
        rule = self.media_converter_rule()
        chk = pr.RestrictedCheck(sets=[set(self.restricted_sites())], rules=[rule] if rule else [])
        if chk(domain):
            return True
        fs = self.forwarder.filters if self.forwarder is not None else None
        return bool(fs is not None and not fs.allowed(domain) and fs.restricted_by(domain))

    def restricted_upstream_check(self, domain: str) -> None:
        """Raise pax_restricted.RestrictedSite when CleanBrowsing Family blocks
        `domain` or can't be asked (fail closed).

        v0.8.18: Pax's own lists already ran (restricted_static). The outside
        lookup is made only when the user turned on the extra family layer (its
        lookups go through that filter) or when Pax's own filter can't answer right
        now (lists not loaded or in the fallback); otherwise Pax's lists decide."""
        fwd = self.forwarder
        if fwd is not None and fwd.pax_filter_ok and not self.family_layer:
            return
        lookup = None
        if self.forwarder is not None:
            cb = next((u for u in self.forwarder.upstreams if u.name.startswith("CleanBrowsing")), None)
            if cb is not None:
                lookup = cb.query
        if lookup is None:
            lookup = pr.doh_lookup(pr.CLEANBROWSING_FAMILY_DOH)
        blocked, why = pr.upstream_blocked(domain, lookup)
        if blocked:
            raise pr.RestrictedSite(domain, why)

    # ------------------------------------------------- v0.8.12 Pax Max
    PAX_MAX_ONLINE_MAX_AGE = 900      # network time no older than 15 minutes = online

    @property
    def pax_max_switchable(self) -> bool:
        return bool(self.cfg.pax_max_switchable and self.cfg.local_escrow)

    def pax_max_on(self) -> bool | None:
        """Pax Max in effect on a switchable Mac (None: chosen at set-up only). An
        unknown set-up choice counts as on, so nothing is ever loosened by mistake."""
        if not self.pax_max_switchable:
            return None
        default = self.cfg.pax_max_default if isinstance(self.cfg.pax_max_default, bool) else True
        return self.blocklist.pax_max(default)

    def pax_max_view(self) -> dict:
        import local_blocklist as lb
        on = self.pax_max_on()
        return {"switchable": self.pax_max_switchable, "on": on,
                "pending": self.blocklist.pax_max_pending() if self.pax_max_switchable else None,
                "off_delay_seconds": lb.PAX_MAX_OFF_SECONDS}

    def hosts_extra(self) -> list[tuple[str, str]]:
        """The Pax Max off signal, written only when it is switchable and off."""
        if self.pax_max_on() is False:
            return [(gc.PAX_MAX_OFF_ADDR, gc.PAX_MAX_OFF_NAME)]
        return []

    def online(self) -> bool:
        """Recent TLS-checked time from a filtered upstream: Pax is online and the
        clock can be trusted. Without the forwarder there's no proof: offline."""
        if self.forwarder is None:
            return False
        return self.forwarder.trusted_now(max_age=self.PAX_MAX_ONLINE_MAX_AGE) is not None

    def _waited_change_applied(self, r: dict) -> None:
        if r.get("action") == "pax_max_off":
            self.tamper_log.append("setting:pax_max", {"from": True, "to": False, "request_id": r.get("id")})
            log("Pax Max off (its hour is over)")
        if r.get("action") == "family_layer_off":
            self.tamper_log.append("setting:family_layer", {"from": True, "to": False, "request_id": r.get("id")})
            log("extra family filter off (the wait is over)")
            self.update_forwarder_policy()

    def handle_pax_max(self, cmd: str, req: dict, uid) -> dict:
        """paxmax.get / paxmax.on (instant) / paxmax.off (partner first, then a fixed
        hour; never offline) / paxmax.cancel {request_id}."""
        if cmd == "paxmax.get":
            return {"ok": True, "pax_max": self.pax_max_view()}
        if not self.pax_max_switchable:
            return {"ok": False, "code": "PAX-GUARD-015",
                    "error": "Pax Max can only be changed by setting Pax up again on this Mac"}
        if self.blocklist.partner is None and self.escrow.exists():
            self.blocklist.partner = self.escrow.partner
        if cmd == "paxmax.on":
            before = self.pax_max_on()
            if self.blocklist.pax_max_on() or before is False:
                self.tamper_log.append("setting:pax_max", {"from": before, "to": True, "uid": uid})
                log(f"Pax Max on (uid {uid})")
            self._enforce_hosts_quietly()
            return {"ok": True, "pax_max": self.pax_max_view()}
        if cmd == "paxmax.off":
            if self.pax_max_on() is False:
                return {"ok": True, "pax_max": self.pax_max_view()}
            if self.blocklist.pax_max_pending() is None and not self.online():
                return {"ok": False, "code": "PAX-GUARD-014",
                        "error": "Pax couldn't go online, so Pax Max stays on"}
            had = self.blocklist.pax_max_pending()
            try:
                out = self.blocklist.request_pax_max_off()
            finally:
                if had is None and self.blocklist.pax_max_pending() is not None:
                    self.tamper_log.append("setting:pax_max_off_requested", {"uid": uid})
            return {"ok": True, "request": out["request"], "pax_max": self.pax_max_view()}
        if cmd == "paxmax.cancel":
            pending = self.blocklist.pax_max_pending()
            rid = str(req.get("request_id", "")) or (pending or {}).get("request_id", "")
            if not pending or pending["request_id"] != rid:
                return {"ok": False, "code": "PAX-ESCROW-005", "error": "no such waiting change"}
            self.blocklist.cancel(rid)
            self.tamper_log.append("setting:pax_max_off_cancelled", {"uid": uid})
            return {"ok": True, "pax_max": self.pax_max_view()}
        return {"ok": False, "code": "PAX-GUARD-012", "error": f"unknown request {cmd!r}"}

    def update_forwarder_policy(self) -> None:
        if self.forwarder is None:
            return
        key = json.dumps([self.remote.get("blocked"), self.remote.get("allowed"),
                          self.remote_desktop_blocked, self.youtube_restricted, self.family_layer],
                         sort_keys=True)
        if key != getattr(self, "_policy_key", None):
            self._policy_key = key
            self.forwarder.set_policy(self.forwarder_policy())

    # ---------------------------------------------------------- bypass apps
    def app_dirs(self) -> list[str]:
        dirs = list(APP_DIRS)
        home = self.sys.home_of(self.cfg.user)
        if home:
            dirs += [f"{home}/Applications", f"{home}/Downloads", f"{home}/Desktop"]
        return dirs

    def enforce_apps(self) -> list[str]:
        """Kill running bypass apps, then move their bundles into the root-only
        quarantine folder. Returns what it acted on."""
        acted: list[str] = []
        apps = self.sys.list_apps(self.app_dirs())
        bad: dict[str, gc.BypassApp] = {}
        for path in apps:
            hit = gc.is_bypass_app(os.path.basename(path), self.sys.bundle_id(path))
            if hit:
                bad[path] = hit
        for pid, comm in self.sys.processes():
            bundle = gc.app_bundle_of(comm)
            if not bundle:
                if gc.is_vm_process(comm):
                    self.sys.kill(pid)
                    acted.append(f"killed virtual machine {comm.rsplit('/', 1)[-1]} ({pid})")
                continue
            hit = bad.get(bundle) or gc.is_bypass_app(os.path.basename(bundle), self.sys.bundle_id(bundle))
            if hit:
                self.sys.kill(pid)
                acted.append(f"killed {hit.name} ({pid})")
                bad.setdefault(bundle, hit)
        for path, hit in bad.items():
            if not self.sys.exists(path):
                continue
            dest = str(self.quarantine_dir / f"{self.sys.now()}-{os.path.basename(path)}")
            try:
                self.sys.move(path, dest)
                self._record_quarantine(path, dest)
                acted.append(f"quarantined {hit.name}: {path}")
            except OSError as exc:
                acted.append(f"could not quarantine {path}: {exc}")
        for a in acted:
            log(a)
        return acted

    def _record_quarantine(self, src: str, dest: str) -> None:
        q = self._load_json("quarantine.json", [])
        q.append({"from": src, "to": dest})
        self._save_json("quarantine.json", q)

    # -------------------------------------------------------------- profile
    PROFILE_QUERIES = (["/usr/bin/profiles", "show", "-type", "configuration"],
                       ["/usr/bin/profiles", "-P"])

    def profile_installed(self) -> bool | None:
        """True/False, or None if macOS wouldn't say (never treated as missing)."""
        if not self.cfg.profile_identifier:
            return None
        answered = False
        for args in self.PROFILE_QUERIES:
            code, out = self.sys.run(args)
            if code != 0:
                continue
            answered = True
            if self.cfg.profile_identifier in out:
                return True
        return False if answered else None

    # v0.8.14: is this Mac's Chrome extension list older than this version's?
    def chrome_policy_paths(self) -> list[str]:
        """Where macOS puts Chrome's locked policy from the Pax profile: the device
        file, then any per-user copies."""
        top = gc.CHROME_MANAGED_PREFS
        base = os.path.dirname(top)
        users = []
        try:
            for name in sorted(os.listdir(base)):
                p = os.path.join(base, name, os.path.basename(top))
                if os.path.isfile(p):
                    users.append(p)
        except OSError:
            pass
        return [top] + users

    def browser_rules(self) -> dict | None:
        """Compares the Chrome rules macOS is applying with the ones this version
        would write. Only ever reports (never changes anything): an older list just
        allows fewer extensions, so nothing is weaker. None when there is nothing to
        compare (no Pax Chrome rules found, or they can't be read)."""
        for path in self.chrome_policy_paths():
            try:
                pol = plistlib.loads(Path(path).read_bytes())
            except (OSError, plistlib.InvalidFileException, ValueError):
                continue
            if not isinstance(pol, dict):
                continue
            allow = pol.get("ExtensionInstallAllowlist")
            if pol.get("ExtensionInstallBlocklist") != ["*"] or not isinstance(allow, list):
                continue        # not Pax's rules
            settings = pol.get("ExtensionSettings")
            settings = settings if isinstance(settings, dict) else {}
            star = settings.get("*") if isinstance(settings.get("*"), dict) else {}
            missing = []
            for ext, name in gc.CHROME_ALLOWED_EXTENSIONS.items():
                entry = settings.get(ext) if isinstance(settings.get(ext), dict) else {}
                blocked_by_settings = (star.get("installation_mode") == "blocked"
                                       and entry.get("installation_mode") not in ("allowed", "force_installed",
                                                                                  "normal_installed"))
                if ext not in allow or blocked_by_settings:
                    missing.append(name)
            return {"browser": "Chrome", "outdated": bool(missing), "missing": missing}
        return None

    def console_uid(self) -> int | None:
        code, out = self.sys.run(["/usr/bin/stat", "-f", "%u", "/dev/console"])
        try:
            uid = int(out.strip()) if code == 0 else None
        except ValueError:
            return None
        return uid if uid and uid >= 500 else None

    def notify(self, text: str) -> None:
        uid = self.console_uid()
        if uid is None:
            return
        script = f'display notification "{text}" with title "Pax"'
        self.sys.run(["/bin/launchctl", "asuser", str(uid), "/usr/bin/osascript", "-e", script])

    def check_profile(self) -> bool | None:
        ok = self.profile_installed()
        if ok is False:
            meta = self._load_json("alerts.json", {})
            log("ALERT: the Pax profile is missing; hosts + pf still enforced")
            if self.sys.now() - int(meta.get("profile_missing", 0)) > 3600:
                self.notify("The Pax profile is missing. Open Pax to put it back.")
                meta["profile_missing"] = self.sys.now()
                self._save_json("alerts.json", meta)
        return ok

    # ------------------------------------------------------------------ VPN
    def enforce_vpn(self) -> list[str]:
        """Disconnect any VPN service macOS has connected (System Settings VPNs
        and Network Extension VPN apps register here)."""
        code, out = self.sys.run(["/usr/sbin/scutil", "--nc", "list"])
        stopped = []
        if code != 0:
            return stopped
        for name in gc.connected_vpn_services(out):
            self.sys.run(["/usr/sbin/scutil", "--nc", "stop", name])
            stopped.append(name)
            log(f"stopped VPN service: {name}")
        return stopped

    # ----------------------------------------------------------------- loop
    def cycle(self) -> dict:
        if self.cfg.local_escrow and self.escrow.exists():
            try:
                self.escrow.heartbeat()
                self.flush_partner()
            except Exception as exc:  # noqa: BLE001
                log(f"PAX-GUARD-010 escrow heartbeat failed: {exc}")
        self.sync_remote()
        if self.remote.get("released"):
            # The wait ended and the password was released: stop re-asserting,
            # but don't tear anything down; the Remove Pax flow does that.
            if not self.released:
                log("password released: enforcement paused until Pax is removed")
            self.released = True
            return {"released": True}
        self.released = False
        self.refresh_lists()
        self.update_forwarder_policy()
        result = {
            "hosts_changed": self.enforce_hosts(),
            "pf_changed": self.enforce_pf(),
            "dns_settings": self.enforce_dns_settings(),
            "apps": self.enforce_apps(),
            "user_apps": self.enforce_user_apps(),
            "vpn_stopped": self.enforce_vpn(),
            "profile_installed": self.check_profile(),
        }
        return result

    # ------------------------------------------------------- v0.8 services
    def start_services(self, dns: bool = True, ipc: bool = True) -> None:
        """The forwarder (SERVFAIL until the lists load, never open) and the app socket."""
        import dns_forwarder as dnsf
        import filter_lists as fl
        import pax_update as pu
        self.filter_store = fl.FilterStore(self.state_dir, bundled_dir=Path(__file__).resolve().parent / "filters",
                                           plugin_dirs=[self.base_dir / "lists.d",
                                                        Path(__file__).resolve().parent / "filters" / "plugins"],
                                           log=log)
        ups = dnsf.default_upstreams()
        # v0.8.18: Pax's own filter, then the malware-only resolvers; the family
        # chain when the user turned on the extra layer, or automatically when Pax's
        # filter fails a check (canary), logged to the tamper log.
        self.forwarder = dnsf.Forwarder(ups, None, self.forwarder_policy(), log=log,
                                        youtube_upstreams=dnsf.youtube_upstreams(ups),
                                        primary_upstreams=dnsf.primary_upstreams(),
                                        on_fallback=self._dns_fallback_changed)
        self.updater = pu.Updater(self.sys, self.state_dir, VERSION, log=log, notify=self.notify,
                                  app_running=self.pax_app_running, runtime=self.runtime_manager())
        if dns and self.cfg.dns_mode == "local":
            try:
                dnsf.DNSServer(self.forwarder, log=log).start()
            except OSError as exc:
                log(f"PAX-DNS-008 the DNS forwarder couldn't start on 127.0.0.1:53 ({exc})")
            threading.Thread(target=self._load_filters, name="pax-lists-load", daemon=True).start()
            threading.Thread(target=self._dns_health_loop, name="pax-dns-health", daemon=True).start()
        if self.cfg.local_escrow:
            threading.Thread(target=self._app_watch_loop, name="pax-app-watch", daemon=True).start()
            threading.Thread(target=self.list_sync.loop, name="pax-list-sync", daemon=True).start()
        if ipc:
            import guard_ipc
            try:
                self.installer().cleanup_stale()      # v0.8.33: a job cut short by a restart
            except Exception as exc:  # noqa: BLE001
                log(f"install staging cleanup: {type(exc).__name__}")
            self._update_rate = guard_ipc.RateLimit(2)
            self._reveal_rate = guard_ipc.RateLimit(10)
            try:
                guard_ipc.IPCServer(self.handle_request, log=log).start()
            except OSError as exc:
                log(f"PAX-GUARD-012 the app socket couldn't start ({exc})")

    def _dns_fallback_changed(self, entering: bool, reason: str) -> None:
        """v0.8.18: Pax's filter failed (or passed again) its self-test."""
        self.tamper_log.append("dns:fallback_on" if entering else "dns:fallback_off", {"reason": reason[:160]})

    def _load_filters(self) -> None:
        import filter_lists as fl
        try:
            fs = self.filter_store.load()
        except Exception as exc:  # noqa: BLE001 - a bad updated copy: back to the previous/bundled
            log(f"PAX-DNS-006 lists failed to load ({exc}); rolling back to the last good copy")
            self.filter_store.rollback()
            try:
                fs = self.filter_store.load()
            except Exception as exc2:  # noqa: BLE001
                log(f"PAX-DNS-006 bundled lists failed too ({exc2}); the family filter answers every lookup")
                fs = fl.empty_filterset()
        self.forwarder.set_filters(fs)
        log(f"local lists ready: {fs.entries} entries ({fs.info.get('version')})")

    def _dns_health_loop(self) -> None:
        import dns_forwarder as dnsf
        n = 0
        while True:
            try:
                self.forwarder.health_check()
                if n % 60 == 0:
                    self.forwarder.refresh_pinned_ips()
                self._save_json("dns-status.json", {"active": self.forwarder.active, "at": self.sys.now()})
            except Exception as exc:  # noqa: BLE001
                log(f"DNS health check error: {type(exc).__name__}")
            n += 1
            time.sleep(dnsf.HEALTH_INTERVAL)

    def pax_app_running(self) -> bool:
        return any(comm.endswith("/Pax.app/Contents/MacOS/Pax") for _pid, comm in self.sys.processes())

    def _background(self, name: str, fn) -> None:
        t = self._bg.get(name)
        if t is not None and t.is_alive():
            return
        t = threading.Thread(target=fn, name=f"pax-{name}", daemon=True)
        self._bg[name] = t
        t.start()

    def update_lists_now(self) -> dict:
        """v0.8.19: fetch the signed filter pack (every ~6 h). The canary runs on the
        new lists before they're swapped in; if the swapped-in lists then fail the
        canary in use, roll back to the previous good copy at once. Each outcome
        goes to the tamper log."""
        import dns_forwarder as dnsf
        report = self.filter_store.update(lambda url: self.sys.fetch(url, timeout=300),
                                          canary=dnsf.check_filterset)
        version = report.get("version")
        if report.get("taken") and not report.get("changed"):
            self._load_filters()          # same lists, newer pack version
            log(f"filter pack {version} taken (no list changes)")
        elif report.get("changed"):
            self._load_filters()
            result = self.forwarder.last_canary if self.forwarder is not None else {}
            if self.forwarder is not None and not self.forwarder.primary_upstreams:
                fails = dnsf.check_filterset(self.forwarder.filters)
                result = {"ok": not fails, "failures": fails}
            if result and not result.get("ok", True):
                why = "; ".join(result.get("failures") or [])[:160] or "canary failed"
                self.filter_store.rollback_pack(why)
                self._load_filters()
                report["rolled_back"] = True
                self.tamper_log.append("filters:pack_rolled_back", {"version": version, "reason": why})
                log(f"PAX-DNS-005 filter pack {version} failed the canary after the swap ({why}); "
                    "rolled back to the previous good lists")
            else:
                # A normal nightly event: the guard log and status, not a security notice.
                log(f"filter pack {version} applied ({', '.join(report.get('changed') or [])})")
        elif report.get("canary") or (report.get("error") and "refused" in report.get("error", "")):
            self.tamper_log.append("filters:pack_refused", {"version": version,
                                                            "reason": str(report.get("error"))[:160]})
        return report

    def standard_accounts(self) -> list[str]:
        """v0.8.10: the configured accounts pax-guard keeps standard. Never the
        everyday account's own entry, paxadmin, root or a name dseditgroup could misread."""
        out: list[str] = []
        for n in self.cfg.demoted_admins or []:
            if (isinstance(n, str) and SHORT_NAME.fullmatch(n) and n not in (self.cfg.user, "paxadmin", "root")
                    and n not in out):
                out.append(n)
        return out

    def _is_admin(self, user: str) -> bool | None:
        code, out = self.sys.run(["/usr/sbin/dseditgroup", "-o", "checkmember", "-m", user, "admin"])
        t = out.strip().lower()
        if t.startswith("yes"):
            return True
        if t.startswith("no ") and "not a member" in t:
            return False
        return None

    def enforce_standard_accounts(self) -> list[str]:
        """v0.8.10, every minute: an account made standard at set-up that is an
        administrator again is made standard again and logged. Only while paxadmin is
        an administrator, so the Mac is never left without one."""
        names = self.standard_accounts()
        if not names:
            return []
        seen = self._load_json("standard-accounts.json", {})
        if seen.get("accounts") != names:
            self.tamper_log.append("accounts:made_standard", {"accounts": names})
            self._save_json("standard-accounts.json", {"accounts": names})
        if self._is_admin("paxadmin") is not True:
            return []
        fixed: list[str] = []
        for n in names:
            if self._is_admin(n) is not True:
                continue
            self.sys.run(["/usr/sbin/dseditgroup", "-o", "edit", "-d", n, "-t", "user", "admin"])
            ok = self._is_admin(n) is False
            self.tamper_log.append("admin:made_standard_again", {"user": n, "ok": ok})
            log(f"PAX-GUARD-011 tamper: {n} was an administrator again; "
                + ("made standard" if ok else "could not make it standard"))
            if ok:
                fixed.append(n)
        if fixed:
            self.notify(f"{', '.join(fixed)} became an administrator again, so Pax made "
                        + ("it a standard account" if len(fixed) == 1 else "them standard accounts") + " again.")
        return fixed

    def periodic(self) -> None:
        """Slower jobs, from the daemon loop: list and app updates (in the
        background), tamper checks, the recovery-key/firmware cheap wins."""
        now = self.sys.now()
        try:
            self.enforce_standard_accounts()
        except Exception as exc:  # noqa: BLE001 - never stop the loop
            log(f"PAX-GUARD-011 standard-accounts check error: {type(exc).__name__}: {exc}")
        if self.filter_store is not None and self.cfg.dns_mode == "local" and self.filter_store.due(now):
            self._background("lists", self.update_lists_now)
        if self.updater is not None and self.cfg.updates:
            self._background("update", lambda: self.updater.check())
        if now - self._runtime_checked >= RUNTIME_CHECK_INTERVAL:
            self._runtime_checked = now
            self.check_runtime()
        if self.cfg.local_escrow and self.escrow.exists():
            import recovery_guard as rg
            import tamper as tp
            state = {"load": self._load_json, "save": self._save_json}
            rec = rg.RecoveryGuard(self.sys, self.escrow, self.cfg, state, log=log, tamper=self.tamper_log.append)
            skip_mdm = bool(self.cfg.mdm_managed or self.cfg.testing_allow_extra_admins)
            watch = tp.TamperWatch(self.sys, self.tamper_log, state, self.cfg, escrow=self.escrow,
                                   apple_silicon=rg.is_apple_silicon(self.sys.run),
                                   guard_files=self.guard_files(),
                                   logger=log, notify=self.notify)
            try:
                done = rec.maybe_run(now)
                if done.get("recovery_key", {}).get("ok"):
                    watch.rebaseline(["recovery_key", "recovery_key_matches_escrow"])
                if done.get("firmware", {}).get("ok"):
                    watch.rebaseline(["firmware"])
                watch.check(now, skip_mdm=skip_mdm)
            except Exception as exc:  # noqa: BLE001
                log(f"PAX-GUARD-011 tamper/recovery check error: {type(exc).__name__}: {exc}")

    # ------------------------------------------------- v0.8.6 own runtime
    def guard_files(self) -> list[str]:
        """What the tamper checks hash: pax-guard's code, its launcher and plist,
        and the runtime's manifest (whose files check_runtime re-hashes)."""
        here = Path(__file__).resolve().parent
        return [str(Path(__file__).resolve()), str(PLIST_PATH), str(here / "guard_runtime.py"),
                str(here / grt.LAUNCHER_NAME), str(self.base_dir / "runtime" / grt.MANIFEST_NAME)]

    def runtime_manager(self):
        return grt.Runtime(self.sys, base=self.base_dir, state_dir=self.state_dir, log=log)

    def runtime_status(self) -> dict:
        rt = self.runtime_manager()
        return {"interpreter": sys.executable, "on_runtime": rt.running_on_runtime(),
                "installed": rt.manifest_path.exists(), "starts": rt.starts(), "note": self._runtime_note}

    def check_runtime(self) -> dict | None:
        """Every 10 minutes: re-hash /Library/PaxGuard/runtime; anything changed,
        missing or added goes to the tamper log and the copy is rebuilt from Pax.app."""
        rt = self.runtime_manager()
        if not rt.dir.exists() and not rt.running_on_runtime():
            return None
        try:
            r = rt.heal(Path(__file__).resolve())
        except Exception as exc:  # noqa: BLE001 - never stop the loop
            log(f"PAX-GUARD-013 runtime check error: {type(exc).__name__}: {exc}")
            return None
        if r.get("problems"):
            self.tamper_log.append("changed:runtime", {"problems": r["problems"][:5], "repaired": r["repaired"]})
            self.notify("Pax noticed a change to its own files" + (" and repaired it." if r["repaired"] else "."))
            if r["repaired"]:
                self._rebaseline_guard_files()
        return r

    def _rebaseline_guard_files(self) -> None:
        import tamper as tp
        state = {"load": self._load_json, "save": self._save_json}
        tp.TamperWatch(self.sys, self.tamper_log, state, self.cfg).rebaseline(["guard_files"])

    def maybe_switch_runtime(self) -> list[str] | None:
        """After a healthy cycle. On the runtime: clear the start counter. On another
        Python (0.8.4/0.8.5 plist, or the launcher's fallback): build and check the
        runtime and return the argv to os.execv into, or None to stay put."""
        rt = self.runtime_manager()
        if rt.running_on_runtime():
            if rt.starts():
                rt.set_starts(0)
            self._runtime_note = ""
            return None
        here = Path(__file__).resolve()
        if here.parent != (self.base_dir / "bin").resolve():
            return None                       # a copy outside /Library/PaxGuard (tests, the repo)
        plan = rt.migrate(here, PLIST_PATH)
        if "exec" in plan:
            self._rebaseline_guard_files()
            return plan["exec"]
        if plan.get("stay") != self._runtime_note:
            self._runtime_note = plan.get("stay", "")
            log(f"pax-guard stays on {sys.executable}: {self._runtime_note}")
        return None

    # ------------------------------------------------------------ app socket
    def handle_request(self, req: dict, uid) -> dict:
        import local_blocklist as lb
        import local_escrow as le
        cmd = str(req.get("cmd", ""))
        try:
            if cmd == "status":
                return {"ok": True, **self.status_summary()}
            if cmd == "dns.status":
                return {"ok": True, "dns": self.forwarder.status() if self.forwarder else None}
            if cmd == "tamper.list":
                intact, n = self.tamper_log.verify()
                return {"ok": True, "intact": intact, "count": n, "events": self.tamper_log.entries(50)}
            if cmd == "settings.get":
                return {"ok": True, "settings": self.settings_view()}
            if cmd == "settings.set":
                return self.handle_settings_set(req, uid)
            if cmd == "update.status":
                return {"ok": True, "update": self.updater.status() if self.updater else None}
            if cmd == "update.now":
                if self.updater is None:
                    return {"ok": False, "code": "PAX-UPDATE-001", "error": "updates aren't running"}
                if self._update_rate is not None and not self._update_rate.allow():
                    return {"ok": True, "update": self.updater.status(), "note": "checked a moment ago"}
                self._background("update", lambda: self.updater.check(force=True))
                return {"ok": True, "update": self.updater.status(), "note": "checking now"}
            if cmd.startswith(("escrow.", "partner.")):
                if not self.cfg.local_escrow:
                    return {"ok": False, "code": "PAX-ESCROW-009", "error": "this Mac uses the Pax server"}
                if not self.escrow.exists():
                    return {"ok": False, "code": "PAX-ESCROW-009", "error": "nothing is held yet"}
                if cmd == "escrow.status":
                    return {"ok": True, "device": self.escrow.status()}
                if cmd == "escrow.request":
                    return {"ok": True, "device": self.escrow.request_removal(str(req.get("reason", "remove")))}
                if cmd == "escrow.cancel":
                    return {"ok": True, "device": self.escrow.cancel()}
                if cmd == "escrow.emergency":
                    return {"ok": True, "device": self.escrow.emergency(str(req.get("reason", "")))}
                if cmd == "escrow.set_wait":
                    return {"ok": True, "device": self.escrow.set_wait(req.get("seconds"))}
                if cmd == "escrow.end_trial":
                    # v0.8.18 "Start my wait now": ends the trial day early (stricter, instant).
                    return {"ok": True, "device": self.escrow.end_trial()}
                if cmd == "partner.get":
                    return {"ok": True, "partner": self.escrow.partner.public_view()}
                if cmd == "partner.set":
                    return {"ok": True, "device": self.escrow.set_partner(req.get("email"))}
                if cmd == "partner.transport":
                    return {"ok": True, "partner": self.escrow.partner.set_transport(
                        req.get("transport"), req.get("owner_email"))}
                if cmd == "escrow.support_release":
                    # v0.8.15 "Allow verified support release": off at once, on after the wait.
                    return {"ok": True, "device": self.escrow.set_support_release(req.get("allowed"))}
                if cmd == "escrow.redeem_support":
                    # v0.8.15: a one-time code from Pax support for this Mac only.
                    if not self._support_rate().allow():
                        self.tamper_log.append("support_code_refused", {"code": "PAX-ESCROW-019"})
                        return {"ok": False, "code": "PAX-ESCROW-019", "error": "too many tries; wait a minute"}
                    out = self.escrow.redeem_support(str(req.get("code", ""))[:400])
                    log(f"escrow released (verified support code) to uid {uid}")
                    return {"ok": True, "released": out}
                if cmd == "escrow.reveal":
                    if not self._reveal_rate.allow():
                        return {"ok": False, "code": "PAX-ESCROW-006", "error": "too many tries; wait a minute"}
                    out = self.escrow.reveal()
                    log(f"escrow released ({out.get('reason')}) to uid {uid}")
                    return {"ok": True, "released": out}
            if cmd.startswith("paxmax."):
                return self.handle_pax_max(cmd, req, uid)
            if cmd.startswith(("installs.", "system_updates.")):
                return self.handle_installs(cmd, req, uid)
            if cmd.startswith("apps."):
                if not self.cfg.local_escrow:
                    return {"ok": False, "code": "PAX-ESCROW-009",
                            "error": "Blocked apps need this Mac to keep its own key"}
                if cmd == "apps.get":
                    return {"ok": True, "apps": self.blocklist.apps_view()}
                if cmd == "apps.add":
                    return {"ok": True, **self.add_user_app(str(req.get("path", "")), uid)}
                if cmd == "apps.unblock":
                    return {"ok": True, **self.blocklist.request_unblock_app(str(req.get("bundle_id", "")))}
                if cmd == "apps.cancel":
                    self.blocklist.cancel(str(req.get("request_id", "")))
                    return {"ok": True, "apps": self.blocklist.apps_view()}
            if cmd.startswith("sync."):
                # v0.8.9: blocked-sites sync with the user's Pax account.
                if not self.cfg.local_escrow:
                    return {"ok": False, "code": "PAX-ESCROW-009", "error": "this Mac's list is on the Pax server"}
                if cmd == "sync.get":
                    return {"ok": True, "sync": self.list_sync.status()}
                if cmd == "sync.set":
                    return {"ok": True, "sync": self.list_sync.set_enabled(req.get("enabled"), uid)}
                if cmd == "sync.link":
                    return {"ok": True, "sync": self.list_sync.link(str(req.get("server_url", "")),
                                                                   str(req.get("token", "")),
                                                                   req.get("account_email"), uid)}
                if cmd == "sync.now":
                    self.list_sync.kick()
                    return {"ok": True, "sync": self.list_sync.status()}
            if cmd.startswith("blocklist."):
                if not self.cfg.local_escrow:
                    return {"ok": False, "code": "PAX-ESCROW-009", "error": "this Mac's list is on the Pax server"}
                if cmd == "blocklist.get":
                    return {"ok": True, "list": self.list_sync.decorate(self.blocklist.view())}
                if cmd == "blocklist.add":
                    r = self.blocklist.add(str(req.get("domain", "")))
                    self.list_sync.note_added(r["domain"])
                    self._refresh_after_list_change()
                    r["list"] = self.list_sync.decorate(r["list"])
                    return {"ok": True, **r}
                if cmd == "blocklist.unblock":
                    if self.list_sync.active():
                        return {"ok": True, **self.list_sync.request_unblock(str(req.get("domain", "")))}
                    return {"ok": True, **self.blocklist.request_unblock(str(req.get("domain", "")))}
                if cmd == "blocklist.allow":
                    return {"ok": True, **self.blocklist.request_allow(str(req.get("domain", "")))}
                if cmd == "blocklist.remove_allow":
                    v = self.blocklist.remove_allow(str(req.get("domain", "")))
                    self._refresh_after_list_change()
                    return {"ok": True, "list": v}
                if cmd == "blocklist.cancel":
                    rid = str(req.get("request_id", ""))
                    if self.list_sync.active() and self.list_sync.owns_request(rid):
                        return {"ok": True, "list": self.list_sync.cancel(rid)}
                    return {"ok": True, "list": self.list_sync.decorate(self.blocklist.cancel(rid))}
            return {"ok": False, "code": "PAX-GUARD-012", "error": f"unknown request {cmd!r}"}
        except Exception as exc:  # noqa: BLE001
            import partner as pt
            import app_installs as ai
            if not isinstance(exc, (le.EscrowError, lb.BlocklistError, pt.NotifyError, ai.InstallError)):
                raise
            return {"ok": False, "code": exc.code, "error": exc.message,
                    **({k: v for k, v in getattr(exc, "extra", {}).items()})}

    # ------------------------------------- v0.8.33 Pax-approved installs and updates
    def installer(self):
        """app_installs.AppInstaller, staging in /Library/PaxGuard/installs (root 0700), or, if
        /Applications is on another volume, in a root-only folder inside /Applications, so the
        final step is always a rename on one volume."""
        if self._installer is None:
            import app_installs as ai
            staging = str(self.base_dir / "installs")
            try:
                if os.stat(str(self.base_dir)).st_dev != os.stat(ai.APPLICATIONS).st_dev:
                    staging = os.path.join(ai.APPLICATIONS, ".pax-installing")
            except OSError:
                pass
            self._installer = ai.AppInstaller(
                self.sys.run, self.sys.processes, staging=staging,
                state_file=self.state_dir / "installs.json", log=log, clock=self.sys.now,
                blocked_entries=lambda: self._blocked_entries() if self.cfg.local_escrow else [])
        return self._installer

    def install_home(self, uid) -> str | None:
        """The home folder of the local account asking (uid 501+ with a home in /Users), or
        the protected account's for root. Anyone else can't install."""
        import pwd
        if uid is None:
            return None
        try:
            if int(uid) == 0:
                return self.sys.home_of(self.cfg.user)
            pw = pwd.getpwuid(int(uid))
        except (KeyError, ValueError, TypeError):
            return None
        if pw.pw_uid < 501 or not pw.pw_dir.startswith("/Users/") or not self.sys.exists(pw.pw_dir):
            return None
        return pw.pw_dir

    def handle_installs(self, cmd: str, req: dict, uid) -> dict:
        """installs.start {path, choice?, update_only?} / installs.status / installs.updates /
        system_updates.check / system_updates.status / system_updates.install {label}.
        Nothing here loosens Pax: every app is checked as root on a staged copy (see
        app_installs.py), and what isn't allowed still needs the turn-off wait."""
        import app_installs as ai
        inst = self.installer()
        if cmd == "installs.status":
            return {"ok": True, **inst.status()}
        if cmd == "system_updates.status":
            return {"ok": True, "system_updates": dict(inst.su)}
        home = self.install_home(uid)
        if home is None:
            log(f"{ai.BAD_FILE} {cmd} refused for uid {uid}")
            raise ai.InstallError(ai.BAD_FILE, "only an account on this Mac can install apps")
        if self._install_rate is None:
            import guard_ipc
            self._install_rate = guard_ipc.RateLimit(6)
        if cmd == "installs.updates":
            return {"ok": True, "updates": inst.downloaded_updates(home)}
        if not self._install_rate.allow():
            raise ai.InstallError(ai.BUSY, "too many requests; wait a minute")
        if cmd == "installs.start":
            choice = req.get("choice")
            job = inst.start(req.get("path"), roots=[home, "/Volumes"], uid=int(uid),
                             allowed_uids={int(uid)}, choice=choice if choice not in ("", None) else None,
                             update_only=req.get("update_only") is True)
            return {"ok": True, "job": job}
        if cmd == "system_updates.check":
            return {"ok": True, "system_updates": inst.su_check()}
        if cmd == "system_updates.install":
            return {"ok": True, "system_updates": inst.su_install(req.get("label"))}
        return {"ok": False, "code": "PAX-GUARD-012", "error": f"unknown request {cmd!r}"}

    def _support_rate(self):
        """v0.8.15: at most 3 support codes a minute (a code is 146 letters; this only
        stops a runaway loop, the signature is what keeps codes unguessable)."""
        if getattr(self, "_support_limit", None) is None:
            import guard_ipc
            self._support_limit = guard_ipc.RateLimit(3)
        return self._support_limit

    # ------------------------------------------------ v0.8.7 Blocked apps
    APP_IDENTITY_TTL = 600
    APP_WATCH_INTERVAL = 2

    def app_identity(self, path: str, fresh: bool = False):
        """Bundle ID and name from Info.plist, identifier/Team ID from the code
        signature (as root, from disk: never what the app tells us)."""
        now = self.sys.now()
        hit = self._ident_cache.get(path)
        if hit and not fresh and now - hit[0] < self.APP_IDENTITY_TTL:
            return hit[1]
        plist = self.sys.app_plist(path)
        code, out = self.sys.run(["/usr/bin/codesign", "-dv", "--verbose=2", path], timeout=15)
        sig = gc.parse_codesign(out if code == 0 else "")
        folder = os.path.basename(path)
        folder = folder[:-4] if folder.endswith(".app") else folder
        name = str(plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or folder)
        ident = gc.AppIdentity(path=path, bundle_id=str(self.sys.bundle_id(path) or plist.get("CFBundleIdentifier") or ""),
                               name=name, executable=str(plist.get("CFBundleExecutable") or ""), **sig)
        self._ident_cache[path] = (now, ident)
        return ident

    def add_user_app(self, path: str, uid=None) -> dict:
        """apps.add {path}: an app the user picked in /Applications or ~/Applications.
        Instant; refuses Pax, Apple's own apps and password managers (PAX-MAC-016)."""
        import local_blocklist as lb
        path = os.path.normpath(path or "")
        home = self.sys.home_of(self.cfg.user)
        roots = ["/Applications"] + ([f"{home}/Applications"] if home else [])
        if (not path.endswith(".app") or not any(path.startswith(r + "/") for r in roots)
                or not self.sys.exists(path)):
            raise lb.BlocklistError("PAX-MAC-017", "choose an app in Applications")
        ident = self.app_identity(path, fresh=True)
        if not ident.bundle_id:
            raise lb.BlocklistError("PAX-MAC-017", "Pax couldn't read that app")
        why = gc.app_protected_reason(ident)
        if why:
            raise lb.BlocklistError("PAX-MAC-016", f"{ident.name} can't be blocked: it's {why}")
        out = self.blocklist.add_app(gc.app_entry(ident, self.sys.now()))
        if out["created"]:
            log(f"blocked app added: {ident.name} ({ident.bundle_id}, team {ident.team_id or 'none'}) uid {uid}")
        self.enforce_user_apps()
        return {"bundle_id": out["bundle_id"], "created": out["created"], "apps": self.blocklist.apps_view()}

    def _blocked_entries(self) -> list[dict]:
        return [{"bundle_id": b, **v} for b, v in self.blocklist.apps().items()]

    def _matching_entry(self, ident, entries):
        return next((e for e in entries if gc.app_matches(ident, e)), None)

    def kill_user_apps(self, entries: list[dict] | None = None) -> list[tuple[int, str]]:
        """Kill running programs that belong to a blocked app; returns (pid, app path)."""
        entries = self._blocked_entries() if entries is None else entries
        if not entries:
            return []
        hits = []
        for pid, comm in self.sys.processes():
            bundle = gc.app_bundle_of(comm)
            if not bundle:
                continue
            if self._matching_entry(self.app_identity(bundle), entries):
                self.sys.kill(pid)
                hits.append((pid, bundle))
        return hits

    def enforce_user_apps(self) -> list[str]:
        """Kill blocked apps that are running, quarantine their bundles (in the usual
        folders and wherever one was running from), and put back apps whose
        unblock wait has ended."""
        if not self.cfg.local_escrow:
            return []
        with self._apps_lock:
            acted: list[str] = []
            entries = self._blocked_entries()
            running = self.kill_user_apps(entries)
            acted += [f"closed blocked app {os.path.basename(b)} ({pid})" for pid, b in running]
            paths = {p for p in self.sys.list_apps(self.app_dirs())}
            paths |= {b for _pid, b in running}
            for path in sorted(paths):
                if not entries or not self.sys.exists(path) or path.startswith(("/System/", "/Volumes/")):
                    continue
                entry = self._matching_entry(self.app_identity(path), entries)
                if not entry:
                    continue
                dest = str(self.quarantine_dir / f"{self.sys.now()}-{os.path.basename(path)}")
                try:
                    self.sys.move(path, dest)
                    q = self._load_json("quarantine.json", [])
                    q.append({"from": path, "to": dest, "kind": "user", "bundle_id": entry["bundle_id"]})
                    self._save_json("quarantine.json", q)
                    self._ident_cache.pop(path, None)
                    acted.append(f"put blocked app away: {path}")
                except OSError as exc:
                    acted.append(f"could not put {path} away: {exc}")
            acted += self._restore_unblocked_apps(entries)
        for a in acted:
            log(a)
        return acted

    def _restore_unblocked_apps(self, entries: list[dict]) -> list[str]:
        """An app whose unblock wait ended goes back where it was (if that's free)."""
        blocked = {e["bundle_id"] for e in entries}
        q = self._load_json("quarantine.json", [])
        keep, done = [], []
        for item in q:
            if item.get("kind") == "user" and item.get("bundle_id") not in blocked:
                if self.sys.exists(item["to"]) and not self.sys.exists(item["from"]):
                    try:
                        self.sys.move(item["to"], item["from"])
                        try:
                            os.chmod(item["from"], 0o755)
                        except OSError:
                            pass
                        done.append(f"unblocked app put back: {item['from']}")
                        continue
                    except OSError:
                        pass
                elif not self.sys.exists(item["to"]):
                    continue
            keep.append(item)
        if len(keep) != len(q):
            self._save_json("quarantine.json", keep)
        return done

    def _app_watch_loop(self) -> None:
        """Every 2 s: a blocked app that was just opened is closed again. Cheap
        when the list is empty (no process listing at all)."""
        while True:
            try:
                if not self.released and self.blocklist.apps():
                    hits = self.kill_user_apps()
                    if hits:
                        self._background("user-apps", self.enforce_user_apps)
            except Exception as exc:  # noqa: BLE001 - never stop watching
                log(f"app watch error: {type(exc).__name__}")
            time.sleep(self.APP_WATCH_INTERVAL)

    def handle_settings_set(self, req: dict, uid) -> dict:
        """settings.set {youtube_restricted?: bool, adblock?: bool}. Everything in the
        request is checked before anything changes, so a refused part changes nothing."""
        # v0.8.13: pictures and video on X and Bluesky are always blocked.
        if any(req.get(k) is False for k in ("x_media", "bluesky_media")):
            return {"ok": False, "code": "PAX-DNS-016",
                    "error": "pictures and video on X and Bluesky are always off"}
        keys = [k for k in ("youtube_restricted", "adblock", "family_layer") if k in req]
        if not keys:
            return {"ok": False, "code": "PAX-GUARD-012", "error": "nothing to change"}
        for k in keys:
            if not isinstance(req.get(k), bool):
                return {"ok": False, "code": "PAX-GUARD-012", "error": f"{k} must be true or false"}
        if "youtube_restricted" in req and self.cfg.dns_mode != "local":
            return {"ok": False, "code": "PAX-DNS-011",
                    "error": "this Mac's filtering doesn't go through Pax, so it can't change YouTube"}
        if "adblock" in req and not self.cfg.local_escrow:
            return {"ok": False, "code": "PAX-ESCROW-009",
                    "error": "this Mac's ad setting is on the Pax server"}
        if "family_layer" in req and not self.cfg.local_escrow:
            return {"ok": False, "code": "PAX-ESCROW-009",
                    "error": "this Mac's extra family filter is set in your Pax account"}
        if "family_layer" in req and self.cfg.dns_mode != "local":
            return {"ok": False, "code": "PAX-DNS-011",
                    "error": "this Mac's filtering doesn't go through Pax, so it can't change this"}
        view = None
        if "youtube_restricted" in req:
            view = self.set_youtube_restricted(req["youtube_restricted"], uid)
        if "adblock" in req:
            view = self.set_adblock(req["adblock"], uid)
        if "family_layer" in req:
            out = self.set_family_layer(req["family_layer"], uid)
            if not out.get("ok", True):
                return out
            view = out["settings"]
            if out.get("request"):
                return {"ok": True, "settings": view, "request": out["request"]}
        return {"ok": True, "settings": view}

    def set_family_layer(self, on: bool, uid=None) -> dict:
        """v0.8.18 Advanced. On (stricter) is immediate; off loosens the filter, so
        it waits like a removal: the partner first (fail closed), then the user's
        own turn-off wait. Both are written to the tamper log."""
        import local_blocklist as lb
        if self.blocklist.partner is None and self.escrow.exists():
            self.blocklist.partner = self.escrow.partner
        before = self.family_layer
        if on:
            if self.blocklist.family_layer_on() or not before:
                self.tamper_log.append("setting:family_layer", {"from": before, "to": True, "uid": uid})
                log(f"extra family filter on (uid {uid})")
            self.update_forwarder_policy()
            return {"ok": True, "settings": self.settings_view()}
        if not before:
            return {"ok": True, "settings": self.settings_view()}
        had = self.blocklist.family_layer_pending()
        try:
            out = self.blocklist.request_family_layer_off()
        except lb.BlocklistError as exc:
            return {"ok": False, "code": exc.code, "error": exc.message}
        if had is None:
            self.tamper_log.append("setting:family_layer_off_requested", {"uid": uid})
        return {"ok": True, "settings": self.settings_view(), "request": out["request"]}

    def _refresh_after_list_change(self) -> None:
        self.sync_remote()
        self.update_forwarder_policy()
        try:
            self.enforce_hosts()
        except OSError:
            pass

    def status_summary(self) -> dict:
        esc = None
        if self.cfg.local_escrow and self.escrow.exists():
            try:
                esc = self.escrow.status()
            except Exception as exc:  # noqa: BLE001
                esc = {"error": str(exc), "code": getattr(exc, "code", "PAX-GUARD-010")}
        intact, n = self.tamper_log.verify()
        events = _shown_tamper_events(
            [e for e in self.tamper_log.entries(80) if e.get("kind") != "baseline"])
        return {
            "version": VERSION,
            "escrow_mode": "local" if self.cfg.local_escrow else "server",
            "released": self.released,
            "dns": self.forwarder.status() if self.forwarder else None,
            "escrow": esc,
            "update": self.updater.status() if self.updater else None,
            "tamper": {"intact": intact, "count": n, "recent": events[-5:]},
            "recovery": self._load_json("recovery.json", {}),
            "settings": self.settings_view(),
            "runtime": self.runtime_status(),
            "sync": self.list_sync.status() if self.cfg.local_escrow else None,   # v0.8.9
            "browser_rules": self.browser_rules(),                                 # v0.8.14
            # v0.8.19: which filter pack is in use and how the last check went.
            "filter_pack": self.filter_store.pack_status() if self.filter_store is not None else None,
        }

    # ------------------------------------------------------------------ loop
    def run_forever(self) -> None:
        log(f"pax-guard {VERSION} starting")
        if self.cfg.media_forced_on:
            log("v0.8.13: pictures and video on X and Bluesky are always blocked now; "
                "this Mac's earlier set-up choice to show them no longer applies")
        self.start_services()
        last_net = self._network_signature()
        confirmed = False
        switched = False
        last_periodic = 0
        while True:
            try:
                self.cycle()
                if not confirmed and self.updater is not None:
                    self.updater.confirm_trial()
                    confirmed = True
                if not switched:
                    switched = True
                    argv = self.maybe_switch_runtime()
                    if argv:
                        log(f"switching pax-guard {VERSION} to its own runtime ({argv[0]})")
                        sys.stdout.flush()
                        sys.stderr.flush()
                        os.execv(argv[0], argv)
                if self.sys.now() - last_periodic >= 60:
                    last_periodic = self.sys.now()
                    self.periodic()
            except Exception as exc:  # noqa: BLE001 - never die; launchd would respawn anyway
                log(f"cycle error: {type(exc).__name__}: {exc}")
            # Sleep in short steps and wake early when the network changes.
            for _ in range(max(1, self.cfg.interval // 5)):
                time.sleep(5)
                sig = self._network_signature()
                if sig != last_net:
                    last_net = sig
                    log("network change")
                    break

    def _network_signature(self) -> str:
        code, out = self.sys.run(["/usr/sbin/scutil", "--nwi"], timeout=5)
        return hashlib.sha256(out.encode()).hexdigest() if code == 0 else ""

    # ------------------------------------------------------------ uninstall
    def uninstall(self, restore_apps: bool = True) -> list[str]:
        """Undo everything pax-guard did. Used only by the Remove Pax flow (as root)."""
        done = []
        current = self.sys.read(gc.HOSTS_PATH)
        stripped = gc.strip_pax_block(current)
        if stripped != current:
            self.sys.write_atomic(gc.HOSTS_PATH, stripped, 0o644)
            self.sys.run(["/usr/bin/dscacheutil", "-flushcache"])
            self.sys.run(["/usr/bin/killall", "-HUP", "mDNSResponder"])
            done.append("hosts block removed")
        self.sys.run(["/sbin/pfctl", "-a", gc.PF_ANCHOR, "-F", "all"])
        done.append("pf anchor flushed")
        restored = self.restore_dns_settings()
        if restored:
            self.sys.run(["/usr/bin/dscacheutil", "-flushcache"])
            done.append(f"DNS settings restored ({', '.join(restored)})")
        try:
            if self.escrow.exists() and self.escrow.released():
                import recovery_guard as rg
                state = {"load": self._load_json, "save": self._save_json}
                if rg.RecoveryGuard(self.sys, self.escrow, self.cfg, state, log=log).delete_firmware_password():
                    done.append("firmware password removed")
        except Exception as exc:  # noqa: BLE001
            done.append(f"firmware password left in place ({type(exc).__name__})")
        if restore_apps:
            for item in self._load_json("quarantine.json", []):
                if self.sys.exists(item["to"]) and not self.sys.exists(item["from"]):
                    try:
                        self.sys.move(item["to"], item["from"])
                        os.chmod(item["from"], 0o755)
                        done.append(f"restored {item['from']}")
                    except OSError:
                        pass
        return done


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "run"
    if cmd not in ("run", "once", "uninstall", "status", "selftest", "ask"):
        print(__doc__)
        return 2
    if cmd == "selftest":
        return selftest()
    if cmd == "ask":
        import guard_ipc
        print(json.dumps(guard_ipc.request(json.loads(argv[1] if len(argv) > 1 else '{"cmd":"status"}'))))
        return 0
    if os.geteuid() != 0:
        print("pax-guard must run as root", file=sys.stderr)
        return 1
    cfg = GuardConfig.load() if CONFIG_PATH.exists() else GuardConfig()
    guard = Guard(cfg)
    if cmd == "run":
        guard.run_forever()
    elif cmd == "once":
        guard.sync_remote()
        guard.refresh_lists(force=True)
        print(json.dumps(guard.cycle()))
    elif cmd == "uninstall":
        print(json.dumps(guard.uninstall()))
    else:
        print(json.dumps({
            "version": VERSION,
            "profile_installed": guard.profile_installed(),
            "hosts_entries": guard.sys.read(gc.HOSTS_PATH).count("\n0.0.0.0 "),
            "remote": {k: v for k, v in guard._load_json("remote.json", {}).items()
                       if k in ("blocked", "adblock", "released", "categories")},
            "escrow_mode": "local" if cfg.local_escrow else "server",
            "dns_active": guard._load_json("dns-status.json", {}).get("active"),
            "update": guard._load_json("update.json", {}).get("state"),
        }))
    return 0


def selftest() -> int:
    """What an update checks before swapping this pax-guard in: every module
    imports, the bundled lists are complete and match filters.json, and the
    installed config (if any) still parses."""
    here = Path(__file__).resolve().parent
    problems = []
    for mod in ("guard_config", "ed25519", "pax_signing", "domain_matcher", "filter_lists", "dns_forwarder",
                "local_escrow", "local_blocklist", "list_sync", "guard_ipc", "pax_update", "tamper", "recovery_guard",
                "pax_restricted", "guard_runtime", "support_code", "app_installs",
                # v0.8.6: the standard-library pieces pax-guard needs from whichever Python runs it
                "ssl", "smtplib", "plistlib", "http.client", "socketserver", "email.message", "urllib.request"):
        try:
            __import__(mod)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"import {mod}: {type(exc).__name__}: {exc}")
    try:
        import filter_lists as fl
        man = json.loads((here / "filters" / "filters.json").read_text())
        for lid, item in man["lists"].items():
            data = fl.read_bytes_maybe_parts(here / "filters" / item["file"])
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                problems.append(f"bundled list {lid} damaged")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"bundled lists: {type(exc).__name__}: {exc}")
    try:
        import ed25519
        if not ed25519.verify(ed25519.public_key(b"\x01" * 32), b"pax",
                              ed25519.sign(b"\x01" * 32, b"pax")):
            problems.append("ed25519 self-check failed")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"ed25519: {exc}")
    try:
        import app_installs
        app_installs.load_deny()                 # v0.8.33: the install rules must parse
    except Exception as exc:  # noqa: BLE001
        problems.append(f"app-install-deny.txt: {type(exc).__name__}: {exc}")
    if CONFIG_PATH.exists():
        try:
            GuardConfig.load()
        except Exception as exc:  # noqa: BLE001
            problems.append(f"config: {type(exc).__name__}")
    print(json.dumps({"version": VERSION, "ok": not problems, "problems": problems}))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
