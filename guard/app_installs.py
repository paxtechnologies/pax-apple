# SPDX-License-Identifier: GPL-3.0-only
"""Pax-approved installs and updates (v0.8.33).

On a protected Mac the everyday account is Standard and the only administrator
(paxadmin) is behind the turn-off wait, so macOS asks for an administrator to put an
app in /Applications or to update one there. pax-guard (root) does it instead, for
apps it can check, and refuses the rest. docs/APP_INSTALLS.md has the full rules.

  * Updates to an app already in /Applications: same bundle ID, same Apple Developer
    Team ID, `codesign --verify --deep --strict`, `spctl --assess --type execute`
    says "Notarized Developer ID", not blocked. Installed at once, no wait.
  * New apps: the same checks, then refused if the app is in a blocked category
    (guard_config's bypass lists, app-install-deny.txt, the user's Blocked apps, or a
    web browser Pax can't apply its rules to).
  * .pkg installers: refused (their scripts run as root and could remove Pax), except
    packages signed by Apple itself (pkgutil: "signed Apple Software", Apple Root CA).
  * Never touched: Pax, Apple's own apps, /System, anything outside /Applications, an
    app with a different Team ID, unsigned / ad-hoc / unnotarised apps.

How a request is handled (the request comes over a 0666 socket, so it's untrusted):
  1. the path must be absolute, already normalised, with no symlinks on the way
     (realpath == path), inside the requesting user's home or /Volumes, owned by that
     user or world-readable, and an .app folder, .dmg file or .pkg file;
  2. it's copied into a fresh root-only staging folder (0700) before anything is
     checked: a .dmg is copied, then mounted read-only, nobrowse, noautoopen at a
     mount point inside the staging folder, the chosen app copied out and the image
     detached; an .app is copied with ditto (no ACLs);
  3. the staged copy is walked: symlinks must stay inside the bundle, no setuid /
     setgid files, no devices, pipes or sockets, size and file-count limits;
  4. every check runs on the staged copy only; then quarantine is cleared, it's made
     root:admin and not group/other-writable, its signature re-checked, and it's
     renamed into /Applications (an update swaps: the old copy is renamed away first
     and put back if anything fails). Nothing outside the staging folder changes
     until every check has passed.
Every install and refusal is logged (/var/log/pax-guard.log) and kept in
state/installs.json (the last 200). Any unexpected error refuses (fail closed).
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import stat
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

APPLICATIONS = "/Applications"
STAGING = "/Library/PaxGuard/installs"
DENY_FILE = Path(__file__).resolve().parent / "app-install-deny.txt"
HISTORY_MAX = 200
MAX_IMAGE_BYTES = 20 * 1024 ** 3          # a .dmg or .pkg
MAX_TREE_BYTES = 20 * 1024 ** 3           # an app's files
MAX_TREE_ENTRIES = 300_000
MAX_PATH = 1024
MAX_NAME = 255
MAX_OPTIONS = 20
SCAN_MAX_DIRS = 3000
SCAN_MAX_DEPTH = 6

PAX_TEAM_ID = "Z94GSK7JA8"
PAX_BUNDLE_PREFIXES = ("org.paxpeace.", "org.paxmobile.")
# Browsers whose Chromium/Firefox policies the Mac profile sets (guard_config.POLICY_MANAGED_BROWSERS
# lists them by name; these are their real bundle IDs). Safari is part of macOS.
MANAGED_BROWSER_BUNDLE_IDS = frozenset({
    "com.google.chrome", "com.microsoft.edgemac", "com.brave.browser", "org.chromium.chromium",
    "org.mozilla.firefox",
})

# ------------------------------------------------------------------ codes
BAD_FILE = "PAX-MAC-018"          # not an app/image/package we can open, path not allowed
NOT_SIGNED = "PAX-MAC-019"        # codesign failed, ad hoc, no Developer ID
NOT_NOTARISED = "PAX-MAC-020"     # spctl didn't say Notarized Developer ID
BLOCKED = "PAX-MAC-021"           # a blocked category
OTHER_DEVELOPER = "PAX-MAC-022"   # the installed copy has a different Team ID
UNTOUCHABLE = "PAX-MAC-023"       # Pax itself, Apple's apps, /System
PACKAGE = "PAX-MAC-024"           # a .pkg not signed by Apple
CHOOSE = "PAX-MAC-025"            # more than one app in the image
RUNNING = "PAX-MAC-026"           # quit it first
OLDER = "PAX-MAC-027"             # older than the installed version
FAILED = "PAX-MAC-028"            # copy/mount/move failed: nothing changed
BUSY = "PAX-MAC-029"              # one install at a time
NAME_TAKEN = "PAX-MAC-030"        # another app already has that name
UNSAFE = "PAX-MAC-031"            # symlinks out of the bundle, setuid, devices, too big
SU_CHECK = "PAX-UPDATE-009"       # softwareupdate --list failed
SU_INSTALL = "PAX-UPDATE-010"     # softwareupdate --install failed
SU_ADMIN = "PAX-UPDATE-011"       # macOS wanted an administrator (Apple silicon owner auth)


class InstallError(Exception):
    def __init__(self, code: str, message: str, **extra):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.extra = extra


# ------------------------------------------------------------------ deny list
@dataclass
class DenyCategory:
    cid: str
    label: str
    bundles: set = field(default_factory=set)
    prefixes: list = field(default_factory=list)
    teams: set = field(default_factory=set)
    names: set = field(default_factory=set)


_RULE_RE = re.compile(r"^(bundle|team|name) (\S.*)$")
_HEAD_RE = re.compile(r"^\[([a-z_]+)\] (\S.*)$")
_TEAM_RE = re.compile(r"^[A-Z0-9]{10}$")


def parse_deny(text: str) -> list[DenyCategory]:
    """app-install-deny.txt -> categories. Any line it doesn't understand is an error."""
    cats: list[DenyCategory] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _HEAD_RE.match(line)
        if m:
            cats.append(DenyCategory(m.group(1), m.group(2)))
            continue
        m = _RULE_RE.match(line)
        if not m or not cats:
            raise ValueError(f"app-install-deny.txt line {n} isn't a rule")
        kind, value = m.group(1), m.group(2).strip()
        c = cats[-1]
        if kind == "bundle":
            v = value.lower()
            if v.endswith(".*"):
                if len(v) < 4:
                    raise ValueError(f"app-install-deny.txt line {n}: prefix too short")
                c.prefixes.append(v[:-1])
            else:
                c.bundles.add(v)
        elif kind == "team":
            if not _TEAM_RE.match(value):
                raise ValueError(f"app-install-deny.txt line {n}: not a Team ID")
            c.teams.add(value)
        else:
            c.names.add(value.lower())
    if not cats:
        raise ValueError("app-install-deny.txt is empty")
    return cats


def load_deny(path: Path = DENY_FILE) -> list[DenyCategory]:
    return parse_deny(Path(path).read_text())


# ------------------------------------------------------------------ parsing tools' output
def parse_codesign_details(out: str) -> dict:
    """`codesign -dv --verbose=4 <app>` (stderr) -> identifier, team, authorities."""
    info = {"identifier": "", "team_id": "", "authorities": []}
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("Identifier="):
            info["identifier"] = line.split("=", 1)[1].strip()
        elif line.startswith("TeamIdentifier="):
            v = line.split("=", 1)[1].strip()
            info["team_id"] = "" if v.lower() in ("not set", "") else v
        elif line.startswith("Authority="):
            info["authorities"].append(line.split("=", 1)[1].strip())
    return info


def developer_id_problem(sig: dict) -> str | None:
    """None when the signature is a proper Developer ID chain for its Team ID."""
    auth = sig.get("authorities") or []
    team = sig.get("team_id") or ""
    if not team or not _TEAM_RE.match(team):
        return "it isn't signed with a Developer ID (no Team ID)"
    if not auth:
        return "it has no signing certificate (ad hoc)"
    leaf = auth[0]
    if not (leaf.startswith("Developer ID Application:") and leaf.endswith(f"({team})")):
        return f"it isn't signed with a Developer ID Application certificate ({leaf[:80]})"
    if "Developer ID Certification Authority" not in auth or auth[-1] != "Apple Root CA":
        return "its certificate doesn't chain to Apple's Developer ID authority"
    return None


def is_apple_signed(sig: dict) -> bool:
    auth = sig.get("authorities") or []
    return bool(auth) and auth[0] in ("Software Signing", "Apple Mac OS Application Signing",
                                      "Apple iPhone OS Application Signing")


def parse_spctl(out: str) -> dict:
    """`spctl --assess --type execute -vv <app>`:
    '<path>: accepted\\nsource=Notarized Developer ID\\norigin=Developer ID Application: X (TEAM)'"""
    res = {"accepted": False, "source": "", "origin_team": ""}
    for line in (out or "").splitlines():
        s = line.strip()
        if s.endswith(": accepted") or s == "accepted":
            res["accepted"] = True
        elif s.startswith("source="):
            res["source"] = s.split("=", 1)[1].strip()
        elif s.startswith("origin="):
            m = re.search(r"\(([A-Z0-9]{10})\)\s*$", s)
            res["origin_team"] = m.group(1) if m else ""
    return res


APPLE_PKG_CERTS = {"Software Update", "Apple Software", "Apple Software Update Certification Authority",
                   "Apple Code Signing Certification Authority", "Apple Root CA"}


def parse_pkg_signature(out: str) -> dict:
    """`pkgutil --check-signature <pkg>` -> {"status": ..., "chain": [...], "apple": bool}.
    Apple's own packages read 'Status: signed Apple Software' with a chain of
    'Software Update' -> 'Apple Software Update Certification Authority' -> 'Apple Root CA'.
    A Developer ID package reads 'signed by a developer certificate issued by Apple ...'."""
    status = ""
    chain: list[str] = []
    in_chain = False
    for line in (out or "").splitlines():
        s = line.strip()
        if s.startswith("Status:"):
            status = s.split(":", 1)[1].strip()
        elif s.startswith("Certificate Chain:"):
            in_chain = True
        elif in_chain:
            m = re.match(r"^(\d+)\.\s+(.+)$", s)
            if m:
                chain.append(m.group(2).strip())
    apple = (status == "signed Apple Software" and len(chain) >= 2 and chain[-1] == "Apple Root CA"
             and chain[0] in ("Software Update", "Apple Software")
             and all(c in APPLE_PKG_CERTS for c in chain))
    return {"status": status, "chain": chain, "apple": apple}


def parse_softwareupdate_list(out: str) -> list[dict]:
    """`softwareupdate --list` (macOS 11+):
       * Label: Safari18.1VenturaAuto-18.1
       \tTitle: Safari, Version: 18.1, Size: 166428KiB, Recommended: YES, Action: restart,"""
    items: list[dict] = []
    cur: dict | None = None
    for line in (out or "").splitlines():
        s = line.strip()
        if s.startswith("* Label:"):
            label = s.split(":", 1)[1].strip()
            cur = {"label": label, "title": label, "version": "", "restart": False, "recommended": False,
                   "size": ""}
            if valid_label(label):
                items.append(cur)
        elif cur is not None and s.startswith("Title:"):
            for part in s.split(","):
                if ":" not in part:
                    continue
                k, v = (x.strip() for x in part.split(":", 1))
                if k == "Title":
                    cur["title"] = v
                elif k == "Version":
                    cur["version"] = v
                elif k == "Size":
                    cur["size"] = v
                elif k == "Recommended":
                    cur["recommended"] = v.upper() == "YES"
                elif k == "Action":
                    cur["restart"] = v.lower() in ("restart", "shut down", "shutdown")
            cur = None
    return items


_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()+:,-]{0,199}$")


def valid_label(label: str) -> bool:
    return bool(isinstance(label, str) and _LABEL_RE.match(label))


def version_tuple(v) -> tuple | None:
    if not isinstance(v, str) or not v.strip():
        return None
    parts = re.findall(r"\d+", v)
    if not parts or not re.match(r"^\s*\d", v):
        return None
    return tuple(int(p) for p in parts[:6])


def is_older(new_short, new_build, old_short, old_build) -> bool:
    """True only when both versions parse and the new one is lower (never refuses on doubt)."""
    a, b = version_tuple(new_short), version_tuple(old_short)
    if a is not None and b is not None and a != b:
        return a < b
    a, b = version_tuple(new_build), version_tuple(old_build)
    return a is not None and b is not None and a < b


# ------------------------------------------------------------------ paths and trees
def safe_app_name(name: str) -> bool:
    return (isinstance(name, str) and name.lower().endswith(".app") and 4 < len(name) <= MAX_NAME
            and "/" not in name and not name.startswith(".") and name not in (".app",)
            and not any(ord(ch) < 32 or ord(ch) == 127 for ch in name)
            and name.lower() != "pax.app")


def check_request_path(path, roots: list[str]) -> tuple[str, str]:
    """-> (path, kind) with kind in app|dmg|pkg, or raises BAD_FILE."""
    if not isinstance(path, str) or not path or "\x00" in path or len(path) > MAX_PATH:
        raise InstallError(BAD_FILE, "no usable path")
    if not path.startswith("/") or any(p in (".", "..") for p in path.split("/")):
        raise InstallError(BAD_FILE, "the path must be absolute, without . or ..")
    p = path.rstrip("/") if path != "/" else path
    if os.path.normpath(p) != p:
        raise InstallError(BAD_FILE, "the path isn't in its simplest form")
    if not any(p.startswith(r.rstrip("/") + "/") for r in roots if r):
        raise InstallError(BAD_FILE, "choose a file in your home folder or on a mounted disk")
    try:
        if os.path.realpath(p) != p:
            raise InstallError(BAD_FILE, "the path goes through a link")
    except OSError:
        raise InstallError(BAD_FILE, "Pax couldn't read that path") from None
    low = p.lower()
    if low.endswith(".app"):
        kind = "app"
    elif low.endswith(".dmg"):
        kind = "dmg"
    elif low.endswith(".pkg") or low.endswith(".mpkg"):
        kind = "pkg"
    else:
        raise InstallError(BAD_FILE, "Pax installs apps (.app) and disk images (.dmg)")
    return p, kind


def check_tree(root: str) -> int:
    """Walk a staged copy (never following links). Returns its size in bytes."""
    root = os.path.normpath(root)
    real_root = os.path.realpath(root)
    try:
        top = os.lstat(root)
    except OSError:
        raise InstallError(FAILED, "the staged copy is missing") from None
    if not stat.S_ISDIR(top.st_mode):
        raise InstallError(UNSAFE, "the app isn't a folder")
    if top.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise InstallError(UNSAFE, "the app folder is setuid/setgid")
    entries = 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                raise InstallError(UNSAFE, "the app has too many files")
            st = os.lstat(p)
            mode = st.st_mode
            if mode & (stat.S_ISUID | stat.S_ISGID):
                raise InstallError(UNSAFE, f"setuid/setgid file inside ({os.path.relpath(p, root)[:120]})")
            if stat.S_ISLNK(mode):
                target = os.readlink(p)
                if target.startswith("/"):
                    raise InstallError(UNSAFE, f"a link points outside the app ({os.path.relpath(p, root)[:120]})")
                lexical = os.path.normpath(os.path.join(dirpath, target))
                real = os.path.realpath(p)
                for t, base in ((lexical, root), (real, real_root)):
                    if not (t == base or t.startswith(base + "/")):
                        raise InstallError(UNSAFE,
                                           f"a link points outside the app ({os.path.relpath(p, root)[:120]})")
            elif stat.S_ISDIR(mode):
                continue
            elif stat.S_ISREG(mode):
                total += st.st_size
                if total > MAX_TREE_BYTES:
                    raise InstallError(UNSAFE, "the app is too big")
            else:
                raise InstallError(UNSAFE, f"special file inside ({os.path.relpath(p, root)[:120]})")
    return total


def copy_regular_file(src: str, dst: str, limit: int = MAX_IMAGE_BYTES) -> int:
    """Copy one regular file without following a link at `src` (O_NOFOLLOW, then fstat)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(src, flags)
    except OSError:
        raise InstallError(BAD_FILE, "Pax couldn't open that file") from None
    with os.fdopen(fd, "rb") as fi:
        st = os.fstat(fi.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise InstallError(BAD_FILE, "that isn't a regular file")
        if st.st_size > limit:
            raise InstallError(UNSAFE, "the file is too big")
        n = 0
        with open(dst, "xb") as fo:
            while True:
                chunk = fi.read(4 * 1024 * 1024)
                if not chunk:
                    break
                n += len(chunk)
                if n > limit:
                    raise InstallError(UNSAFE, "the file is too big")
                fo.write(chunk)
    os.chmod(dst, 0o600)
    return n


def read_plist(app: str) -> dict:
    try:
        with open(os.path.join(app, "Contents", "Info.plist"), "rb") as fh:
            d = plistlib.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}


def url_schemes(plist: dict) -> set[str]:
    out: set[str] = set()
    for t in plist.get("CFBundleURLTypes") or []:
        if isinstance(t, dict):
            for s in t.get("CFBundleURLSchemes") or []:
                if isinstance(s, str):
                    out.add(s.lower())
    return out


@dataclass
class StagedApp:
    path: str
    folder: str
    bundle_id: str
    name: str
    version: str
    build: str
    executable: str
    team_id: str
    signing_id: str
    schemes: set


# ------------------------------------------------------------------ the installer
class AppInstaller:
    """One install at a time. `run(args, stdin=None, timeout=..)` -> (code, output);
    `processes()` -> [(pid, executable path)]; `blocked_entries()` -> the user's Blocked
    apps (guard_config.app_entry dicts)."""

    def __init__(self, run, processes, *, applications: str = APPLICATIONS, staging: str = STAGING,
                 state_file: Path | None = None, log=print, clock=time.time,
                 blocked_entries=lambda: [], deny_file: Path = DENY_FILE, require_root_owner: bool = True):
        self.run = run
        self.processes = processes
        self.applications = applications
        self.staging = staging
        self.state_file = state_file
        self.log = log
        self.clock = clock
        self.blocked_entries = blocked_entries
        self.deny_file = deny_file
        self.require_root_owner = require_root_owner
        self.lock = threading.Lock()
        self.job: dict | None = None
        self._job_n = 0
        self._su_lock = threading.Lock()
        self.su: dict = {"state": "idle", "updates": [], "checked_at": None}

    # ---------------------------------------------------------- history
    def history(self) -> list[dict]:
        if not self.state_file:
            return []
        try:
            data = json.loads(Path(self.state_file).read_text() or "[]")
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def record(self, entry: dict) -> None:
        entry = {"at": int(self.clock()), **entry}
        line = (f"app install {entry.get('result')}: {entry.get('name') or entry.get('source')} "
                f"{entry.get('version') or ''} ({entry.get('bundle_id') or '-'}, team {entry.get('team_id') or '-'})"
                + (f" {entry.get('code')} {entry.get('detail', '')}" if entry.get("code") else ""))
        self.log(line.strip())
        if not self.state_file:
            return
        h = (self.history() + [entry])[-HISTORY_MAX:]
        p = Path(self.state_file)
        tmp = p.with_name(f".{p.name}.pax-tmp")
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(h))
            os.chmod(tmp, 0o600)
            os.replace(tmp, p)
        except OSError as exc:
            self.log(f"couldn't save the install history ({exc})")

    # ---------------------------------------------------------- staging
    def _staging_root(self) -> str:
        root = self.staging
        os.makedirs(root, mode=0o700, exist_ok=True)
        st = os.lstat(root)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise InstallError(FAILED, "the staging folder isn't a plain folder")
        if self.require_root_owner and st.st_uid != 0:
            raise InstallError(FAILED, "the staging folder isn't root's")
        os.chmod(root, 0o700)
        return root

    def new_stage(self) -> str:
        return tempfile.mkdtemp(prefix="job-", dir=self._staging_root())

    def cleanup_stale(self) -> None:
        """At start: detach anything left mounted in staging and remove old jobs."""
        try:
            names = os.listdir(self.staging)
        except OSError:
            return
        for n in names:
            d = os.path.join(self.staging, n)
            mnt = os.path.join(d, "mnt")
            if os.path.ismount(mnt):
                self.run(["/usr/bin/hdiutil", "detach", "-force", mnt], timeout=60)
            shutil.rmtree(d, ignore_errors=True)

    def _detach(self, mnt: str) -> None:
        code, _ = self.run(["/usr/bin/hdiutil", "detach", mnt], timeout=60)
        if code != 0:
            code, out = self.run(["/usr/bin/hdiutil", "detach", "-force", mnt], timeout=60)
            if code != 0:
                self.log(f"couldn't detach {mnt}: {out.strip()[-120:]}")

    def _ditto(self, src: str, dst: str) -> None:
        code, out = self.run(["/usr/bin/ditto", "--noacl", src, dst], timeout=1800)
        if code != 0 or not os.path.isdir(dst):
            raise InstallError(FAILED, f"copying failed: {out.strip()[-160:]}")

    # ---------------------------------------------------------- request entry
    def start(self, path, *, roots: list[str], uid, allowed_uids: set, choice=None,
              update_only: bool = False, background: bool = True) -> dict:
        """Checks the request quickly, then installs in a thread. Returns the job."""
        if uid is None or uid not in allowed_uids:
            self.record({"result": "refused", "code": BAD_FILE, "detail": f"uid {uid} not allowed"})
            raise InstallError(BAD_FILE, "only the Mac's own account can install apps")
        if choice is not None and (not isinstance(choice, str) or "/" in choice or len(choice) > MAX_NAME
                                   or choice.startswith(".")):
            raise InstallError(BAD_FILE, "that choice isn't an app in the image")
        with self.lock:
            if self.job and self.job.get("state") == "working":
                raise InstallError(BUSY, "Pax is already installing something")
            src, kind = check_request_path(path, roots)
            try:
                st = os.lstat(src)
            except OSError:
                raise InstallError(BAD_FILE, "that file isn't there any more") from None
            if stat.S_ISLNK(st.st_mode):
                raise InstallError(BAD_FILE, "that's a link, not the app")
            if kind == "app" and not stat.S_ISDIR(st.st_mode):
                raise InstallError(BAD_FILE, "that app isn't a folder")
            if kind == "pkg" and not stat.S_ISREG(st.st_mode):
                raise InstallError(PACKAGE, "only flat installer packages can be checked")
            if kind == "dmg" and not stat.S_ISREG(st.st_mode):
                raise InstallError(BAD_FILE, "that disk image isn't a file")
            if uid != 0 and st.st_uid != uid and not (st.st_mode & stat.S_IROTH):
                raise InstallError(BAD_FILE, "that file isn't yours")
            self._job_n += 1
            job = {"id": self._job_n, "state": "working", "step": "copying", "kind": kind,
                   "source": os.path.basename(src)[:MAX_NAME], "started_at": int(self.clock())}
            self.job = job
        args = (job, src, kind, choice, bool(update_only))
        if background:
            threading.Thread(target=self._run_job, args=args, name="pax-install", daemon=True).start()
        else:
            self._run_job(*args)
        return dict(self.job)

    def status(self) -> dict:
        return {"job": dict(self.job) if self.job else None, "history": self.history()[-20:]}

    def _run_job(self, job: dict, src: str, kind: str, choice, update_only: bool) -> None:
        stage = None
        try:
            stage = self.new_stage()
            result = self._install(job, stage, src, kind, choice, update_only)
            job.update(result)
            job["state"] = result.get("result", "installed")
        except InstallError as exc:
            job.update({"state": "refused" if exc.code != FAILED else "failed", "code": exc.code,
                        "error": exc.message, **{k: v for k, v in exc.extra.items() if k in ("options", "category")}})
            self.record({"result": job["state"], "code": exc.code, "detail": exc.message[:200],
                         "source": job.get("source"), "name": job.get("name"),
                         "bundle_id": job.get("bundle_id"), "team_id": job.get("team_id")})
        except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected
            job.update({"state": "failed", "code": FAILED, "error": "Pax couldn't finish; nothing changed"})
            self.record({"result": "failed", "code": FAILED, "detail": f"{type(exc).__name__}: {exc}"[:200],
                         "source": job.get("source")})
        finally:
            job["finished_at"] = int(self.clock())
            job.pop("step", None)
            if stage:
                shutil.rmtree(stage, ignore_errors=True)

    # ---------------------------------------------------------- the work
    def _install(self, job: dict, stage: str, src: str, kind: str, choice, update_only: bool) -> dict:
        if kind == "pkg":
            if update_only:
                raise InstallError(PACKAGE, "installer packages aren't app updates")
            staged = os.path.join(stage, "package.pkg")
            copy_regular_file(src, staged)
            return self._install_pkg(job, staged)
        if kind == "dmg":
            image = os.path.join(stage, "image.dmg")
            copy_regular_file(src, image)
            mnt = os.path.join(stage, "mnt")
            os.mkdir(mnt, 0o700)
            job["step"] = "opening"
            # -readonly -nobrowse -noautoopen: nothing in the image runs or shows up in
            # Finder; it's mounted inside the root-only staging folder. "Y" answers an
            # image's licence prompt (the user chose to install from it).
            code, out = self.run(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
                                  "-noautofsck", "-mountpoint", mnt, image], stdin="Y\n", timeout=600)
            if code != 0:
                raise InstallError(FAILED, f"the disk image wouldn't open: {out.strip()[-160:]}")
            try:
                pick, pick_kind = self._choose_in_image(mnt, choice)
                job["step"] = "copying"
                if pick_kind == "pkg":
                    if update_only:
                        raise InstallError(PACKAGE, "installer packages aren't app updates")
                    staged = os.path.join(stage, "package.pkg")
                    copy_regular_file(os.path.join(mnt, pick), staged)
                else:
                    os.mkdir(os.path.join(stage, "app"), 0o700)
                    staged = os.path.join(stage, "app", pick)
                    self._ditto(os.path.join(mnt, pick), staged)
            finally:
                self._detach(mnt)
            if pick_kind == "pkg":
                return self._install_pkg(job, staged)
            folder = pick
        else:
            folder = os.path.basename(src)
            if not safe_app_name(folder):
                raise InstallError(BAD_FILE if folder.lower() != "pax.app" else UNTOUCHABLE,
                                   "that app's name can't be used")
            os.mkdir(os.path.join(stage, "app"), 0o700)
            staged = os.path.join(stage, "app", folder)
            self._ditto(src, staged)
        job["step"] = "checking"
        app = self.verify_app(staged, folder)
        job.update({"name": app.name, "bundle_id": app.bundle_id, "team_id": app.team_id, "version": app.version})
        dest, existing = self.destination(app, update_only)
        job["step"] = "installing"
        self._place(app, dest, existing, stage)
        result = "updated" if existing else "installed"
        self.record({"result": result, "name": app.name, "bundle_id": app.bundle_id, "team_id": app.team_id,
                     "version": app.version, "source": job.get("source"), "dest": dest})
        return {"result": result, "dest": dest}

    def _choose_in_image(self, mnt: str, choice) -> tuple[str, str]:
        apps, pkgs = [], []
        for e in sorted(os.scandir(mnt), key=lambda e: e.name):
            if e.name.startswith("."):
                continue
            if e.is_symlink():
                continue                      # e.g. the "Applications" shortcut
            low = e.name.lower()
            if low.endswith(".app") and e.is_dir(follow_symlinks=False):
                apps.append(e.name)
            elif (low.endswith(".pkg") or low.endswith(".mpkg")):
                pkgs.append(e.name)
        if choice is not None:
            if choice in apps:
                if not safe_app_name(choice):
                    raise InstallError(UNTOUCHABLE if choice.lower() == "pax.app" else BAD_FILE,
                                       "that app's name can't be used")
                return choice, "app"
            if choice in pkgs:
                return self._pkg_choice(mnt, choice)
            raise InstallError(BAD_FILE, "that choice isn't in the image")
        if len(apps) == 1:
            if not safe_app_name(apps[0]):
                raise InstallError(UNTOUCHABLE if apps[0].lower() == "pax.app" else BAD_FILE,
                                   "that app's name can't be used")
            return apps[0], "app"
        if len(apps) > 1 or (not apps and len(pkgs) > 1):
            options = (apps + pkgs)[:MAX_OPTIONS]
            raise InstallError(CHOOSE, "there's more than one thing in this disk image", options=options)
        if pkgs:
            return self._pkg_choice(mnt, pkgs[0])
        raise InstallError(BAD_FILE, "there's no app in this disk image")

    @staticmethod
    def _pkg_choice(mnt: str, name: str) -> tuple[str, str]:
        st = os.lstat(os.path.join(mnt, name))
        if not stat.S_ISREG(st.st_mode):
            raise InstallError(PACKAGE, "only flat installer packages can be checked")
        return name, "pkg"

    def verify_app(self, staged: str, folder: str) -> StagedApp:
        check_tree(staged)
        plist = read_plist(staged)
        bid = str(plist.get("CFBundleIdentifier") or "")
        if not bid or not re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$", bid):
            raise InstallError(BAD_FILE, "that app has no readable bundle ID")
        name = str(plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or folder[:-4])[:MAX_NAME]
        lbid = bid.lower()
        if lbid.startswith(PAX_BUNDLE_PREFIXES):
            raise InstallError(UNTOUCHABLE, "Pax updates itself through its own signed updates")
        if lbid.startswith("com.apple."):
            raise InstallError(UNTOUCHABLE, "Apple's own apps update through the App Store or Software Update")
        code, out = self.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", staged],
                             timeout=600)
        if code != 0:
            raise InstallError(NOT_SIGNED, f"its signature didn't check out: {out.strip()[-160:]}")
        code, out = self.run(["/usr/bin/codesign", "-dv", "--verbose=4", staged], timeout=120)
        sig = parse_codesign_details(out if code == 0 else "")
        if is_apple_signed(sig):
            raise InstallError(UNTOUCHABLE, "Apple's own apps update through the App Store or Software Update")
        if sig["team_id"] == PAX_TEAM_ID:
            raise InstallError(UNTOUCHABLE, "Pax updates itself through its own signed updates")
        why = developer_id_problem(sig)
        if why:
            raise InstallError(NOT_SIGNED, why)
        if sig["identifier"] != bid:
            raise InstallError(NOT_SIGNED, "its signature is for a different bundle ID")
        code, out = self.run(["/usr/sbin/spctl", "--assess", "--type", "execute", "-vv", staged], timeout=600)
        sp = parse_spctl(out)
        if code != 0 or not sp["accepted"] or sp["source"] != "Notarized Developer ID":
            raise InstallError(NOT_NOTARISED, f"Gatekeeper said: {(sp['source'] or out.strip())[-120:]}")
        if sp["origin_team"] and sp["origin_team"] != sig["team_id"]:
            raise InstallError(NOT_SIGNED, "Gatekeeper and the signature disagree on the developer")
        app = StagedApp(path=staged, folder=folder, bundle_id=bid, name=name,
                        version=str(plist.get("CFBundleShortVersionString") or ""),
                        build=str(plist.get("CFBundleVersion") or ""),
                        executable=str(plist.get("CFBundleExecutable") or ""),
                        team_id=sig["team_id"], signing_id=sig["identifier"], schemes=url_schemes(plist))
        why = self.blocked_reason(app)
        if why:
            raise InstallError(BLOCKED, f"Pax doesn't install {why}", category=why)
        return app

    # ---------------------------------------------------------- blocking
    def blocked_reason(self, app: StagedApp) -> str | None:
        import guard_config as gc
        try:
            deny = load_deny(self.deny_file)
        except (OSError, ValueError) as exc:
            # Fail closed: without the list Pax can't tell what's allowed.
            raise InstallError(FAILED, f"the install rules couldn't be read ({exc})") from None
        lbid = app.bundle_id.lower()
        names = {app.name.lower(), app.folder[:-4].lower() if app.folder.lower().endswith(".app") else app.folder.lower()}
        # 1. the user's own Blocked apps (bundle ID, sealed identifier + team, program name)
        ident = gc.AppIdentity(path=os.path.join(self.applications, app.folder), bundle_id=app.bundle_id,
                               name=app.name, executable=app.executable, signing_id=app.signing_id,
                               team_id=app.team_id)
        for e in self.blocked_entries() or []:
            if gc.app_matches(ident, e):
                return "an app you blocked"
        # 2. pax-guard's existing lists (VPN, Tor, proxies, browsers, remote AI, VMs), by bundle
        # ID first, then by name. Unlike the quarantine sweep, a managed browser's *name* doesn't
        # excuse an app with another bundle ID.
        groups = ((gc.REMOTE_AI_APPS, "an app that controls a remote computer or browser"),
                  (gc.UNMANAGEABLE_BROWSERS, "a browser Pax can't apply its rules to"),
                  (gc.VM_APPS, "a virtual machine app"),
                  (gc.BYPASS_APPS, None))
        for apps, label in groups:
            for a in apps:
                hit = lbid in (b.lower() for b in a.bundle_ids) or (
                    any(n in (x.lower() for x in a.app_names) for n in names)
                    and lbid not in MANAGED_BROWSER_BUNDLE_IDS)
                if hit:
                    return label or _bypass_label(a)
        # 3. app-install-deny.txt (remote desktop, rented Macs, mesh VPNs, proxies)
        for c in deny:
            if (lbid in c.bundles or any(lbid.startswith(p) for p in c.prefixes)
                    or (app.team_id and app.team_id in c.teams) or (names & c.names)):
                return c.label
        # 4. any other web browser (an app that offers to open http/https links)
        if ({"http", "https"} & app.schemes) and lbid not in MANAGED_BROWSER_BUNDLE_IDS:
            return "a browser Pax can't apply its rules to"
        return None

    # ---------------------------------------------------------- where it goes
    def installed_apps(self) -> dict:
        """bundle ID (lower) -> [paths] for the top level of /Applications (no links)."""
        out: dict = {}
        try:
            entries = list(os.scandir(self.applications))
        except OSError:
            return out
        for e in entries:
            if not e.name.lower().endswith(".app") or e.is_symlink() or not e.is_dir(follow_symlinks=False):
                continue
            bid = str(read_plist(e.path).get("CFBundleIdentifier") or "").lower()
            if bid:
                out.setdefault(bid, []).append(e.path)
        return out

    def destination(self, app: StagedApp, update_only: bool) -> tuple[str, str | None]:
        same = sorted(self.installed_apps().get(app.bundle_id.lower(), []))
        dest = os.path.join(self.applications, app.folder)
        existing = None
        if same:
            existing = dest if dest in same else same[0]
            dest = existing
        elif update_only:
            raise InstallError(FAILED, "that app isn't in Applications yet, so there's nothing to update")
        elif os.path.lexists(dest):
            raise InstallError(NAME_TAKEN, f"another app is already called {app.folder}")
        if os.path.dirname(dest) != self.applications or not safe_app_name(os.path.basename(dest)):
            raise InstallError(UNTOUCHABLE, "Pax only changes apps in the Applications folder")
        if existing:
            st = os.lstat(existing)
            if stat.S_ISLNK(st.st_mode):
                raise InstallError(UNTOUCHABLE, "the installed app is a link")
            code, out = self.run(["/usr/bin/codesign", "-dv", "--verbose=4", existing], timeout=120)
            cur = parse_codesign_details(out if code == 0 else "")
            if is_apple_signed(cur) or cur["identifier"].lower().startswith("com.apple."):
                raise InstallError(UNTOUCHABLE, "Apple's own apps update through the App Store or Software Update")
            if cur["team_id"] == PAX_TEAM_ID:
                raise InstallError(UNTOUCHABLE, "Pax updates itself through its own signed updates")
            if cur["team_id"] != app.team_id:
                raise InstallError(OTHER_DEVELOPER,
                                   f"the installed copy is from Team ID {cur['team_id'] or 'none'}, "
                                   f"this one from {app.team_id}")
            old = read_plist(existing)
            if is_older(app.version, app.build, str(old.get("CFBundleShortVersionString") or ""),
                        str(old.get("CFBundleVersion") or "")):
                raise InstallError(OLDER, f"{app.version} is older than the installed "
                                          f"{old.get('CFBundleShortVersionString')}")
            for _pid, exe in self.processes():
                if exe.startswith(existing + "/"):
                    raise InstallError(RUNNING, f"quit {app.name} first")
        return dest, existing

    def _place(self, app: StagedApp, dest: str, existing: str | None, stage: str) -> None:
        staged = app.path
        for args in (["/usr/bin/xattr", "-dr", "com.apple.quarantine", staged],
                     ["/usr/sbin/chown", "-h", "-R", "root:admin", staged],
                     ["/bin/chmod", "-R", "go-w", staged]):
            code, out = self.run(args, timeout=600)
            if code != 0 and args[0] != "/usr/bin/xattr":
                raise InstallError(FAILED, f"{os.path.basename(args[0])} failed: {out.strip()[-120:]}")
        # The bundle is root's now; check the very copy that moves in once more.
        code, out = self.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", staged], timeout=600)
        if code != 0:
            raise InstallError(NOT_SIGNED, f"its signature didn't check out: {out.strip()[-160:]}")
        check_tree(staged)
        if os.stat(os.path.dirname(staged)).st_dev != os.stat(self.applications).st_dev:
            raise InstallError(FAILED, "the staging folder is on another disk")
        if existing:
            backup = os.path.join(stage, "previous.app")
            os.rename(existing, backup)
            try:
                os.rename(staged, dest)
            except OSError:
                os.rename(backup, existing)
                raise
        else:
            os.rename(staged, dest)

    def _install_pkg(self, job: dict, pkg: str) -> dict:
        job["step"] = "checking"
        code, out = self.run(["/usr/sbin/pkgutil", "--check-signature", pkg], timeout=300)
        sig = parse_pkg_signature(out)
        if code != 0 or not sig["apple"]:
            raise InstallError(PACKAGE, "installer packages run their own scripts as administrator, "
                                        f"so they wait like turning Pax off ({sig['status'][:80] or 'unsigned'})")
        code, out = self.run(["/usr/sbin/spctl", "--assess", "--type", "install", "-vv", pkg], timeout=300)
        if code != 0 or not parse_spctl(out)["accepted"]:
            raise InstallError(NOT_NOTARISED, f"Gatekeeper said: {out.strip()[-120:]}")
        job.update({"name": job.get("source"), "team_id": "Apple"})
        job["step"] = "installing"
        code, out = self.run(["/usr/sbin/installer", "-pkg", pkg, "-target", "/"], timeout=3600)
        if code != 0:
            raise InstallError(FAILED, f"Apple's installer stopped: {out.strip()[-160:]}")
        self.record({"result": "installed", "name": job.get("source"), "bundle_id": "pkg", "team_id": "Apple",
                     "source": job.get("source")})
        return {"result": "installed"}

    # ---------------------------------------------------------- 1(b) downloaded updates
    def downloaded_updates(self, home: str | None) -> list[dict]:
        """Apps an app's own updater (Sparkle, Squirrel/ShipIt) has already downloaded and
        unpacked in ~/Library/Caches, newer than the copy in /Applications. Only a list:
        installing one goes through start(..., update_only=True) and every check."""
        if not home:
            return []
        caches = os.path.join(home, "Library", "Caches")
        installed = self.installed_apps()
        found: list[dict] = []
        seen_dirs = 0
        try:
            tops = list(os.scandir(caches))
        except OSError:
            return []
        roots = []
        for e in tops:
            if e.is_symlink() or not e.is_dir(follow_symlinks=False):
                continue
            if e.name.endswith(".ShipIt"):
                roots.append(e.path)
            sp = os.path.join(e.path, "org.sparkle-project.Sparkle")
            if os.path.isdir(sp) and not os.path.islink(sp):
                roots.append(sp)
        stack = [(r, 0) for r in roots]
        while stack and seen_dirs < SCAN_MAX_DIRS:
            d, depth = stack.pop()
            seen_dirs += 1
            try:
                kids = list(os.scandir(d))
            except OSError:
                continue
            for k in kids:
                if k.is_symlink() or not k.is_dir(follow_symlinks=False):
                    continue
                if k.name.lower().endswith(".app"):
                    pl = read_plist(k.path)
                    bid = str(pl.get("CFBundleIdentifier") or "").lower()
                    if bid in installed and not bid.startswith(PAX_BUNDLE_PREFIXES + ("com.apple.",)):
                        cur = read_plist(sorted(installed[bid])[0])
                        new_v = str(pl.get("CFBundleShortVersionString") or "")
                        old_v = str(cur.get("CFBundleShortVersionString") or "")
                        newer = is_older(old_v, str(cur.get("CFBundleVersion") or ""), new_v,
                                         str(pl.get("CFBundleVersion") or ""))
                        if newer:
                            found.append({"path": k.path, "name": str(pl.get("CFBundleDisplayName")
                                                                         or pl.get("CFBundleName") or k.name[:-4]),
                                          "bundle_id": str(pl.get("CFBundleIdentifier")), "version": new_v,
                                          "installed_version": old_v})
                elif depth + 1 < SCAN_MAX_DEPTH:
                    stack.append((k.path, depth + 1))
        best: dict = {}
        for f in found:
            k = f["bundle_id"].lower()
            if k not in best or (version_tuple(f["version"]) or ()) > (version_tuple(best[k]["version"]) or ()):
                best[k] = f
        return sorted(best.values(), key=lambda f: f["name"].lower())

    # ---------------------------------------------------------- 4. Apple software updates
    def su_check(self, background: bool = True) -> dict:
        with self._su_lock:
            if self.su.get("state") in ("checking", "installing"):
                return dict(self.su)
            self.su = {**self.su, "state": "checking", "code": None, "error": None}

        def work():
            code, out = self.run(["/usr/sbin/softwareupdate", "--list"], timeout=900)
            with self._su_lock:
                if code != 0 and "No new software available" not in out:
                    self.su = {**self.su, "state": "failed", "code": SU_CHECK,
                               "error": "softwareupdate --list failed"}
                    self.log(f"{SU_CHECK} softwareupdate --list: {out.strip()[-160:]}")
                    return
                self.su = {"state": "idle", "updates": parse_softwareupdate_list(out),
                           "checked_at": int(self.clock()), "code": None, "error": None,
                           "restart_needed": self.su.get("restart_needed", False)}
        if background:
            threading.Thread(target=work, name="pax-softwareupdate", daemon=True).start()
        else:
            work()
        return dict(self.su)

    def su_install(self, label, background: bool = True) -> dict:
        with self._su_lock:
            if self.su.get("state") in ("checking", "installing"):
                raise InstallError(BUSY, "Pax is already working on Apple updates")
            known = {u["label"]: u for u in self.su.get("updates") or []}
            if not valid_label(label) or label not in known:
                raise InstallError(SU_INSTALL, "check for updates first, then choose one from the list")
            self.su = {**self.su, "state": "installing", "installing": label, "code": None, "error": None}
        item = known[label]

        def work():
            # Never --restart / -R: the user restarts when they're ready.
            code, out = self.run(["/usr/sbin/softwareupdate", "--install", label, "--agree-to-license"],
                                 timeout=4 * 3600)
            low = out.lower()
            with self._su_lock:
                st = {**self.su, "state": "idle", "installing": None}
                if code != 0 or ("error" in low and "installed" not in low):
                    admin = ("volume owner" in low or "authenticat" in low or "password" in low
                             or "not authorized" in low)
                    st.update({"code": SU_ADMIN if admin else SU_INSTALL,
                               "error": "macOS wanted an administrator for this update" if admin
                               else "softwareupdate --install failed"})
                    self.record({"result": "refused" if admin else "failed", "code": st["code"],
                                 "name": item.get("title"), "bundle_id": "softwareupdate",
                                 "version": item.get("version"), "detail": out.strip()[-160:]})
                else:
                    restart = item.get("restart") or "restart" in low
                    st["updates"] = [u for u in st.get("updates") or [] if u["label"] != label]
                    st["restart_needed"] = bool(st.get("restart_needed") or restart)
                    self.record({"result": "installed", "name": item.get("title"), "bundle_id": "softwareupdate",
                                 "team_id": "Apple", "version": item.get("version")})
                self.su = st
        if background:
            threading.Thread(target=work, name="pax-softwareupdate", daemon=True).start()
        else:
            work()
        return dict(self.su)


def _bypass_label(a) -> str:
    why = (a.why or "").lower()
    if "tor" in why.split() or why.startswith("tor") or "onion" in why:
        return "Tor"
    if "proxy" in why or "circumvention" in why:
        return "a proxy app"
    if "browser" in why:
        return "a browser Pax can't apply its rules to"
    return "a VPN app"
