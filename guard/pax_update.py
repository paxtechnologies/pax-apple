# SPDX-License-Identifier: GPL-3.0-only
"""Automatic updates for Pax on the Mac, installed by pax-guard (v0.8.0).

The everyday account is a Standard user and can't replace /Applications/Pax.app
or /Library/PaxGuard, so root pax-guard does it. No Sparkle: Sparkle's
installer runs in the user's session and asks for an administrator to update an
app in /Applications, which the Standard user isn't; it would also add a
framework (and its XPC services) to a project that otherwise ships only Swift
and the Command Line Tools' Python. Pax already has a root daemon and an
Ed25519 check (guard/ed25519.py), so the whole updater is this file.

Every 6 hours at most (or on "Update now" in the app):
  1. fetch pax-update.json from the latest GitHub Release, else the jsDelivr
     mirror (the `releases` branch); it must be signed by a pinned Ed25519 key
     (guard/pax_signing.py) or it's ignored;
  2. a version not above the installed one is never installed (no downgrade),
     and a manifest older than one already seen is refused (stale mirror);
  3. installed < minimum_version: install now and show a calm notice;
     otherwise install silently when Pax isn't open, or after 24 hours;
  4. download the zip (release asset, then whole-zip mirrors, then, since v0.8.6,
     the signed list of parts: each part under jsDelivr's 20 MB limit, pinned by
     its own SHA-256, joined and checked against the zip's signed SHA-256 and
     size before anything is unpacked), check its SHA-256 and size,
     unpack with ditto, check the version inside, `codesign --verify --deep
     --strict`, and, if the installed app is signed with a Developer ID, that the
     new one has the same Team ID; self-test the new pax-guard;
     v0.8.6: copy the new app's Python runtime for pax-guard (guard_runtime.py:
     Developer ID Team ID and every file's hash) and run the new pax-guard's
     self-test on that copy;
  5. swap: the old app, guard and runtime move to /Library/PaxGuard/updates/rollback,
     the new ones into place; a watchdog (the *old* updater code, detached) restarts
     pax-guard and waits for the new one to report healthy. If it doesn't
     within 3 minutes, the watchdog puts the old app and guard back, restarts
     them and marks that version bad.
Protection never stops: /etc/hosts and the pf rules stay in place throughout,
and while pax-guard restarts DNS points at 127.0.0.1 with nothing answering,
so lookups fail instead of going around the filter. Users can't turn updates
off; Settings › Updates shows the last check and the version.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pax_signing  # noqa: E402

REPO_SLUG = "paxtechnologies/pax-apple"
MANIFEST_URLS = [
    f"https://github.com/{REPO_SLUG}/releases/latest/download/pax-update.json",
    f"https://cdn.jsdelivr.net/gh/{REPO_SLUG}@releases/pax-update.json",
]
CHECK_INTERVAL = 6 * 3600
CHECK_JITTER = 30 * 60          # spread Macs out so they don't all ask at once
BACKOFF_START, BACKOFF_MAX = 3600, 24 * 3600
DEFER_MAX = 24 * 3600
TRIAL_SECONDS = 180
MAX_ZIP = 300 * 1024 * 1024
# v0.8.6: jsDelivr serves files up to 20 MB from GitHub, so mirror parts stay below it.
MAX_PART = 20 * 1000 * 1000
MAX_PARTS = 64
_PART_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
RUNTIME_DIR = Path("/Library/PaxGuard/runtime")
APP_PATH = Path("/Applications/Pax.app")
GUARD_BIN = Path("/Library/PaxGuard/bin")
UPDATES_DIR = Path("/Library/PaxGuard/updates")
LABEL = "org.paxpeace.pax-guard"
PLIST = Path(f"/Library/LaunchDaemons/{LABEL}.plist")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def is_rate_limited(exc: BaseException) -> bool:
    """429 / 5xx from a source (pax_guard.RateLimited or urllib's HTTPError)."""
    status = getattr(exc, "status", None) or getattr(exc, "code", None)
    return isinstance(status, int) and (status == 429 or status >= 500)


def next_backoff(previous: int, retry_after: int | None = None) -> int:
    """Exponential back-off (1 h, 2 h, 4 h ... 24 h), or the server's Retry-After
    if that is longer, plus a little jitter."""
    wait = min(BACKOFF_MAX, max(BACKOFF_START, previous * 2 if previous else BACKOFF_START))
    if retry_after:
        wait = min(BACKOFF_MAX, max(wait, int(retry_after)))
    return wait + random.randint(0, 300)


class UpdateError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def parse_version(v: str) -> tuple[int, int, int]:
    if not isinstance(v, str) or not _VERSION_RE.match(v):
        raise UpdateError("PAX-UPDATE-003", f"bad version {v!r}")
    a, b, c = v.split(".")
    return int(a), int(b), int(c)


def validate_manifest(p: dict) -> dict:
    if p.get("schema") != "pax.update.v1":
        raise UpdateError("PAX-UPDATE-002", "unknown update manifest schema")
    parse_version(p.get("version", ""))
    parse_version(p.get("minimum_version", "0.0.0"))
    if parse_version(p["minimum_version"]) > parse_version(p["version"]):
        raise UpdateError("PAX-UPDATE-002", "minimum_version is above version")
    if not re.fullmatch(r"[0-9a-f]{64}", str(p.get("sha256", ""))):
        raise UpdateError("PAX-UPDATE-002", "missing SHA-256")
    urls = [p.get("url")] + list(p.get("mirrors") or [])
    if not all(isinstance(u, str) and u.startswith("https://") for u in urls if u is not None) or not p.get("url"):
        raise UpdateError("PAX-UPDATE-002", "download URLs must be https://")
    if not isinstance(p.get("size"), int) or not 0 < p["size"] <= MAX_ZIP:
        raise UpdateError("PAX-UPDATE-002", "bad size")
    if p.get("parts") is not None:
        validate_parts(p["parts"], p["size"])
    return p


def validate_parts(parts, total: int) -> None:
    """v0.8.6 `parts`: {"base_urls": [https://.../], "files": [{"name", "size", "sha256"}]}.
    The parts must add up to the zip's signed size; the joined bytes are then
    checked against its signed SHA-256 too."""
    if not isinstance(parts, dict):
        raise UpdateError("PAX-UPDATE-002", "bad parts list")
    bases = parts.get("base_urls")
    files = parts.get("files")
    if not isinstance(bases, list) or not bases or not all(
            isinstance(b, str) and b.startswith("https://") and b.endswith("/") for b in bases):
        raise UpdateError("PAX-UPDATE-002", "part URLs must be https://")
    if not isinstance(files, list) or not 0 < len(files) <= MAX_PARTS:
        raise UpdateError("PAX-UPDATE-002", "bad parts list")
    seen = set()
    for f in files:
        if not (isinstance(f, dict) and isinstance(f.get("name"), str) and _PART_NAME_RE.match(f["name"])
                and f["name"] not in seen and isinstance(f.get("size"), int) and 0 < f["size"] <= MAX_PART
                and re.fullmatch(r"[0-9a-f]{64}", str(f.get("sha256", "")))):
            raise UpdateError("PAX-UPDATE-002", "bad part in the parts list")
        seen.add(f["name"])
    if sum(f["size"] for f in files) != total:
        raise UpdateError("PAX-UPDATE-002", "the parts don't add up to the zip")


def team_id(codesign_output: str) -> str | None:
    m = re.search(r"^TeamIdentifier=(\S+)", codesign_output, re.M)
    if not m or m.group(1) == "not" or "not set" in m.group(0):
        return None
    return m.group(1)


def is_developer_id(codesign_output: str) -> bool:
    return "Authority=Developer ID Application" in codesign_output


class Updater:
    def __init__(self, system, state_dir: Path, installed_version: str, log=print, notify=lambda t: None,
                 app_path: Path = APP_PATH, guard_bin: Path = GUARD_BIN, updates_dir: Path = UPDATES_DIR,
                 manifest_urls: list[str] | None = None, keys: list[bytes] | None = None,
                 app_running=None, clock=time.time, runtime=None, runtime_dir: Path = RUNTIME_DIR):
        self.sys = system
        self.state_path = Path(state_dir) / "update.json"
        self.installed = installed_version
        self.log = log
        self.notify = notify
        self.app_path, self.guard_bin, self.updates = Path(app_path), Path(guard_bin), Path(updates_dir)
        self.urls = manifest_urls or MANIFEST_URLS
        self.keys = keys
        self.app_running = app_running or (lambda: False)
        self.clock = clock
        # v0.8.6: guard_runtime.Runtime (None: this updater doesn't manage a runtime).
        self.runtime = runtime
        self.runtime_dir = Path(runtime.dir if runtime is not None else runtime_dir)
        self._staged_runtime: Path | None = None

    # --------------------------------------------------------------- state
    def state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self, st: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_name(".update.json.tmp")
        tmp.write_text(json.dumps(st, sort_keys=True))
        os.replace(tmp, self.state_path)

    def status(self) -> dict:
        st = self.state()
        return {"installed": self.installed, "last_checked": st.get("last_checked"),
                "next_check_at": st.get("next_check_at"), "backoff_until": st.get("backoff_until"),
                "latest": st.get("latest"), "minimum": st.get("minimum"),
                "state": st.get("state", "idle"), "last_error": st.get("last_error"),
                "last_installed": st.get("last_installed"), "notice": st.get("notice")}

    # --------------------------------------------------------------- fetch
    def fetch_manifest(self) -> dict:
        errors = []
        limited = None
        for url in self.urls:
            try:
                doc = json.loads(self.sys.fetch(url, timeout=30))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url}: {type(exc).__name__}")
                if is_rate_limited(exc):
                    limited = exc
                continue
            try:
                payload = pax_signing.verify_document(doc, self.keys)
            except pax_signing.SignatureError as exc:
                self.log(f"PAX-UPDATE-002 update manifest from {url} rejected: {exc}")
                errors.append(f"{url}: {exc}")
                continue
            return validate_manifest(payload)
        err = UpdateError("PAX-UPDATE-008" if limited else "PAX-UPDATE-001",
                          ("the update sources asked Pax to slow down: " if limited else
                           "no update source answered with a signed manifest: ") + "; ".join(errors)[-300:])
        err.retry_after = getattr(limited, "retry_after", None) if limited else None
        err.limited = limited is not None
        raise err

    # --------------------------------------------------------------- check
    def check(self, force: bool = False) -> dict:
        """Check (at most every 6 h unless forced) and install if due."""
        now = int(self.clock())
        st = self.state()
        if st.get("state") == "trial":
            return self.status()
        if now < int(st.get("backoff_until", 0)):
            return self.status()           # a source said 429/5xx: even "Update now" waits
        if not force and now < int(st.get("next_check_at", int(st.get("last_checked", 0)) + CHECK_INTERVAL)):
            return self.status()
        st["last_checked"] = now
        st["next_check_at"] = now + CHECK_INTERVAL + random.randint(0, CHECK_JITTER)
        try:
            m = self.fetch_manifest()
        except UpdateError as exc:
            st["last_error"] = f"{exc.code} {exc.message}"[:300]
            if getattr(exc, "limited", False):
                st["backoff_seconds"] = next_backoff(int(st.get("backoff_seconds", 0)),
                                                     getattr(exc, "retry_after", None))
                st["backoff_until"] = now + st["backoff_seconds"]
                self.log(f"PAX-UPDATE-008 update source rate-limited; next try in "
                         f"{st['backoff_seconds'] // 60} min")
            self._save(st)
            return self.status()
        st.pop("backoff_seconds", None)
        st.pop("backoff_until", None)
        seen = st.get("highest_seen")
        if seen and parse_version(m["version"]) < parse_version(seen):
            st["last_error"] = f"PAX-UPDATE-003 refused older manifest {m['version']} (seen {seen})"
            self._save(st)
            return self.status()
        st["highest_seen"] = m["version"]
        st["latest"], st["minimum"] = m["version"], m["minimum_version"]
        st["last_error"] = None
        installed = parse_version(self.installed)
        target = parse_version(m["version"])
        forced = installed < parse_version(m["minimum_version"])
        if target <= installed:
            st["state"] = "up_to_date"
            self._save(st)
            return self.status()
        if m["version"] in st.get("bad_versions", []) and not forced:
            st["state"] = "skipped_bad"
            self._save(st)
            return self.status()
        first_seen = st.setdefault("first_seen", {}).setdefault(m["version"], now)
        due = forced or force or not self.app_running() or now - int(first_seen) >= DEFER_MAX
        if not due:
            st["state"] = "waiting_for_pax_to_close"
            self._save(st)
            return self.status()
        self._save(st)
        try:
            self.install(m, forced=forced)
        except UpdateError as exc:
            st = self.state()
            st["state"], st["last_error"] = "failed", f"{exc.code} {exc.message}"[:300]
            self._save(st)
            self.log(f"{exc.code} update to {m['version']} failed: {exc.message}")
        return self.status()

    # ------------------------------------------------------------- install
    def _download(self, m: dict, dest: Path) -> None:
        errors = []
        for url in [m["url"]] + list(m.get("mirrors") or []):
            try:
                data = self.sys.fetch(url, timeout=600)
            except Exception as exc:  # noqa: BLE001
                errors.append(type(exc).__name__)
                continue
            if len(data) != m["size"] or hashlib.sha256(data).hexdigest() != m["sha256"]:
                errors.append("hash mismatch")
                self.log(f"PAX-UPDATE-004 download from {url} doesn't match the signed SHA-256")
                continue
            dest.write_bytes(data)
            return
        if m.get("parts"):
            try:
                self._download_parts(m, dest)
                return
            except UpdateError as exc:
                errors.append(exc.message)
                if exc.code == "PAX-UPDATE-004":
                    errors.append("hash mismatch")
        if "hash mismatch" in errors:
            raise UpdateError("PAX-UPDATE-004", "the download doesn't match the signed SHA-256")
        raise UpdateError("PAX-UPDATE-001", "couldn't download the update")

    def _download_parts(self, m: dict, dest: Path) -> None:
        """v0.8.6: the zip in signed, hash-pinned parts (each under jsDelivr's 20 MB
        limit), from the first base URL that serves each part intact. The joined
        file must match the zip's signed size and SHA-256, so the Ed25519 signature
        covers exactly the bytes that get unpacked."""
        parts = m["parts"]
        whole = hashlib.sha256()
        tmp = dest.with_name(dest.name + ".parts")
        mismatch = False
        try:
            with open(tmp, "wb") as out:
                for f in parts["files"]:
                    data = None
                    for base in parts["base_urls"]:
                        try:
                            got = self.sys.fetch(base + f["name"], timeout=300)
                        except Exception:  # noqa: BLE001 - next base
                            continue
                        if len(got) == f["size"] and hashlib.sha256(got).hexdigest() == f["sha256"]:
                            data = got
                            break
                        mismatch = True
                        self.log(f"PAX-UPDATE-004 part {f['name']} from {base} doesn't match its signed SHA-256")
                    if data is None:
                        raise UpdateError("PAX-UPDATE-004" if mismatch else "PAX-UPDATE-001",
                                          f"couldn't download part {f['name']}")
                    whole.update(data)
                    out.write(data)
            if os.path.getsize(tmp) != m["size"] or whole.hexdigest() != m["sha256"]:
                raise UpdateError("PAX-UPDATE-004", "the joined parts don't match the signed SHA-256")
            os.replace(tmp, dest)
        finally:
            if tmp.exists():
                tmp.unlink()

    def _run(self, args: list[str], timeout: int = 120) -> tuple[int, str]:
        return self.sys.run(args, timeout=timeout)

    def verify_bundle(self, new_app: Path, version: str) -> None:
        try:
            with open(new_app / "Contents" / "Info.plist", "rb") as fh:
                info = plistlib.load(fh)
        except (OSError, plistlib.InvalidFileException, ValueError):
            raise UpdateError("PAX-UPDATE-005", "the update has no readable Info.plist") from None
        if info.get("CFBundleShortVersionString") != version:
            raise UpdateError("PAX-UPDATE-005", f"the update says {info.get('CFBundleShortVersionString')}, "
                              f"the manifest {version}")
        guard = new_app / "Contents" / "Resources" / "guard" / "pax_guard.py"
        if f'VERSION = "{version}"' not in self.sys.read(str(guard)):
            raise UpdateError("PAX-UPDATE-005", "the update's pax-guard has a different version")
        code, out = self._run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(new_app)])
        if code != 0:
            raise UpdateError("PAX-UPDATE-006", f"codesign rejected the update: {out.strip()[-160:]}")
        _c, cur = self._run(["/usr/bin/codesign", "-dv", "--verbose=2", str(self.app_path)])
        _c, new = self._run(["/usr/bin/codesign", "-dv", "--verbose=2", str(new_app)])
        cur_team = team_id(cur) if is_developer_id(cur) else None
        if cur_team and team_id(new) != cur_team:
            raise UpdateError("PAX-UPDATE-006", f"Team ID {team_id(new)} doesn't match the installed {cur_team}")
        python = self.stage_runtime(new_app, cur_team)
        code, out = self._run([str(python), "-I", "-B", str(guard), "selftest"], timeout=120)
        if code != 0:
            raise UpdateError("PAX-UPDATE-005", f"the new pax-guard failed its self-test: {out.strip()[-160:]}")

    def stage_runtime(self, new_app: Path, cur_team: str | None) -> Path:
        """v0.8.6: copy and check the new app's runtime for pax-guard (Team ID and
        every file's hash) next to the staging area; its interpreter runs the new
        pax-guard's self-test. Without a runtime manager (or for a build that isn't
        Developer ID signed, when the installed one isn't either) the self-test runs
        on this Python, as before."""
        self._staged_runtime = None
        if self.runtime is None:
            return Path(sys.executable)
        import guard_runtime as grt
        dest = self.updates / "staging" / "runtime"
        try:
            manifest = self.runtime.stage(dest, new_app)
        except (OSError, grt.RuntimeProblem) as exc:
            if cur_team:
                raise UpdateError("PAX-UPDATE-006", "the update's runtime didn't verify: "
                                  f"{getattr(exc, 'message', exc)}"[:200]) from None
            self.log(f"update has no Developer ID runtime ({getattr(exc, 'message', exc)}); "
                     "pax-guard keeps its current Python")
            return Path(sys.executable)
        self._staged_runtime = dest
        return self.runtime.python(dest, manifest)

    def install(self, m: dict, forced: bool = False) -> None:
        version = m["version"]
        staging = self.updates / "staging"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)
        os.chmod(self.updates, 0o700)
        zip_path = staging / "Pax.zip"
        self._download(m, zip_path)
        code, out = self._run(["/usr/bin/ditto", "-x", "-k", str(zip_path), str(staging / "x")], timeout=300)
        new_app = staging / "x" / "Pax.app"
        if code != 0 or not new_app.is_dir():
            raise UpdateError("PAX-UPDATE-005", f"couldn't unpack the update: {out.strip()[-160:]}")
        self.sys.run(["/usr/bin/xattr", "-dr", "com.apple.quarantine", str(new_app)])
        self.verify_bundle(new_app, version)
        self.swap(new_app, version, forced)

    def swap(self, new_app: Path, version: str, forced: bool) -> None:
        rollback = self.updates / "rollback"
        shutil.rmtree(rollback, ignore_errors=True)
        rollback.mkdir(parents=True)
        new_guard_src = new_app / "Contents" / "Resources" / "guard"
        staged_bin = self.guard_bin.with_name("bin.new")
        shutil.rmtree(staged_bin, ignore_errors=True)
        moved_app = moved_bin = moved_rt = rt_in = False
        staged_rt = self._staged_runtime
        try:
            stage_guard_bin(new_guard_src, staged_bin)
            if self.app_path.exists():
                os.replace(self.app_path, rollback / "Pax.app")
                moved_app = True
            shutil.move(str(new_app), str(self.app_path))
            os.replace(self.guard_bin, rollback / "bin")
            moved_bin = True
            os.replace(staged_bin, self.guard_bin)
            if staged_rt is not None and staged_rt.is_dir():
                if self.runtime_dir.exists():
                    os.replace(self.runtime_dir, rollback / "runtime")
                    moved_rt = True
                os.replace(staged_rt, self.runtime_dir)
                rt_in = True
        except OSError as exc:
            # Put back whatever moved, newest first.
            if rt_in:
                shutil.rmtree(self.runtime_dir, ignore_errors=True)
            if moved_rt:
                os.replace(rollback / "runtime", self.runtime_dir)
            if moved_bin:
                shutil.rmtree(self.guard_bin, ignore_errors=True)
                os.replace(rollback / "bin", self.guard_bin)
            if moved_app:
                shutil.rmtree(self.app_path, ignore_errors=True)
                os.replace(rollback / "Pax.app", self.app_path)
            raise UpdateError("PAX-UPDATE-007", f"couldn't swap in the update ({exc}); nothing changed") from exc
        st = self.state()
        st.update({"state": "trial", "trial_version": version, "previous": self.installed,
                   "trial_deadline": int(self.clock()) + TRIAL_SECONDS, "forced": forced,
                   "runtime_swapped": rt_in, "runtime_had_previous": moved_rt,
                   "paths": {"app": str(self.app_path), "guard_bin": str(self.guard_bin),
                             "updates": str(self.updates), "runtime": str(self.runtime_dir)}})
        if rt_in and self.runtime is not None:
            self.runtime.set_starts(0)
        if forced:
            st["notice"] = (f"Pax updated itself to {version} to fix an important problem. "
                            "Nothing else changed.")
        self._save(st)
        self.log(f"update to {version} swapped in; restarting pax-guard (watchdog ready to roll back)")
        self.start_watchdog(version)

    def start_watchdog(self, version: str) -> None:
        """The old updater (now in updates/rollback/bin) supervises the restart."""
        old = self.updates / "rollback" / "bin" / "pax_update.py"
        script = old if old.exists() else Path(__file__).resolve()
        python = self.watchdog_python()
        try:
            subprocess.Popen([str(python), "-I", "-B", str(script), "watchdog", "--version", version,
                              "--state", str(self.state_path)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, close_fds=True)
        except OSError as exc:
            self.log(f"PAX-UPDATE-007 couldn't start the update watchdog ({exc}); rolling back now")
            self.rollback(version)

    def watchdog_python(self) -> Path:
        """The Python that was running before the swap: the old runtime (now in
        updates/rollback/runtime) when pax-guard ran on its runtime, else this one.
        Never the new one, which is what the watchdog is checking."""
        exe = Path(sys.executable)
        try:
            on_rt = exe.resolve().is_relative_to(self.runtime_dir.resolve())
        except (OSError, ValueError):
            on_rt = False
        if on_rt:
            old = self.updates / "rollback" / "runtime" / exe.resolve().relative_to(self.runtime_dir.resolve())
            if old.exists():
                return old
        return exe

    # ----------------------------------------------------- trial / rollback
    def confirm_trial(self) -> bool:
        """Called by a freshly started pax-guard after a healthy first cycle."""
        st = self.state()
        if st.get("state") == "trial" and st.get("trial_version") == self.installed:
            st["state"] = "committed"
            st["last_installed"] = {"version": self.installed, "at": int(self.clock()), "from": st.get("previous")}
            self._save(st)
            self.log(f"update to {self.installed} confirmed healthy")
            if st.get("forced") and st.get("notice"):
                self.notify(st["notice"])
            return True
        return False

    def rollback(self, version: str) -> bool:
        rollback = self.updates / "rollback"
        ok = True
        if (rollback / "bin").is_dir():
            bad = self.guard_bin.with_name("bin.bad")
            shutil.rmtree(bad, ignore_errors=True)
            if self.guard_bin.exists():
                os.replace(self.guard_bin, bad)
            os.replace(rollback / "bin", self.guard_bin)
            shutil.rmtree(bad, ignore_errors=True)
        else:
            ok = False
        if (rollback / "Pax.app").is_dir():
            shutil.rmtree(self.app_path, ignore_errors=True)
            os.replace(rollback / "Pax.app", self.app_path)
        st = self.state()
        # v0.8.6: the runtime goes back with the rest (or, if there was none
        # before, the new one is removed so the launcher falls back).
        if (rollback / "runtime").is_dir():
            bad = self.runtime_dir.with_name("runtime.bad")
            shutil.rmtree(bad, ignore_errors=True)
            if self.runtime_dir.exists():
                os.replace(self.runtime_dir, bad)
            os.replace(rollback / "runtime", self.runtime_dir)
            shutil.rmtree(bad, ignore_errors=True)
        elif st.get("runtime_swapped") and not st.get("runtime_had_previous"):
            shutil.rmtree(self.runtime_dir, ignore_errors=True)
        st["state"] = "rolled_back"
        st.setdefault("bad_versions", [])
        if version not in st["bad_versions"]:
            st["bad_versions"].append(version)
        st["last_error"] = f"PAX-UPDATE-007 {version} didn't start cleanly; the previous version is back"
        self._save(st)
        self.log(st["last_error"])
        return ok


def stage_guard_bin(src: Path, dst: Path) -> None:
    """A complete /Library/PaxGuard/bin from the app's Resources/guard (and lists)."""
    dst.mkdir(parents=True)
    os.chmod(dst, 0o755)
    for p in src.iterdir():
        if p.name.startswith("."):
            continue
        target = dst / p.name
        if p.is_dir():
            shutil.copytree(p, target)
        else:
            shutil.copy2(p, target)
            os.chmod(target, 0o755 if p.suffix == ".sh" else 0o644)
    lists = src.parent / "lists"
    if lists.is_dir() and not (dst / "lists").exists():
        shutil.copytree(lists, dst / "lists")
    if not (dst / "pax_guard.py").is_file():
        raise OSError("the update has no pax_guard.py")


def watchdog(version: str, state_path: Path, system=None, sleep=time.sleep, restart=None,
             deadline_s: int = TRIAL_SECONDS) -> str:
    """Restart pax-guard, wait for the new version to confirm, else roll back."""
    restart = restart or (lambda: subprocess.run(["/bin/launchctl", "kickstart", "-k", f"system/{LABEL}"],
                                                 capture_output=True, timeout=60))
    sleep(2)
    restart()
    waited = 0
    while waited < deadline_s:
        sleep(5)
        waited += 5
        try:
            st = json.loads(Path(state_path).read_text())
        except (OSError, ValueError):
            continue
        if st.get("state") == "committed" and st.get("last_installed", {}).get("version") == version:
            return "committed"
    try:
        paths = json.loads(Path(state_path).read_text()).get("paths", {})
    except (OSError, ValueError):
        paths = {}
    up = Updater(system, Path(state_path).parent, version,
                 app_path=Path(paths.get("app", APP_PATH)), guard_bin=Path(paths.get("guard_bin", GUARD_BIN)),
                 updates_dir=Path(paths.get("updates", UPDATES_DIR)),
                 runtime_dir=Path(paths.get("runtime", RUNTIME_DIR)))
    up.rollback(version)
    restart()
    return "rolled_back"


def main(argv: list[str]) -> int:
    if len(argv) >= 5 and argv[0] == "watchdog":
        version = argv[argv.index("--version") + 1]
        state = Path(argv[argv.index("--state") + 1])
        print(watchdog(version, state))
        return 0
    print("usage: pax_update.py watchdog --version V --state PATH", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
