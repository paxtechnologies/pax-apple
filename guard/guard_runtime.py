# SPDX-License-Identifier: GPL-3.0-only
"""pax-guard's own Python runtime (v0.8.6). Standard library only, Python 3.9+.

Before 0.8.6 pax-guard ran on /usr/bin/python3, which only works once Apple's
Command Line Tools are installed. Pax.app now carries a signed, universal
CPython (Contents/Resources/device/python, built for the iPhone helper). A root
LaunchDaemon must not execute anything from /Applications, which the user can
change or delete, so pax-guard runs on its own copy:

  /Library/PaxGuard/runtime/                    root:wheel, nothing group/other-writable
  /Library/PaxGuard/runtime/pax-runtime-manifest.json

The copy is the interpreter and the standard library only: site-packages (the
iPhone helper's pymobiledevice3 and its dependencies) is left out, because
pax-guard imports nothing outside the standard library (`pax_guard.py selftest`
proves it on the copy before it is used).

Trust comes from two places, both checked every time a copy is made:
  * Pax.app passes `codesign --verify --strict` against Pax's Developer ID
    requirement (Team ID Z94GSK7JA8). Its runtime-manifest.json (written by
    build-dmg.sh after every Mach-O is signed) is inside the app's sealed
    resources, so the app's signature covers it.
  * Every file copied matches the manifest's SHA-256 and size, and every Mach-O
    in the copy passes the same Developer ID requirement on its own.
Then the copy must run `pax_guard.py selftest` before anything uses it.

pax-guard re-hashes the installed copy every 10 minutes (with the tamper
checks): a changed, missing or extra file is logged to the tamper log and the
copy is rebuilt from /Applications/Pax.app if that still verifies. If it can't
be repaired, the copy is marked as failing so the launcher stops using it.

Which Python runs pax-guard is decided by the launcher
(bin/pax-guard-launch.sh, the LaunchDaemon's program): the copy, unless it has
failed to start MAX_STARTS times in a row (state/runtime-starts, cleared after a
healthy cycle), else /usr/bin/python3 if the Command Line Tools are there, else
the copy anyway. pax-guard never stops because of this: a copy that won't start
leaves the previous interpreter running.

Installs from 0.8.4/0.8.5 were started on /usr/bin/python3 by a plist that
names it directly. The new pax-guard, started that way by the normal update,
builds the copy, checks it, writes the launcher plist (read by launchd at the
next boot) and replaces itself in place with os.execv: the same process, so
launchd sees no change. If the copy fails the health check, it keeps running on
/usr/bin/python3.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

TEAM_ID = "Z94GSK7JA8"
# Apple's Developer ID requirement, pinned to Pax's team (codesign -R).
REQUIREMENT = ('anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
               'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and '
               f'certificate leaf[subject.OU] = "{TEAM_ID}"')
SCHEMA = "pax.guard-runtime.v1"
MANIFEST_NAME = "pax-runtime-manifest.json"
BASE = Path("/Library/PaxGuard")
APP_PATH = Path("/Applications/Pax.app")
LABEL = "org.paxpeace.pax-guard"
PLIST_PATH = Path(f"/Library/LaunchDaemons/{LABEL}.plist")
LAUNCHER_NAME = "pax-guard-launch.sh"
MAX_STARTS = 3
CA_BUNDLE = "/etc/ssl/cert.pem"
CODESIGN = "/usr/bin/codesign"


class RuntimeProblem(Exception):
    def __init__(self, message: str, code: str = "PAX-GUARD-013"):
        super().__init__(message)
        self.code, self.message = code, message


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_rel(p: str) -> str:
    if not isinstance(p, str) or not p or p.startswith("/") or "\\" in p:
        raise RuntimeProblem(f"bad path in runtime manifest: {p!r}")
    parts = p.split("/")
    if any(x in ("", ".", "..") for x in parts):
        raise RuntimeProblem(f"bad path in runtime manifest: {p!r}")
    return p


def manifest_digest(m: dict) -> str:
    body = json.dumps({"files": m.get("files"), "symlinks": m.get("symlinks"),
                       "interpreter": m.get("interpreter")}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def validate_manifest(m) -> dict:
    if not isinstance(m, dict) or m.get("schema") != SCHEMA:
        raise RuntimeProblem("unknown runtime manifest")
    files = m.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeProblem("runtime manifest lists no files")
    seen = set()
    for f in files:
        if not isinstance(f, dict):
            raise RuntimeProblem("bad file entry in runtime manifest")
        rel = _safe_rel(f.get("path"))
        if rel in seen:
            raise RuntimeProblem(f"duplicate {rel} in runtime manifest")
        seen.add(rel)
        if not (isinstance(f.get("sha256"), str) and len(f["sha256"]) == 64
                and isinstance(f.get("size"), int) and f["size"] >= 0 and isinstance(f.get("mode"), int)):
            raise RuntimeProblem(f"bad entry for {rel} in runtime manifest")
    for s in m.get("symlinks") or []:
        rel = _safe_rel(s.get("path") if isinstance(s, dict) else None)
        target = s.get("target")
        if not isinstance(target, str) or not target or target.startswith("/") or rel in seen \
                or os.path.normpath(os.path.join(os.path.dirname(rel), target)).split("/")[0] == "..":
            raise RuntimeProblem(f"bad symlink {rel} in runtime manifest")
    interp = _safe_rel(m.get("interpreter"))
    if interp not in seen:
        raise RuntimeProblem("runtime manifest has no interpreter")
    if m.get("digest") not in (None, manifest_digest(m)):
        raise RuntimeProblem("runtime manifest digest doesn't match its contents")
    return m


def load_manifest(path: Path) -> dict:
    try:
        return validate_manifest(json.loads(Path(path).read_text()))
    except (OSError, ValueError) as exc:
        raise RuntimeProblem(f"can't read runtime manifest {path}: {type(exc).__name__}") from None


def app_manifest_path(app: Path) -> Path:
    return Path(app) / "Contents" / "Resources" / "guard" / "runtime-manifest.json"


def app_runtime_root(app: Path) -> Path:
    return Path(app) / "Contents" / "Resources" / "device" / "python"


def plist_dict(base: Path = BASE) -> dict:
    """The launchd job (v0.8.6): the launcher picks the interpreter."""
    return {
        "Label": LABEL,
        "ProgramArguments": ["/bin/sh", str(base / "bin" / LAUNCHER_NAME), "run"],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "StandardOutPath": "/var/log/pax-guard.log",
        "StandardErrorPath": "/var/log/pax-guard.log",
    }


def ssl_env() -> None:
    """The bundled CPython doesn't know where macOS keeps its CA bundle. OpenSSL
    reads SSL_CERT_FILE itself (python -I doesn't hide it), so every default TLS
    context in pax-guard (urllib, smtplib, the DoH client) trusts the system's
    /etc/ssl/cert.pem, as /usr/bin/python3 did."""
    if os.path.exists(CA_BUNDLE):
        os.environ.setdefault("SSL_CERT_FILE", CA_BUNDLE)


class Runtime:
    """Builds, checks and repairs /Library/PaxGuard/runtime. `system` is
    pax_guard.System (or a fake): run(args, timeout=) -> (code, output)."""

    def __init__(self, system, base: Path = BASE, state_dir: Path | None = None, app_path: Path = APP_PATH,
                 team_id: str = TEAM_ID, log=print, chown: bool = True):
        self.sys = system
        self.base = Path(base)
        self.dir = self.base / "runtime"
        self.state_dir = Path(state_dir) if state_dir else self.base / "state"
        self.app = Path(app_path)
        self.team_id = team_id
        self.log = log
        self.chown = chown

    # ------------------------------------------------------------ paths
    @property
    def manifest_path(self) -> Path:
        return self.dir / MANIFEST_NAME

    def installed_manifest(self) -> dict | None:
        try:
            return load_manifest(self.manifest_path)
        except RuntimeProblem:
            return None

    def python(self, root: Path | None = None, manifest: dict | None = None) -> Path:
        m = manifest or self.installed_manifest() or {"interpreter": "bin/python3.12"}
        return Path(root or self.dir) / m["interpreter"]

    def running_on_runtime(self, executable: str | None = None) -> bool:
        exe = executable if executable is not None else sys.executable
        try:
            return Path(exe).resolve().is_relative_to(self.dir.resolve()) if hasattr(Path, "is_relative_to") \
                else str(Path(exe).resolve()).startswith(str(self.dir.resolve()) + "/")
        except (OSError, ValueError):
            return False

    # ----------------------------------------------------- start counter
    @property
    def starts_path(self) -> Path:
        return self.state_dir / "runtime-starts"

    def starts(self) -> int:
        try:
            return int(self.starts_path.read_text().strip() or "0")
        except (OSError, ValueError):
            return 0

    def set_starts(self, n: int) -> None:
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.starts_path.with_name(".runtime-starts.tmp")
            tmp.write_text(f"{int(n)}\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.starts_path)
        except OSError as exc:
            self.log(f"PAX-GUARD-013 couldn't record runtime starts ({exc})")

    def failing(self) -> bool:
        return self.starts() >= MAX_STARTS

    def mark_failing(self) -> None:
        self.set_starts(MAX_STARTS)

    # ---------------------------------------------------- verification
    def check_signature(self, path: Path) -> str | None:
        """None when `path` passes Pax's Developer ID requirement, else why not."""
        code, out = self.sys.run([CODESIGN, "--verify", "--strict", "-R", "=" + REQUIREMENT, str(path)],
                                 timeout=120)
        return None if code == 0 else (out.strip()[-160:] or f"codesign exit {code}")

    def verify_tree(self, root: Path, manifest: dict, signatures: bool = True) -> list[str]:
        """Problems with `root` against `manifest` (empty list: identical)."""
        root = Path(root)
        problems: list[str] = []
        listed = {f["path"]: f for f in manifest["files"]}
        links = {s["path"]: s["target"] for s in manifest.get("symlinks") or []}
        for rel, f in listed.items():
            p = root / rel
            try:
                st = os.lstat(p)
            except OSError:
                problems.append(f"missing {rel}")
                continue
            if not os.path.isfile(p) or os.path.islink(p):
                problems.append(f"not a file: {rel}")
                continue
            if st.st_mode & 0o022:
                problems.append(f"writable by others: {rel}")
            if st.st_size != f["size"] or sha256_file(p) != f["sha256"]:
                problems.append(f"changed {rel}")
        for rel, target in links.items():
            p = root / rel
            if not os.path.islink(p) or os.readlink(p) != target:
                problems.append(f"changed link {rel}")
        for d, dirs, files in os.walk(root):
            for name in files + [x for x in dirs if os.path.islink(os.path.join(d, x))]:
                rel = os.path.relpath(os.path.join(d, name), root)
                if rel == MANIFEST_NAME:
                    continue
                if rel not in listed and rel not in links:
                    problems.append(f"unexpected {rel}")
            st = os.lstat(d)
            if st.st_mode & 0o022:
                problems.append(f"writable by others: {os.path.relpath(d, root)}/")
        if signatures and not problems:
            for f in manifest["files"]:
                if f.get("macho"):
                    why = self.check_signature(root / f["path"])
                    if why:
                        problems.append(f"signature {f['path']}: {why}")
        return problems

    def verify_installed(self, signatures: bool = False) -> list[str]:
        m = self.installed_manifest()
        if m is None:
            return ["no runtime installed" if not self.dir.exists() else "runtime manifest missing or damaged"]
        return self.verify_tree(self.dir, m, signatures=signatures)

    # ------------------------------------------------------------ build
    def app_manifest(self, app: Path | None = None) -> dict:
        app = Path(app or self.app)
        why = self.check_signature(app)
        if why:
            raise RuntimeProblem(f"{app} isn't signed by Pax ({self.team_id}): {why}")
        m = load_manifest(app_manifest_path(app))
        if m.get("team_id") != self.team_id:
            raise RuntimeProblem(f"{app}'s runtime isn't Developer ID signed by {self.team_id}")
        return m

    def stage(self, dest: Path, app: Path | None = None) -> dict:
        """Copy the app's runtime into `dest` (which must not exist), checking every
        byte against the app's manifest and every Mach-O's signature."""
        app = Path(app or self.app)
        m = self.app_manifest(app)
        src = app_runtime_root(app)
        dest = Path(dest)
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        os.chmod(dest, 0o755)
        try:
            for f in m["files"]:
                s, d = src / f["path"], dest / f["path"]
                d.parent.mkdir(parents=True, exist_ok=True)
                h = hashlib.sha256()
                n = 0
                with open(s, "rb") as fi, open(d, "wb") as fo:
                    for chunk in iter(lambda: fi.read(1 << 20), b""):
                        h.update(chunk)
                        n += len(chunk)
                        fo.write(chunk)
                if n != f["size"] or h.hexdigest() != f["sha256"]:
                    raise RuntimeProblem(f"{f['path']} in Pax.app doesn't match its manifest")
                os.chmod(d, 0o755 if f["mode"] & 0o111 else 0o644)
            for s in m.get("symlinks") or []:
                p = dest / s["path"]
                p.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(s["target"], p)
            for d, dirs, _files in os.walk(dest):
                for x in dirs:
                    if not os.path.islink(os.path.join(d, x)):
                        os.chmod(os.path.join(d, x), 0o755)
            (dest / MANIFEST_NAME).write_text(json.dumps(m, sort_keys=True))
            os.chmod(dest / MANIFEST_NAME, 0o644)
            if self.chown:
                self._chown_root(dest)
            self.sys.run(["/usr/bin/xattr", "-cr", str(dest)])
            problems = self.verify_tree(dest, m, signatures=True)
            if problems:
                raise RuntimeProblem("the runtime copy didn't verify: " + "; ".join(problems[:3]))
        except (OSError, RuntimeProblem):
            shutil.rmtree(dest, ignore_errors=True)
            raise
        return m

    @staticmethod
    def _chown_root(root: Path) -> None:
        for d, dirs, files in os.walk(root):
            for name in [d] + [os.path.join(d, x) for x in dirs + files]:
                try:
                    os.lchown(name, 0, 0)
                except PermissionError:
                    return          # tests (not root)

    def health(self, root: Path, guard_script: Path, manifest: dict | None = None) -> str | None:
        """None when the copy at `root` runs pax-guard's self-test, else why not."""
        py = self.python(root, manifest)
        code, out = self.sys.run([str(py), "-I", "-B", str(guard_script), "selftest"], timeout=120)
        if code == 0 and '"ok": true' in out:
            return None
        return out.strip()[-200:] or f"exit {code}"

    def install(self, guard_script: Path, app: Path | None = None) -> dict:
        """Build a checked copy beside the current one and swap it in."""
        staging = self.base / "runtime.new"
        m = self.stage(staging, app)
        why = self.health(staging, guard_script, m)
        if why:
            shutil.rmtree(staging, ignore_errors=True)
            raise RuntimeProblem(f"the runtime copy failed pax-guard's self-test: {why}")
        self.swap_in(staging)
        return m

    def swap_in(self, staging: Path) -> None:
        old = self.base / "runtime.old"
        shutil.rmtree(old, ignore_errors=True)
        if self.dir.exists():
            os.replace(self.dir, old)
        try:
            os.replace(staging, self.dir)
        except OSError:
            if old.exists():
                os.replace(old, self.dir)
            raise
        shutil.rmtree(old, ignore_errors=True)
        self.set_starts(0)

    # ---------------------------------------------------- self-healing
    def heal(self, guard_script: Path) -> dict:
        """Called every 10 minutes. {"ok": bool, "problems": [...], "repaired": bool}."""
        problems = self.verify_installed()
        if not problems:
            return {"ok": True, "problems": [], "repaired": False}
        if not self.dir.exists() and not app_manifest_path(self.app).exists():
            return {"ok": False, "problems": problems, "repaired": False, "absent": True}
        try:
            self.install(guard_script)
            self.log("PAX-GUARD-013 pax-guard's runtime was rebuilt from Pax.app")
            return {"ok": True, "problems": problems, "repaired": True}
        except (OSError, RuntimeProblem) as exc:
            if self.dir.exists():
                self.mark_failing()
            self.log(f"PAX-GUARD-013 pax-guard's runtime is damaged and couldn't be rebuilt "
                     f"({getattr(exc, 'message', exc)}); the launcher won't use it")
            return {"ok": False, "problems": problems, "repaired": False}

    # ------------------------------------------------------- migration
    def plist_is_current(self, plist_path: Path = PLIST_PATH) -> bool:
        import plistlib
        try:
            with open(plist_path, "rb") as fh:
                return plistlib.load(fh).get("ProgramArguments") == plist_dict(self.base)["ProgramArguments"]
        except (OSError, ValueError, plistlib.InvalidFileException):
            return False

    def write_plist(self, plist_path: Path = PLIST_PATH) -> None:
        """The launcher plist, atomically. launchd reads it at the next boot (or
        bootstrap); until then the job it loaded keeps its arguments."""
        import plistlib
        plist_path = Path(plist_path)
        tmp = plist_path.with_name(f".{plist_path.name}.pax-tmp")
        with open(tmp, "wb") as fh:
            plistlib.dump(plist_dict(self.base), fh)
        os.chmod(tmp, 0o644)
        try:
            os.chown(tmp, 0, 0)
        except PermissionError:
            pass
        os.replace(tmp, plist_path)

    def migrate(self, guard_script: Path, plist_path: Path = PLIST_PATH, executable: str | None = None) -> dict:
        """On a pax-guard not running on its runtime: make sure a checked copy is
        installed and healthy and the plist uses the launcher. Returns
        {"exec": [argv...]} when the caller should os.execv into the copy, or
        {"stay": reason} to keep running where it is."""
        if self.running_on_runtime(executable):
            return {"stay": "already on the runtime"}
        if self.failing():
            return {"stay": f"the runtime failed to start {MAX_STARTS} times"}
        try:
            m = self.installed_manifest()
            if m is None or self.verify_installed():
                m = self.install(guard_script)
            else:
                why = self.health(self.dir, guard_script, m)
                if why:
                    raise RuntimeProblem(f"health check failed: {why}")
        except (OSError, RuntimeProblem) as exc:
            return {"stay": f"runtime not usable: {getattr(exc, 'message', exc)}"}
        launcher = Path(guard_script).resolve().parent / LAUNCHER_NAME
        if launcher.is_file() and not self.plist_is_current(plist_path):
            try:
                self.write_plist(plist_path)
            except OSError as exc:
                self.log(f"PAX-GUARD-013 couldn't write the launcher plist ({exc}); next boot uses the old one")
        self.set_starts(self.starts() + 1)
        py = str(self.python(manifest=m))
        return {"exec": [py, "-I", "-B", str(guard_script), "run"]}


def main(argv: list[str]) -> int:
    """`guard_runtime.py install --app PATH [--base DIR]` (pax-guard-install.sh,
    as root): build and check /Library/PaxGuard/runtime. Prints one JSON line."""
    import subprocess

    class _Sys:
        def run(self, args, timeout=60, stdin=None):
            try:
                r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=stdin)
                return r.returncode, (r.stdout or "") + (r.stderr or "")
            except (OSError, subprocess.TimeoutExpired) as exc:
                return 127, str(exc)

    if not argv or argv[0] != "install" or "--app" not in argv:
        print("usage: guard_runtime.py install --app Pax.app [--base /Library/PaxGuard]", file=sys.stderr)
        return 2
    app = Path(argv[argv.index("--app") + 1])
    base = Path(argv[argv.index("--base") + 1]) if "--base" in argv else BASE
    rt = Runtime(_Sys(), base=base, app_path=app, log=lambda m: print(m, file=sys.stderr))
    try:
        m = rt.install(base / "bin" / "pax_guard.py", app)
    except (OSError, RuntimeProblem) as exc:
        print(json.dumps({"ok": False, "error": str(getattr(exc, "message", exc))}))
        return 1
    print(json.dumps({"ok": True, "python": str(rt.python(manifest=m)), "files": len(m["files"]),
                      "python_version": m.get("python_version")}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
