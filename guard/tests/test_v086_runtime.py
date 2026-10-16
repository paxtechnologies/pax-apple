# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.6: pax-guard runs on its own checked copy of Pax.app's signed Python
(/Library/PaxGuard/runtime), not /usr/bin/python3 (Command Line Tools).

Covers: the manifest rules, copying with hash checks, the Developer ID check on
the app and on every Mach-O, tamper detection (changed, missing, extra, writable
files), self-healing from the app, the start counter and launcher plist, the
in-place switch from /usr/bin/python3 (0.8.4/0.8.5 installs) with its fallback,
and the launcher script's choice of Python."""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import stat
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "mac-app" / "scripts"))
import guard_runtime as grt  # noqa: E402
import helper_runtime as hr  # noqa: E402

MACHO = b"\xcf\xfa\xed\xfe" + b"\x07\x00\x00\x01" + b"\x03\x00\x00\x00" + b"\x02\x00\x00\x00" + b"\0" * 16


def make_app(tmp: Path, team="Z94GSK7JA8") -> Path:
    """A Pax.app with a tiny 'runtime' (fake Mach-Os + stdlib + site-packages)."""
    app = tmp / "Applications" / "Pax.app"
    root = grt.app_runtime_root(app)
    files = {
        "bin/python3.12": MACHO + b"interp",
        "lib/libpython3.12.dylib": MACHO + b"lib",
        "lib/python3.12/os.py": b"# os\n",
        "lib/python3.12/json/__init__.py": b"# json\n",
        "lib/python3.12/lib-dynload/_ssl.cpython-312-darwin.so": MACHO + b"ssl",
        "lib/python3.12/site-packages/pymobiledevice3/__init__.py": b"# helper only\n",
        "LICENSES/LICENSE.python.txt": b"PSF\n",
    }
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    os.chmod(root / "bin/python3.12", 0o755)
    os.symlink("python3.12", root / "bin" / "python3")
    m = hr.guard_manifest(root, team)
    (app / "Contents" / "Resources" / "guard").mkdir(parents=True)
    grt.app_manifest_path(app).write_text(json.dumps(m))
    return app


class FakeSys:
    """codesign answers from `bad_sig` (paths that fail); selftest from `selftest_ok`."""

    def __init__(self):
        self.calls = []
        self.bad_sig = set()
        self.selftest_ok = True

    def run(self, args, timeout=30, stdin=None):
        self.calls.append(args)
        if args[0] == grt.CODESIGN:
            assert args[1:4] == ["--verify", "--strict", "-R"] and args[4] == "=" + grt.REQUIREMENT
            return (1, "code object is not signed at all") if any(b in args[-1] for b in self.bad_sig) else (0, "")
        if args[-1] == "selftest":
            return (0, '{"version": "0.8.6", "ok": true}') if self.selftest_ok else (1, "import failed")
        return 0, ""


def setup(tmp_path, team="Z94GSK7JA8"):
    app = make_app(tmp_path, team)
    base = tmp_path / "PaxGuard"
    (base / "bin").mkdir(parents=True)
    (base / "bin" / "pax_guard.py").write_text('VERSION = "0.8.6"\n')
    (base / "bin" / grt.LAUNCHER_NAME).write_text("#!/bin/sh\n")
    s = FakeSys()
    logs = []
    rt = grt.Runtime(s, base=base, app_path=app, log=logs.append, chown=False)
    return rt, s, app, base, logs


def test_manifest_lists_stdlib_not_site_packages(tmp_path):
    app = make_app(tmp_path)
    m = grt.load_manifest(grt.app_manifest_path(app))
    paths = {f["path"] for f in m["files"]}
    assert "bin/python3.12" in paths and "lib/python3.12/os.py" in paths
    assert not any("site-packages" in p for p in paths)
    assert {f["path"] for f in m["files"] if f["macho"]} == {
        "bin/python3.12", "lib/libpython3.12.dylib", "lib/python3.12/lib-dynload/_ssl.cpython-312-darwin.so"}
    assert m["symlinks"] == [{"path": "bin/python3", "target": "python3.12"}]
    assert m["team_id"] == "Z94GSK7JA8" and m["digest"] == grt.manifest_digest(m)


@pytest.mark.parametrize("bad", [
    {"files": [{"path": "../evil", "sha256": "0" * 64, "size": 1, "mode": 420}]},
    {"files": [{"path": "/etc/x", "sha256": "0" * 64, "size": 1, "mode": 420}]},
    {"symlinks": [{"path": "bin/x", "target": "/usr/bin/python3"}]},
    {"symlinks": [{"path": "bin/x", "target": "../../outside"}]},
    {"interpreter": "bin/nope"},
    {"digest": "f" * 64},
    {"schema": "other"},
])
def test_manifest_rules_refuse_unsafe_entries(tmp_path, bad):
    m = grt.load_manifest(grt.app_manifest_path(make_app(tmp_path)))
    m.update(bad)
    if "digest" not in bad:
        m["digest"] = grt.manifest_digest(m)
    with pytest.raises(grt.RuntimeProblem):
        grt.validate_manifest(m)


def test_install_copies_checks_and_swaps(tmp_path):
    rt, s, app, base, _ = setup(tmp_path)
    m = rt.install(base / "bin" / "pax_guard.py")
    assert (base / "runtime" / "bin" / "python3.12").read_bytes().endswith(b"interp")
    assert not (base / "runtime" / "lib" / "python3.12" / "site-packages").exists()
    assert os.readlink(base / "runtime" / "bin" / "python3") == "python3.12"
    assert rt.verify_installed() == [] and rt.installed_manifest()["digest"] == m["digest"]
    signed = [c[-1] for c in s.calls if c[0] == grt.CODESIGN]
    assert str(app) in signed                                   # the app, against Pax's Team ID
    assert sum("/runtime.new/" in p for p in signed) == 3       # every Mach-O in the copy
    selftests = [c for c in s.calls if c[-1] == "selftest"]
    assert selftests and selftests[0][0].endswith("runtime.new/bin/python3.12") and selftests[0][1:3] == ["-I", "-B"]
    assert not (base / "runtime.new").exists() and rt.starts() == 0


def test_app_not_signed_by_pax_is_refused(tmp_path):
    rt, s, app, base, _ = setup(tmp_path)
    s.bad_sig.add(str(app))
    with pytest.raises(grt.RuntimeProblem, match="isn't signed by Pax"):
        rt.install(base / "bin" / "pax_guard.py")
    assert not (base / "runtime").exists()


def test_adhoc_build_manifest_is_refused(tmp_path):
    rt, s, app, base, _ = setup(tmp_path, team=None)
    with pytest.raises(grt.RuntimeProblem, match="Developer ID"):
        rt.install(base / "bin" / "pax_guard.py")


def test_unsigned_macho_in_copy_is_refused(tmp_path):
    rt, s, app, base, _ = setup(tmp_path)
    s.bad_sig.add("runtime.new/lib/libpython3.12.dylib")
    with pytest.raises(grt.RuntimeProblem, match="signature lib/libpython3.12.dylib"):
        rt.install(base / "bin" / "pax_guard.py")
    assert not (base / "runtime.new").exists() and not (base / "runtime").exists()


def test_changed_app_file_is_refused(tmp_path):
    rt, s, app, base, _ = setup(tmp_path)
    (grt.app_runtime_root(app) / "lib/python3.12/os.py").write_bytes(b"# changed\n")
    with pytest.raises(grt.RuntimeProblem, match="doesn't match its manifest"):
        rt.install(base / "bin" / "pax_guard.py")


def test_failed_selftest_leaves_the_old_copy(tmp_path):
    rt, s, app, base, _ = setup(tmp_path)
    rt.install(base / "bin" / "pax_guard.py")
    before = rt.installed_manifest()["digest"]
    s.selftest_ok = False
    with pytest.raises(grt.RuntimeProblem, match="self-test"):
        rt.install(base / "bin" / "pax_guard.py")
    assert rt.installed_manifest()["digest"] == before and rt.verify_installed() == []


def test_tamper_is_found_and_healed(tmp_path):
    rt, s, app, base, logs = setup(tmp_path)
    rt.install(base / "bin" / "pax_guard.py")
    rtdir = base / "runtime"
    (rtdir / "lib/python3.12/os.py").write_bytes(b"import evil\n")
    (rtdir / "lib/python3.12/sitecustomize.py").write_text("print('x')\n")      # would run as root
    (rtdir / "LICENSES/LICENSE.python.txt").unlink()
    os.chmod(rtdir / "lib/python3.12/json/__init__.py", 0o666)
    probs = rt.verify_installed()
    assert "changed lib/python3.12/os.py" in probs
    assert "unexpected lib/python3.12/sitecustomize.py" in probs
    assert "missing LICENSES/LICENSE.python.txt" in probs
    assert "writable by others: lib/python3.12/json/__init__.py" in probs
    r = rt.heal(base / "bin" / "pax_guard.py")
    assert r["repaired"] and r["ok"] and rt.verify_installed() == []
    assert not (rtdir / "lib/python3.12/sitecustomize.py").exists()


def test_heal_without_a_good_app_marks_the_copy_failing(tmp_path):
    rt, s, app, base, logs = setup(tmp_path)
    rt.install(base / "bin" / "pax_guard.py")
    (base / "runtime/lib/python3.12/os.py").write_bytes(b"import evil\n")
    s.bad_sig.add(str(app))                                  # app replaced by something else
    r = rt.heal(base / "bin" / "pax_guard.py")
    assert not r["ok"] and not r["repaired"]
    assert rt.failing() and rt.starts() == grt.MAX_STARTS    # the launcher stops using it
    assert any("PAX-GUARD-013" in line for line in logs)


def test_migrate_from_clt_python_builds_writes_plist_and_execs(tmp_path):
    rt, s, app, base, _ = setup(tmp_path)
    plist = tmp_path / "org.paxpeace.pax-guard.plist"
    plist.write_bytes(plistlib.dumps({"Label": grt.LABEL, "ProgramArguments":
                                      ["/usr/bin/python3", "-I", "/Library/PaxGuard/bin/pax_guard.py", "run"]}))
    plan = rt.migrate(base / "bin" / "pax_guard.py", plist, executable="/usr/bin/python3")
    assert plan["exec"] == [str(base / "runtime/bin/python3.12"), "-I", "-B", str(base / "bin/pax_guard.py"), "run"]
    assert plistlib.loads(plist.read_bytes())["ProgramArguments"] == [
        "/bin/sh", str(base / "bin" / grt.LAUNCHER_NAME), "run"]
    assert rt.starts() == 1                                  # counted before the exec
    # Running on the copy: nothing more to do.
    assert "stay" in rt.migrate(base / "bin" / "pax_guard.py", plist, executable=plan["exec"][0])


def test_migrate_keeps_the_old_python_when_the_copy_is_unhealthy(tmp_path):
    rt, s, app, base, _ = setup(tmp_path)
    plist = tmp_path / "p.plist"
    old = plistlib.dumps({"ProgramArguments": ["/usr/bin/python3", "-I", "x", "run"]})
    plist.write_bytes(old)
    s.selftest_ok = False
    plan = rt.migrate(base / "bin" / "pax_guard.py", plist, executable="/usr/bin/python3")
    assert "stay" in plan and "self-test" in plan["stay"]
    assert plist.read_bytes() == old                         # the old job is left exactly as it was
    assert rt.starts() == 0


def test_migrate_stops_trying_after_repeated_failed_starts(tmp_path):
    rt, s, app, base, _ = setup(tmp_path)
    rt.set_starts(grt.MAX_STARTS)
    plan = rt.migrate(base / "bin" / "pax_guard.py", tmp_path / "p.plist", executable="/usr/bin/python3")
    assert "failed to start" in plan["stay"]
    assert not any(c[-1] == "selftest" for c in s.calls)


def test_launcher_plist_in_repo_matches(tmp_path):
    d = plistlib.loads((HERE.parent / "org.paxpeace.pax-guard.plist").read_bytes())
    assert d == grt.plist_dict()


def _launcher(tmp_path, rt_exists: bool, starts: int | None, clt: bool):
    """Run pax-guard-launch.sh with its paths moved under tmp_path; fake programs
    print what they were asked to run."""
    base = tmp_path / "PaxGuard"
    (base / "state").mkdir(parents=True)
    (base / "bin").mkdir()
    fake = tmp_path / "fake"
    fake.mkdir()
    for name, ok in (("xcode-select", clt), ("python3", clt)):
        (fake / name).write_text(f"#!/bin/sh\nif [ \"$1\" = '-I' ] && [ \"$2\" != '-c' ]; then echo CLT \"$@\"; fi\n"
                                 f"exit {0 if ok else 1}\n")
        os.chmod(fake / name, 0o755)
    if rt_exists:
        py = base / "runtime" / "bin" / "python3.12"
        py.parent.mkdir(parents=True)
        py.write_text('#!/bin/sh\necho RUNTIME "$@" "SSL=$SSL_CERT_FILE"\n')
        os.chmod(py, 0o755)
    if starts is not None:
        (base / "state" / "runtime-starts").write_text(f"{starts}\n")
    src = (HERE.parent / "scripts" / grt.LAUNCHER_NAME).read_text()
    src = (src.replace("BASE=/Library/PaxGuard", f"BASE={base}")
              .replace("/usr/bin/xcode-select", str(fake / "xcode-select"))
              .replace("/usr/bin/python3", str(fake / "python3")))
    script = tmp_path / "launch.sh"
    script.write_text(src)
    r = subprocess.run(["/bin/sh", str(script), "run"], capture_output=True, text=True)
    count = (base / "state" / "runtime-starts").read_text().strip() if (base / "state" / "runtime-starts").exists() else None
    return r, count


def test_launcher_prefers_the_runtime_and_counts_starts(tmp_path):
    r, count = _launcher(tmp_path, rt_exists=True, starts=None, clt=True)
    assert r.stdout.startswith("RUNTIME -I -B ") and "pax_guard.py run" in r.stdout and count == "1"


def test_launcher_falls_back_to_clt_after_three_failed_starts(tmp_path):
    r, count = _launcher(tmp_path, rt_exists=True, starts=3, clt=True)
    assert r.stdout.startswith("CLT -I -B ") and count == "3"


def test_launcher_without_clt_still_runs_the_runtime(tmp_path):
    r, _ = _launcher(tmp_path, rt_exists=True, starts=3, clt=False)
    assert r.stdout.startswith("RUNTIME ")


def test_launcher_with_nothing_exits_with_a_code(tmp_path):
    r, _ = _launcher(tmp_path, rt_exists=False, starts=None, clt=False)
    assert r.returncode == 78 and "PAX-GUARD-002" in r.stderr


def test_ssl_env_points_at_the_system_bundle(monkeypatch, tmp_path):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    bundle = tmp_path / "cert.pem"
    bundle.write_text("x")
    monkeypatch.setattr(grt, "CA_BUNDLE", str(bundle))
    grt.ssl_env()
    assert os.environ["SSL_CERT_FILE"] == str(bundle)


def test_guard_runtime_main_installs(tmp_path, monkeypatch):
    rt, s, app, base, _ = setup(tmp_path)
    monkeypatch.setattr(grt.Runtime, "__init__", lambda self, system, **kw: grt.Runtime.__dict__  # noqa: E731
                        and _init(self, s, kw))
    assert grt.main(["install", "--app", str(app), "--base", str(base)]) == 0
    assert (base / "runtime" / grt.MANIFEST_NAME).exists()


def _init(self, s, kw):
    self.sys = s
    self.base = Path(kw["base"])
    self.dir = self.base / "runtime"
    self.state_dir = self.base / "state"
    self.app = Path(kw["app_path"])
    self.team_id = grt.TEAM_ID
    self.log = kw.get("log", print)
    self.chown = False


def test_guard_logs_runtime_tamper_and_repairs(tmp_path):
    from test_v08_guard import local_guard
    g, _ = local_guard(tmp_path / "g")
    app = make_app(tmp_path / "a")
    s = FakeSys()
    (g.base_dir / "bin").mkdir(parents=True, exist_ok=True)
    rt = grt.Runtime(s, base=g.base_dir, state_dir=g.state_dir, app_path=app, chown=False)
    rt.install(g.base_dir / "bin" / "pax_guard.py")
    g.runtime_manager = lambda: rt
    assert g.check_runtime()["ok"] and not [e for e in g.tamper_log.entries() if e["kind"] == "changed:runtime"]
    (g.base_dir / "runtime/lib/python3.12/os.py").write_bytes(b"import evil\n")
    r = g.check_runtime()
    assert r["repaired"]
    ev = [e for e in g.tamper_log.entries() if e["kind"] == "changed:runtime"]
    assert ev and ev[-1]["detail"]["problems"] == ["changed lib/python3.12/os.py"] and ev[-1]["detail"]["repaired"]
    assert g.status_summary()["runtime"]["installed"] is True
    assert str(g.base_dir / "runtime" / grt.MANIFEST_NAME) in g.guard_files()


def test_guard_outside_paxguard_never_switches(tmp_path):
    from test_v08_guard import local_guard
    g, _ = local_guard(tmp_path)
    assert g.maybe_switch_runtime() is None          # tests and the repo copy stay put
