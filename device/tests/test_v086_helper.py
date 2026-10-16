# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.6: the iPhone helper needs no Terminal step.

* backup and the seed restore use pymobiledevice3's own Mobilebackup2 (no
  idevicebackup2, no Homebrew), with EXACTLY the Restore options idevicebackup2 sent;
* PAX_IDEVICEBACKUP2 stays as an optional developer override and is the only way
  idevicebackup2 is ever used;
* `selftest` checks the bundled runtime without an iPhone.
No iPhone needed: pymobiledevice3's services are replaced by fakes.
"""
import asyncio
import json
import plistlib
import sys
import types
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import seed  # noqa: E402
import pax_device  # noqa: E402
from test_seed import install_fake_phone, run_cmd  # noqa: E402

# ---------------- the restore-flag mapping ----------------

# What libimobiledevice's idevicebackup2 (tools/idevicebackup2.c, CMD_RESTORE) puts in the
# MobileBackup2 "Restore" request for the flags Pax passed up to v0.8.5. Typed out here
# on purpose, independently of seed.idevicebackup2_options.
IOS_17_26 = {  # --system --skip-apps --no-reboot
    "RestoreSystemFiles": True,
    "RestoreShouldReboot": False,
    "RestoreDontCopyBackup": True,
    "RestorePreserveSettings": True,
    "RemoveItemsNotRestored": False,
}
IOS_27 = {  # --skip-apps --remove --reboot   (no RestoreShouldReboot key at all)
    "RestoreSystemFiles": False,
    "RestoreDontCopyBackup": True,
    "RestorePreserveSettings": True,
    "RemoveItemsNotRestored": True,
}


def test_restore_options_ios_17_to_26_match_idevicebackup2():
    assert seed.restore_options(seed.MODE_RESTORED) == IOS_17_26


def test_restore_options_ios_27_match_idevicebackup2():
    opts = seed.restore_options(seed.MODE_LIVE)
    assert opts == IOS_27
    assert "RestoreShouldReboot" not in opts      # the phone's default (reboot), as tested
    assert opts["RestoreSystemFiles"] is False    # never system files on iOS 27
    assert opts["RemoveItemsNotRestored"] is True


def test_both_methods_skip_apps():
    for mode in (seed.MODE_RESTORED, seed.MODE_LIVE):
        assert "--skip-apps" in seed.RESTORE_FLAGS[mode]
        assert seed.restore_writes_app_list(mode) is False


def test_flags_and_override_arguments_agree():
    for mode in (seed.MODE_RESTORED, seed.MODE_LIVE):
        assert seed.restore_arguments("U", Path("/s"), mode)[3:-1] == list(seed.RESTORE_FLAGS[mode])


@pytest.mark.parametrize("flags, expected", [
    ([], {"RestoreSystemFiles": False, "RestoreDontCopyBackup": True, "RestorePreserveSettings": True,
          "RemoveItemsNotRestored": False}),
    (["--no-reboot", "--reboot"], {"RestoreSystemFiles": False, "RestoreDontCopyBackup": True,
                                   "RestorePreserveSettings": True, "RemoveItemsNotRestored": False}),
    (["--reboot", "--no-reboot"], {"RestoreSystemFiles": False, "RestoreShouldReboot": False,
                                   "RestoreDontCopyBackup": True, "RestorePreserveSettings": True,
                                   "RemoveItemsNotRestored": False}),
    (["--copy", "--settings"], {"RestoreSystemFiles": False, "RestorePreserveSettings": False,
                                "RemoveItemsNotRestored": False}),
])
def test_idevicebackup2_option_model(flags, expected):
    assert seed.idevicebackup2_options(flags) == expected


def test_idevicebackup2_option_model_rejects_unknown_flags():
    with pytest.raises(ValueError):
        seed.idevicebackup2_options(["--password"])
    with pytest.raises(ValueError):
        seed.restore_options("full")


def test_restore_request_shape():
    req = seed.restore_request("UDID-1", seed.MODE_LIVE)
    assert req == {"MessageName": "Restore", "TargetIdentifier": "UDID-1",
                   "SourceIdentifier": "UDID-1", "Options": IOS_27}
    assert "Password" not in req["Options"]


def test_mapping_is_documented_in_code_and_readme():
    src = (HERE.parent / "seed.py").read_text()
    for key in IOS_17_26:
        assert key in src
    readme = (HERE.parent.parent / "README.md").read_text()
    for key in ("RestoreSystemFiles", "RestoreShouldReboot", "RemoveItemsNotRestored",
                "RestoreDontCopyBackup", "RestorePreserveSettings", "RestoreApplications.plist"):
        assert key in readme, key


# ---------------- Mobilebackup2 restore through fake pymobiledevice3 services ----------------

class FakeDL:
    def __init__(self, log, fail_loop=None):
        self.log, self.fail_loop = log, fail_loop

    async def send_process_message(self, msg):
        self.log.append(("send", msg))

    async def dl_loop(self, progress=None):
        self.log.append(("dl_loop",))
        if progress:
            for pct in (0, 1, 7, 50, 100):
                progress(pct)
        if self.fail_loop:
            raise self.fail_loop


def install_fake_pmd(monkeypatch, *, fail_loop=None, fail_unlock=None):
    log = []

    class Ctx:
        def __init__(self, name, value=None, fail=None):
            self.name, self.value, self.fail = name, value, fail

        async def __aenter__(self):
            log.append(("enter", self.name))
            return self.value

        async def __aexit__(self, *exc):
            log.append(("exit", self.name))
            if self.fail:
                raise self.fail
            return False

    class Mobilebackup2Service:
        def __init__(self, ld):
            log.append(("mb2", ld))

        def device_link(self, root):
            log.append(("device_link", Path(root)))
            return Ctx("device_link", FakeDL(log, fail_loop))

        def _backup_lock(self, afc, notifications):
            return Ctx("lock", fail=fail_unlock)

        async def backup(self, **kw):
            log.append(("backup", kw["full"], Path(kw["backup_directory"])))
            udid_dir = Path(kw["backup_directory"]) / "U"
            udid_dir.mkdir(parents=True, exist_ok=True)
            (udid_dir / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))
            (udid_dir / "Manifest.db").write_bytes(b"db")
            (udid_dir / "Manifest.plist").write_bytes(plistlib.dumps({"Version": "10.0"}))
            kw["progress_callback"](100)

        async def close(self):
            log.append(("close",))

    def service(name):
        class S:
            def __init__(self, ld):
                pass

            async def __aenter__(self):
                log.append(("enter", name))
                return self

            async def __aexit__(self, *exc):
                log.append(("exit", name))
                return False
        return S

    mods = {
        "pymobiledevice3": types.ModuleType("pymobiledevice3"),
        "pymobiledevice3.services": types.ModuleType("pymobiledevice3.services"),
        "pymobiledevice3.services.mobilebackup2": types.ModuleType("m"),
        "pymobiledevice3.services.afc": types.ModuleType("a"),
        "pymobiledevice3.services.notification_proxy": types.ModuleType("n"),
    }
    mods["pymobiledevice3.services.mobilebackup2"].Mobilebackup2Service = Mobilebackup2Service
    mods["pymobiledevice3.services.afc"].AfcService = service("afc")
    mods["pymobiledevice3.services.notification_proxy"].NotificationProxyService = service("np")
    for name, mod in mods.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return log


def make_seed(tmp_path, mode):
    cfg = seed.plan_cloud_configuration({}, organization_magic="T")
    seed.write_seed(tmp_path, "U", cfg, mode)
    return tmp_path


@pytest.mark.parametrize("mode, expected", [(seed.MODE_RESTORED, IOS_17_26), (seed.MODE_LIVE, IOS_27)])
def test_mobilebackup2_restore_sends_exact_request(monkeypatch, tmp_path, capsys, mode, expected):
    log = install_fake_pmd(monkeypatch)
    root = make_seed(tmp_path, mode)
    sent = asyncio.run(pax_device.mobilebackup2_restore("LD", root, "U", mode))
    sends = [e[1] for e in log if e[0] == "send"]
    assert sends == [{"MessageName": "Restore", "TargetIdentifier": "U", "SourceIdentifier": "U",
                      "Options": expected}] == [sent]
    assert ("device_link", root) in log and ("dl_loop",) in log
    # the sync lock is taken before the request and released after the loop
    names = [e for e in log if e[0] in ("enter", "exit", "send", "dl_loop")]
    assert names.index(("enter", "lock")) < names.index(("send", sent)) < names.index(("exit", "lock"))
    assert ("close",) in log
    events = [json.loads(line)["event"] for line in capsys.readouterr().out.splitlines()]
    assert [e["percent"] for e in events if e.get("phase") == "restore_progress"] == [0, 7, 50, 100]


def test_mobilebackup2_restore_refuses_unfinished_seed(monkeypatch, tmp_path):
    log = install_fake_pmd(monkeypatch)
    root = make_seed(tmp_path, seed.MODE_LIVE)
    (root / "U" / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "uploading"}))
    with pytest.raises(pax_device.HelperError) as e:
        asyncio.run(pax_device.mobilebackup2_restore("LD", root, "U", seed.MODE_LIVE))
    assert e.value.code == "seed_invalid"
    assert not [x for x in log if x[0] == "send"]


def test_mobilebackup2_restore_error_before_answer_propagates(monkeypatch, tmp_path):
    install_fake_pmd(monkeypatch, fail_loop=RuntimeError("Device link error: {'ErrorCode': 211}"))
    root = make_seed(tmp_path, seed.MODE_LIVE)
    with pytest.raises(RuntimeError):
        asyncio.run(pax_device.mobilebackup2_restore("LD", root, "U", seed.MODE_LIVE))


def test_mobilebackup2_restore_ignores_cleanup_error_after_answer(monkeypatch, tmp_path, capsys):
    """iOS 27 reboots straight after answering: losing the lock release is fine, as it
    was for idevicebackup2."""
    install_fake_pmd(monkeypatch, fail_unlock=ConnectionResetError("rebooting"))
    root = make_seed(tmp_path, seed.MODE_LIVE)
    asyncio.run(pax_device.mobilebackup2_restore("LD", root, "U", seed.MODE_LIVE))
    assert "restore_cleanup_ignored" in capsys.readouterr().out


def test_seed_restore_ios27_uses_mobilebackup2_not_idevicebackup2(monkeypatch, tmp_path):
    install_fake_phone(monkeypatch, version="27.2")
    monkeypatch.delenv("PAX_IDEVICEBACKUP2", raising=False)
    monkeypatch.setattr(pax_device.shutil, "which", lambda *_a: pytest.fail("no PATH lookup"))
    monkeypatch.setattr(pax_device.subprocess, "run", lambda *a, **k: pytest.fail("no subprocess"))
    seen = []

    async def fake_restore(ld, root, udid, mode):
        assert (Path(root) / udid / "Manifest.mbdb").exists()   # seed exists while restoring
        seen.append((udid, mode, Path(root)))
        return seed.restore_request(udid, mode)
    monkeypatch.setattr(pax_device, "mobilebackup2_restore", fake_restore)
    out = run_cmd(["seed-restore", "--udid", "U"])
    assert out == {"mode": "live", "next": "reconnect_then_live_configure"}
    assert seen[0][:2] == ("U", "live") and not seen[0][2].exists()   # temp seed removed


def test_seed_restore_ios26_restores_then_restarts(monkeypatch):
    install_fake_phone(monkeypatch, version="26.1")
    monkeypatch.delenv("PAX_IDEVICEBACKUP2", raising=False)
    modes, restarts = [], []

    async def fake_restore(ld, root, udid, mode):
        modes.append(mode)
        return {}

    async def fake_restart(ld):
        restarts.append(ld)
    monkeypatch.setattr(pax_device, "mobilebackup2_restore", fake_restore)
    monkeypatch.setattr(pax_device, "restart", fake_restart)
    out = run_cmd(["seed-restore", "--udid", "U"])
    assert out == {"mode": "restored", "next": "reconnect_then_verify"}
    assert modes == ["restored"] and len(restarts) == 1


def test_seed_restore_classifies_device_refusal(monkeypatch):
    install_fake_phone(monkeypatch, version="27.0")
    monkeypatch.delenv("PAX_IDEVICEBACKUP2", raising=False)

    async def refuse(*_a):
        raise RuntimeError("Device link error: Find My iPhone must be turned off")
    monkeypatch.setattr(pax_device, "mobilebackup2_restore", refuse)
    with pytest.raises(pax_device.HelperError) as e:
        run_cmd(["seed-restore", "--udid", "U"])
    assert e.value.code == "find_my_on"


# ---------------- backup ----------------

def test_backup_uses_mobilebackup2(monkeypatch, tmp_path):
    install_fake_phone(monkeypatch)
    monkeypatch.delenv("PAX_IDEVICEBACKUP2", raising=False)
    monkeypatch.setattr(pax_device.subprocess, "run", lambda *a, **k: pytest.fail("no subprocess"))
    log = install_fake_pmd(monkeypatch)
    out = run_cmd(["backup", "--udid", "U", "--dir", str(tmp_path / "b")])
    assert out == {"backup": str(tmp_path / "b" / "U"), "verified": True}
    assert ("backup", True, tmp_path / "b") in log


def test_backup_incomplete_is_reported(monkeypatch, tmp_path):
    install_fake_phone(monkeypatch)
    monkeypatch.delenv("PAX_IDEVICEBACKUP2", raising=False)

    async def half(ld, target):
        (Path(target) / "U").mkdir(parents=True)
    monkeypatch.setattr(pax_device, "mobilebackup2_backup", half)
    with pytest.raises(pax_device.HelperError) as e:
        run_cmd(["backup", "--udid", "U", "--dir", str(tmp_path)])
    assert e.value.code == "backup_incomplete"


# ---------------- PAX_IDEVICEBACKUP2 override ----------------

def test_override_unset_means_builtin(monkeypatch):
    monkeypatch.delenv("PAX_IDEVICEBACKUP2", raising=False)
    monkeypatch.setattr(pax_device.shutil, "which", lambda *_a: "/opt/homebrew/bin/idevicebackup2")
    assert pax_device.idevicebackup2_override() is None


def test_override_must_be_runnable(monkeypatch, tmp_path):
    monkeypatch.setenv("PAX_IDEVICEBACKUP2", str(tmp_path / "missing"))
    with pytest.raises(pax_device.HelperError) as e:
        pax_device.idevicebackup2_override()
    assert e.value.code == "tool_missing"
    tool = tmp_path / "idevicebackup2"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PAX_IDEVICEBACKUP2", str(tool))
    assert pax_device.idevicebackup2_override() == str(tool)


def test_no_homebrew_or_path_lookup_left():
    src = (HERE.parent / "pax_device.py").read_text()
    assert "/opt/homebrew" not in src and "brew install" not in src
    assert 'which("idevicebackup2")' not in src


# ---------------- progress ----------------

def test_progress_reporter_throttles(capsys):
    report = pax_device.progress_reporter("p")
    for v in (0, 1, 2, 4.9, 5, 9, 10.5, "bad", None, 100, 100):
        report(v)
    events = [json.loads(line)["event"]["percent"] for line in capsys.readouterr().out.splitlines()]
    assert events == [0, 5, 10.5, 100]


# ---------------- selftest ----------------

def test_selftest_parser():
    a = pax_device.build_parser().parse_args(["selftest", "--expect-pymobiledevice3", "1.2", "--expect-arch", "arm64"])
    assert a.expect_pymobiledevice3 == "1.2" and a.expect_arch == "arm64"


def test_selftest_covers_every_pymobiledevice3_import():
    """Every `from pymobiledevice3... import X` in the helper is in SELFTEST_IMPORTS."""
    import re
    src = (HERE.parent / "pax_device.py").read_text()
    for module, names in re.findall(r"from (pymobiledevice3[\w.]*) import ([\w, ]+)", src):
        for name in [n.strip().split(" as ")[0] for n in names.split(",")]:
            if module == "pymobiledevice3" and name == "exceptions":
                assert "pymobiledevice3.exceptions" in pax_device.SELFTEST_IMPORTS
                continue
            assert name in pax_device.SELFTEST_IMPORTS.get(module, []), (module, name)


def test_selftest_runs_where_pymobiledevice3_is_installed(capsys):
    pytest.importorskip("pymobiledevice3")
    pytest.importorskip("cryptography")
    rc = pax_device.main(["selftest"])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 0 and out["ok"] and out["selftest"] == "passed", out
    assert out["bundled"] is False


def test_selftest_fails_on_wrong_version_or_arch(capsys):
    pytest.importorskip("pymobiledevice3")
    assert pax_device.main(["selftest", "--expect-pymobiledevice3", "0.0.1"]) == 1
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["code"] == "selftest_failed" and "0.0.1" in out["error"]
    assert pax_device.main(["selftest", "--expect-arch", "pdp11"]) == 1


def test_selftest_reports_missing_module(monkeypatch, capsys):
    monkeypatch.setitem(pax_device.SELFTEST_IMPORTS, "pax_no_such_module", ["x"])
    assert pax_device.main(["selftest"]) == 1
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["code"] == "selftest_failed" and "pax_no_such_module" in out["error"]


def test_dependency_message_no_longer_points_users_at_pip(monkeypatch, capsys):
    async def boom(_a):
        raise ImportError("No module named 'pymobiledevice3'")
    monkeypatch.setitem(pax_device.COMMANDS, "list", boom)
    assert pax_device.main(["list"]) == 1
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["code"] == "dependency_missing" and out["error"].startswith("Part of Pax's iPhone helper")
