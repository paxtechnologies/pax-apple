# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.35 (Ruben, 28 Oct 2026): Pax opens itself when the Standard user starts installing or updating
an app, even when Pax isn't running. (a) a root-owned StartOnMount LaunchAgent, kept like the
open-at-login one; (b) macOS's authorisation dialog / an app's updater appearing while Pax isn't
running starts Pax in the console user's session, rate-limited; (c) an update an app already
downloaded starts Pax so the card/notification appear. Tests never touch the real Mac."""
import json
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pax_guard as pg  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
AGENT = "/Library/LaunchAgents/org.paxpeace.pax-installs.plist"
SA = "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent"
PAX = "/Applications/Pax.app/Contents/MacOS/Pax"


def tamper_kinds(g):
    p = g.state_dir / "tamper.jsonl"
    return [json.loads(x)["kind"] for x in p.read_text().splitlines()] if p.exists() else []


class Mac:
    """A console user (uid 501, 'alex'), admin or not, and a process list."""

    def __init__(self, g, s, tmp_path, admin=False, uid=501):
        self.g, self.s = g, s
        self.admin, self.uid = admin, uid
        self.procs = []
        self.launch_code = 0
        self.print_code = 0
        self.disabled = ""
        app = tmp_path / "Applications" / "Pax.app"
        app.mkdir(parents=True)
        g.pax_app_path = app
        s.processes_with_uid = lambda: list(self.procs)
        s.user_of = lambda u: ("alex", "/Users/alex") if u == self.uid else None
        run = s.run

        def fake(args, stdin=None, timeout=30):
            if args == ["/usr/bin/stat", "-f", "%u", "/dev/console"]:
                return 0, f"{self.uid}\n" if self.uid is not None else "0\n"
            if args[:3] == ["/usr/sbin/dseditgroup", "-o", "checkmember"]:
                return 0, ("yes alex is a member of admin" if self.admin else "no alex is NOT a member of admin")
            if args[:2] == ["/bin/launchctl", "asuser"]:
                s.commands.append(args)
                return self.launch_code, ""
            if args[:2] == ["/bin/launchctl", "print-disabled"]:
                s.commands.append(args)
                return 0, self.disabled
            if args[:2] == ["/bin/launchctl", "print"]:
                s.commands.append(args)
                return self.print_code, ""
            return run(args, stdin, timeout)
        s.run = fake

    def launches(self):
        return [c for c in self.s.commands if c[:2] == ["/bin/launchctl", "asuser"]]


@pytest.fixture
def mac(tmp_path):
    g, s = local_guard(tmp_path)
    return Mac(g, s, tmp_path)


# ------------------------------------------------------------------ (a) the mount agent
def test_installs_agent_plist_starts_on_mount_for_standard_users_only():
    d = plistlib.loads(pg.Guard.installs_agent_plist().encode())
    assert d["Label"] == "org.paxpeace.pax-installs" == pg.INSTALLS_AGENT_LABEL
    assert str(pg.INSTALLS_AGENT_PATH) == AGENT
    assert d["StartOnMount"] is True
    assert d["LimitLoadToSessionType"] == "Aqua"
    assert "RunAtLoad" not in d and "KeepAlive" not in d     # only on a mount; quitting isn't fought
    assert "UserName" not in d                               # runs as the logged-in user
    assert d["AssociatedBundleIdentifiers"] == ["org.paxmobile.pax"]
    sh, dash_c, script = d["ProgramArguments"]
    assert (sh, dash_c) == ("/bin/sh", "-c")
    assert '*" 80 "*) exit 0' in script                      # administrators: nothing
    assert '/usr/bin/pgrep -qx -U "$(/usr/bin/id -u)" Pax && exit 0' in script
    assert "/Volumes/*/*.app" in script
    assert "exec /usr/bin/open -g -j -a /Applications/Pax.app --args --pax-install-check" in script
    assert subprocess.run(["sh", "-n", "-c", script]).returncode == 0


def test_agent_script_behaviour_with_stub_tools(tmp_path):
    """Run the script with stub id/pgrep/open and a fake /Volumes (paths rewritten)."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    vols = tmp_path / "Volumes"
    log = tmp_path / "open.log"

    def stub(name, body):
        p = bin_ / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(0o755)
    script = pg.INSTALLS_AGENT_SCRIPT.replace("/usr/bin/", str(bin_) + "/").replace("/Volumes", str(vols))

    def run(groups, pax_running, apps):
        shutil.rmtree(vols, ignore_errors=True)
        vols.mkdir()
        for a in apps:
            (vols / a).mkdir(parents=True)
        if log.exists():
            log.unlink()
        stub("id", f'[ "$1" = "-G" ] && echo "{groups}" || echo 501')
        stub("pgrep", "exit 0" if pax_running else "exit 1")
        stub("open", f'echo "$@" >> {log}')
        subprocess.run(["sh", "-c", script], check=True)
        return log.read_text() if log.exists() else ""
    assert run("20 12 61", False, ["Writer/Writer.app"]) == "-g -j -a /Applications/Pax.app --args --pax-install-check\n"
    assert run("20 80 12", False, ["Writer/Writer.app"]) == ""          # an administrator
    assert run("20 12", True, ["Writer/Writer.app"]) == ""              # Pax already running
    assert run("20 12", False, ["Backup/Data"]) == ""                   # no app on any volume
    assert run("20 12", False, ["Disk/Folder/Deep.app"]) == ""          # only the top level counts


def test_first_cycle_installs_agent_quietly_then_repairs_and_logs(tmp_path):
    g, s = local_guard(tmp_path)
    res = g.cycle()
    assert res["installs_agent"] == "installed" and s.files[AGENT] == pg.Guard.installs_agent_plist()
    assert "changed:installs_agent" not in tamper_kinds(g)
    assert g.cycle()["installs_agent"] is None
    del s.files[AGENT]
    assert g.cycle()["installs_agent"] == "repaired"
    s.files[AGENT] = s.files[AGENT].replace("<true/>", "<false/>")
    assert g.cycle()["installs_agent"] == "repaired"
    assert tamper_kinds(g).count("changed:installs_agent") == 2
    assert s.files[AGENT] == pg.Guard.installs_agent_plist()


def test_wrong_mode_on_disk_is_rewritten(tmp_path):
    g, s = local_guard(tmp_path)
    real = tmp_path / "LA" / "org.paxpeace.pax-installs.plist"
    real.parent.mkdir()
    g.installs_agent_path = real
    g.cycle()
    real.write_text(pg.Guard.installs_agent_plist())
    real.chmod(0o666)
    assert g.cycle()["installs_agent"] == "repaired"


def test_disabled_agent_is_enabled_and_unloaded_agent_is_loaded(mac):
    g, s = mac.g, mac.s
    g.cycle()
    mac.disabled = 'disabled services = {\n\t"org.paxpeace.pax-installs" => disabled\n}\n'
    mac.print_code = 113
    assert g.ensure_installs_agent_loaded() == "enabled"
    assert ["/bin/launchctl", "enable", "gui/501/org.paxpeace.pax-installs"] in s.commands
    assert ["/bin/launchctl", "bootstrap", "gui/501", AGENT] in s.commands
    assert "changed:installs_agent" in tamper_kinds(g)
    s.commands.clear()
    mac.disabled = 'disabled services = {\n\t"org.paxpeace.pax-installs" => enabled\n}\n'
    mac.print_code = 0
    assert g.ensure_installs_agent_loaded() is None
    assert not any(c[:2] in (["/bin/launchctl", "enable"], ["/bin/launchctl", "bootstrap"]) for c in s.commands)


def test_no_console_user_or_no_agent_file_does_nothing(tmp_path):
    g, s = local_guard(tmp_path)
    assert g.ensure_installs_agent_loaded() is None
    m = Mac(g, s, tmp_path)
    assert g.ensure_installs_agent_loaded() is None          # the file isn't written yet
    assert m.launches() == []


def test_uninstall_removes_the_agent_and_unloads_it(mac):
    g, s = mac.g, mac.s
    g.cycle()
    done = g.uninstall()
    assert "install helper removed" in done
    assert ["/bin/rm", "-f", AGENT] in s.commands
    assert ["/bin/launchctl", "bootout", "gui/501/org.paxpeace.pax-installs"] in s.commands


def test_emergency_uninstaller_and_package_rules_cover_the_agent():
    src = (ROOT / "scripts" / "pax-uninstall-emergency.sh").read_text()
    assert 'rm -f "/Library/LaunchAgents/org.paxpeace.pax-installs.plist"' in src
    assert subprocess.run(["bash", "-n", str(ROOT / "scripts" / "pax-uninstall-emergency.sh")]).returncode == 0
    import app_installs
    assert '"/library/launchagents/org.paxpeace."' in Path(app_installs.__file__).read_text()
    pg_src = (ROOT / "pax_guard.py").read_text()
    assert 'if r.get("installs_agent") in ("repaired", "error"):' in pg_src


# ------------------------------------------------------------------ (b) the admin dialog / updaters
def test_install_trigger_classifies_processes():
    t = pg.Guard.install_trigger
    assert t(501, 92, SA) == "auth"                      # whoever owns SecurityAgent
    assert t(501, 501, "SecurityAgent") == "auth"
    assert t(501, 501, "/Users/alex/Library/Caches/com.x/org.sparkle-project.Sparkle/Launcher/a/Autoupdate.app/Contents/MacOS/Autoupdate") == "update"
    assert t(501, 501, "/Applications/X.app/Contents/Frameworks/Sparkle.framework/Versions/B/Updater.app/Contents/MacOS/Updater") == "update"
    assert t(501, 501, "/Users/alex/Library/Caches/com.x.ShipIt/ShipIt") == "update"
    assert t(501, 502, "/Users/sam/Library/Caches/com.x.ShipIt/ShipIt") is None     # someone else's
    assert t(501, 501, "/Applications/Updater.app/Contents/MacOS/Updater") is None  # not Sparkle's
    assert t(501, 501, "/usr/libexec/securityd") is None
    assert t(501, 501, "/Applications/Finder.app") is None


def test_dialog_while_pax_not_running_opens_pax_once(mac):
    g = mac.g
    mac.procs = [(10, 501, "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder")]
    assert g.install_watch_tick() is None                # first tick: baseline
    mac.procs.append((77, 92, SA))
    assert g.install_watch_tick() == "auth"
    assert mac.launches() == [["/bin/launchctl", "asuser", "501", "/usr/bin/open", "-g", "-j", "-a",
                               "/Applications/Pax.app", "--args", "--pax-install-check",
                               "--pax-install-reason=auth"]]
    mac.s.t += 120
    assert g.install_watch_tick() is None                # same dialog: not again, even after the gap
    assert len(mac.launches()) == 1


def test_finder_drag_to_applications_dialog_opens_pax(mac):
    """Ruben: dragging an app to Applications in Finder -> macOS asks for an administrator -> Pax
    appears (the panel offers to install it; a mounted disk image gets its Install sheet)."""
    g = mac.g
    mac.procs = [(10, 501, "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder")]
    g.install_watch_tick()
    mac.procs.append((300, 0, SA))
    assert g.install_watch_tick() == "auth"
    assert mac.launches()[-1][-2:] == ["--pax-install-check", "--pax-install-reason=auth"]


def test_running_pax_admin_user_or_released_mac_never_launches(mac):
    g = mac.g
    mac.procs = []
    g.install_watch_tick()
    mac.procs = [(5, 501, PAX), (77, 92, SA)]
    assert g.install_watch_tick() is None                # Pax is running: it shows the panel itself
    mac.procs = [(78, 92, SA)]
    mac.admin = True
    g._standard_cache = {}
    assert g.install_watch_tick() is None                # administrators can install themselves
    mac.admin = False
    g._standard_cache = {}
    g.released = True
    mac.procs = [(79, 92, SA)]
    assert g.install_watch_tick() is None
    assert mac.launches() == []


def test_pax_running_for_another_user_doesnt_count(mac):
    g = mac.g
    mac.procs = []
    g.install_watch_tick()
    mac.procs = [(5, 502, PAX), (77, 92, SA)]
    assert g.install_watch_tick() == "auth"


def test_unknown_admin_status_counts_as_admin(mac):
    g, s = mac.g, mac.s
    s.user_of = lambda u: None
    mac.procs = []
    g.install_watch_tick()
    mac.procs = [(77, 92, SA)]
    assert g.install_watch_tick() is None and mac.launches() == []


def test_rate_limited_to_once_every_30_seconds_and_retried_after(mac):
    g, s = mac.g, mac.s
    mac.procs = []
    g.install_watch_tick()
    mac.procs = [(77, 92, SA)]
    assert g.install_watch_tick() == "auth"
    mac.procs = [(88, 92, SA)]                           # a second dialog 2 s later
    s.t += 2
    assert g.install_watch_tick() is None                # rate-limited, not forgotten
    s.t += pg.INSTALL_LAUNCH_MIN_GAP
    assert g.install_watch_tick() == "auth"
    assert len(mac.launches()) == 2


def test_new_login_baselines_existing_processes(mac):
    g = mac.g
    mac.procs = [(77, 92, SA)]                           # the login window's SecurityAgent
    mac.uid = None
    assert g.install_watch_tick() is None
    mac.uid = 501
    assert g.install_watch_tick() is None                # baseline for the new user
    assert mac.launches() == []


def test_updater_process_opens_pax_hidden(mac):
    g = mac.g
    mac.procs = []
    g.install_watch_tick()
    mac.procs = [(90, 501, "/Users/alex/Library/Caches/com.x.ShipIt/ShipIt")]
    assert g.install_watch_tick() == "update"
    assert mac.launches()[-1] == ["/bin/launchctl", "asuser", "501", "/usr/bin/open", "-g", "-j", "-a",
                                  "/Applications/Pax.app", "--args", "--pax-install-check",
                                  "--pax-install-reason=update"]


def test_missing_pax_app_is_not_opened(mac, tmp_path):
    g = mac.g
    shutil.rmtree(g.pax_app_path)
    mac.procs = []
    g.install_watch_tick()
    mac.procs = [(77, 92, SA)]
    assert g.install_watch_tick() is None and mac.launches() == []


def test_failed_launch_is_logged_and_retried_later(mac):
    g, s = mac.g, mac.s
    mac.launch_code = 1
    mac.procs = []
    g.install_watch_tick()
    mac.procs = [(77, 92, SA)]
    assert g.install_watch_tick() is None
    s.t += pg.INSTALL_LAUNCH_MIN_GAP
    mac.launch_code = 0
    assert g.install_watch_tick() == "auth"


# ------------------------------------------------------------------ (c) updates already downloaded
class FakeInstaller:
    def __init__(self):
        self.found = []
        self.job = None

    def downloaded_updates(self, home):
        return list(self.found)


def test_downloaded_update_opens_pax_once_per_app_and_version(mac, monkeypatch):
    g, s = mac.g, mac.s
    inst = FakeInstaller()
    g._installer = inst
    monkeypatch.setattr(g, "install_home", lambda uid: "/Users/alex")
    assert g.staged_updates_tick(force=True) is None
    inst.found = [{"bundle_id": "com.example.Notes", "version": "2.0", "name": "Notes", "path": "/x"}]
    assert g.staged_updates_tick(force=True) == "launched"
    assert mac.launches()[-1][-1] == "--pax-install-reason=update"
    s.t += 100
    assert g.staged_updates_tick(force=True) is None     # remembered
    inst.found.append({"bundle_id": "com.example.Mail", "version": "3.0", "name": "Mail", "path": "/y"})
    mac.procs = [(5, 501, PAX)]
    assert g.staged_updates_tick(force=True) == "running"   # Pax's own scan shows it
    assert len(mac.launches()) == 1


def test_downloaded_updates_scan_interval_and_admin(mac, monkeypatch):
    g, s = mac.g, mac.s
    inst = FakeInstaller()
    inst.found = [{"bundle_id": "com.example.Notes", "version": "2.0"}]
    g._installer = inst
    monkeypatch.setattr(g, "install_home", lambda uid: "/Users/alex")
    mac.admin = True
    assert g.staged_updates_tick() is None
    mac.admin = False
    g._standard_cache = {}
    assert g.staged_updates_tick() is None               # within the scan interval
    s.t += pg.STAGED_UPDATE_SCAN_INTERVAL
    assert g.staged_updates_tick() == "launched"


def test_rate_limited_downloaded_update_is_tried_again(mac, monkeypatch):
    g, s = mac.g, mac.s
    inst = FakeInstaller()
    g._installer = inst
    monkeypatch.setattr(g, "install_home", lambda uid: "/Users/alex")
    g._install_launch_at = s.t                           # (b) just opened Pax
    inst.found = [{"bundle_id": "com.example.Notes", "version": "2.0"}]
    assert g.staged_updates_tick(force=True) is None
    s.t += pg.INSTALL_LAUNCH_MIN_GAP
    assert g.staged_updates_tick(force=True) == "launched"


def test_error_codes_and_app_wording_exist():
    sys.path.insert(0, str(ROOT.parent / "common"))
    import pax_errors
    codes = {c.code for c in pax_errors.CODES}
    assert {"PAX-GUARD-017", "PAX-GUARD-018"} <= codes
    swift = (ROOT.parent / "mac-app" / "Sources" / "PaxCore" / "SecurityNotices.swift").read_text()
    assert '"changed:installs_agent"' in swift and '"changed:pax_app"' in swift
    launch = (ROOT.parent / "mac-app" / "Sources" / "PaxCore" / "InstallCheckLaunch.swift").read_text()
    assert '"--pax-install-check"' in launch and '"--pax-install-reason="' in launch
    assert pg.INSTALL_CHECK_ARG == "--pax-install-check" and pg.INSTALL_REASON_PREFIX == "--pax-install-reason="
