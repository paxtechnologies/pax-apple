# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.34 (Ruben, 28 Oct 2026): Pax opens at login on a Mac it protects. pax-guard keeps a
root-owned LaunchAgent that starts Pax.app hidden for every login session, puts it back when it's
removed, changed or disabled (tamper log), and removes it with Pax. Tests never touch the real Mac."""
import json
import plistlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pax_guard as pg  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
AGENT = "/Library/LaunchAgents/org.paxpeace.pax-login.plist"


def tamper_kinds(g):
    return [json.loads(x)["kind"] for x in (g.state_dir / "tamper.jsonl").read_text().splitlines()] \
        if (g.state_dir / "tamper.jsonl").exists() else []


def test_agent_plist_launches_pax_hidden_at_login_without_keepalive():
    d = plistlib.loads(pg.Guard.login_agent_plist().encode())
    assert d["Label"] == "org.paxpeace.pax-login" == pg.LOGIN_AGENT_LABEL
    assert str(pg.LOGIN_AGENT_PATH) == AGENT
    assert d["ProgramArguments"] == ["/usr/bin/open", "-g", "-j", "-F", "-a", "/Applications/Pax.app",
                                     "--args", "--pax-login"]
    assert d["RunAtLoad"] is True
    assert "KeepAlive" not in d                    # quitting Pax isn't fought, no relaunch loop
    assert d["LimitLoadToSessionType"] == "Aqua"   # only real login sessions (not ssh)
    assert d["AssociatedBundleIdentifiers"] == ["org.paxmobile.pax"]
    assert "UserName" not in d and "Program" not in d   # runs as the logged-in user, nothing as root


def test_first_cycle_installs_the_agent_quietly(tmp_path):
    g, s = local_guard(tmp_path)
    res = g.cycle()
    assert res["login_agent"] == "installed"
    assert s.files[AGENT] == pg.Guard.login_agent_plist()
    assert "changed:login_agent" not in tamper_kinds(g)
    # nothing is loaded into the current session: it starts at the next login, never pops Pax open now
    assert not any(c[:2] == ["/bin/launchctl", "bootstrap"] for c in s.commands)
    assert not any("/usr/bin/open" in c for c in s.commands)
    assert g.cycle()["login_agent"] is None        # unchanged: nothing to do


def test_removed_or_changed_agent_is_put_back_and_logged(tmp_path):
    g, s = local_guard(tmp_path)
    g.cycle()
    del s.files[AGENT]
    assert g.cycle()["login_agent"] == "repaired"
    assert s.files[AGENT] == pg.Guard.login_agent_plist()
    s.files[AGENT] = s.files[AGENT].replace("--pax-login", "--other")
    assert g.cycle()["login_agent"] == "repaired"
    assert s.files[AGENT] == pg.Guard.login_agent_plist()
    s.files[AGENT] = s.files[AGENT].replace("<key>RunAtLoad</key>\n\t<true/>", "<key>RunAtLoad</key>\n\t<false/>")
    assert g.cycle()["login_agent"] == "repaired"
    assert tamper_kinds(g).count("changed:login_agent") == 3


def test_wrong_owner_or_mode_on_disk_is_rewritten(tmp_path):
    g, s = local_guard(tmp_path)
    real = tmp_path / "LaunchAgents" / "org.paxpeace.pax-login.plist"
    real.parent.mkdir()
    g.login_agent_path = real
    g.cycle()                                      # fake System: the dict, not the disk
    real.write_text(pg.Guard.login_agent_plist())
    real.chmod(0o666)                              # group/other-writable (and not root-owned in tests)
    assert g._login_agent_file_ok(str(real)) is False
    assert g.cycle()["login_agent"] == "repaired"
    real.unlink()
    real.symlink_to(tmp_path / "elsewhere")
    assert g._login_agent_file_ok(str(real)) is False


def test_user_disable_override_is_undone_as_root(tmp_path):
    g, s = local_guard(tmp_path)
    run = s.run

    def fake(args, stdin=None, timeout=30):
        if args == ["/usr/bin/stat", "-f", "%u", "/dev/console"]:
            s.commands.append(args)
            return 0, "501\n"
        if args == ["/bin/launchctl", "print-disabled", "gui/501"]:
            s.commands.append(args)
            return 0, 'disabled services = {\n\t"org.paxpeace.pax-login" => disabled\n\t"com.x" => enabled\n}\n'
        return run(args, stdin, timeout)
    s.run = fake
    assert g.ensure_login_agent_enabled() is True
    assert ["/bin/launchctl", "enable", "gui/501/org.paxpeace.pax-login"] in s.commands
    assert "changed:login_agent" in tamper_kinds(g)


def test_enabled_or_no_console_user_does_nothing(tmp_path):
    g, s = local_guard(tmp_path)
    assert g.ensure_login_agent_enabled() is False          # no console user in the fake
    run = s.run

    def fake(args, stdin=None, timeout=30):
        if args == ["/usr/bin/stat", "-f", "%u", "/dev/console"]:
            return 0, "501\n"
        if args[:2] == ["/bin/launchctl", "print-disabled"]:
            return 0, 'disabled services = {\n\t"org.paxpeace.pax-login" => enabled\n\t"org.paxpeace.pax-login-x" => true\n}\n'
        return run(args, stdin, timeout)
    s.run = fake
    assert g.ensure_login_agent_enabled() is False
    assert not any(c[:2] == ["/bin/launchctl", "enable"] for c in s.commands)


def test_released_mac_keeps_agent_until_removal_and_uninstall_removes_it(tmp_path):
    g, s = local_guard(tmp_path)
    g.cycle()
    done = g.uninstall()
    assert "open at login removed" in done
    assert ["/bin/rm", "-f", AGENT] in s.commands


def test_package_that_breaks_the_agent_fails_the_post_install_check(tmp_path):
    """The trusted .pkg self-check counts a put-back login item as a failure (never looser)."""
    src = (ROOT / "pax_guard.py").read_text()
    assert 'if r.get("login_agent") in ("repaired", "error"):' in src
    assert "Pax's open-at-login item had to be put back" in src


def test_packages_cant_write_paxs_launch_agents():
    import app_installs
    src = Path(app_installs.__file__).read_text()
    assert '"/library/launchagents/org.paxpeace."' in src


def test_emergency_uninstaller_removes_the_agent():
    src = (ROOT / "scripts" / "pax-uninstall-emergency.sh").read_text()
    assert 'rm -f "/Library/LaunchAgents/org.paxpeace.pax-login.plist"' in src
    assert subprocess.run(["bash", "-n", str(ROOT / "scripts" / "pax-uninstall-emergency.sh")]).returncode == 0


def test_error_code_and_app_wording_exist():
    sys.path.insert(0, str(ROOT.parent / "common"))
    import pax_errors
    codes = {c.code: c for c in pax_errors.CODES} if hasattr(pax_errors, "CODES") else None
    text = (ROOT.parent / "common" / "pax_errors.py").read_text()
    assert "PAX-GUARD-016" in text
    if codes:
        assert "PAX-GUARD-016" in codes
    swift = (ROOT.parent / "mac-app" / "Sources" / "PaxCore" / "SecurityNotices.swift").read_text()
    assert '"changed:login_agent"' in swift
    login = (ROOT.parent / "mac-app" / "Sources" / "PaxCore" / "LoginLaunch.swift").read_text()
    assert '"--pax-login"' in login and pg.LOGIN_AGENT_ARG == "--pax-login"
