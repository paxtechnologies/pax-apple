# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.34 (Ruben, 28 Oct 2026): trusted-team installer packages without the turn-off wait.

A .pkg runs scripts as root, so it is installed straight away ONLY when it is a notarised
Developer ID Installer package from a team on guard/pkg-trusted-teams.txt, its expanded
contents reach for nothing Pax protects, and pax-guard's full self-check passes afterwards.
Any failure after installing fails closed (PkgIntegrity.failed). Everything else still waits.
pkgutil, spctl, codesign, installer and stapler are faked; nothing touches a real Mac."""
import os
import plistlib
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import app_installs as ai  # noqa: E402
from test_v0833_installs import World, dev_sig  # noqa: E402

MS = "UBF8T346G9"          # on the shipped list
UNLISTED = "ABCDE12345"


def pkg_sig(team, name="Microsoft Corporation", notarized=True):
    return ("Package \"Writer.pkg\":\n   Status: signed by a developer certificate issued by Apple for distribution\n"
            + ("   Notarization: trusted by the Apple notary service\n" if notarized else "")
            + "   Signed with a trusted timestamp on: 2026-10-01 10:00:00 +0000\n   Certificate Chain:\n"
            f"    1. Developer ID Installer: {name} ({team})\n       Expires: 2030-01-01\n"
            "       SHA256 Fingerprint:\n           AA BB CC\n"
            "    2. Developer ID Certification Authority\n    3. Apple Root CA\n")


def info_xml(ident="com.microsoft.package.Writer", loc="/Applications", extra=""):
    return (f'<?xml version="1.0" encoding="utf-8"?>\n<pkg-info format-version="2" identifier="{ident}" '
            f'version="1.0" install-location="{loc}" auth="root">{extra}</pkg-info>\n')


def make_bundle(root: Path, rel: str, bid: str, kind="app", plist_extra=None):
    b = root / rel
    (b / "Contents" / "MacOS").mkdir(parents=True, exist_ok=True)
    pl = {"CFBundleIdentifier": bid, "CFBundleName": Path(rel).stem, "CFBundleShortVersionString": "1.0",
          "CFBundleVersion": "1", "CFBundleExecutable": Path(rel).stem}
    pl.update(plist_extra or {})
    with open(b / "Contents" / "Info.plist", "wb") as fh:
        plistlib.dump(pl, fh)
    (b / "Contents" / "MacOS" / Path(rel).stem).write_text("binary")
    return b


class PkgWorld(World):
    """World + packages: pkgutil --expand-full copies a prepared tree; --payload-files lists it."""

    def __init__(self, tmp):
        super().__init__(tmp)
        self.trees: dict = {}           # pkg file text -> expanded fixture folder
        self.ent: dict = {}             # bundle id -> entitlements xml
        self.stapler = (1, "does not have a ticket stapled to it.")
        self.expand_ok = True
        self.order: list = []
        self.teams_file = self.tmp / "pkg-trusted-teams.txt"
        shutil.copy(HERE.parent / "pkg-trusted-teams.txt", self.teams_file)

    def run(self, args, stdin=None, timeout=30):
        tool = args[0]
        if tool == "/usr/sbin/pkgutil" and args[1] == "--expand-full":
            self.commands.append(list(args))
            if not self.expand_ok:
                return 1, "Error: could not expand"
            shutil.copytree(self.trees[Path(args[2]).read_text()], args[3], symlinks=True)
            return 0, ""
        if tool == "/usr/sbin/pkgutil" and args[1] == "--payload-files":
            self.commands.append(list(args))
            src = Path(self.trees[Path(args[2]).read_text()])
            out = []
            for pay in src.rglob("Payload"):
                for p in sorted(pay.rglob("*")):
                    out.append("./" + str(p.relative_to(pay)))
            return 0, ".\n" + "\n".join(out) + "\n"
        if tool == "/usr/bin/codesign" and args[1] == "-d" and "--entitlements" in args:
            self.commands.append(list(args))
            return 0, self.ent.get(self.plist_bid(args[-1]), "")
        if tool == "/usr/bin/xcrun":
            self.commands.append(list(args))
            return self.stapler
        if tool == "/usr/sbin/installer":
            self.order.append("installer")
        return super().run(args, stdin, timeout)

    def package(self, name="Writer.pkg", team=MS, comps=None, dist=None, notarized=True):
        """comps: [(folder, info xml, build(payload_dir), scripts {name: bytes})]."""
        tree = self.tmp / "trees" / name
        tree.mkdir(parents=True)
        if dist is not None:
            (tree / "Distribution").write_text(dist)
        for folder, info, build, scripts in comps or [("Writer.pkg", info_xml(), default_payload, {})]:
            c = tree / folder
            c.mkdir()
            (c / "PackageInfo").write_text(info)
            (c / "Payload").mkdir()
            build(c / "Payload")
            if scripts:
                (c / "Scripts").mkdir()
                for n, data in scripts.items():
                    (c / "Scripts" / n).write_bytes(data)
        p = self.home / "Downloads" / name
        p.write_text(name)
        self.trees[name] = str(tree)
        self.pkgsig = pkg_sig(team, notarized=notarized)
        self.pkg_spctl = (0, f"{name}: accepted\nsource=Notarized Developer ID\n"
                             f"origin=Developer ID Installer: Microsoft Corporation ({team})\n")
        return p

    def installer(self, **kw):
        kw.setdefault("trusted_teams_file", self.teams_file)
        return super().installer(**kw)


def default_payload(pay: Path):
    make_bundle(pay, "Writer.app", "com.microsoft.writer")


class Hooks:
    def __init__(self, world, problems=(), allowed=True, check_raises=False, snapshot_raises=False):
        self.world, self.problems, self.allowed = world, list(problems), allowed
        self.check_raises, self.snapshot_raises = check_raises, snapshot_raises
        self.failed_with = None

    def fastpath_allowed(self):
        return self.allowed

    def snapshot(self):
        if self.snapshot_raises:
            raise OSError("no")
        self.world.order.append("snapshot")
        return {"x": 1}

    def check(self, before):
        self.world.order.append("check")
        assert before == {"x": 1}
        if self.check_raises:
            raise RuntimeError("boom")
        return self.problems

    def failed(self, info, problems):
        self.failed_with = (info, problems)


@pytest.fixture
def w(tmp_path):
    pw = PkgWorld(tmp_path)
    pw.sign("com.microsoft.writer", team=MS)
    return pw


def ran(w, tool):
    return [c for c in w.commands if c[0] == tool]


# ------------------------------------------------------------------ the happy path
def test_trusted_notarised_clean_package_installs_without_a_wait_and_is_checked_after(w):
    hooks = Hooks(w)
    job = w.install(w.installer(pkg_hooks=hooks), w.package())
    assert job["state"] == "installed", job
    assert w.order == ["snapshot", "installer", "check"]
    cmd = ran(w, "/usr/sbin/installer")[0]
    assert cmd[2].startswith(str(w.staging)) and cmd[-2:] == ["-target", "/"]
    # the package was expanded inside the root-only staging folder, from the staged copy
    exp = ran(w, "/usr/sbin/pkgutil")
    assert any(c[1] == "--expand-full" and c[2].startswith(str(w.staging)) and c[3].startswith(str(w.staging))
               for c in exp)
    last = w.installer().history()[-1]
    assert last["result"] == "installed" and last["team_id"] == MS and last["apps"] == ["Writer"]
    assert hooks.failed_with is None


# ------------------------------------------------------------------ who may skip the wait
def test_unlisted_teams_unsigned_and_apple_paths_are_unchanged(w):
    hooks = Hooks(w)
    job = w.install(w.installer(pkg_hooks=hooks), w.package(team=UNLISTED))
    assert job["code"] == ai.PACKAGE and "trusted developers" in job["error"]
    assert not ran(w, "/usr/sbin/installer") and w.order == []
    assert not any(c[1] == "--expand-full" for c in ran(w, "/usr/sbin/pkgutil"))
    w.pkgsig = "Package \"Writer.pkg\":\n   Status: no signature\n"
    assert w.install(w.installer(pkg_hooks=hooks), w.home / "Downloads" / "Writer.pkg")["code"] == ai.PACKAGE
    # a Developer ID *Application* certificate on a package isn't an installer signature
    w.pkgsig = pkg_sig(MS).replace("Developer ID Installer:", "Developer ID Application:")
    assert w.install(w.installer(pkg_hooks=hooks), w.home / "Downloads" / "Writer.pkg")["code"] == ai.PACKAGE
    assert not ran(w, "/usr/sbin/installer")


def test_not_notarised_is_refused(w):
    hooks = Hooks(w)
    p = w.package(notarized=False)
    assert w.install(w.installer(pkg_hooks=hooks), p)["code"] == ai.NOT_NOTARISED       # no line, no staple
    w.stapler = (0, "The validate action worked!")
    w.pkg_spctl = (3, "Writer.pkg: rejected\nsource=Unnotarized Developer ID\n")
    assert w.install(w.installer(pkg_hooks=hooks), p)["code"] == ai.NOT_NOTARISED       # Gatekeeper says no
    w.pkg_spctl = (0, "Writer.pkg: accepted\nsource=Notarized Developer ID\n"
                      "origin=Developer ID Installer: Someone (ZYXWV98765)\n")
    assert w.install(w.installer(pkg_hooks=hooks), p)["code"] == ai.NOT_SIGNED          # teams disagree
    assert not ran(w, "/usr/sbin/installer")
    w.pkg_spctl = (0, f"Writer.pkg: accepted\nsource=Notarized Developer ID\n"
                      f"origin=Developer ID Installer: Microsoft Corporation ({MS})\n")
    assert w.install(w.installer(pkg_hooks=hooks), p)["state"] == "installed"           # stapled ticket ok


def test_no_hooks_fast_path_off_or_broken_list_all_wait(w, tmp_path):
    p = w.package()
    assert w.install(w.installer(), p)["code"] == ai.PACKAGE                            # no hooks
    assert w.install(w.installer(pkg_hooks=Hooks(w, allowed=False)), p)["code"] == ai.PACKAGE
    for bad in ("team lowercase0 X\n", "", "team Z94GSK7JA8 Pax\n", "team W5364U7YZB Tailscale\n",
                "trust everyone\n"):
        w.teams_file.write_text(bad)
        job = w.install(w.installer(pkg_hooks=Hooks(w)), p)
        assert job["code"] == ai.PACKAGE, bad
    w.teams_file.unlink()
    assert w.install(w.installer(pkg_hooks=Hooks(w)), p)["code"] == ai.PACKAGE
    assert not ran(w, "/usr/sbin/installer")


def test_no_before_picture_no_install(w):
    job = w.install(w.installer(pkg_hooks=Hooks(w, snapshot_raises=True)), w.package())
    assert job["code"] == ai.FAILED and not ran(w, "/usr/sbin/installer")


# ------------------------------------------------------------------ what a package may contain
def _kext(pay):
    default_payload(pay)
    (pay / "Writer.app" / "Contents" / "Resources").mkdir()
    (pay / "Writer.app" / "Contents" / "Resources" / "Driver.kext").mkdir()


def _sysext(pay):
    default_payload(pay)
    d = pay / "Writer.app" / "Contents" / "Library" / "SystemExtensions" / "com.microsoft.net.systemextension"
    d.mkdir(parents=True)


def _profile(pay):
    default_payload(pay)
    (pay / "Writer.app" / "Contents" / "Resources").mkdir()
    (pay / "Writer.app" / "Contents" / "Resources" / "settings.mobileconfig").write_text("<plist/>")


def _ne_appex(pay):
    default_payload(pay)
    make_bundle(pay, "Writer.app/Contents/PlugIns/Tunnel.appex", "com.microsoft.writer.tunnel",
                plist_extra={"NSExtension": {"NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel"}})


def _teamviewer(pay):
    default_payload(pay)
    make_bundle(pay, "Writer.app/Contents/Helpers/TeamViewer.app", "com.teamviewer.helper")


def _other_team_app(pay):
    default_payload(pay)
    make_bundle(pay, "Other.app", "com.example.other")


def _link_to_pax(pay):
    default_payload(pay)
    os.symlink("/Library/PaxGuard/bin/pax_guard.py", pay / "Writer.app" / "Contents" / "guard")


def _setuid(pay):
    default_payload(pay)
    f = pay / "Writer.app" / "Contents" / "MacOS" / "helper"
    f.write_text("x")
    os.chmod(f, 0o4755)


ROOT = "/"


@pytest.mark.parametrize("loc,build,code,words", [
    ("/Applications", _kext, ai.PKG_CONTENTS, "kernel extension"),
    ("/Applications", _sysext, ai.PKG_CONTENTS, "system extension"),
    ("/Applications", _profile, ai.PKG_CONTENTS, "configuration profile"),
    ("/Applications", _ne_appex, ai.PKG_CONTENTS, "network extension"),
    ("/Applications", _teamviewer, ai.BLOCKED, "remote-desktop"),
    ("/Applications", _other_team_app, ai.PKG_CONTENTS, "another developer"),
    ("/Applications", _link_to_pax, ai.PKG_CONTENTS, "PaxGuard"),
    ("/Applications", _setuid, ai.UNSAFE, "rights"),
    (ROOT, lambda p: (p / "Library" / "PaxGuard").mkdir(parents=True), ai.PKG_CONTENTS, "PaxGuard"),
    (ROOT, lambda p: ((p / "Library" / "LaunchDaemons").mkdir(parents=True),
                      (p / "Library" / "LaunchDaemons" / "org.paxpeace.pax-guard.plist").write_text("x")),
     ai.PKG_CONTENTS, "over Pax"),
    (ROOT, lambda p: ((p / "private" / "etc").mkdir(parents=True), (p / "private" / "etc" / "hosts").write_text("x")),
     ai.PKG_CONTENTS, "/private/etc"),
    (ROOT, lambda p: (p / "Library" / "Preferences" / "SystemConfiguration").mkdir(parents=True),
     ai.PKG_CONTENTS, "SystemConfiguration"),
    (ROOT, lambda p: (p / "Users" / "alex").mkdir(parents=True), ai.PKG_CONTENTS, "/Users"),
    (ROOT, lambda p: (p / "Applications" / "Pax.app").mkdir(parents=True), ai.PKG_CONTENTS, "Pax.app"),
])
def test_payloads_that_reach_for_pax_are_refused_before_anything_runs(w, loc, build, code, words):
    w.sign("com.example.other", team="ZYXWV98765")
    hooks = Hooks(w)
    job = w.install(w.installer(pkg_hooks=hooks), w.package(comps=[("Writer.pkg", info_xml(loc=loc), build, {})]))
    assert job["code"] == code, job
    assert words.lower() in (job["error"] + " " + str(job.get("category"))).lower(), job
    assert not ran(w, "/usr/sbin/installer") and w.order == []


@pytest.mark.parametrize("script", [
    b"#!/bin/sh\n/sbin/pfctl -d\n",
    b"#!/bin/sh\necho 0.0.0.0 x >> /etc/hosts\n",
    b"#!/bin/sh\n/usr/bin/profiles install -path /tmp/x.mobileconfig\n",
    b"#!/bin/sh\nlaunchctl bootout system/org.paxpeace.pax-guard\n",
    b"#!/bin/sh\ndseditgroup -o edit -a alex -t user admin\n",
    b"#!/bin/sh\nnetworksetup -setdnsservers Wi-Fi 1.1.1.1\n",
    b"#!/bin/sh\nsystemextensionsctl reset\n",
    b"\xcf\xfa\xed\xfe\x00\x00binary\x00/usr/bin/profiles\x00remove\x00",       # a compiled helper's strings
])
def test_scripts_that_reach_for_pax_are_refused(w, script):
    job = w.install(w.installer(pkg_hooks=Hooks(w)), w.package(
        comps=[("Writer.pkg", info_xml(), default_payload, {"postinstall": script})]))
    assert job["code"] == ai.PKG_CONTENTS, job
    assert not ran(w, "/usr/sbin/installer")


def test_ordinary_scripts_and_launch_daemons_are_fine(w):
    def payload(pay):
        make_bundle(pay / "Applications", "Writer.app", "com.microsoft.writer")
        (pay / "Library" / "LaunchDaemons").mkdir(parents=True)
        (pay / "Library" / "LaunchDaemons" / "com.microsoft.autoupdate.helper.plist").write_text("x")
        (pay / "Library" / "PrivilegedHelperTools").mkdir(parents=True)
        (pay / "Library" / "PrivilegedHelperTools" / "com.microsoft.autoupdate.helper").write_text("x")
    script = b"#!/bin/sh\nlaunchctl bootout system/com.microsoft.autoupdate.helper 2>/dev/null\nexit 0\n"
    job = w.install(w.installer(pkg_hooks=Hooks(w)), w.package(
        comps=[("Writer.pkg", info_xml(loc="/"), payload, {"preinstall": script})],
        dist='<?xml version="1.0"?><installer-gui-script minSpecVersion="2"><title>Writer</title>'
             '</installer-gui-script>'))
    assert job["state"] == "installed", job
    assert job["name"] == "Writer"


def test_distribution_and_package_info_tricks_are_refused(w):
    for dist in ('<?xml version="1.0"?><installer-gui-script><options allow-external-scripts="yes"/>'
                 '</installer-gui-script>',
                 '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><installer-gui-script/>'):
        job = w.install(w.installer(pkg_hooks=Hooks(w)), w.package(name=f"D{len(dist)}.pkg", dist=dist))
        assert job["code"] == ai.PKG_CONTENTS, (dist, job)
    for i, info in enumerate((info_xml(ident="com.teamviewer.pkg.host"), info_xml(ident="org.paxpeace.fake"),
                              info_xml(loc="relative/place"),
                              info_xml(extra="").replace('auth="root"', 'auth="root" relocatable="true"')
                              .replace('install-location="/Applications"', 'install-location="/"'))):
        job = w.install(w.installer(pkg_hooks=Hooks(w)), w.package(
            name=f"I{i}.pkg", comps=[("Writer.pkg", info, default_payload, {})]))
        assert job["code"] in (ai.PKG_CONTENTS,), (info, job)
    w.expand_ok = False
    job = w.install(w.installer(pkg_hooks=Hooks(w)), w.package(name="E.pkg"))
    assert job["code"] == ai.PKG_CONTENTS
    assert not ran(w, "/usr/sbin/installer")


def test_apps_that_want_network_or_system_extensions_are_refused(w):
    w.ent["com.microsoft.writer"] = ("<plist><dict><key>com.apple.developer.networking.networkextension</key>"
                                     "<array><string>packet-tunnel-provider</string></array></dict></plist>")
    job = w.install(w.installer(pkg_hooks=Hooks(w)), w.package())
    assert job["code"] == ai.PKG_CONTENTS and "network" in job["error"]


# ------------------------------------------------------------------ after installing: fail closed
def test_a_failed_self_check_fails_closed(w):
    hooks = Hooks(w, problems=["the hosts block had to be put back"])
    job = w.install(w.installer(pkg_hooks=hooks), w.package())
    assert job["code"] == ai.PKG_CHECK and job["state"] == "refused"
    info, problems = hooks.failed_with
    assert info["team_id"] == MS and problems == ["the hosts block had to be put back"]
    last = w.installer().history()[-1]
    assert last["result"] == "refused" and last["code"] == ai.PKG_CHECK


def test_a_check_that_cannot_run_counts_as_failed_and_a_stopped_installer_is_still_checked(w):
    hooks = Hooks(w, check_raises=True)
    assert w.install(w.installer(pkg_hooks=hooks), w.package())["code"] == ai.PKG_CHECK
    assert "couldn't run" in hooks.failed_with[1][0]
    w.order.clear()
    w.installer_out = (1, "installer: The install failed.")
    hooks = Hooks(w)
    job = w.install(w.installer(pkg_hooks=hooks), w.home / "Downloads" / "Writer.pkg")
    assert w.order == ["snapshot", "installer", "check"] and job["code"] == ai.FAILED
    hooks = Hooks(w, problems=["pax-guard isn't loaded by launchd"])
    assert w.install(w.installer(pkg_hooks=hooks), w.home / "Downloads" / "Writer.pkg")["code"] == ai.PKG_CHECK


# ------------------------------------------------------------------ pax-guard's side
def _guard(tmp_path, monkeypatch):
    from test_v08_guard import local_guard
    import pax_guard as pg
    g, s = local_guard(tmp_path)
    monkeypatch.setattr(g, "guard_files", lambda: [])
    return pg, g, s


def test_integrity_check_passes_on_a_quiet_mac_and_catches_changes(tmp_path, monkeypatch):
    pg, g, s = _guard(tmp_path, monkeypatch)
    hooks = pg.PkgIntegrity(g)
    assert hooks.fastpath_allowed()
    before = hooks.snapshot()
    assert before["loaded"] is True
    assert hooks.check(before) == []
    # launchd lost pax-guard
    real = s.run

    def no_guard(args, stdin=None, timeout=30):
        if args[:2] == ["/bin/launchctl", "print"]:
            return 113, "Could not find service"
        return real(args, stdin, timeout)
    monkeypatch.setattr(s, "run", no_guard)
    assert "pax-guard isn't loaded by launchd" in hooks.check(before)
    monkeypatch.setattr(s, "run", real)
    # a new admin, the Pax profile gone, a new system extension, the hosts block rewritten
    monkeypatch.setattr(hooks, "_tamper_snapshot", lambda: {**before["tamper"], "admins": ["alex", "paxadmin", "x"]})
    assert "admins changed" in hooks.check({**before, "tamper": {**before["tamper"], "admins": ["paxadmin"]}})
    monkeypatch.undo()
    monkeypatch.setattr(g, "guard_files", lambda: [])
    monkeypatch.setattr(g, "profile_installed", lambda: False)
    assert "the Pax profile is missing" in hooks.check({**before, "profile": True})
    monkeypatch.setattr(g, "profile_installed", lambda: True)
    monkeypatch.setattr(hooks, "_system_extensions", lambda: "different")
    assert "a system extension changed" in hooks.check(before)
    monkeypatch.setattr(hooks, "_system_extensions", lambda: before["sysext"])
    monkeypatch.setattr(g, "cycle", lambda: {"hosts_changed": True, "dns_settings": ["Wi-Fi"]})
    got = hooks.check(before)
    assert "the hosts block had to be put back" in got and "DNS settings had to be stopped or put back" in got

    def boom():
        raise RuntimeError("x")
    monkeypatch.setattr(g, "check_runtime", boom)
    assert any("couldn't be checked" in p for p in hooks.check(before))


def test_failure_turns_the_fast_path_off_logs_tamper_and_tells_the_trusted_person(tmp_path, monkeypatch):
    pg, g, s = _guard(tmp_path, monkeypatch)
    hooks = pg.PkgIntegrity(g)
    sent, cycles = [], []
    monkeypatch.setattr(g.escrow, "exists", lambda: True)
    monkeypatch.setattr(g.escrow.partner, "notify", lambda *a, **k: sent.append(a) or True)
    monkeypatch.setattr(g, "console_uid", lambda: 501)
    real_cycle = g.cycle
    monkeypatch.setattr(g, "cycle", lambda: cycles.append(1) or real_cycle())
    hooks.failed({"name": 'Writer"; do shell script "x', "team_id": MS}, ["the hosts block had to be put back"])
    assert not hooks.fastpath_allowed()
    kinds = [e["kind"] for e in g.tamper_log.entries(10)]
    assert "install:pkg_check_failed" in kinds
    assert cycles, "protection is re-applied"
    assert sent and sent[0][0] == "pkg_check_failed" and "hosts block" in sent[0][2]
    note = [c for c in s.commands if c[:1] == ["/bin/launchctl"] and "/usr/bin/osascript" in c]
    assert note and '"; do shell' not in note[0][-1]       # the package's name can't break out
    # and the next trusted package waits again
    inst = g.installer()
    assert inst.pkg_hooks is not None and not inst.pkg_hooks.fastpath_allowed()


def test_a_restart_during_a_package_install_fails_closed(tmp_path, monkeypatch):
    pg, g, s = _guard(tmp_path, monkeypatch)
    hooks = pg.PkgIntegrity(g)
    assert not hooks.resume_after_restart()
    hooks.snapshot()                                   # the installer would run now; pax-guard dies
    fresh = pg.PkgIntegrity(g)                         # ...and starts again
    assert fresh.resume_after_restart()
    assert not fresh.fastpath_allowed()
    assert "install:pkg_check_failed" in [e["kind"] for e in g.tamper_log.entries(10)]
    assert not fresh.resume_after_restart()            # once
    # a normal check clears the marker
    pg2, g2, _ = _guard(tmp_path / "b", monkeypatch)
    h2 = pg2.PkgIntegrity(g2)
    h2.check(h2.snapshot())
    assert not h2.resume_after_restart() and h2.fastpath_allowed()


# ------------------------------------------------------------------ parsing and shipping
def test_pkg_signature_parsing_for_developer_id_installers():
    s = ai.parse_pkg_signature(pkg_sig(MS))
    assert s["developer_id"] and s["team"] == MS and s["notarized"] and not s["apple"]
    assert not ai.parse_pkg_signature(pkg_sig(MS, notarized=False))["notarized"]
    assert not ai.parse_pkg_signature(pkg_sig(MS).replace("3. Apple Root CA", "3. Evil Root"))["developer_id"]
    assert not ai.parse_pkg_signature(pkg_sig(MS).replace("Developer ID Certification Authority",
                                                          "Some CA"))["developer_id"]
    assert not ai.parse_pkg_signature(pkg_sig(MS).replace("signed by a developer certificate issued by Apple "
                                                          "for distribution", "no signature"))["developer_id"]


def test_shipped_trusted_list_is_short_verified_and_never_pax_or_denied():
    teams = ai.load_trusted_teams(deny=ai.load_deny())
    assert set(teams) == {"UBF8T346G9", "EQHXZ8M8AV", "JQ525L2MZD", "BJ4HAAB9B3"}
    text = (HERE.parent / "pkg-trusted-teams.txt").read_text()
    for t in teams:                        # each one says where it was confirmed
        assert text.count(t) >= 2, t
    assert ai.PAX_TEAM_ID not in teams
    with pytest.raises(ValueError):
        ai.parse_trusted_teams("team Z94GSK7JA8 Pax\n")


def test_targets_and_scripts_rules():
    assert ai.pkg_target_problem("/Applications/Writer.app/Contents/MacOS/Writer") is None
    assert ai.pkg_target_problem("/Library/Application Support/Microsoft/x") is None
    assert ai.pkg_target_problem("/usr/local/bin/tool") is None
    for bad in ("/Library/PaxGuard/x", "/etc/hosts", "/private/etc/pf.conf", "/System/Library/x",
                "/Library/LaunchDaemons/org.paxpeace.pax-guard.plist", "/Applications/PAX.app/x",
                "/Library/Extensions/X.kext", "/Library/Profiles/x", "/Users/alex/x"):
        assert ai.pkg_target_problem(bad), bad
    assert ai.script_problem(b"#!/bin/sh\nopen -a Writer\n") is None
    assert ai.script_problem(b"#!/bin/sh\nPFCTL -d\n")


def test_shipped_with_the_app_and_the_guard_and_selftest_reads_it():
    repo = HERE.parent.parent
    dmg = (repo / "mac-app" / "scripts" / "build-dmg.sh").read_text()
    inst = (repo / "guard" / "scripts" / "pax-guard-install.sh").read_text()
    assert "guard/pkg-trusted-teams.txt" in dmg and "pkg-trusted-teams.txt" in inst
    src = (repo / "guard" / "pax_guard.py").read_text()
    assert "load_trusted_teams" in src and "pkg_hooks=PkgIntegrity(self)" in src


def test_error_codes_exist():
    import importlib
    sys.path.insert(0, str(HERE.parent.parent / "common"))
    pe = importlib.import_module("pax_errors")
    codes = {c.code for c in pe.CODES} if hasattr(pe, "CODES") else set(str(pe.__dict__))
    assert ai.PKG_CONTENTS in str(codes) and ai.PKG_CHECK in str(codes)
