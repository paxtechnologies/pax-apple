# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.33: Pax-approved installs and updates (guard/app_installs.py).

The Standard account can't write /Applications, so pax-guard (root) installs and
updates apps for it, but only ones it can check: same bundle ID and Team ID for an
update, Developer ID signed, notarised, not a blocked kind of app. Every check runs
on a root-only staged copy. .pkg installers are refused unless Apple signed them.
codesign, spctl, pkgutil, hdiutil, ditto, installer and softwareupdate are all
faked here; nothing touches the real Mac."""
import os
import plistlib
import shutil
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import app_installs as ai  # noqa: E402

TEAM = "ABCDE12345"
OTHER = "ZYXWV98765"


def dev_sig(bid, team=TEAM, name="Example Ltd"):
    return (f"Executable=/x\nIdentifier={bid}\nFormat=app bundle with Mach-O universal\n"
            f"Authority=Developer ID Application: {name} ({team})\n"
            "Authority=Developer ID Certification Authority\nAuthority=Apple Root CA\n"
            f"TeamIdentifier={team}\n")


def make_app(parent, folder, bid, version="1.0", build="100", schemes=(), extra=None):
    app = Path(parent) / folder
    (app / "Contents" / "MacOS").mkdir(parents=True)
    pl = {"CFBundleIdentifier": bid, "CFBundleName": folder[:-4], "CFBundleShortVersionString": version,
          "CFBundleVersion": build, "CFBundleExecutable": folder[:-4]}
    if schemes:
        pl["CFBundleURLTypes"] = [{"CFBundleURLSchemes": list(schemes)}]
    with open(app / "Contents" / "Info.plist", "wb") as fh:
        plistlib.dump(pl, fh)
    (app / "Contents" / "MacOS" / folder[:-4]).write_text("binary")
    # a framework with the usual relative links
    fw = app / "Contents" / "Frameworks" / "Lib.framework"
    (fw / "Versions" / "A").mkdir(parents=True)
    (fw / "Versions" / "A" / "Lib").write_text("lib")
    os.symlink("A", fw / "Versions" / "Current")
    os.symlink("Versions/Current/Lib", fw / "Lib")
    if extra:
        extra(app)
    return app


class World:
    """A fake Mac: /Applications, a home, codesign/spctl/... answers by bundle ID."""

    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.apps = self.tmp / "Applications"
        self.apps.mkdir(parents=True)
        self.home = self.tmp / "Users" / "alex"
        (self.home / "Downloads").mkdir(parents=True)
        self.staging = self.tmp / "PaxGuard" / "installs"
        self.sigs: dict = {}            # bundle id -> codesign -dv output
        self.verify_ok: dict = {}       # bundle id -> bool
        self.spctl: dict = {}           # bundle id -> spctl output
        self.images: dict = {}          # image file text -> fixture folder
        self.pkgsig = "Package \"x.pkg\":\n   Status: no signature\n"
        self.pkg_spctl = (0, "x.pkg: accepted\nsource=Apple Installer\n")
        self.su_list = (0, "")
        self.su_install = (0, "Installing Safari\nDone with Safari\nDone.\n")
        self.procs: list = []
        self.commands: list = []
        self.mounted: list = []
        self.installer_out = (0, "installer: The install was successful.")
        self.entries: list = []

    def plist_bid(self, path):
        try:
            with open(Path(path) / "Contents" / "Info.plist", "rb") as fh:
                return plistlib.load(fh).get("CFBundleIdentifier")
        except OSError:
            return None

    def sign(self, bid, team=TEAM, notarised=True, verify=True):
        self.sigs[bid] = dev_sig(bid, team)
        self.verify_ok[bid] = verify
        self.spctl[bid] = ((0, "x: accepted\nsource=Notarized Developer ID\n"
                            f"origin=Developer ID Application: Example Ltd ({team})\n") if notarised
                           else (3, "x: rejected\nsource=Unnotarized Developer ID\n"))

    def run(self, args, stdin=None, timeout=30):
        self.commands.append(list(args))
        tool = args[0]
        if tool == "/usr/bin/ditto":
            def cp(a, b):
                if stat.S_ISFIFO(os.lstat(a).st_mode):
                    os.mkfifo(b)
                else:
                    shutil.copy2(a, b)
            shutil.copytree(args[-2], args[-1], symlinks=True, copy_function=cp)
            return 0, ""
        if tool == "/usr/bin/hdiutil" and args[1] == "attach":
            assert {"-readonly", "-nobrowse", "-noautoopen"} <= set(args)
            mnt = args[args.index("-mountpoint") + 1]
            key = Path(args[-1]).read_text()
            for item in Path(self.images[key]).iterdir():
                if item.is_symlink():
                    os.symlink(os.readlink(item), Path(mnt) / item.name)
                elif item.is_dir():
                    shutil.copytree(item, Path(mnt) / item.name, symlinks=True)
                else:
                    shutil.copy2(item, Path(mnt) / item.name)
            self.mounted.append(mnt)
            return 0, ""
        if tool == "/usr/bin/hdiutil" and args[1] == "detach":
            mnt = args[-1]
            if mnt in self.mounted:
                self.mounted.remove(mnt)
                for item in Path(mnt).iterdir():
                    shutil.rmtree(item) if item.is_dir() and not item.is_symlink() else item.unlink()
            return 0, ""
        if tool == "/usr/bin/codesign" and args[1] == "--verify":
            bid = self.plist_bid(args[-1])
            return (0, "valid on disk") if self.verify_ok.get(bid) else (1, f"{args[-1]}: code object is not signed")
        if tool == "/usr/bin/codesign" and args[1] == "-dv":
            bid = self.plist_bid(args[-1])
            return (0, self.sigs[bid]) if bid in self.sigs else (1, "code object is not signed at all")
        if tool == "/usr/sbin/spctl" and "execute" in args:
            return self.spctl.get(self.plist_bid(args[-1]), (3, "rejected"))
        if tool == "/usr/sbin/spctl" and "install" in args:
            return self.pkg_spctl
        if tool == "/usr/sbin/pkgutil":
            return 0, self.pkgsig
        if tool == "/usr/sbin/installer":
            return self.installer_out
        if tool == "/usr/sbin/softwareupdate" and "--list" in args:
            return self.su_list
        if tool == "/usr/sbin/softwareupdate" and "--install" in args:
            return self.su_install
        return 0, ""          # xattr, chown, chmod

    def processes(self):
        return list(self.procs)

    def installer(self, **kw):
        return ai.AppInstaller(self.run, self.processes, applications=str(self.apps), staging=str(self.staging),
                               state_file=self.tmp / "state" / "installs.json", log=lambda m: None,
                               blocked_entries=lambda: self.entries, require_root_owner=False, **kw)

    def install(self, inst, path, **kw):
        kw.setdefault("roots", [str(self.home), str(self.tmp / "Volumes")])
        kw.setdefault("uid", os.getuid())
        kw.setdefault("allowed_uids", {os.getuid()})
        job = inst.start(str(path), background=False, **kw)
        return inst.job if job else job

    def image(self, name, fixture):
        p = self.home / "Downloads" / name
        p.write_text(name)
        self.images[name] = str(fixture)
        return p

    def checked_paths(self):
        """Every path codesign/spctl/pkgutil looked at."""
        return [c[-1] for c in self.commands if c[0] in ("/usr/bin/codesign", "/usr/sbin/spctl", "/usr/sbin/pkgutil")]


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def installed_version(w, folder):
    with open(w.apps / folder / "Contents" / "Info.plist", "rb") as fh:
        return plistlib.load(fh)["CFBundleShortVersionString"]


# ------------------------------------------------------------------ 1. updates
def test_update_same_team_notarised_installs_without_a_wait(w):
    make_app(w.apps, "Notes Plus.app", "com.example.notes", "1.0")
    new = make_app(w.home / "Downloads", "Notes Plus.app", "com.example.notes", "1.1", "110")
    w.sign("com.example.notes")
    inst = w.installer()
    job = w.install(inst, new)
    assert job["state"] == "updated", job
    assert installed_version(w, "Notes Plus.app") == "1.1"
    # every check ran on the staged copy, never on the user's file or /Applications' new copy
    staged = [p for p in w.checked_paths() if str(w.staging) in p]
    assert staged and all(str(w.home) not in p for p in w.checked_paths())
    # quarantine cleared, made root's, not group/other-writable, before the move
    tools = [c[0] for c in w.commands]
    for t in ("/usr/bin/xattr", "/usr/sbin/chown", "/bin/chmod"):
        c = next(c for c in w.commands if c[0] == t)
        assert str(w.staging) in c[-1]
    assert ["/usr/sbin/chown", "-h", "-R", "root:admin"] == next(c for c in w.commands if c[0] == "/usr/sbin/chown")[:4]
    # the signature is checked again on the root-owned copy that moves in
    verifies = [i for i, c in enumerate(w.commands) if c[:2] == ["/usr/bin/codesign", "--verify"]]
    assert verifies[-1] > tools.index("/bin/chmod") > tools.index("/usr/sbin/chown")
    assert os.listdir(w.staging) == []                       # staging cleaned up
    h = inst.history()[-1]
    assert h["result"] == "updated" and h["bundle_id"] == "com.example.notes" and h["team_id"] == TEAM


def test_update_keeps_the_installed_folder_name(w):
    make_app(w.apps, "Notes.app", "com.example.notes", "1.0")
    new = make_app(w.home / "Downloads", "Notes 2.app", "com.example.notes", "2.0")
    w.sign("com.example.notes")
    job = w.install(w.installer(), new)
    assert job["state"] == "updated" and job["dest"].endswith("/Notes.app")
    assert not (w.apps / "Notes 2.app").exists() and installed_version(w, "Notes.app") == "2.0"


def test_update_from_a_different_team_is_refused_and_nothing_changes(w):
    make_app(w.apps, "Notes.app", "com.example.notes", "1.0")
    w.sign("com.example.notes", team=OTHER)
    old_sig = w.sigs["com.example.notes"]
    new = make_app(w.home / "Downloads", "Notes.app", "com.example.notes", "9.0")
    # the new copy is a properly notarised app from someone else
    w.sigs["com.example.notes"] = dev_sig("com.example.notes", TEAM)
    w.spctl["com.example.notes"] = (0, "x: accepted\nsource=Notarized Developer ID\n")

    def run(args, stdin=None, timeout=30):
        if args[:2] == ["/usr/bin/codesign", "-dv"] and args[-1].startswith(str(w.apps)):
            w.commands.append(list(args))
            return 0, old_sig
        return World.run(w, args, stdin, timeout)
    inst = w.installer()
    inst.run = run
    job = w.install(inst, new)
    assert job["state"] == "refused" and job["code"] == ai.OTHER_DEVELOPER
    assert installed_version(w, "Notes.app") == "1.0"


def test_older_version_running_app_and_update_only_without_install(w):
    make_app(w.apps, "Notes.app", "com.example.notes", "2.0", "200")
    w.sign("com.example.notes")
    old = make_app(w.home / "Downloads", "Notes.app", "com.example.notes", "1.9", "190")
    assert w.install(w.installer(), old)["code"] == ai.OLDER
    shutil.rmtree(old)
    new = make_app(w.home / "Downloads", "Notes.app", "com.example.notes", "2.1", "210")
    w.procs = [(55, f"{w.apps}/Notes.app/Contents/MacOS/Notes")]
    assert w.install(w.installer(), new)["code"] == ai.RUNNING
    w.procs = []
    other = make_app(w.home / "Desktop", "Fresh.app", "com.example.fresh")
    w.sign("com.example.fresh")
    job = w.install(w.installer(), other, update_only=True)
    assert job["state"] == "failed" and job["code"] == ai.FAILED and not (w.apps / "Fresh.app").exists()


def test_a_failed_swap_puts_the_old_copy_back(w, monkeypatch):
    make_app(w.apps, "Notes.app", "com.example.notes", "1.0")
    new = make_app(w.home / "Downloads", "Notes.app", "com.example.notes", "1.1")
    w.sign("com.example.notes")
    real = os.rename
    calls = []

    def flaky(a, b):
        calls.append((a, b))
        if len(calls) == 2:
            raise OSError("disk full")
        return real(a, b)
    monkeypatch.setattr(ai.os, "rename", flaky)
    job = w.install(w.installer(), new)
    assert job["state"] == "failed" and job["code"] == ai.FAILED
    assert installed_version(w, "Notes.app") == "1.0"


# ------------------------------------------------------------------ 2. new apps
def test_new_app_from_a_disk_image_is_installed_and_the_image_detached(w, tmp_path):
    fx = tmp_path / "fx"
    fx.mkdir()
    make_app(fx, "Writer.app", "com.example.writer", "3.0")
    os.symlink("/Applications", fx / "Applications")          # the usual shortcut is ignored
    w.sign("com.example.writer")
    dmg = w.image("Writer-3.0.dmg", fx)
    job = w.install(w.installer(), dmg)
    assert job["state"] == "installed", job
    assert installed_version(w, "Writer.app") == "3.0"
    assert w.mounted == []                                     # detached
    attach = next(c for c in w.commands if c[:2] == ["/usr/bin/hdiutil", "attach"])
    assert attach[-1].startswith(str(w.staging))               # the staged copy of the image, not the user's
    assert any(c[:2] == ["/usr/bin/hdiutil", "detach"] for c in w.commands)


def test_image_with_several_apps_asks_which_then_installs_the_choice(w, tmp_path):
    fx = tmp_path / "fx"
    fx.mkdir()
    make_app(fx, "Alpha.app", "com.example.alpha")
    make_app(fx, "Beta.app", "com.example.beta")
    w.sign("com.example.alpha")
    w.sign("com.example.beta")
    dmg = w.image("Suite.dmg", fx)
    inst = w.installer()
    job = w.install(inst, dmg)
    assert job["code"] == ai.CHOOSE and job["options"] == ["Alpha.app", "Beta.app"]
    assert w.mounted == []
    job = w.install(inst, dmg, choice="Beta.app")
    assert job["state"] == "installed" and (w.apps / "Beta.app").exists() and not (w.apps / "Alpha.app").exists()
    with pytest.raises(ai.InstallError):
        w.install(inst, dmg, choice="../x.app")


@pytest.mark.parametrize("bid,folder,team,label", [
    ("com.philandro.anydesk", "AnyDesk.app", TEAM, "remote-desktop"),
    ("com.teamviewer.TeamViewer", "TeamViewer.app", TEAM, "remote-desktop"),
    ("tv.parsec.www", "Parsec.app", TEAM, "remote-desktop"),
    ("com.example.anything", "RustDesk.app", TEAM, "remote-desktop"),
    ("com.example.vpnclient", "Tunnel.app", "W5364U7YZB", "private network"),      # Tailscale's Team ID
    ("io.tailscale.ipn.macsys", "Tailscale.app", TEAM, "private network"),
    ("com.example.zt", "ZeroTier One.app", TEAM, "private network"),
    ("com.example.nb", "NetBird.app", TEAM, "private network"),
    ("com.zuler.deskin", "DeskIn.app", TEAM, "rented Mac"),
    ("com.nordvpn.NordVPN", "NordVPN.app", TEAM, "VPN"),
    ("org.torproject.torbrowser", "Tor Browser.app", TEAM, "Tor"),
    ("com.example.shadow", "Shadowrocket.app", TEAM, "proxy"),
    ("com.example.clash", "ClashX.app", TEAM, "proxy"),
    ("com.operasoftware.Opera", "Opera.app", TEAM, "browser"),
    ("com.utmapp.UTM", "UTM.app", TEAM, "virtual machine"),
    ("com.openai.chat", "ChatGPT.app", TEAM, "remote computer"),
])
def test_blocked_kinds_are_refused(w, bid, folder, team, label):
    app = make_app(w.home / "Downloads", folder, bid)
    w.sign(bid, team=team)
    job = w.install(w.installer(), app)
    assert job["state"] == "refused" and job["code"] == ai.BLOCKED, job
    assert label.lower() in job["category"].lower(), job["category"]
    assert not (w.apps / folder).exists()


def test_browsers_pax_manages_are_allowed_and_others_refused(w):
    chrome = make_app(w.home / "Downloads", "Google Chrome.app", "com.google.Chrome", schemes=("http", "https"))
    w.sign("com.google.Chrome")
    assert w.install(w.installer(), chrome)["state"] == "installed"
    # any other browser (offers to open web links) is one Pax can't apply rules to, even renamed
    fake = make_app(w.home / "Desktop", "Firefox.app", "com.example.newbrowser", schemes=("https",))
    w.sign("com.example.newbrowser")
    job = w.install(w.installer(), fake)
    assert job["code"] == ai.BLOCKED and "browser" in job["category"]
    # a browser's own name doesn't excuse a blocked bundle ID
    opera = make_app(w.home / "Movies", "Google Chrome.app", "com.operasoftware.Opera", schemes=("http",))
    w.sign("com.operasoftware.Opera")
    job = w.install(w.installer(), opera)
    assert job["code"] == ai.BLOCKED and "browser" in job["category"]


def test_the_users_own_blocked_apps_are_refused(w):
    w.entries = [{"bundle_id": "com.example.game", "name": "Game", "signing_id": "com.example.game",
                  "team_id": TEAM, "executable": "Game"}]
    app = make_app(w.home / "Downloads", "Game.app", "com.example.game")
    w.sign("com.example.game")
    job = w.install(w.installer(), app)
    assert job["code"] == ai.BLOCKED and job["category"] == "an app you blocked"


def test_name_taken_by_another_app(w):
    make_app(w.apps, "Writer.app", "com.other.writer")
    app = make_app(w.home / "Downloads", "Writer.app", "com.example.writer")
    w.sign("com.example.writer")
    job = w.install(w.installer(), app)
    assert job["code"] == ai.NAME_TAKEN
    assert w.plist_bid(w.apps / "Writer.app") == "com.other.writer"


# ------------------------------------------------------------------ signatures
def test_unsigned_ad_hoc_and_unnotarised_apps_are_refused(w):
    a = make_app(w.home / "Downloads", "A.app", "com.example.a")
    w.sign("com.example.a", verify=False)
    assert w.install(w.installer(), a)["code"] == ai.NOT_SIGNED
    b = make_app(w.home / "Downloads", "B.app", "com.example.b")
    w.sign("com.example.b")
    w.sigs["com.example.b"] = "Identifier=com.example.b\nSignature=adhoc\nTeamIdentifier=not set\n"
    assert w.install(w.installer(), b)["code"] == ai.NOT_SIGNED
    c = make_app(w.home / "Downloads", "C.app", "com.example.c")
    w.sign("com.example.c", notarised=False)
    assert w.install(w.installer(), c)["code"] == ai.NOT_NOTARISED
    d = make_app(w.home / "Downloads", "D.app", "com.example.d")
    w.sign("com.example.d")
    w.sigs["com.example.d"] = dev_sig("com.example.other")       # signature for another bundle ID
    assert w.install(w.installer(), d)["code"] == ai.NOT_SIGNED
    e = make_app(w.home / "Downloads", "E.app", "com.example.e")
    w.sign("com.example.e")
    w.sigs["com.example.e"] = ("Identifier=com.example.e\nAuthority=Apple Development: me (ABCDE12345)\n"
                               "Authority=Apple Worldwide Developer Relations Certification Authority\n"
                               "Authority=Apple Root CA\nTeamIdentifier=ABCDE12345\n")
    assert w.install(w.installer(), e)["code"] == ai.NOT_SIGNED
    assert list(w.apps.iterdir()) == []


def test_pax_apple_and_system_apps_are_never_touched(w):
    pax = make_app(w.home / "Downloads", "Pax Copy.app", "org.paxpeace.pax")
    w.sign("org.paxpeace.pax")
    assert w.install(w.installer(), pax)["code"] == ai.UNTOUCHABLE
    paxteam = make_app(w.home / "Downloads", "Helper.app", "com.example.helper")
    w.sign("com.example.helper", team="Z94GSK7JA8")
    assert w.install(w.installer(), paxteam)["code"] == ai.UNTOUCHABLE
    named = make_app(w.home / "Desktop", "Pax.app", "com.example.pax")
    w.sign("com.example.pax")
    assert w.install(w.installer(), named)["code"] == ai.UNTOUCHABLE
    apple = make_app(w.home / "Downloads", "Keynote.app", "com.apple.iWork.Keynote")
    w.sign("com.apple.iWork.Keynote")
    assert w.install(w.installer(), apple)["code"] == ai.UNTOUCHABLE
    signed_by_apple = make_app(w.home / "Downloads", "Tool.app", "com.example.tool")
    w.sign("com.example.tool")
    w.sigs["com.example.tool"] = "Identifier=com.example.tool\nAuthority=Software Signing\nTeamIdentifier=not set\n"
    assert w.install(w.installer(), signed_by_apple)["code"] == ai.UNTOUCHABLE


# ------------------------------------------------------------------ untrusted requests
def test_request_paths_are_checked(w, tmp_path):
    inst = w.installer()
    app = make_app(w.home / "Downloads", "Ok.app", "com.example.ok")
    w.sign("com.example.ok")
    bad = ["Ok.app", f"{w.home}/Downloads/../Downloads/Ok.app", f"{w.home}//Downloads/Ok.app",
           "/System/Applications/Safari.app", f"{w.apps}/Ok.app", f"{w.home}/Downloads/Ok.zip",
           "", "x" * 2000, f"{w.home}/Downloads/Ok.app\x00"]
    for p in bad:
        with pytest.raises(ai.InstallError) as e:
            inst.start(p, roots=[str(w.home)], uid=os.getuid(), allowed_uids={os.getuid()}, background=False)
        assert e.value.code == ai.BAD_FILE, p
    # a link to an app, or a path through a linked folder
    os.symlink(app, w.home / "Downloads" / "Link.app")
    os.symlink(w.home / "Downloads", w.home / "dl")
    for p in (w.home / "Downloads" / "Link.app", w.home / "dl" / "Ok.app"):
        with pytest.raises(ai.InstallError) as e:
            inst.start(str(p), roots=[str(w.home)], uid=os.getuid(), allowed_uids={os.getuid()}, background=False)
        assert e.value.code == ai.BAD_FILE
    # someone else asking
    with pytest.raises(ai.InstallError) as e:
        inst.start(str(app), roots=[str(w.home)], uid=777, allowed_uids={os.getuid()}, background=False)
    assert e.value.code == ai.BAD_FILE
    with pytest.raises(ai.InstallError):
        inst.start(str(app), roots=[str(w.home)], uid=None, allowed_uids={os.getuid()}, background=False)
    assert list(w.apps.iterdir()) == []


def test_a_file_the_asker_cant_read_is_refused(w):
    app = make_app(w.home / "Downloads", "Ok.app", "com.example.ok")
    os.chmod(app, 0o700)
    inst = w.installer()
    # pretend the asker is another (allowed) account: the folder isn't theirs or world-readable
    with pytest.raises(ai.InstallError) as e:
        inst.start(str(app), roots=[str(w.home)], uid=4242, allowed_uids={4242}, background=False)
    assert e.value.code == ai.BAD_FILE


def _escape_abs(app):
    os.symlink("/etc/passwd", app / "Contents" / "Resources")


def _escape_rel(app):
    os.symlink("../../../../../../etc", app / "Contents" / "Shared")


def _setuid(app):
    p = app / "Contents" / "MacOS" / "helper"
    p.write_text("x")
    os.chmod(p, 0o4755)


def _fifo(app):
    os.mkfifo(app / "Contents" / "pipe")


@pytest.mark.parametrize("extra", [_escape_abs, _escape_rel, _setuid, _fifo])
def test_unsafe_bundles_are_refused(w, extra):
    app = make_app(w.home / "Downloads", "Odd.app", "com.example.odd", extra=extra)
    w.sign("com.example.odd")
    job = w.install(w.installer(), app)
    assert job["state"] == "refused" and job["code"] == ai.UNSAFE, job
    assert not (w.apps / "Odd.app").exists()


def test_the_staged_copy_is_what_gets_checked_and_installed(w):
    """Swapping the user's copy after the request (TOCTOU) changes nothing: the
    staged copy was made first and is the only one checked and moved."""
    app = make_app(w.home / "Downloads", "Safe.app", "com.example.safe", "1.0")
    w.sign("com.example.safe")
    inst = w.installer()
    real_ditto = World.run

    def run(args, stdin=None, timeout=30):
        out = real_ditto(w, args, stdin, timeout)
        if args[0] == "/usr/bin/ditto":
            # after the copy, the user replaces their file with a different app
            shutil.rmtree(app)
            make_app(app.parent, "Safe.app", "com.example.evil", "6.6")
        return out
    inst.run = run
    job = w.install(inst, app)
    assert job["state"] == "installed"
    assert w.plist_bid(w.apps / "Safe.app") == "com.example.safe"


def test_one_job_at_a_time(w):
    app = make_app(w.home / "Downloads", "Slow.app", "com.example.slow")
    w.sign("com.example.slow")
    inst = w.installer()
    inst.job = {"id": 9, "state": "working"}
    with pytest.raises(ai.InstallError) as e:
        w.install(inst, app)
    assert e.value.code == ai.BUSY


def test_missing_or_broken_deny_list_fails_closed(w, tmp_path):
    app = make_app(w.home / "Downloads", "Fine.app", "com.example.fine")
    w.sign("com.example.fine")
    job = w.install(w.installer(deny_file=tmp_path / "nope.txt"), app)
    assert job["state"] == "failed" and not (w.apps / "Fine.app").exists()
    bad = tmp_path / "bad.txt"
    bad.write_text("[x] y\nbundel com.typo\n")
    job = w.install(w.installer(deny_file=bad), app)
    assert job["state"] == "failed" and not (w.apps / "Fine.app").exists()


def test_unexpected_errors_fail_closed(w):
    app = make_app(w.home / "Downloads", "Boom.app", "com.example.boom")
    w.sign("com.example.boom")
    inst = w.installer()

    def boom(*a, **k):
        raise RuntimeError("surprise")
    inst.destination = boom
    job = w.install(inst, app)
    assert job["state"] == "failed" and job["code"] == ai.FAILED
    assert not (w.apps / "Boom.app").exists() and os.listdir(w.staging) == []


# ------------------------------------------------------------------ 3. packages
def test_packages_are_refused_unless_apple_signed(w, tmp_path):
    pkg = w.home / "Downloads" / "Tool.pkg"
    pkg.write_bytes(b"xar!")
    w.pkgsig = ("Package \"Tool.pkg\":\n   Status: signed by a developer certificate issued by Apple for distribution\n"
                "   Notarization: trusted by the Apple notary service\n   Certificate Chain:\n"
                "    1. Developer ID Installer: Example Ltd (ABCDE12345)\n"
                "    2. Developer ID Certification Authority\n    3. Apple Root CA\n")
    job = w.install(w.installer(), pkg)
    assert job["code"] == ai.PACKAGE
    assert not any(c[0] == "/usr/sbin/installer" for c in w.commands)
    w.pkgsig = ("Package \"Tool.pkg\":\n   Status: signed Apple Software\n   Certificate Chain:\n"
                "    1. Software Update\n       Expires: 2027-01-01\n       SHA256 Fingerprint:\n"
                "           AA BB\n    2. Apple Software Update Certification Authority\n"
                "    3. Apple Root CA\n")
    job = w.install(w.installer(), pkg)
    assert job["state"] == "installed", job
    inst_cmd = next(c for c in w.commands if c[0] == "/usr/sbin/installer")
    assert inst_cmd[2].startswith(str(w.staging)) and inst_cmd[-2:] == ["-target", "/"]
    # a package inside a disk image goes the same way
    fx = tmp_path / "fx"
    fx.mkdir()
    (fx / "Other.pkg").write_bytes(b"xar!")
    w.pkgsig = "Package: \n   Status: no signature\n"
    assert w.install(w.installer(), w.image("Other.dmg", fx))["code"] == ai.PACKAGE
    # a folder-style package can't be checked
    (w.home / "Downloads" / "Old.pkg").mkdir()
    with pytest.raises(ai.InstallError) as e:
        w.install(w.installer(), w.home / "Downloads" / "Old.pkg")
    assert e.value.code == ai.PACKAGE


def test_pkg_signature_parsing():
    apple = ("   Status: signed Apple Software\n   Certificate Chain:\n    1. Software Update\n"
             "    2. Apple Software Update Certification Authority\n    3. Apple Root CA\n")
    assert ai.parse_pkg_signature(apple)["apple"]
    assert not ai.parse_pkg_signature(apple.replace("signed Apple Software", "signed by a developer certificate"))["apple"]
    assert not ai.parse_pkg_signature(apple.replace("1. Software Update", "1. Developer ID Installer: X (T)"))["apple"]
    assert not ai.parse_pkg_signature(apple.replace("3. Apple Root CA", "3. Evil Root"))["apple"]
    assert not ai.parse_pkg_signature("")["apple"]


# ------------------------------------------------------------------ 1(b) downloaded updates
def test_downloaded_updates_are_found_in_sparkle_and_shipit_caches(w):
    make_app(w.apps, "Chat.app", "com.example.chat", "1.0", "10")
    make_app(w.apps, "Edit.app", "com.example.edit", "4.0", "40")
    caches = w.home / "Library" / "Caches"
    make_app(caches / "com.example.chat.ShipIt" / "update.abc", "Chat.app", "com.example.chat", "1.2", "12")
    make_app(caches / "com.example.edit" / "org.sparkle-project.Sparkle" / "Installation" / "x",
             "Edit.app", "com.example.edit", "3.9", "39")                       # older: not offered
    make_app(caches / "com.example.other.ShipIt" / "u", "Other.app", "com.example.other", "9")   # not installed
    found = w.installer().downloaded_updates(str(w.home))
    assert [(f["bundle_id"], f["version"], f["installed_version"]) for f in found] == [("com.example.chat", "1.2", "1.0")]
    # installing it goes through every check, as an update only
    w.sign("com.example.chat")
    job = w.install(w.installer(), found[0]["path"], update_only=True)
    assert job["state"] == "updated" and installed_version(w, "Chat.app") == "1.2"


# ------------------------------------------------------------------ 4. Apple software updates
SU_LIST = """Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: Safari18.1VenturaAuto-18.1
\tTitle: Safari, Version: 18.1, Size: 166428KiB, Recommended: YES,
* Label: macOS Ventura 13.7.1-22H221
\tTitle: macOS Ventura 13.7.1, Version: 13.7.1, Size: 1023456KiB, Recommended: YES, Action: restart,
"""


def test_softwareupdate_list_parsing_and_install_never_restarts(w):
    items = ai.parse_softwareupdate_list(SU_LIST)
    assert [i["label"] for i in items] == ["Safari18.1VenturaAuto-18.1", "macOS Ventura 13.7.1-22H221"]
    assert items[1]["restart"] and not items[0]["restart"]
    w.su_list = (0, SU_LIST)
    inst = w.installer()
    inst.su_check(background=False)
    assert len(inst.su["updates"]) == 2
    with pytest.raises(ai.InstallError) as e:
        inst.su_install("Something; rm -rf /", background=False)
    assert e.value.code == ai.SU_INSTALL
    with pytest.raises(ai.InstallError):
        inst.su_install("NotInTheList-1.0", background=False)
    w.su_install = (0, "Downloading macOS Ventura\nDone.\nPlease restart immediately.\n")
    st = inst.su_install("macOS Ventura 13.7.1-22H221", background=False)
    cmd = next(c for c in w.commands if "--install" in c)
    assert cmd == ["/usr/sbin/softwareupdate", "--install", "macOS Ventura 13.7.1-22H221", "--agree-to-license"]
    assert not any(a in cmd for a in ("--restart", "-R", "-r"))
    assert st["restart_needed"] and [u["label"] for u in st["updates"]] == ["Safari18.1VenturaAuto-18.1"]


def test_softwareupdate_wanting_an_owner_is_reported_not_worked_around(w):
    w.su_list = (0, SU_LIST)
    w.su_install = (1, "Authenticating as a volume owner is required to install this update.\n")
    inst = w.installer()
    inst.su_check(background=False)
    st = inst.su_install("Safari18.1VenturaAuto-18.1", background=False)
    assert st["code"] == ai.SU_ADMIN
    assert not any("--user" in c or "--stdinpass" in c for c in w.commands)
    w.su_list = (1, "Network error")
    assert inst.su_check(background=False)["code"] == ai.SU_CHECK


# ------------------------------------------------------------------ helpers
def test_spctl_and_codesign_parsing_and_versions():
    sp = ai.parse_spctl("/x.app: accepted\nsource=Notarized Developer ID\n"
                        "origin=Developer ID Application: Example Ltd (ABCDE12345)\n")
    assert sp == {"accepted": True, "source": "Notarized Developer ID", "origin_team": "ABCDE12345"}
    assert not ai.parse_spctl("/x.app: rejected\nsource=Unnotarized Developer ID\n")["accepted"]
    sig = ai.parse_codesign_details(dev_sig("com.example.a"))
    assert ai.developer_id_problem(sig) is None and sig["team_id"] == TEAM
    assert ai.developer_id_problem(ai.parse_codesign_details("Identifier=x\nTeamIdentifier=not set\n"))
    assert ai.is_older("1.9", "", "2.0", "") and not ai.is_older("2.0", "", "2.0", "")
    assert ai.is_older("2.0", "5", "2.0", "6") and not ai.is_older("beta", "", "2.0", "")
    assert not ai.safe_app_name(".hidden.app") and not ai.safe_app_name("a/b.app") and ai.safe_app_name("Ok.app")
    assert not ai.safe_app_name("Pax.app")


def test_deny_list_parses_and_never_names_what_pax_allows():
    cats = ai.load_deny()
    ids = {c.cid for c in cats}
    assert {"remote_desktop", "rented_mac", "mesh_vpn", "proxy"} <= ids
    every = set().union(*(c.bundles for c in cats)) | set().union(*(c.names for c in cats))
    for allowed in ("com.google.chrome", "org.mozilla.firefox", "google chrome", "firefox", "safari",
                    "1password", "bitwarden", "pax", "zoom.us", "slack"):
        assert allowed not in every
    for c in cats:
        for p in c.prefixes:
            assert not "com.google.chrome.".startswith(p) and not p.startswith(("com.apple.", "org.paxpeace."))
    with pytest.raises(ValueError):
        ai.parse_deny("bundle com.x\n")
    with pytest.raises(ValueError):
        ai.parse_deny("[a] b\nteam lowercase\n")


# ------------------------------------------------------------------ pax-guard's socket
def test_guard_socket_commands(tmp_path, monkeypatch):
    from test_v08_guard import local_guard
    g, _ = local_guard(tmp_path)
    w = World(tmp_path / "world")
    inst = w.installer()
    monkeypatch.setattr(g, "installer", lambda: inst)
    r = g.handle_request({"cmd": "installs.status"}, 501)
    assert r["ok"] and r["job"] is None
    # nobody the guard can map to a local account
    monkeypatch.setattr(g, "install_home", lambda uid: None)
    r = g.handle_request({"cmd": "installs.start", "path": "/x.app"}, 501)
    assert not r["ok"] and r["code"] == ai.BAD_FILE
    monkeypatch.setattr(g, "install_home", lambda uid: str(w.home))
    app = make_app(w.home / "Downloads", "Calm.app", "com.example.calm")
    w.sign("com.example.calm")
    r = g.handle_request({"cmd": "installs.start", "path": str(app)}, os.getuid())
    assert r["ok"] and r["job"]["state"] == "working"
    for _ in range(200):
        if inst.job["state"] != "working":
            break
        time.sleep(0.02)
    assert g.handle_request({"cmd": "installs.status"}, 501)["job"]["state"] == "installed"
    r = g.handle_request({"cmd": "installs.start", "path": "relative.app"}, os.getuid())
    assert not r["ok"] and r["code"] == ai.BAD_FILE
    r = g.handle_request({"cmd": "system_updates.install", "label": "x"}, os.getuid())
    assert not r["ok"] and r["code"] == ai.SU_INSTALL
    assert g.handle_request({"cmd": "installs.updates"}, os.getuid())["updates"] == []


def test_install_home_maps_only_local_accounts(tmp_path, monkeypatch):
    from test_v08_guard import local_guard
    import pwd
    g, s = local_guard(tmp_path)

    class PW:
        def __init__(self, uid, home):
            self.pw_uid, self.pw_dir = uid, home
    table = {501: PW(501, "/Users/alex"), 1: PW(1, "/var/root"), 600: PW(600, "/private/tmp/x")}
    monkeypatch.setattr(pwd, "getpwuid", lambda u: table[u] if u in table else (_ for _ in ()).throw(KeyError(u)))
    monkeypatch.setattr(s, "exists", lambda p: True, raising=False)
    assert g.install_home(501) == "/Users/alex"
    assert g.install_home(1) is None and g.install_home(600) is None and g.install_home(9999) is None
    assert g.install_home(None) is None


def test_shipped_with_the_app_and_the_guard():
    repo = HERE.parent.parent
    dmg = (repo / "mac-app" / "scripts" / "build-dmg.sh").read_text()
    inst = (repo / "guard" / "scripts" / "pax-guard-install.sh").read_text()
    assert "guard/app_installs.py" in dmg and "guard/app-install-deny.txt" in dmg
    assert "app_installs.py app-install-deny.txt" in inst
    src = (repo / "guard" / "pax_guard.py").read_text()
    assert '"app_installs"' in src and "app_installs.load_deny()" in src
