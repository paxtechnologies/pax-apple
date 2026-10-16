# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.7: the Mac's own Blocked apps, kept and enforced by pax-guard.

Adding is instant (the app is closed and put away). Unblocking is a loosening:
it goes through exactly the path unblocking a site does (your wait, partner
told first, fail closed, cancellable). An app is recognised by its bundle ID and
the identifier and Team ID sealed in its code signature, so renaming, copying
or editing a copy's Info.plist doesn't get round it. Pax, Apple's own apps and
password managers can never be blocked."""
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import guard_config as gc  # noqa: E402
import local_blocklist as lb  # noqa: E402
from test_v08_guard import NetSystem, local_guard  # noqa: E402

GAME = "/Applications/Game.app"


class AppSystem(NetSystem):
    """Apps with Info.plists and code signatures."""

    def __init__(self, tmp):
        super().__init__(tmp)
        self.plists: dict[str, dict] = {}
        self.signatures: dict[str, str] = {}

    def add_app(self, path, bundle_id, name=None, team="TEAM123456", signing_id=None, exe=None, apple=False):
        self.apps[path] = bundle_id
        self.plists[path] = {"CFBundleIdentifier": bundle_id, "CFBundleName": name or Path(path).stem,
                             "CFBundleExecutable": exe or Path(path).stem}
        sig = [f"Executable={path}/Contents/MacOS/x", f"Identifier={signing_id or bundle_id}",
               f"TeamIdentifier={team or 'not set'}"]
        if apple:
            sig.append("Authority=Software Signing")
        self.signatures[path] = "\n".join(sig) + "\n"

    def move(self, src, dst):
        self.moved.append((src, dst))
        for d in (self.apps, self.plists, self.signatures):
            if src in d:
                d[dst] = d.pop(src)

    def app_plist(self, app_path):
        return dict(self.plists.get(app_path, {}))

    def run(self, args, stdin=None, timeout=30):
        if args[:2] == ["/usr/bin/codesign", "-dv"]:
            self.commands.append(args)
            return 0, self.signatures.get(args[-1], "code object is not signed at all\n")
        return super().run(args, stdin, timeout)


def guard(tmp_path, **cfg):
    g, _ = local_guard(tmp_path, **cfg)
    s = AppSystem(tmp_path)
    g.sys = s
    g.escrow.clock = s.now
    g.blocklist.clock = s.now
    s.add_app(GAME, "com.example.game", "Game", exe="Game")
    return g, s


def ask(g, cmd, **kw):
    return g.handle_request({"cmd": cmd, **kw}, 501)


# ------------------------------------------------------------------ adding
def test_adding_is_instant_closes_and_puts_away(tmp_path):
    g, s = guard(tmp_path)
    s.procs = [(77, f"{GAME}/Contents/MacOS/Game"), (78, f"{GAME}/Contents/Frameworks/Game Helper.app/Contents/MacOS/Game Helper"),
               (79, "/Applications/Safari.app/Contents/MacOS/Safari")]
    r = ask(g, "apps.add", path=GAME)
    assert r["ok"] and r["created"] and r["apps"]["apps"][0]["name"] == "Game"
    assert sorted(s.killed) == [77, 78]
    assert any(src == GAME for src, _ in s.moved) and GAME not in s.apps
    q = g._load_json("quarantine.json", [])
    assert q[-1]["kind"] == "user" and q[-1]["bundle_id"] == "com.example.game"
    entry = g.blocklist.apps()["com.example.game"]
    assert entry["team_id"] == "TEAM123456" and entry["signing_id"] == "com.example.game"


def test_renamed_or_copied_copies_are_still_blocked(tmp_path):
    g, s = guard(tmp_path)
    ask(g, "apps.add", path=GAME)
    s.killed.clear()
    # Renamed and copied into Documents (not a folder pax-guard scans): closed when it runs.
    copy = "/Users/alex/Documents/Totally Work.app"
    s.add_app(copy, "com.example.game", "Totally Work")
    s.procs = [(90, f"{copy}/Contents/MacOS/Game")]
    g.cycle()
    assert 90 in s.killed and any(src == copy for src, _ in s.moved)


def test_a_copy_with_an_edited_bundle_id_is_caught_by_its_signature(tmp_path):
    g, s = guard(tmp_path)
    ask(g, "apps.add", path=GAME)
    edited = "/Users/alex/Desktop/Notes.app"
    # Info.plist says Apple; the sealed signature still says it's the game.
    s.add_app(edited, "com.apple.Notes", "Notes", signing_id="com.example.game", team="TEAM123456")
    s.procs = [(91, f"{edited}/Contents/MacOS/Game")]
    g.enforce_user_apps()
    assert 91 in s.killed


def test_an_ad_hoc_re_signed_copy_is_caught_by_identifier_or_program_name(tmp_path):
    g, s = guard(tmp_path)
    ask(g, "apps.add", path=GAME)
    same_id = "/Users/alex/Downloads/G1.app"
    s.add_app(same_id, "org.other.g1", "G1", signing_id="com.example.game", team="")
    new_id = "/Users/alex/Downloads/G2.app"
    s.add_app(new_id, "org.other.g2", "G2", signing_id="org.other.g2", team="", exe="Game")
    s.procs = [(92, f"{same_id}/Contents/MacOS/x"), (93, f"{new_id}/Contents/MacOS/Game")]
    g.enforce_user_apps()
    assert {92, 93} <= set(s.killed)


def test_other_apps_and_other_vendors_are_left_alone(tmp_path):
    g, s = guard(tmp_path)
    ask(g, "apps.add", path=GAME)
    other = "/Applications/Other.app"
    # Same signing identifier from a different vendor: not the blocked app.
    s.add_app(other, "org.other.app", "Other", signing_id="com.example.game", team="OTHERTEAM1", exe="Game")
    s.procs = [(94, f"{other}/Contents/MacOS/Game")]
    g.enforce_user_apps()
    assert 94 not in s.killed and other in s.apps


def test_never_blocks_pax_apple_or_password_managers(tmp_path):
    g, s = guard(tmp_path)
    s.add_app("/Applications/Pax.app", "org.paxmobile.pax", "Pax", team=gc.PAX_TEAM_ID)
    s.add_app("/Applications/Safari.app", "com.apple.Safari", "Safari", team="", apple=True)
    s.add_app("/Applications/Bitwarden.app", "com.bitwarden.desktop", "Bitwarden")
    s.add_app("/Applications/1Password.app", "com.1password.1password", "1Password")
    s.add_app("/Applications/Vault Beta.app", "com.example.vaultbeta", "KeePassXC Beta")
    for path in ("/Applications/Pax.app", "/Applications/Safari.app", "/Applications/Bitwarden.app",
                 "/Applications/1Password.app", "/Applications/Vault Beta.app"):
        r = ask(g, "apps.add", path=path)
        assert r["ok"] is False and r["code"] == "PAX-MAC-016", path
    assert g.blocklist.apps() == {}
    # An Apple-signed program is never closed, even if a blocked entry matched it somehow.
    ident = gc.AppIdentity(path="/System/Applications/Notes.app", bundle_id="com.example.game", apple=True)
    assert not gc.app_matches(ident, {"bundle_id": "com.example.game"})


def test_only_apps_in_applications_can_be_added(tmp_path):
    g, s = guard(tmp_path)
    s.add_app("/Users/alex/Downloads/X.app", "com.example.x", "X")
    for path in ("/Users/alex/Downloads/X.app", "/Applications/Nope.app", "/etc/hosts", "/Applications/../tmp/a.app"):
        r = ask(g, "apps.add", path=path)
        assert r["ok"] is False and r["code"] == "PAX-MAC-017", path
    s.add_app("/Users/alex/Applications/Y.app", "com.example.y", "Y")
    assert ask(g, "apps.add", path="/Users/alex/Applications/Y.app")["ok"]


def test_list_is_capped(tmp_path):
    g, s = guard(tmp_path)
    for i in range(lb.MAX_APPS):
        g.blocklist.add_app({"bundle_id": f"com.example.a{i}", "name": f"A{i}"})
    r = ask(g, "apps.add", path=GAME)
    assert r["ok"] is False and r["code"] == "PAX-MAC-017"


# -------------------------------------------------------------- unblocking
def test_unblocking_waits_like_a_site_and_puts_the_app_back(tmp_path):
    g, s = guard(tmp_path)
    ask(g, "apps.add", path=GAME)
    wait = g._wait_seconds()
    r = ask(g, "apps.unblock", bundle_id="com.example.game")
    assert r["ok"] and r["request"]["action"] == "unblock_app" and r["request"]["display_domain"] == "Game"
    assert r["request"]["seconds_remaining"] == wait
    # Still blocked during the wait, and the site list's view doesn't show app requests.
    assert "com.example.game" in g.blocklist.apps()
    assert g.blocklist.view()["pending"] == []
    assert r["apps"]["apps"][0]["pending_removal"]["request_id"] == r["request"]["request_id"]
    s.t += wait + 1
    g.cycle()
    assert g.blocklist.apps() == {}
    assert GAME in s.apps                                         # put back where it was
    assert not [q for q in g._load_json("quarantine.json", []) if q.get("kind") == "user"]


def test_cancelling_and_re_adding_keep_it_blocked(tmp_path):
    g, s = guard(tmp_path)
    ask(g, "apps.add", path=GAME)
    r = ask(g, "apps.unblock", bundle_id="com.example.game")
    out = ask(g, "apps.cancel", request_id=r["request"]["request_id"])
    assert out["ok"] and out["apps"]["pending"] == []
    ask(g, "apps.unblock", bundle_id="com.example.game")
    g.blocklist.add_app({"bundle_id": "com.example.game", "name": "Game"})       # blocking again cancels
    assert g.blocklist.apps_view()["pending"] == []
    s.t += 10 * 24 * 3600
    g.cycle()
    assert "com.example.game" in g.blocklist.apps()


class FailingPartner:
    def __init__(self):
        self.gates = []

    def partner(self):
        return "partner@example.com"

    def notify(self, kind, subject, own, theirs, gate=None):
        self.gates.append(gate)
        return False                      # couldn't tell the partner

    def drop_gate(self, gate):
        pass


def test_unblocking_fails_closed_when_the_partner_cant_be_told(tmp_path):
    g, s = guard(tmp_path)
    ask(g, "apps.add", path=GAME)
    g.blocklist.partner = FailingPartner()
    r = ask(g, "apps.unblock", bundle_id="com.example.game")
    assert r["ok"] is False and r["code"] == "PAX-ESCROW-010"
    s.t += 30 * 24 * 3600
    g.cycle()
    assert "com.example.game" in g.blocklist.apps()             # never started, never applied
    v = g.blocklist.apps_view()
    assert v["pending"][0]["status"] == "notifying"


def test_server_escrow_has_no_app_list(tmp_path):
    g, s = guard(tmp_path)
    g.cfg.escrow_mode = "server"
    r = ask(g, "apps.get")
    assert r["ok"] is False and r["code"] == "PAX-ESCROW-009"
    assert g.enforce_user_apps() == []


def test_unknown_app_unblock_and_get(tmp_path):
    g, s = guard(tmp_path)
    r = ask(g, "apps.unblock", bundle_id="com.example.none")
    assert r["ok"] is False and r["code"] == "PAX-MAC-017"
    assert ask(g, "apps.get")["apps"]["limits"]["max_apps"] == lb.MAX_APPS


def test_nothing_is_listed_or_signed_while_the_list_is_empty(tmp_path):
    g, s = guard(tmp_path)
    s.procs = [(1, f"{GAME}/Contents/MacOS/Game")]
    assert g.kill_user_apps() == []
    g.enforce_user_apps()
    assert not [c for c in s.commands if c[:1] == ["/usr/bin/codesign"]]


def test_identity_is_cached_and_read_fresh_when_adding(tmp_path):
    g, s = guard(tmp_path)
    a = g.app_identity(GAME)
    s.signatures[GAME] = s.signatures[GAME].replace("TEAM123456", "NEWTEAM999")
    assert g.app_identity(GAME) is a
    assert g.app_identity(GAME, fresh=True).team_id == "NEWTEAM999"


def test_parse_codesign():
    out = ("Executable=/Applications/X.app/Contents/MacOS/X\nIdentifier=com.example.x\nFormat=app bundle\n"
           "Authority=Developer ID Application: Example (ABCDE12345)\nTeamIdentifier=ABCDE12345\n")
    assert gc.parse_codesign(out) == {"signing_id": "com.example.x", "team_id": "ABCDE12345", "apple": False}
    adhoc = "Identifier=x\nSignature=adhoc\nTeamIdentifier=not set\n"
    assert gc.parse_codesign(adhoc)["team_id"] == ""
    assert gc.parse_codesign("Identifier=com.apple.Safari\nAuthority=Software Signing\n")["apple"] is True


def test_rules_match_the_iphone_picker():
    sys.path.insert(0, str(HERE.parents[1] / "profile"))
    import app_blocks
    assert set(app_blocks.PASSWORD_MANAGER_BUNDLE_IDS) == set(gc.PASSWORD_MANAGER_BUNDLE_IDS)
    assert tuple(app_blocks.PASSWORD_MANAGER_NAMES) == tuple(gc.PASSWORD_MANAGER_NAMES)
    assert tuple(app_blocks.NEVER_BLOCK_PREFIXES) == tuple(gc.NEVER_BLOCK_APP_PREFIXES)
    assert app_blocks.MAX_CUSTOM_APP_BLOCKS == gc.MAX_BLOCKED_APPS == lb.MAX_APPS


def test_swift_rules_match_too():
    swift = (HERE.parents[1] / "mac-app" / "Sources" / "PaxCore" / "AppBlocks.swift").read_text()
    for bid in gc.PASSWORD_MANAGER_BUNDLE_IDS:
        assert f'"{bid}"' in swift, bid
    for n in gc.PASSWORD_MANAGER_NAMES:
        assert f'"{n}"' in swift, n


@pytest.mark.parametrize("cmd", ["apps.get", "apps.add", "apps.unblock", "apps.cancel"])
def test_ipc_doc_lists_the_app_commands(cmd):
    import guard_ipc
    assert cmd in guard_ipc.__doc__
