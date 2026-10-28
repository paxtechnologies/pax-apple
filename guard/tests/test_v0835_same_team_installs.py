# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.35 (Ruben, 28 Oct 2026): PAX-MAC-023 ("Pax doesn't change this app") protects only Pax
itself: a Pax bundle ID (org.paxpeace. / org.paxmobile.), the name Pax.app, or an installed
/Applications/Pax.app. Other apps signed by Pax's developer team (Swoop, com.swoopkey.swoop) go
through every normal check and install or update like any other notarised Developer ID app."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import app_installs as ai  # noqa: E402
from test_v0833_installs import World, make_app, installed_version, dev_sig, w  # noqa: E402,F401

PAX_TEAM = ai.PAX_TEAM_ID


def test_same_team_app_like_swoop_installs(w):
    swoop = make_app(w.home / "Downloads", "Swoop.app", "com.swoopkey.swoop", "1.2", "12")
    w.sign("com.swoopkey.swoop", team=PAX_TEAM)
    inst = w.installer()
    job = w.install(inst, swoop)
    assert job["state"] == "installed", job
    assert installed_version(w, "Swoop.app") == "1.2"
    h = inst.history()[-1]
    assert h["bundle_id"] == "com.swoopkey.swoop" and h["team_id"] == PAX_TEAM
    # the normal checks all ran on the staged copy: codesign strict, Gatekeeper
    cmds = [c[:2] for c in w.commands]
    assert ["/usr/bin/codesign", "--verify"] in cmds and ["/usr/sbin/spctl", "--assess"] in cmds


def test_same_team_app_updates_under_the_same_team_rule(w):
    make_app(w.apps, "Swoop.app", "com.swoopkey.swoop", "1.0", "10")
    new = make_app(w.home / "Downloads", "Swoop.app", "com.swoopkey.swoop", "1.1", "11")
    w.sign("com.swoopkey.swoop", team=PAX_TEAM)
    job = w.install(w.installer(), new)
    assert job["state"] == "updated", job
    assert installed_version(w, "Swoop.app") == "1.1"


def test_same_team_app_from_a_dmg_installs(w, tmp_path):
    fixture = tmp_path / "img"
    fixture.mkdir()
    make_app(fixture, "Swoop.app", "com.swoopkey.swoop", "2.0")
    w.sign("com.swoopkey.swoop", team=PAX_TEAM)
    job = w.install(w.installer(), w.image("Swoop-2.0.dmg", fixture))
    assert job["state"] == "installed", job


def test_same_team_app_still_needs_notarisation_and_a_valid_signature(w):
    a = make_app(w.home / "Downloads", "Swoop.app", "com.swoopkey.swoop")
    w.sign("com.swoopkey.swoop", team=PAX_TEAM, notarised=False)
    assert w.install(w.installer(), a)["code"] == ai.NOT_NOTARISED
    w.sign("com.swoopkey.swoop", team=PAX_TEAM, verify=False)
    assert w.install(w.installer(), a)["code"] == ai.NOT_SIGNED
    assert not (w.apps / "Swoop.app").exists()


def test_same_team_app_still_obeys_the_deny_rules(w):
    """A same-team app that is a browser (http/https handler) is still refused."""
    b = make_app(w.home / "Downloads", "Surf.app", "com.swoopkey.surf", schemes=("http", "https"))
    w.sign("com.swoopkey.surf", team=PAX_TEAM)
    assert w.install(w.installer(), b)["code"] == ai.BLOCKED


def test_a_same_team_update_from_another_team_is_still_refused(w):
    make_app(w.apps, "Swoop.app", "com.swoopkey.swoop", "1.0")
    w.sign("com.swoopkey.swoop", team=PAX_TEAM)
    installed_sig = w.sigs["com.swoopkey.swoop"]
    new = make_app(w.home / "Downloads", "Swoop.app", "com.swoopkey.swoop", "9.0")
    w.sigs["com.swoopkey.swoop"] = dev_sig("com.swoopkey.swoop", "ZYXWV98765")
    w.spctl["com.swoopkey.swoop"] = (0, "x: accepted\nsource=Notarized Developer ID\n")

    def run(args, stdin=None, timeout=30):
        if args[:2] == ["/usr/bin/codesign", "-dv"] and args[-1].startswith(str(w.apps)):
            return 0, installed_sig
        return World.run(w, args, stdin, timeout)
    inst = w.installer()
    inst.run = run
    assert w.install(inst, new)["code"] == ai.OTHER_DEVELOPER
    assert installed_version(w, "Swoop.app") == "1.0"


def test_pax_bundle_ids_and_the_name_pax_app_are_still_untouchable(w):
    for folder, bid in (("Pax Copy.app", "org.paxpeace.pax"), ("Thing.app", "org.paxmobile.pax"),
                        ("Pax Helper.app", "org.paxpeace.helper")):
        a = make_app(w.home / "Downloads", folder, bid)
        w.sign(bid, team=PAX_TEAM)
        job = w.install(w.installer(), a)
        assert job["code"] == ai.UNTOUCHABLE, (folder, job)
        assert "Pax updates itself" in job["error"]
    named = make_app(w.home / "Desktop", "Pax.app", "com.swoopkey.other")
    w.sign("com.swoopkey.other", team=PAX_TEAM)
    assert w.install(w.installer(), named)["code"] == ai.UNTOUCHABLE
    # a Pax bundle ID from another team is refused too (never "installed over" Pax)
    fake = make_app(w.home / "Downloads", "Fake.app", "org.paxpeace.fake")
    w.sign("org.paxpeace.fake")
    assert w.install(w.installer(), fake)["code"] == ai.UNTOUCHABLE
    assert sorted(p.name for p in w.apps.iterdir()) == []


def test_signing_identifier_claiming_pax_is_untouchable(w):
    """Info.plist says com.swoopkey.x but the sealed signing identifier is Pax's."""
    a = make_app(w.home / "Downloads", "X.app", "com.swoopkey.x")
    w.sign("com.swoopkey.x", team=PAX_TEAM)
    w.sigs["com.swoopkey.x"] = dev_sig("org.paxmobile.pax", PAX_TEAM)
    assert w.install(w.installer(), a)["code"] == ai.UNTOUCHABLE


def test_an_installed_pax_app_is_never_replaced(w):
    """The installed /Applications copy is Pax (bundle ID) — whatever the new copy claims."""
    make_app(w.apps, "Swoop.app", "org.paxmobile.pax", "1.0")
    new = make_app(w.home / "Downloads", "Swoop.app", "com.swoopkey.swoop", "2.0")
    w.sign("com.swoopkey.swoop", team=PAX_TEAM)
    w.sign("org.paxmobile.pax", team=PAX_TEAM)
    job = w.install(w.installer(), new)
    # not the same bundle ID, so it's a new install into a taken name; never a replacement of Pax
    assert job["state"] == "refused" and job["code"] in (ai.NAME_TAKEN, ai.UNTOUCHABLE)
    assert installed_version(w, "Swoop.app") == "1.0"


def test_is_pax_itself(tmp_path):
    p = make_app(tmp_path, "Pax.app", "com.example.whatever")
    assert ai.is_pax_itself(str(p))
    q = make_app(tmp_path, "Other.app", "org.paxpeace.pax")
    assert ai.is_pax_itself(str(q))
    r = make_app(tmp_path, "Swoop.app", "com.swoopkey.swoop")
    assert not ai.is_pax_itself(str(r))
    assert not ai.is_pax_itself(str(r), {"identifier": "com.swoopkey.swoop", "team_id": PAX_TEAM})
    assert ai.is_pax_itself(str(r), {"identifier": "org.paxmobile.pax"})


def test_installed_copy_signed_as_pax_blocks_the_update(w):
    """destination(): the installed copy's signing identifier is Pax's -> PAX-MAC-023."""
    make_app(w.apps, "Swoop.app", "com.swoopkey.swoop", "1.0")
    new = make_app(w.home / "Downloads", "Swoop.app", "com.swoopkey.swoop", "2.0")
    w.sign("com.swoopkey.swoop", team=PAX_TEAM)

    def run(args, stdin=None, timeout=30):
        if args[:2] == ["/usr/bin/codesign", "-dv"] and args[-1].startswith(str(w.apps)):
            return 0, dev_sig("org.paxmobile.pax", PAX_TEAM)
        return World.run(w, args, stdin, timeout)
    inst = w.installer()
    inst.run = run
    assert w.install(inst, new)["code"] == ai.UNTOUCHABLE
    assert installed_version(w, "Swoop.app") == "1.0"
