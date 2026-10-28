# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.35 (Ruben, 28 Oct 2026): a cleaner app deleted /Applications/Pax.app on a protected Mac;
pax-guard survived. pax-guard now puts a missing or broken Pax.app back by itself from the signed
update channel (the same pax-update.json path the updater uses), never older than itself, Team ID
pinned, notarisation checked, swapped in atomically, logged to the tamper log. Nothing touches the
real Mac."""
import hashlib
import json
import os
import plistlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pax_guard as pg  # noqa: E402
import pax_signing  # noqa: E402
import pax_update as pu  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402
from test_v08_update import PUB, SEED, URL, ZIP_URL  # noqa: E402

TEAM = "Z94GSK7JA8"


def make_pax(path: Path, version: str, bid="org.paxmobile.pax", marker=""):
    (path / "Contents" / "Resources" / "guard").mkdir(parents=True)
    (path / "Contents" / "Info.plist").write_bytes(plistlib.dumps(
        {"CFBundleShortVersionString": version, "CFBundleIdentifier": bid}))
    (path / "Contents" / "Resources" / "guard" / "pax_guard.py").write_text(f'VERSION = "{version}"\n# {marker}\n')


class Sys:
    def __init__(self, version="0.8.35", bid="org.paxmobile.pax", team=TEAM, notarised=True, verify=True):
        self.urls, self.commands = {}, []
        self.version, self.bid, self.team = version, bid, team
        self.notarised, self.verify = notarised, verify

    def fetch(self, url, headers=None, timeout=20):
        if url not in self.urls:
            raise OSError("offline")
        return self.urls[url]

    def read(self, path):
        try:
            return Path(path).read_text()
        except OSError:
            return ""

    def run(self, args, stdin=None, timeout=30):
        self.commands.append(args)
        if args[:3] == ["/usr/bin/ditto", "-x", "-k"]:
            make_pax(Path(args[-1]) / "Pax.app", self.version, self.bid, "restored")
            return 0, ""
        if args[:2] == ["/usr/bin/codesign", "--verify"]:
            return (0, "") if self.verify else (1, "invalid signature")
        if args[:2] == ["/usr/bin/codesign", "-dv"]:
            if not Path(args[-1]).exists():
                return 1, f"{args[-1]}: No such file or directory"
            return 0, (f"Authority=Developer ID Application: Pax Technologies ({self.team})\n"
                       f"TeamIdentifier={self.team}\n")
        if args[0] == "/usr/sbin/spctl":
            return (0, "x: accepted\nsource=Notarized Developer ID\n") if self.notarised else \
                (3, "x: rejected\nsource=Unnotarized Developer ID\n")
        return 0, ""


def publish(s, version="0.8.35", zip_bytes=b"PK restore zip"):
    payload = {"schema": "pax.update.v1", "version": version, "minimum_version": "0.8.0", "url": ZIP_URL,
               "mirrors": [], "sha256": hashlib.sha256(zip_bytes).hexdigest(), "size": len(zip_bytes)}
    s.urls[URL] = json.dumps(pax_signing.sign_document(payload, SEED)).encode()
    s.urls[ZIP_URL] = zip_bytes


def updater(tmp_path, s, installed="0.8.35"):
    app = tmp_path / "Applications" / "Pax.app"
    app.parent.mkdir(parents=True, exist_ok=True)
    return pu.Updater(s, tmp_path / "PaxGuard" / "state", installed, log=lambda m: None,
                      app_path=app, guard_bin=tmp_path / "PaxGuard" / "bin",
                      updates_dir=tmp_path / "PaxGuard" / "updates", manifest_urls=[URL], keys=[PUB],
                      clock=lambda: 1_800_000_000, pinned_team=TEAM), app


# ------------------------------------------------------------------ Updater.restore_app
def test_restore_puts_a_deleted_pax_back(tmp_path):
    s = Sys()
    publish(s)
    up, app = updater(tmp_path, s)
    up.restore_app(up.fetch_manifest())
    assert "restored" in (app / "Contents" / "Resources" / "guard" / "pax_guard.py").read_text()
    assert not (tmp_path / "PaxGuard" / "updates" / "restore").exists()      # staging cleaned
    assert not (tmp_path / "Applications" / ".pax-restore").exists()
    assert any(c[0] == "/usr/sbin/spctl" for c in s.commands)
    assert ["/usr/bin/codesign", "--verify", "--deep", "--strict"] == next(
        c for c in s.commands if c[:2] == ["/usr/bin/codesign", "--verify"])[:4]


def test_restore_replaces_a_broken_copy_atomically(tmp_path):
    s = Sys()
    publish(s)
    up, app = updater(tmp_path, s)
    make_pax(app, "0.8.35", marker="broken")
    up.restore_app(up.fetch_manifest())
    assert "restored" in (app / "Contents" / "Resources" / "guard" / "pax_guard.py").read_text()
    assert sorted(os.listdir(app.parent)) == ["Pax.app"]                        # no leftovers


@pytest.mark.parametrize("kw,code", [
    ({"team": "ABCDE12345"}, "PAX-UPDATE-006"),      # someone else's Developer ID
    ({"notarised": False}, "PAX-UPDATE-006"),
    ({"verify": False}, "PAX-UPDATE-006"),
    ({"bid": "com.example.fake"}, "PAX-UPDATE-005"),
    ({"version": "0.8.36"}, "PAX-UPDATE-005"),       # the zip isn't the version the manifest signed
])
def test_restore_refuses_anything_that_isnt_paxs_signed_app(tmp_path, kw, code):
    s = Sys(**kw)
    publish(s)
    up, app = updater(tmp_path, s)
    make_pax(app, "0.8.35", marker="broken")
    with pytest.raises(pu.UpdateError) as e:
        up.restore_app(up.fetch_manifest())
    assert e.value.code == code
    assert "broken" in (app / "Contents" / "Resources" / "guard" / "pax_guard.py").read_text()   # untouched


def test_restore_never_downgrades_and_needs_a_signed_manifest(tmp_path):
    s = Sys(version="0.8.34")
    publish(s, version="0.8.34")
    up, app = updater(tmp_path, s)
    with pytest.raises(pu.UpdateError) as e:
        up.restore_app(up.fetch_manifest())
    assert e.value.code == "PAX-UPDATE-003" and not app.exists()
    payload = {"schema": "pax.update.v1", "version": "0.8.35", "minimum_version": "0.8.0", "url": ZIP_URL,
               "sha256": "0" * 64, "size": 3}
    s.urls[URL] = json.dumps(pax_signing.sign_document(payload, b"\x09" * 32)).encode()   # wrong key
    with pytest.raises(pu.UpdateError):
        up.fetch_manifest()


def test_restore_needs_a_pinned_team(tmp_path):
    s = Sys()
    publish(s)
    up, _app = updater(tmp_path, s)
    up.pinned_team = None
    with pytest.raises(pu.UpdateError) as e:
        up.restore_app(up.fetch_manifest())
    assert e.value.code == "PAX-UPDATE-006"


def test_hash_mismatch_is_refused(tmp_path):
    s = Sys()
    publish(s)
    s.urls[ZIP_URL] = b"PK something else"
    up, app = updater(tmp_path, s)
    with pytest.raises(pu.UpdateError) as e:
        up.restore_app(up.fetch_manifest())
    assert e.value.code == "PAX-UPDATE-004" and not app.exists()


def test_normal_update_pins_paxs_team_when_the_app_is_gone(tmp_path):
    """verify_bundle used to accept any team when /Applications/Pax.app was missing."""
    s = Sys(version="0.8.36", team="ABCDE12345")
    publish(s, version="0.8.36")
    up, app = updater(tmp_path, s)
    with pytest.raises(pu.UpdateError) as e:
        up.install(up.fetch_manifest())
    assert e.value.code == "PAX-UPDATE-006" and not app.exists()


# ------------------------------------------------------------------ atomic_replace
def test_atomic_replace_with_and_without_a_swap_call(tmp_path, monkeypatch):
    for swap in (True, False):
        d = tmp_path / ("a" if swap else "b")
        new, dest = d / "new" / "Pax.app", d / "Apps" / "Pax.app"
        make_pax(new, "2", marker="new")
        make_pax(dest, "1", marker="old")
        if not swap:
            monkeypatch.setattr(pu, "_swap_entries", lambda a, b: False)
        pu.atomic_replace(new, dest)
        assert "new" in (dest / "Contents" / "Resources" / "guard" / "pax_guard.py").read_text()
        assert not new.exists() and sorted(os.listdir(dest.parent)) == ["Pax.app"]


def test_atomic_replace_into_an_empty_place_and_over_a_link(tmp_path):
    new, dest = tmp_path / "n" / "Pax.app", tmp_path / "Apps" / "Pax.app"
    make_pax(new, "1", marker="new")
    dest.parent.mkdir()
    pu.atomic_replace(new, dest)
    assert dest.is_dir()
    new2 = tmp_path / "n" / "Pax2.app"
    make_pax(new2, "1", marker="new2")
    dest2 = tmp_path / "Apps" / "Link.app"
    dest2.symlink_to(tmp_path / "elsewhere")
    pu.atomic_replace(new2, dest2)
    assert dest2.is_dir() and not dest2.is_symlink() and not new2.exists()


def test_atomic_replace_puts_the_old_copy_back_when_the_move_fails(tmp_path, monkeypatch):
    new, dest = tmp_path / "n" / "Pax.app", tmp_path / "Apps" / "Pax.app"
    make_pax(dest, "1", marker="old")
    monkeypatch.setattr(pu, "_swap_entries", lambda a, b: False)
    with pytest.raises(OSError):
        pu.atomic_replace(new, dest)                 # `new` doesn't exist: the second rename fails
    assert "old" in (dest / "Contents" / "Resources" / "guard" / "pax_guard.py").read_text()


# ------------------------------------------------------------------ the guard's check
class FakeUpdater:
    def __init__(self, version="0.8.34"):
        self.version = version
        self.restored = []
        self.checked = 0
        self.fail = None
        self._state = {}

    def state(self):
        return dict(self._state)

    def fetch_manifest(self):
        if self.fail:
            raise pu.UpdateError("PAX-UPDATE-001", self.fail)
        return {"version": self.version}

    def restore_app(self, m, pinned_team=None):
        assert pinned_team == TEAM
        self.restored.append(m["version"])
        make_pax(self.app, m["version"], marker="restored")

    def check(self, force=False):
        self.checked += 1
        make_pax(self.app, self.version, marker="updated")


def tamper(g):
    p = g.state_dir / "tamper.jsonl"
    rows = [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []
    return [{"kind": r["kind"], **(r.get("detail") or {})} for r in rows]


@pytest.fixture
def heal(tmp_path, monkeypatch):
    g, s = local_guard(tmp_path)
    app = tmp_path / "Applications" / "Pax.app"
    app.parent.mkdir()
    g.pax_app_path = app
    up = FakeUpdater(pg.VERSION)
    up.app = app
    g.updater = up
    monkeypatch.setattr(g, "_background", lambda name, fn: fn())
    monkeypatch.setattr(g, "_developer_id_install", lambda: True)
    notes = []
    monkeypatch.setattr(g, "notify", notes.append)
    return g, s, up, app, notes


def good_sig(s):
    run = s.run

    def fake(args, stdin=None, timeout=30):
        if args[:2] == ["/usr/bin/codesign", "-dv"]:
            return 0, ("Identifier=org.paxmobile.pax\nAuthority=Developer ID Application: Pax Technologies (Z94GSK7JA8)\n"
                       "Authority=Developer ID Certification Authority\nAuthority=Apple Root CA\n"
                       "TeamIdentifier=Z94GSK7JA8\n")
        return run(args, stdin, timeout)
    s.run = fake


def test_deleted_pax_app_is_put_back_and_logged(heal):
    g, s, up, app, notes = heal
    assert g.check_pax_app() == "missing"
    assert up.restored == [pg.VERSION] and app.is_dir()
    ev = [e for e in tamper(g) if e["kind"] == "changed:pax_app"]
    assert ev and ev[-1]["why"] == "missing" and ev[-1]["repaired"] is True
    assert notes == ["Pax was removed from Applications, so Pax put it back."]
    good_sig(s)
    assert g.check_pax_app() is None                 # fine now: nothing more


def test_healthy_pax_app_is_left_alone(heal):
    g, s, up, app, notes = heal
    make_pax(app, pg.VERSION)
    good_sig(s)
    assert g.check_pax_app() is None and up.restored == [] and tamper(g) == []


@pytest.mark.parametrize("damage,why", [
    ("not_pax", "not Pax"), ("link", "replaced by a link"), ("unsigned", "not signed by Pax"),
])
def test_broken_pax_app_is_put_back(heal, tmp_path, damage, why):
    g, s, up, app, notes = heal
    if damage == "not_pax":
        make_pax(app, pg.VERSION, bid="com.example.other")
    elif damage == "link":
        app.symlink_to(tmp_path)
    else:
        make_pax(app, pg.VERSION)                     # the fake codesign -dv answers "" (no team)
    if damage == "link":
        app.unlink()
        app.symlink_to(tmp_path / "x")
        up.restore_app = lambda m, pinned_team=None: (app.unlink(), make_pax(app, m["version"]))
    assert g.check_pax_app() == why
    assert [e["why"] for e in tamper(g) if e["kind"] == "changed:pax_app"] == [why]


def test_ad_hoc_installs_only_restore_a_missing_app(heal, monkeypatch):
    g, s, up, app, notes = heal
    monkeypatch.setattr(g, "_developer_id_install", lambda: False)
    make_pax(app, pg.VERSION)                         # not Developer ID signed: expected on such builds
    assert g.check_pax_app() is None and up.restored == []


def test_newer_release_goes_through_the_normal_update(heal):
    g, s, up, app, notes = heal
    up.version = "9.9.9"
    assert g.check_pax_app() == "missing"
    assert up.checked == 1 and up.restored == [] and app.is_dir()


def test_failure_backs_off_and_logs_the_incident_once(heal):
    g, s, up, app, notes = heal
    up.fail = "offline"
    assert g.check_pax_app() == "missing"
    meta = g._load_json("pax-app.json", {})
    assert meta["retry_at"] == s.t + pg.PAX_APP_RETRY_START
    assert g.check_pax_app() == "missing"            # within the back-off: no new attempt
    s.t += pg.PAX_APP_RETRY_START
    assert g.check_pax_app() == "missing"
    assert g._load_json("pax-app.json", {})["retry_delay"] == 2 * pg.PAX_APP_RETRY_START
    ev = [e for e in tamper(g) if e["kind"] == "changed:pax_app"]
    assert len(ev) == 1 and ev[0]["repaired"] is False
    up.fail = None
    s.t += 3600
    assert g.check_pax_app() == "missing"
    ev = [e for e in tamper(g) if e["kind"] == "changed:pax_app"]
    assert ev[-1]["repaired"] is True and g._load_json("pax-app.json", {}) == {}


def test_older_manifest_never_restores(heal):
    g, s, up, app, notes = heal
    up.version = "0.0.1"
    g.check_pax_app()
    assert up.restored == [] and not app.exists()


def test_skipped_while_updating_released_or_without_updater(heal):
    g, s, up, app, notes = heal
    up._state = {"state": "trial"}
    assert g.check_pax_app() is None
    up._state = {}
    g.released = True
    assert g.check_pax_app() is None
    g.released = False
    g.updater = None
    assert g.check_pax_app() is None
    assert up.restored == []


def test_periodic_runs_the_check(heal, monkeypatch):
    g, s, up, app, notes = heal
    called = []
    monkeypatch.setattr(g, "check_pax_app", lambda: called.append(1))
    g.periodic()
    assert called == [1]
