# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0 automatic updates: signature failure, downgrade refused, stale
manifest refused, minimum_version forces an immediate install with a notice,
hash and Team ID checks, the atomic swap, confirm, and rollback."""
import hashlib
import json
import plistlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ed25519  # noqa: E402
import pax_signing  # noqa: E402
import pax_update as pu  # noqa: E402

SEED = b"\x07" * 32
PUB = ed25519.public_key(SEED)
URL = "https://releases.test/pax-update.json"
ZIP_URL = "https://releases.test/Pax-0.8.1.zip"


def make_app(path: Path, version: str, marker: str = "") -> None:
    (path / "Contents" / "Resources" / "guard").mkdir(parents=True)
    (path / "Contents" / "Info.plist").write_bytes(plistlib.dumps({"CFBundleShortVersionString": version}))
    (path / "Contents" / "Resources" / "guard" / "pax_guard.py").write_text(
        f'VERSION = "{version}"\n# {marker}\n')
    (path / "Contents" / "Resources" / "guard" / "guard_config.py").write_text("# cfg\n")


class FakeSys:
    def __init__(self, tmp: Path, new_version="0.8.1", team_cur=None, team_new=None, selftest_ok=True):
        self.tmp = tmp
        self.urls = {}
        self.commands = []
        self.new_version = new_version
        self.team_cur, self.team_new = team_cur, team_new
        self.selftest_ok = selftest_ok

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
        if args[0] == "/usr/bin/ditto":
            make_app(Path(args[-1]) / "Pax.app", self.new_version, "new")
            return 0, ""
        if args[:2] == ["/usr/bin/codesign", "--verify"]:
            return 0, ""
        if args[:2] == ["/usr/bin/codesign", "-dv"]:
            team = self.team_cur if "Applications" in args[-1] else self.team_new
            if team:
                return 0, f"Authority=Developer ID Application: Alex ({team})\nTeamIdentifier={team}\n"
            return 0, "Signature=adhoc\nTeamIdentifier=not set\n"
        if "-I" in args and args[-1] == "selftest":       # v0.8.6: whichever Python runs it
            return (0, '{"ok": true}') if self.selftest_ok else (1, "import failed")
        return 0, ""


def setup(tmp_path, installed="0.8.0", **kw):
    app = tmp_path / "Applications" / "Pax.app"
    make_app(app, installed, "old")
    gbin = tmp_path / "PaxGuard" / "bin"
    gbin.mkdir(parents=True)
    (gbin / "pax_guard.py").write_text(f'VERSION = "{installed}"\n# old guard\n')
    s = FakeSys(tmp_path, **kw)
    notes = []
    logs = []
    up = pu.Updater(s, tmp_path / "PaxGuard" / "state", installed, log=logs.append, notify=notes.append,
                    app_path=app, guard_bin=gbin, updates_dir=tmp_path / "PaxGuard" / "updates",
                    manifest_urls=[URL], keys=[PUB], clock=lambda: 1_800_000_000)
    up.start_watchdog = lambda v: None        # the tests drive confirm / rollback directly
    return up, s, notes, logs, app, gbin


def publish(s, version="0.8.1", minimum="0.8.0", seed=SEED, zip_bytes=b"PK fake zip", tamper=False, **extra):
    payload = {"schema": "pax.update.v1", "version": version, "minimum_version": minimum,
               "url": ZIP_URL, "mirrors": [], "sha256": hashlib.sha256(zip_bytes).hexdigest(),
               "size": len(zip_bytes), "released_at": "2026-10-20T00:00:00Z", **extra}
    doc = pax_signing.sign_document(payload, seed)
    if tamper:
        doc["payload"]["url"] = "https://evil.test/Pax.zip"
    s.urls[URL] = json.dumps(doc).encode()
    s.urls[ZIP_URL] = zip_bytes


def test_installs_signed_update_silently_and_confirms(tmp_path):
    up, s, notes, logs, app, gbin = setup(tmp_path)
    publish(s)
    st = up.check(force=False)
    assert st["state"] == "trial"
    assert "new" in (app / "Contents" / "Resources" / "guard" / "pax_guard.py").read_text()
    assert 'VERSION = "0.8.1"' in (gbin / "pax_guard.py").read_text()
    assert (tmp_path / "PaxGuard" / "updates" / "rollback" / "Pax.app").is_dir()
    # the new guard starts and confirms
    up2 = pu.Updater(s, up.state_path.parent, "0.8.1", log=logs.append, notify=notes.append,
                     app_path=app, guard_bin=gbin, updates_dir=up.updates)
    assert up2.confirm_trial()
    assert up2.status()["state"] == "committed" and notes == []      # silent: no notice


def test_unsigned_and_wrongly_signed_manifests_are_ignored(tmp_path):
    up, s, *_ = setup(tmp_path)
    publish(s, seed=b"\x08" * 32)
    st = up.check(force=True)
    assert st["state"] == "idle" and "PAX-UPDATE-001" in st["last_error"]
    publish(s, tamper=True)                      # payload changed after signing
    assert "bad signature" in up.check(force=True)["last_error"]
    s.urls[URL] = json.dumps({"payload": {"schema": "pax.update.v1", "version": "9.9.9"}}).encode()
    assert "unsigned" in up.check(force=True)["last_error"]
    assert not (tmp_path / "PaxGuard" / "updates" / "rollback").exists()


def test_downgrade_and_same_version_never_install(tmp_path):
    up, s, *_ = setup(tmp_path, installed="0.8.1")
    publish(s, version="0.8.0", minimum="0.7.0")
    assert up.check(force=True)["state"] == "up_to_date"
    publish(s, version="0.8.1", minimum="0.8.1")
    assert up.check(force=True)["state"] == "up_to_date"
    assert not any(c[0] == "/usr/bin/ditto" for c in s.commands)


def test_stale_manifest_refused_after_newer_seen(tmp_path):
    up, s, *_ = setup(tmp_path, installed="0.9.0")
    publish(s, version="0.9.2", minimum="0.9.0")
    up.app_running = lambda: True
    up.check(force=False)
    publish(s, version="0.9.1", minimum="0.9.0")
    assert "older manifest" in up.check(force=True)["last_error"]


def test_minimum_version_forces_install_now_with_notice(tmp_path):
    up, s, notes, logs, app, gbin = setup(tmp_path)
    up.app_running = lambda: True                # normally an open Pax defers the update
    publish(s, version="0.8.1", minimum="0.8.0")
    assert up.check(force=False)["state"] == "waiting_for_pax_to_close"
    publish(s, version="0.8.1", minimum="0.8.1")
    up._save(dict(up.state(), last_checked=0, next_check_at=0))
    st = up.check(force=False)
    assert st["state"] == "trial" and "important" in st["notice"]
    up2 = pu.Updater(s, up.state_path.parent, "0.8.1", notify=notes.append, app_path=app, guard_bin=gbin,
                     updates_dir=up.updates, log=logs.append)
    up2.confirm_trial()
    assert notes and "fix an important problem" in notes[0]


def test_hash_mismatch_rejected(tmp_path):
    up, s, *_ = setup(tmp_path)
    publish(s)
    s.urls[ZIP_URL] = b"PK something else!"
    st = up.check(force=True)
    assert st["state"] == "failed" and "PAX-UPDATE-004" in st["last_error"]
    assert 'VERSION = "0.8.0"' in up.app_path.joinpath("Contents/Resources/guard/pax_guard.py").read_text()


def test_version_inside_bundle_must_match(tmp_path):
    up, s, *_ = setup(tmp_path, new_version="0.8.2")
    publish(s, version="0.8.1")
    assert "PAX-UPDATE-005" in up.check(force=True)["last_error"]


def test_team_id_must_match_developer_id(tmp_path):
    up, s, *_ = setup(tmp_path, team_cur="ABCDE12345", team_new="ZZZZZ99999")
    publish(s)
    assert "PAX-UPDATE-006" in up.check(force=True)["last_error"]
    up2, s2, *_ = setup(tmp_path / "b", team_cur="ABCDE12345", team_new="ABCDE12345")
    publish(s2)
    assert up2.check(force=True)["state"] == "trial"
    # ad-hoc installed build (no Developer ID): no Team ID to compare
    up3, s3, *_ = setup(tmp_path / "c", team_cur=None, team_new="ZZZZZ99999")
    publish(s3)
    assert up3.check(force=True)["state"] == "trial"


def test_selftest_failure_stops_before_swap(tmp_path):
    up, s, *_ = setup(tmp_path, selftest_ok=False)
    publish(s)
    assert "self-test" in up.check(force=True)["last_error"]
    assert not (tmp_path / "PaxGuard" / "updates" / "rollback" / "Pax.app").exists()


def test_watchdog_rolls_back_when_new_guard_never_confirms(tmp_path):
    up, s, notes, logs, app, gbin = setup(tmp_path)
    publish(s)
    up.check(force=True)
    restarts = []
    result = pu.watchdog("0.8.1", up.state_path, sleep=lambda t: None, restart=lambda: restarts.append(1),
                         deadline_s=10)
    assert result == "rolled_back" and len(restarts) == 2
    assert "old" in (app / "Contents" / "Resources" / "guard" / "pax_guard.py").read_text()
    assert 'VERSION = "0.8.0"' in (gbin / "pax_guard.py").read_text()
    st = json.loads(up.state_path.read_text())
    assert st["state"] == "rolled_back" and "0.8.1" in st["bad_versions"]
    # a bad version isn't retried by itself
    up.app_running = lambda: False
    assert up.check(force=True)["state"] == "skipped_bad"


def test_watchdog_leaves_a_confirmed_update(tmp_path):
    up, s, notes, logs, app, gbin = setup(tmp_path)
    publish(s)
    up.check(force=True)

    def restart():
        pu.Updater(s, up.state_path.parent, "0.8.1", app_path=app, guard_bin=gbin,
                   updates_dir=up.updates, log=logs.append).confirm_trial()
    assert pu.watchdog("0.8.1", up.state_path, sleep=lambda t: None, restart=restart) == "committed"
    assert 'VERSION = "0.8.1"' in (gbin / "pax_guard.py").read_text()


def test_swap_failure_puts_everything_back(tmp_path, monkeypatch):
    up, s, notes, logs, app, gbin = setup(tmp_path)
    publish(s)
    real_replace = pu.os.replace
    calls = {"n": 0}

    def flaky(a, b):
        calls["n"] += 1
        if str(a).endswith("bin.new"):       # the last step: bin.new -> bin
            raise OSError("disk full")
        return real_replace(a, b)
    monkeypatch.setattr(pu.os, "replace", flaky)
    st = up.check(force=True)
    monkeypatch.setattr(pu.os, "replace", real_replace)
    assert "PAX-UPDATE-007" in st["last_error"]
    assert 'VERSION = "0.8.0"' in (gbin / "pax_guard.py").read_text()
    assert "old" in (app / "Contents" / "Resources" / "guard" / "pax_guard.py").read_text()


def test_check_interval_six_hours(tmp_path):
    up, s, *_ = setup(tmp_path, installed="0.8.1")
    publish(s, version="0.8.1", minimum="0.8.0")
    up.check()
    n = len([c for c in s.commands])
    s.urls.clear()
    assert up.check()["last_error"] is None          # not re-fetched within 6 h
    assert pu.CHECK_INTERVAL == 6 * 3600


class Limited(OSError):
    def __init__(self, status, retry_after=None):
        super().__init__(f"HTTP {status}")
        self.status, self.retry_after = status, retry_after


def test_jitter_and_backoff_on_429_and_5xx(tmp_path):
    up, s, notes, logs, app, gbin = setup(tmp_path, installed="0.8.1")
    calls = []

    def limited(url, headers=None, timeout=20):
        calls.append(url)
        raise Limited(429, None)
    s.fetch = limited
    st = up.check(force=True)
    assert "PAX-UPDATE-008" in st["last_error"]
    state = up.state()
    assert pu.BACKOFF_START <= state["backoff_seconds"] <= pu.BACKOFF_START + 300
    n = len(calls)
    up.check(force=True)                       # "Update now" during back-off: no request
    assert len(calls) == n
    up.clock = lambda: 1_800_000_000 + state["backoff_seconds"] + 1
    s.fetch = lambda url, headers=None, timeout=20: (_ for _ in ()).throw(Limited(502))
    up.check(force=True)
    assert up.state()["backoff_seconds"] >= 2 * pu.BACKOFF_START       # doubled
    # a normal check schedules the next one 6 h + up to 30 min later
    up2, s2, *_ = setup(tmp_path / "j", installed="0.8.1")
    publish(s2, version="0.8.1", minimum="0.8.0")
    up2.check()
    nxt = up2.state()["next_check_at"] - 1_800_000_000
    assert pu.CHECK_INTERVAL <= nxt <= pu.CHECK_INTERVAL + pu.CHECK_JITTER
    assert pu.MANIFEST_URLS[0].startswith("https://github.com/") and "api.github.com" not in " ".join(pu.MANIFEST_URLS)


def test_manifest_validation():
    good = {"schema": "pax.update.v1", "version": "0.8.1", "minimum_version": "0.8.0", "url": "https://x/y.zip",
            "sha256": "a" * 64, "size": 10}
    assert pu.validate_manifest(dict(good))
    for bad in ({"url": "http://x/y.zip"}, {"sha256": "nope"}, {"version": "0.8"}, {"minimum_version": "0.9.0"},
                {"size": 0}, {"schema": "other"}):
        with pytest.raises(pu.UpdateError):
            pu.validate_manifest(dict(good, **bad))
    assert pu.team_id("TeamIdentifier=ABCDE12345\n") == "ABCDE12345"
    assert pu.team_id("TeamIdentifier=not set\n") is None
