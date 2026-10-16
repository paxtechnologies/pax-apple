# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.6 updates: the mirror carries the zip as signed, hash-pinned parts under
jsDelivr's 20 MB per-file limit, and the updater copies, checks and swaps
pax-guard's runtime together with the app and guard (rollback included).

The mirror tests play GitHub and jsDelivr as they behave: jsDelivr answers 403
for a file over 20 MB, GitHub can be down. Updates must work from GitHub alone
and from the mirror alone, and only bytes matching the signed SHA-256 are ever
unpacked."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import guard_runtime as grt  # noqa: E402
import pax_signing  # noqa: E402
import pax_update as pu  # noqa: E402
from test_v08_update import PUB, SEED, URL, ZIP_URL, setup  # noqa: E402

MIRROR_MANIFEST = "https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/pax-update.json"
JSD = "https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/parts/0.8.1/"
GH = "https://github.com/paxtechnologies/pax-apple/releases/download/v0.8.1/"
JSDELIVR_LIMIT = 20 * 1024 * 1024


def _load_sign_release():
    spec = importlib.util.spec_from_file_location("sign_release", HERE.parents[1] / "scripts" / "sign-release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sr = _load_sign_release()


class CDN:
    """GitHub + jsDelivr: per-URL bodies, jsDelivr's 20 MB rule, outages."""

    def __init__(self, fs):
        self.fs = fs
        self.down: set[str] = set()
        fs.fetch = self.fetch

    def fetch(self, url, headers=None, timeout=20):
        host = url.split("/")[2]
        host = "github.com" if host == "releases.test" else host     # the base tests' GitHub stand-in
        if host in self.down:
            raise OSError(f"{host} unreachable")
        if url not in self.fs.urls:
            raise OSError("HTTP 404")
        data = self.fs.urls[url]
        if host == "cdn.jsdelivr.net" and len(data) > JSDELIVR_LIMIT:
            raise OSError("HTTP 403 File size exceeded the configured limit of 20 MB")
        return data


def release(tmp_path, s, zip_bytes, part_size=sr.PART_SIZE, corrupt_part=None, seed=SEED):
    """What build-dmg.yml publishes for a tag: zip on GitHub, parts on both, manifest on both."""
    z = tmp_path / "Pax-0.8.1.zip"
    z.write_bytes(zip_bytes)
    parts = sr.split_zip(z, tmp_path / "parts", part_size)
    payload = sr.build_payload(z, "0.8.1", "0.8.0", ZIP_URL, [], None, parts, [JSD, GH])
    doc = json.dumps(pax_signing.sign_document(payload, seed)).encode()
    s.urls[URL] = doc
    s.urls[MIRROR_MANIFEST] = doc
    s.urls[ZIP_URL] = zip_bytes
    for p in parts:
        data = (tmp_path / "parts" / p["name"]).read_bytes()
        if corrupt_part == p["name"]:
            data = b"X" + data[1:]
        s.urls[JSD + p["name"]] = data
        s.urls[GH + p["name"]] = data
    return payload


def big_zip(n=45 * 1024 * 1024):
    return (b"PK\x03\x04" + os.urandom(1024)) * (n // 1028)


def make(tmp_path, **kw):
    up, s, notes, logs, app, gbin = setup(tmp_path, **kw)
    up.urls = [URL, MIRROR_MANIFEST]
    cdn = CDN(s)
    unpacked = []
    orig = up.install

    def install(m, forced=False):
        zp = up.updates / "staging" / "Pax.zip"
        try:
            orig(m, forced)
        finally:
            if zp.exists():
                unpacked.append(hashlib.sha256(zp.read_bytes()).hexdigest())
    up.install = install
    return up, s, cdn, logs, unpacked


def test_parts_are_under_the_jsdelivr_limit_and_join_back(tmp_path):
    data = big_zip()
    z = tmp_path / "z.zip"
    z.write_bytes(data)
    parts = sr.split_zip(z, tmp_path / "p")
    assert len(parts) == 3 and all(p["size"] <= sr.PART_SIZE < 20_000_000 for p in parts)
    assert b"".join((tmp_path / "p" / p["name"]).read_bytes() for p in parts) == data
    with pytest.raises(SystemExit):
        sr.split_zip(z, tmp_path / "q", 21_000_000)


def test_github_alone(tmp_path):
    up, s, cdn, logs, unpacked = make(tmp_path)
    data = big_zip()
    m = release(tmp_path, s, data)
    cdn.down.add("cdn.jsdelivr.net")
    assert up.check(force=True)["state"] == "trial"
    assert unpacked == [m["sha256"]]


def test_mirror_alone_reassembles_the_parts(tmp_path):
    up, s, cdn, logs, unpacked = make(tmp_path)
    data = big_zip()
    m = release(tmp_path, s, data)
    cdn.down.add("github.com")
    s.urls["https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/Pax-0.8.1.zip"] = data   # what 0.8.5 used
    st = up.check(force=True)
    assert st["state"] == "trial", st
    assert unpacked == [hashlib.sha256(data).hexdigest()] == [m["sha256"]]
    # the whole zip from jsDelivr would have been refused (403): only parts work there
    with pytest.raises(OSError, match="20 MB"):
        cdn.fetch("https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/Pax-0.8.1.zip")


def test_a_bad_part_on_the_mirror_falls_through_to_the_next_base(tmp_path):
    up, s, cdn, logs, unpacked = make(tmp_path)
    data = big_zip()
    release(tmp_path, s, data, corrupt_part="Pax-0.8.1.zip.part-001")
    s.urls[GH + "Pax-0.8.1.zip.part-001"] = s.urls[GH + "Pax-0.8.1.zip.part-000"]  # put back below
    z = tmp_path / "parts" / "Pax-0.8.1.zip.part-001"
    s.urls[GH + "Pax-0.8.1.zip.part-001"] = z.read_bytes()
    del s.urls[ZIP_URL]                                   # GitHub zip missing, GitHub parts fine
    st = up.check(force=True)
    assert st["state"] == "trial"
    assert any("part Pax-0.8.1.zip.part-001" in line and "doesn't match" in line for line in logs)


def test_tampered_parts_everywhere_install_nothing(tmp_path):
    up, s, cdn, logs, unpacked = make(tmp_path)
    data = big_zip()
    release(tmp_path, s, data, corrupt_part="Pax-0.8.1.zip.part-002")
    cdn.down.add("github.com")
    s.urls[URL] = s.urls[MIRROR_MANIFEST]
    st = up.check(force=True)
    assert st["state"] == "failed" and "PAX-UPDATE-004" in st["last_error"]
    assert not (up.updates / "rollback").exists() and unpacked == []


def test_parts_must_add_up_and_be_https(tmp_path):
    good = {"base_urls": [JSD], "files": [{"name": "a.part-000", "size": 10, "sha256": "0" * 64}]}
    pu.validate_parts(good, 10)
    for bad, total in (
        (dict(good, base_urls=["http://x/"]), 10),
        (dict(good, base_urls=["https://x"]), 10),
        (good, 11),
        (dict(good, files=[{"name": "../x", "size": 10, "sha256": "0" * 64}]), 10),
        (dict(good, files=[{"name": "a", "size": 25_000_000, "sha256": "0" * 64}]), 25_000_000),
        (dict(good, files=[]), 10),
    ):
        with pytest.raises(pu.UpdateError):
            pu.validate_parts(bad, total)


def test_parts_cannot_be_swapped_without_breaking_the_signature(tmp_path):
    up, s, cdn, logs, unpacked = make(tmp_path)
    m = release(tmp_path, s, big_zip())
    doc = json.loads(s.urls[URL])
    doc["payload"]["parts"]["base_urls"] = ["https://evil.example/"]
    s.urls[URL] = s.urls[MIRROR_MANIFEST] = json.dumps(doc).encode()
    st = up.check(force=True)
    assert "bad signature" in st["last_error"]


def test_manifest_stays_v1_for_older_readers(tmp_path):
    """0.8.4/0.8.5 pax-guard and the server self-updater read the same document."""
    z = tmp_path / "Pax-0.8.6.zip"
    z.write_bytes(b"PK" * 1000)
    parts = sr.split_zip(z, tmp_path / "p", 700)
    payload = sr.build_payload(z, "0.8.6", "0.8.0", None, [], None, parts, [JSD])
    assert payload["schema"] == "pax.update.v1" and payload["mirrors"] == []
    assert payload["url"].endswith("/releases/download/v0.8.6/Pax-0.8.6.zip")
    assert {"version", "minimum_version", "url", "sha256", "size"} <= payload.keys()
    assert all(isinstance(v, (str, int, list, dict)) for v in payload.values())      # no floats: canonical JSON
    # the 0.8.5 rules, verbatim: only these keys are looked at
    old = dict(payload)
    old.pop("parts")
    assert pu.validate_manifest(dict(payload)) and pu.validate_manifest(old)
    doc = pax_signing.sign_document(payload, SEED)
    assert pax_signing.verify_document(doc, [PUB])["version"] == "0.8.6"


# ------------------------------------------------------------------ runtime swap
class FakeRuntime:
    """Stands in for guard_runtime.Runtime: stage() writes a marker tree."""

    def __init__(self, base: Path, ok=True):
        self.dir = base / "runtime"
        self.ok = ok
        self.starts_set = []

    def stage(self, dest, app):
        if not self.ok:
            raise grt.RuntimeProblem("the update's runtime isn't signed by Pax")
        (Path(dest) / "bin").mkdir(parents=True)
        (Path(dest) / "bin" / "python3.12").write_text("new runtime")
        return {"interpreter": "bin/python3.12"}

    def python(self, root=None, manifest=None):
        return Path(root or self.dir) / "bin" / "python3.12"

    def set_starts(self, n):
        self.starts_set.append(n)


def runtime_setup(tmp_path, ok=True, team="Z94GSK7JA8"):
    up, s, notes, logs, app, gbin = setup(tmp_path, team_cur=team, team_new=team)
    base = tmp_path / "PaxGuard"
    (base / "runtime" / "bin").mkdir(parents=True)
    (base / "runtime" / "bin" / "python3.12").write_text("old runtime")
    up.runtime = FakeRuntime(base, ok)
    up.runtime_dir = up.runtime.dir
    from test_v08_update import publish
    publish(s)
    return up, s, logs, base


def test_update_stages_checks_and_swaps_the_runtime(tmp_path):
    up, s, logs, base = runtime_setup(tmp_path)
    assert up.check(force=True)["state"] == "trial"
    assert (base / "runtime/bin/python3.12").read_text() == "new runtime"
    assert (up.updates / "rollback/runtime/bin/python3.12").read_text() == "old runtime"
    selftest = [c for c in s.commands if c[-1] == "selftest"][0]
    assert selftest[0].endswith("staging/runtime/bin/python3.12") and selftest[1:3] == ["-I", "-B"]
    assert up.runtime.starts_set == [0]
    st = up.state()
    assert st["runtime_swapped"] and st["runtime_had_previous"] and st["paths"]["runtime"] == str(base / "runtime")


def test_rollback_restores_the_old_runtime(tmp_path):
    up, s, logs, base = runtime_setup(tmp_path)
    up.check(force=True)
    up.rollback("0.8.1")
    assert (base / "runtime/bin/python3.12").read_text() == "old runtime"
    assert not (base / "runtime.bad").exists()


def test_watchdog_rollback_from_state_restores_runtime(tmp_path):
    up, s, logs, base = runtime_setup(tmp_path)
    up.check(force=True)
    restarted = []
    out = pu.watchdog("0.8.1", up.state_path, system=s, sleep=lambda n: None,
                      restart=lambda: restarted.append(1), deadline_s=10)
    assert out == "rolled_back" and len(restarted) == 2
    assert (base / "runtime/bin/python3.12").read_text() == "old runtime"


def test_unverified_runtime_on_a_developer_id_install_refuses_the_update(tmp_path):
    up, s, logs, base = runtime_setup(tmp_path, ok=False)
    st = up.check(force=True)
    assert st["state"] == "failed" and "PAX-UPDATE-006" in st["last_error"]
    assert (base / "runtime/bin/python3.12").read_text() == "old runtime"


def test_adhoc_install_updates_without_touching_the_runtime(tmp_path):
    up, s, logs, base = runtime_setup(tmp_path, ok=False, team=None)
    assert up.check(force=True)["state"] == "trial"
    assert (base / "runtime/bin/python3.12").read_text() == "old runtime"
    selftest = [c for c in s.commands if c[-1] == "selftest"][0]
    assert selftest[0] == sys.executable


def test_watchdog_runs_on_the_old_runtime(tmp_path, monkeypatch):
    up, s, logs, base = runtime_setup(tmp_path)
    up.check(force=True)
    monkeypatch.setattr(pu.sys, "executable", str(base / "runtime/bin/python3.12"))
    assert up.watchdog_python() == up.updates / "rollback/runtime/bin/python3.12"
    monkeypatch.setattr(pu.sys, "executable", "/usr/bin/python3")
    assert up.watchdog_python() == Path("/usr/bin/python3")
