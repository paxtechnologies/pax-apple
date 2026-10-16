# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0 local filter lists: the bundled set, loading, the update checks
(signature, SHA-256, format, minimum size, no mass deletions, no rollback to
older lists), keeping the last good copy, the bundled fallback, plugins, and
the new-registration name rule. v0.8.1: restricted vs overridable lists. Real
restricted names come from common/pax_restricted.py, decoded at run time."""
import gzip
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent
REPO = GUARD.parent
sys.path.insert(0, str(GUARD))
import ed25519  # noqa: E402
import filter_lists as fl  # noqa: E402
import pax_signing  # noqa: E402
sys.path.insert(0, str(REPO / "common"))
import pax_restricted as pr  # noqa: E402

TLD = sorted(pr.restricted_tlds())[0]
KW = pr.keywords()

SEED = bytes(range(32))
PUB = ed25519.public_key(SEED)
BASE = "https://lists.test/"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def gz(lines):
    return gzip.compress(("\n".join(lines) + "\n").encode(), mtime=0)


def make_bundle(tmp: Path, block_lines, version="2026.1001.0", split=False, bypass_lines=None):
    b = tmp / "bundled"
    b.mkdir()
    block = gz(block_lines)
    if split:
        for i in range(0, len(block), 100):
            (b / f"pax-block.txt.gz.part-{i // 100:03d}").write_bytes(block[i:i + 100])
    else:
        (b / "pax-block.txt.gz").write_bytes(block)
    allow = b"tailscale.com\ncharacter.ai\n"
    (b / "pax-allowlist.txt").write_bytes(allow)
    ss = b"host_exact,rewrite_to,note\n" + b"".join(
        f"www.google.c{i},forcesafesearch.google.com,x\n".encode() for i in range(10))
    (b / "safesearch_rules.csv").write_bytes(ss)
    man = {"schema": "pax.lists.v1", "version": version, "lists": {
        "pax-block": {"file": "pax-block.txt.gz", "kind": "block", "format": "domains", "min_entries": 5,
                      "max_drop": 0.10, "sha256": _sha(block), "entries": len(block_lines)},
        "pax-allow": {"file": "pax-allowlist.txt", "kind": "allow", "format": "domains", "min_entries": 1,
                      "max_drop": 1.0, "sha256": _sha(allow), "entries": 2},
        "safesearch": {"file": "safesearch_rules.csv", "kind": "safesearch", "format": "csv",
                       "min_entries": 5, "max_drop": 0.1, "sha256": _sha(ss), "entries": 10}}}
    if bypass_lines is not None:
        bp = gz(bypass_lines)
        (b / "pax-bypass.txt.gz").write_bytes(bp)
        man["lists"]["pax-bypass"] = {"file": "pax-bypass.txt.gz", "kind": "block", "format": "domains",
                                      "restricted": False, "min_entries": 1, "max_drop": 0.3,
                                      "sha256": _sha(bp), "entries": len(bypass_lines)}
        man["lists"]["pax-block"]["restricted"] = True
    (b / "filters.json").write_text(json.dumps(man))
    return b, man


def store(tmp, bundled, plugins=None):
    return fl.FilterStore(tmp / "state", bundled_dir=bundled, plugin_dirs=plugins or [],
                          compile_in_subprocess=False, log=lambda m: None)


def signed_manifest(man, version, files: dict, seed=SEED):
    payload = json.loads(json.dumps(man))
    payload["version"] = version
    for lid, data in files.items():
        payload["lists"][lid]["sha256"] = _sha(data)
        payload["lists"][lid]["bytes"] = len(data)
    return json.dumps(pax_signing.sign_document(payload, seed)).encode()


@pytest.fixture(autouse=True)
def pin_test_key(monkeypatch):
    monkeypatch.setattr(pax_signing, "PUBLIC_KEYS_HEX", [PUB.hex()])


BLOCK = [f"bad{i}.example" for i in range(50)] + [TLD]


def test_load_bundled_and_split_parts(tmp_path):
    b, _ = make_bundle(tmp_path, BLOCK, split=True)
    fs = store(tmp_path, b).load()
    assert fs.blocked_by("www.bad7.example") == "bad7.example"
    assert fs.blocked_by(f"site.{TLD}") == TLD
    assert fs.allowed("login.tailscale.com")
    assert fs.safesearch_target("www.google.c3") == "forcesafesearch.google.com"
    assert fs.info["lists"]["pax-block"]["origin"] == "bundled"


def test_update_swaps_in_good_list_and_keeps_previous(tmp_path):
    b, man = make_bundle(tmp_path, BLOCK)
    st = store(tmp_path, b)
    new = gz(BLOCK + ["new-bad.example"])
    urls = {BASE + "lists-manifest.json": signed_manifest(man, "2026.1002.0", {"pax-block": new}),
            BASE + "pax-block.txt.gz": new}
    rep = st.update(lambda u: urls[u], bases=[BASE])
    assert rep["ok"] and rep["changed"] == ["pax-block"]
    fs = st.load()
    assert fs.blocked_by("new-bad.example") and fs.info["lists"]["pax-block"]["origin"] == "updated"
    # a second good update keeps the first as "previous"
    newer = gz(BLOCK + ["new-bad.example", "newer.example"])
    urls = {BASE + "lists-manifest.json": signed_manifest(man, "2026.1003.0", {"pax-block": newer}),
            BASE + "pax-block.txt.gz": newer}
    assert st.update(lambda u: urls[u], bases=[BASE])["changed"] == ["pax-block"]
    assert (st.root / "previous" / "pax-block.txt.gz").read_bytes() == new
    assert st.rollback() and st.load().blocked_by("newer.example") is None


def test_unsigned_or_wrongly_signed_manifest_changes_nothing(tmp_path):
    b, man = make_bundle(tmp_path, BLOCK)
    st = store(tmp_path, b)
    new = gz(BLOCK + ["evil-unblock.example"])
    unsigned = json.dumps({"payload": dict(man, version="2026.1009.0")}).encode()
    rep = st.update(lambda u: {BASE + "lists-manifest.json": unsigned, BASE + "pax-block.txt.gz": new}[u],
                    bases=[BASE])
    assert not rep["ok"] and "unsigned" in rep["error"]
    other = signed_manifest(man, "2026.1009.0", {"pax-block": new}, seed=bytes(32))
    rep = st.update(lambda u: {BASE + "lists-manifest.json": other, BASE + "pax-block.txt.gz": new}[u],
                    bases=[BASE])
    assert not rep["ok"] and "bad signature" in rep["error"]
    assert st.current_manifest() is None


def test_hash_mismatch_mass_deletion_and_tiny_lists_rejected(tmp_path):
    b, man = make_bundle(tmp_path, BLOCK)
    st = store(tmp_path, b)
    good = gz(BLOCK + ["x.example"])
    tampered = gz(BLOCK + ["y.example"])
    urls = {BASE + "lists-manifest.json": signed_manifest(man, "2026.1002.0", {"pax-block": good}),
            BASE + "pax-block.txt.gz": tampered}
    rep = st.update(lambda u: urls[u], bases=[BASE])
    assert rep["rejected"] and "SHA-256" in rep["rejected"][0]["why"]
    # 51 -> 40 entries is more than the 10% max_drop
    shrunk = gz(BLOCK[:40])
    urls = {BASE + "lists-manifest.json": signed_manifest(man, "2026.1002.0", {"pax-block": shrunk}),
            BASE + "pax-block.txt.gz": shrunk}
    rep = st.update(lambda u: urls[u], bases=[BASE])
    assert rep["rejected"] and "removed" in rep["rejected"][0]["why"]
    tiny = gz(["a.example", "b.example"])
    urls = {BASE + "lists-manifest.json": signed_manifest(man, "2026.1002.0", {"pax-block": tiny}),
            BASE + "pax-block.txt.gz": tiny}
    rep = st.update(lambda u: urls[u], bases=[BASE])
    assert rep["rejected"] and "minimum" in rep["rejected"][0]["why"]
    junk = b"\x1f\x8bnot really gzip"
    urls = {BASE + "lists-manifest.json": signed_manifest(man, "2026.1002.0", {"pax-block": junk}),
            BASE + "pax-block.txt.gz": junk}
    rep = st.update(lambda u: urls[u], bases=[BASE])
    assert rep["rejected"] and "unreadable" in rep["rejected"][0]["why"]
    assert st.load().info["lists"]["pax-block"]["origin"] == "bundled"


def test_manifest_cannot_loosen_bundled_floors(tmp_path):
    b, man = make_bundle(tmp_path, BLOCK)
    st = store(tmp_path, b)
    shrunk = gz(BLOCK[:30])
    payload_man = json.loads(json.dumps(man))
    payload_man["lists"]["pax-block"]["max_drop"] = 0.99
    payload_man["lists"]["pax-block"]["min_entries"] = 1
    urls = {BASE + "lists-manifest.json": signed_manifest(payload_man, "2026.1002.0", {"pax-block": shrunk}),
            BASE + "pax-block.txt.gz": shrunk}
    assert st.update(lambda u: urls[u], bases=[BASE])["rejected"]


def test_older_lists_refused_and_mirror_used(tmp_path):
    b, man = make_bundle(tmp_path, BLOCK, version="2026.1010.0")
    st = store(tmp_path, b)
    old = gz(BLOCK + ["z.example"])
    urls = {BASE + "lists-manifest.json": signed_manifest(man, "2026.0901.0", {"pax-block": old}),
            BASE + "pax-block.txt.gz": old}
    rep = st.update(lambda u: urls[u], bases=[BASE])
    assert not rep["ok"] and "older" in rep["error"]
    mirror = "https://mirror.test/"
    urls = {mirror + "lists-manifest.json": signed_manifest(man, "2026.1011.0", {"pax-block": old}),
            mirror + "pax-block.txt.gz": old}

    def fetch(u):
        if u.startswith(BASE):
            raise OSError("down")
        return urls[u]
    assert st.update(fetch, bases=[BASE, mirror])["changed"] == ["pax-block"]


def test_damaged_updated_copy_falls_back_to_bundled(tmp_path):
    b, man = make_bundle(tmp_path, BLOCK)
    st = store(tmp_path, b)
    new = gz(BLOCK + ["n.example"])
    urls = {BASE + "lists-manifest.json": signed_manifest(man, "2026.1002.0", {"pax-block": new}),
            BASE + "pax-block.txt.gz": new}
    st.update(lambda u: urls[u], bases=[BASE])
    (st.root / "current" / "pax-block.txt.gz").write_bytes(b"garbage")
    fs = st.load()
    assert fs.info["lists"]["pax-block"]["origin"] == "bundled" and fs.blocked_by("bad1.example")


def test_due_daily(tmp_path):
    b, _ = make_bundle(tmp_path, BLOCK)
    st = store(tmp_path, b)
    assert st.due(1000)
    st._save_meta({"checked_at": 1000})
    assert not st.due(1000 + 3600) and st.due(1000 + 86400 + fl.UPDATE_JITTER + 1)


class Limited(OSError):
    def __init__(self, status, retry_after=None):
        super().__init__(f"HTTP {status}")
        self.status, self.retry_after = status, retry_after


def test_rate_limited_sources_back_off(tmp_path):
    b, _ = make_bundle(tmp_path, BLOCK)
    st = store(tmp_path, b)

    def fetch(u):
        raise Limited(429, 7200)
    rep = st.update(fetch, now=10_000, bases=[BASE])
    assert not rep["ok"] and rep["backoff_seconds"] == 7200
    assert not st.due(10_000 + 7000) and st.due(10_000 + 86400 + fl.UPDATE_JITTER + 1)
    rep = st.update(lambda u: (_ for _ in ()).throw(Limited(503)), now=20_000, bases=[BASE])
    assert rep["backoff_seconds"] == 14400                 # doubled
    assert fl.MAX_DOWNLOAD == 20 * 1024 * 1024


def test_plugin_lists_drop_in(tmp_path):
    b, _ = make_bundle(tmp_path, BLOCK)
    plug = tmp_path / "lists.d"
    plug.mkdir()
    (plug / "extra.txt").write_text("restricted-site.example\n0.0.0.0 hosts-style.example\n")
    (plug / "extra.json").write_text(json.dumps({"id": "extra-sites", "file": "extra.txt", "kind": "block",
                                                 "format": "hosts", "enabled": True, "min_entries": 1}))
    (plug / "fp.txt").write_text("overridable.example\n")
    (plug / "fp.json").write_text(json.dumps({"id": "extra-overridable", "file": "fp.txt", "kind": "block",
                                              "enabled": True, "restricted": False}))
    (plug / "kw.txt").write_text(f"{KW[0]}\n{KW[-1]}\n")
    (plug / "kw.json").write_text(json.dumps({"id": "name-words", "file": "kw.txt", "kind": "block",
                                              "format": "keywords", "enabled": True}))
    (plug / "off.json").write_text(json.dumps({"id": "off", "file": "extra.txt", "kind": "block", "enabled": False}))
    (plug / "evil.json").write_text(json.dumps({"id": "evil", "file": "../x", "kind": "block", "enabled": True}))
    fs = store(tmp_path, b, plugins=[plug]).load()
    assert fs.blocked_by("www.restricted-site.example") == "restricted-site.example"
    assert fs.restricted_by("www.restricted-site.example")       # plug-ins are restricted by default
    assert fs.blocked_by("hosts-style.example")
    assert fs.overridable_by("overridable.example") and not fs.restricted_by("overridable.example")
    assert fs.restricted_by(f"free{KW[0]}.example") == "keyword"       # keyword at label edge
    assert fs.restricted_by(f"{KW[-1]}-site.example") == "keyword"
    assert not fs.blocked_by(f"a{KW[0]}b.example")                   # mid-word: no
    assert "plugin:off" not in fs.info["lists"] and "plugin:evil" not in fs.info["lists"]


def test_restricted_and_overridable_lists_are_kept_apart(tmp_path):
    b, man = make_bundle(tmp_path, BLOCK, bypass_lines=["vpn-brand.example"])
    st = store(tmp_path, b)
    fs = st.load()
    assert fs.restricted_by("bad3.example") == "bad3.example" and not fs.overridable_by("bad3.example")
    assert fs.overridable_by("www.vpn-brand.example") == "vpn-brand.example"
    assert not fs.restricted_by("vpn-brand.example")
    assert fs.info["lists"]["pax-bypass"]["restricted"] is False
    # A signed update can't turn a restricted list into an overridable one.
    new = gz(BLOCK + ["new-bad.example"])
    payload = json.loads(json.dumps(man))
    payload["lists"]["pax-block"]["restricted"] = False
    urls = {BASE + "lists-manifest.json": signed_manifest(payload, "2026.1002.0", {"pax-block": new}),
            BASE + "pax-block.txt.gz": new}
    assert st.update(lambda u: urls[u], bases=[BASE])["changed"] == ["pax-block"]
    fs = st.load()
    assert fs.restricted_by("new-bad.example") and not fs.overridable_by("new-bad.example")


def test_keyword_rule_edges_and_allow_words():
    allow = [w for w in pr.keyword_allow_words() if any(k in w for k in KW)]
    assert allow, "the allow words cover place names that contain a keyword"
    r = fl.KeywordRule(KW, pr.keyword_allow_words())
    k = KW[0]
    for hit in (f"{k}shop.example", f"free{k}.example", f"my-{k}-site.example", f"{k}24.example",
                f"24{k}.example"):
        assert r.match(hit), hit
    for miss in [f"{w}.example" for w in allow] + [f"un{k}y.example", "camera.example",
                                                   f"xn--{k}-abc.example", f"the{k}club.example"]:
        assert not r.match(miss), miss


def _load_build():
    spec = importlib.util.spec_from_file_location("lists_build", REPO / "lists" / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_build_nrd_rule_matches_project_brief():
    b = _load_build()
    hit = b.nrd_rule()
    assert "cam" not in KW
    for k in KW:
        assert hit(f"{k}movieshouse") and hit(f"snap{k}24") and hit(f"izmir-vip-{k}"), k
        assert not hit(f"cmr{k}am") and not hit(f"curiou{k}istence"), k
    assert not hit("menucard") and not hit("camocruise") and not hit("sycamore")
    for w in pr.keyword_allow_words():
        assert not hit(w), w


def test_build_finalize_excludes_exact_and_allowlist_suffix():
    b = _load_build()
    out = b.finalize({"dmm.com", "sub.dmm.com", "sa.com", "x.sa.com", "tailscale.com", "a.tailscale.com",
                      "bad.example", "sub.bad.example", TLD, f"foo.{TLD}"},
                     exclude={"dmm.com", "sa.com"}, allow={"tailscale.com"})
    assert out == sorted(["sub.dmm.com", "bad.example", "x.sa.com", TLD])


def test_real_bundled_lists_are_complete_and_as_briefed():
    man = json.loads((GUARD / "filters" / "filters.json").read_text())
    assert set(man["lists"]) == {"pax-block", "pax-bypass", "pax-nrd", "pax-allow", "safesearch"}
    assert man["lists"]["pax-block"]["restricted"] is True and man["lists"]["pax-nrd"]["restricted"] is True
    assert man["lists"]["pax-bypass"]["restricted"] is False
    data = {}
    for lid, item in man["lists"].items():
        data[lid] = fl.read_bytes_maybe_parts(GUARD / "filters" / item["file"])
        assert _sha(data[lid]) == item["sha256"], lid
    assert man["lists"]["pax-block"]["entries"] > 1_300_000
    names = set(fl.decode_text(data["pax-block"], "pax-block.txt.gz").split("\n"))
    for must in ["redd.it", "redditmedia.com", "redditstatic.com", "imgur.io", "reddit.com", "co.cc", "cz.cc",
                 "translate.goog", "restricted-check.paxpeace.com"] + sorted(pr.restricted_tlds()):
        assert must in names, must
    for d in pr.hand_list():
        assert d in names, d
    bypass = set(fl.decode_text(data["pax-bypass"], "pax-bypass.txt.gz").split("\n"))
    assert man["lists"]["pax-bypass"]["entries"] > 10_000 and "nordvpn.com" in bypass
    assert not (bypass - {""}) & names
    for never in ("cosmopolitan.com", "pocketoption.com", "51.la", "dmm.com", "dynu.net", "sa.com",
                  "tailscale.com", "character.ai"):
        assert never not in names, never
    assert fl.parse_domains(data["pax-allow"].decode()) == ["tailscale.com", "character.ai"]
    assert len(fl.parse_safesearch(data["safesearch"].decode())) == 385
    for part in (GUARD / "filters").iterdir():
        assert part.stat().st_size < 90_000, part.name       # contents-API push limit
