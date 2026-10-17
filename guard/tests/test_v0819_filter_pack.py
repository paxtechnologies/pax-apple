# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.19 filter packs: signed list-only updates from the nightly filter workflow.

The pack must be signed with the filter key (never the app update key), be newer
than the copy in use, change block lists only, keep the bundled floors, max-drop
and "restricted" flags, pass the canary before it is swapped in, and be rolled
back (and never taken again) if it fails the canary after the swap."""
import gzip
import hashlib
import json
import sys
import types
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent
REPO = GUARD.parent
sys.path.insert(0, str(GUARD))
sys.path.insert(0, str(HERE))
import ed25519  # noqa: E402
import filter_lists as fl  # noqa: E402
import pax_signing  # noqa: E402
import test_v08_lists as base  # noqa: E402

SEED = base.SEED
PUB = base.PUB
APP_SEED = bytes(range(1, 33))
APP_PUB = ed25519.public_key(APP_SEED)
BASE = base.BASE
BLOCK = base.BLOCK


@pytest.fixture(autouse=True)
def pin_keys(monkeypatch):
    monkeypatch.setattr(pax_signing, "FILTER_PUBLIC_KEYS_HEX", [PUB.hex()])
    monkeypatch.setattr(pax_signing, "PUBLIC_KEYS_HEX", [APP_PUB.hex()])


def sha(b):
    return hashlib.sha256(b).hexdigest()


def pack(man, version, files: dict, seed=SEED, objects=True, **extra):
    """(manifest bytes, {url: bytes}) for a pack with content-addressed objects."""
    payload = json.loads(json.dumps(man))
    payload.update(schema=fl.PACK_SCHEMA, version=version, **extra)
    urls = {}
    for lid, data in files.items():
        item = payload["lists"][lid]
        item["sha256"], item["bytes"] = sha(data), len(data)
        if objects:
            stem = item["file"].split(".")[0]
            ext = item["file"][len(stem):]
            item["object"] = f"{stem}-{sha(data)[:16]}{ext}"
            urls[BASE + item["object"]] = data
        else:
            urls[BASE + item["file"]] = data
    doc = json.dumps(pax_signing.sign_document(payload, seed, context=pax_signing.FILTER_CONTEXT)).encode()
    urls[BASE + fl.PACK_MANIFEST] = doc
    return urls


def fetcher(urls):
    def fetch(u):
        if u not in urls:
            raise OSError(f"404 {u}")
        return urls[u]
    return fetch


def test_keys_are_separate_and_pinned():
    import importlib
    fresh = importlib.reload(pax_signing)
    try:
        assert len(fresh.FILTER_PUBLIC_KEYS_HEX) == 1 and len(bytes.fromhex(fresh.FILTER_PUBLIC_KEYS_HEX[0])) == 32
        assert not set(fresh.FILTER_PUBLIC_KEYS_HEX) & set(fresh.PUBLIC_KEYS_HEX)
        assert fresh.FILTER_CONTEXT == b"pax-filter-pack-v1"
    finally:
        importlib.reload(pax_signing)


def test_signatures_never_cross_between_packs_and_app_updates():
    """Even with the very same key, a pack signature can't pass as an app update or back."""
    payload = {"version": "2026.1018.300", "schema": fl.PACK_SCHEMA, "lists": {}}
    as_pack = pax_signing.sign_document(payload, SEED, context=pax_signing.FILTER_CONTEXT)
    as_app = pax_signing.sign_document(payload, SEED)
    keys = [PUB]
    assert pax_signing.verify_document(as_pack, keys, context=pax_signing.FILTER_CONTEXT) == payload
    assert pax_signing.verify_document(as_app, keys) == payload
    with pytest.raises(pax_signing.SignatureError):
        pax_signing.verify_document(as_pack, keys)
    with pytest.raises(pax_signing.SignatureError):
        pax_signing.verify_document(as_app, keys, context=pax_signing.FILTER_CONTEXT)
    with pytest.raises(ValueError):
        pax_signing.sign_document(payload, SEED, context=b"other")


def test_pack_signed_with_the_app_key_is_refused(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK)
    st = base.store(tmp_path, b)
    urls = pack(man, "2026.1018.300", {"pax-block": base.gz(BLOCK + ["n.example"])}, seed=APP_SEED)
    rep = st.update(fetcher(urls), bases=[BASE])
    assert not rep["ok"] and "bad signature" in rep["error"] and st.current_manifest() is None
    # signed with the filter key but without the pack context (as an app update would be)
    payload = json.loads(urls[BASE + fl.PACK_MANIFEST])["payload"]
    urls[BASE + fl.PACK_MANIFEST] = json.dumps(pax_signing.sign_document(payload, SEED)).encode()
    rep = st.update(fetcher(urls), bases=[BASE])
    assert not rep["ok"] and "bad signature" in rep["error"]
    # ...and a document signed with the filter key never passes as an app update
    doc = pax_signing.sign_document({"version": "9.9.9"}, SEED)
    with pytest.raises(pax_signing.SignatureError):
        pax_signing.verify_document(doc)


def test_good_pack_swaps_in_with_content_addressed_objects(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK)
    st = base.store(tmp_path, b)
    new = base.gz(BLOCK + ["fresh-bad.example"])
    seen = []
    urls = pack(man, "2026.1018.300", {"pax-block": new})
    rep = st.update(fetcher(urls), bases=[BASE], canary=lambda fs: seen.append(fs) or [])
    assert rep["ok"] and rep["changed"] == ["pax-block"] and rep["version"] == "2026.1018.300"
    assert seen and seen[0].blocked_by("fresh-bad.example")       # canary saw the new lists
    fs = st.load()
    assert fs.blocked_by("fresh-bad.example") and fs.info["origin"] == "pack"
    assert fs.info["version"] == "2026.1018.300"
    status = st.pack_status()
    assert status["version"] == "2026.1018.300" and status["origin"] == "pack" and status["last_ok"]


def test_same_version_is_a_no_op_and_older_is_refused(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK, version="2026.1017.1")
    st = base.store(tmp_path, b)
    urls = pack(man, "2026.1017.1", {"pax-block": base.gz(BLOCK + ["a.example"])})
    rep = st.update(fetcher(urls), bases=[BASE])
    assert rep["ok"] and rep.get("up_to_date") and not rep["changed"]
    urls = pack(man, "2026.1016.2359", {"pax-block": base.gz(BLOCK + ["a.example"])})
    rep = st.update(fetcher(urls), bases=[BASE])
    assert not rep["ok"] and "older" in rep["error"]
    # numeric, not string, comparison: 1017.1630 is newer than 1017.1
    urls = pack(man, "2026.1017.1630", {"pax-block": base.gz(BLOCK + ["a.example"])})
    assert st.update(fetcher(urls), bases=[BASE])["changed"] == ["pax-block"]
    assert fl.version_key("2026.1017.1630") > fl.version_key("2026.1017.1")


def test_pack_cannot_free_a_restricted_list_or_touch_allow_and_safesearch(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK, bypass_lines=["proxy1.example", "proxy2.example"])
    st = base.store(tmp_path, b)
    payload_man = json.loads(json.dumps(man))
    payload_man["lists"]["pax-block"]["restricted"] = False          # try to make it freeable
    new_block = base.gz(BLOCK + ["r.example"])
    new_allow = b"tailscale.com\ncharacter.ai\nr.example\n"
    urls = pack(payload_man, "2026.1018.300", {"pax-block": new_block, "pax-allow": new_allow})
    rep = st.update(fetcher(urls), bases=[BASE])
    assert rep["changed"] == ["pax-block"]
    assert any(r["list"] == "pax-allow" and "block lists" in r["why"] for r in rep["rejected"])
    fs = st.load()
    assert fs.restricted_by("r.example") == "r.example"                # still restricted
    assert not fs.allowed("r.example")
    assert st.current_manifest()["lists"]["pax-block"]["restricted"] is True


def test_floors_hold_against_the_bundled_copy_too(tmp_path):
    big = [f"bad{i}.example" for i in range(100)]
    b, man = base.make_bundle(tmp_path, big)
    man["lists"]["pax-block"]["entries"] = 100
    (b / "filters.json").write_text(json.dumps(man))
    st = base.store(tmp_path, b)
    # 100 -> 92 (within 10%), then 92 -> 84 is within 10% of 92 but 16% below the bundled 100
    step1 = base.gz(big[:92])
    assert st.update(fetcher(pack(man, "2026.1018.1", {"pax-block": step1})), bases=[BASE])["changed"]
    step2 = base.gz(big[:84])
    rep = st.update(fetcher(pack(man, "2026.1018.2", {"pax-block": step2})), bases=[BASE])
    assert not rep["changed"] and "removed" in json.dumps(rep["rejected"])
    assert len(st.load().restricted[0]) == 92


def test_canary_failure_before_the_swap_keeps_the_last_good_lists(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK)
    st = base.store(tmp_path, b)
    good = base.gz(BLOCK + ["g.example"])
    assert st.update(fetcher(pack(man, "2026.1018.1", {"pax-block": good})), bases=[BASE])["changed"]
    bad = base.gz(BLOCK + ["b.example"])
    urls = pack(man, "2026.1018.2", {"pax-block": bad})
    rep = st.update(fetcher(urls), bases=[BASE], canary=lambda fs: ["an everyday name was blocked (x)"])
    assert not rep["ok"] and not rep["changed"] and "canary" in rep["error"]
    assert st.load().blocked_by("g.example") and st.load().blocked_by("b.example") is None
    assert "2026.1018.2" in st.refused_versions()
    # the same pack offered again is ignored without downloading anything
    calls = []
    rep = st.update(lambda u: calls.append(u) or urls[u], bases=[BASE], canary=lambda fs: [])
    assert rep.get("up_to_date") and calls == [BASE + fl.PACK_MANIFEST]


def test_a_pack_that_will_not_load_fails_its_canary(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK)
    st = base.store(tmp_path, b)

    def boom(fs):
        raise RuntimeError("engine broke")
    rep = st.update(fetcher(pack(man, "2026.1018.1", {"pax-block": base.gz(BLOCK + ["q.example"])})),
                    bases=[BASE], canary=boom)
    assert not rep["changed"] and st.current_manifest() is None


def test_rollback_after_the_swap_restores_previous_and_refuses_that_version(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK)
    st = base.store(tmp_path, b)
    one = base.gz(BLOCK + ["one.example"])
    two = base.gz(BLOCK + ["one.example", "two.example"])
    st.update(fetcher(pack(man, "2026.1018.1", {"pax-block": one})), bases=[BASE])
    urls = pack(man, "2026.1019.1", {"pax-block": two})
    st.update(fetcher(urls), bases=[BASE])
    assert st.load().blocked_by("two.example")
    assert st.rollback_pack("canary: a known restricted name was not blocked")
    fs = st.load()
    assert fs.blocked_by("one.example") and fs.blocked_by("two.example") is None
    assert fs.info["version"] == "2026.1018.1"
    status = st.pack_status()
    assert status["rolled_back"]["version"] == "2026.1019.1" and "2026.1019.1" in status["refused"]
    assert st.update(fetcher(urls), bases=[BASE]).get("up_to_date")       # never again


def test_bad_object_names_and_download_failures(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK)
    st = base.store(tmp_path, b)
    data = base.gz(BLOCK + ["o.example"])
    urls = pack(man, "2026.1018.1", {"pax-block": data})
    doc = json.loads(urls[BASE + fl.PACK_MANIFEST])
    doc["payload"]["lists"]["pax-block"]["object"] = "../../etc/passwd"
    urls[BASE + fl.PACK_MANIFEST] = json.dumps(pax_signing.sign_document(doc["payload"], SEED, context=pax_signing.FILTER_CONTEXT)).encode()
    rep = st.update(fetcher(urls), bases=[BASE])
    assert not rep["changed"] and "bad object name" in json.dumps(rep["rejected"])
    # a download failure is not a bad pack: nothing changes and the version is not refused
    urls = pack(man, "2026.1018.2", {"pax-block": data})
    del urls[[u for u in urls if u.endswith(".txt.gz")][0]]
    rep = st.update(fetcher(urls), bases=[BASE])
    assert not rep["changed"] and "downloaded" in rep["error"]
    assert "2026.1018.2" not in st.refused_versions()


def test_an_older_updated_copy_than_the_bundled_one_is_ignored(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK, version="2026.1001.0")
    st = base.store(tmp_path, b)
    st.update(fetcher(pack(man, "2026.1002.0", {"pax-block": base.gz(BLOCK + ["old.example"])})), bases=[BASE])
    assert st.load().blocked_by("old.example")
    # an app update bundles newer lists than the pack in use
    man2 = json.loads((b / "filters.json").read_text())
    man2["version"] = "2026.1017.1"
    (b / "filters.json").write_text(json.dumps(man2))
    fs = st.load()
    assert fs.blocked_by("old.example") is None and fs.info["version"] == "2026.1017.1"
    assert st.pack_status()["origin"] == "bundled"


def test_real_canary_vets_a_staged_pack(tmp_path):
    """dns_forwarder.check_filterset is the canary the guard and the server pass in."""
    import dns_forwarder as dnsf
    import pax_restricted as pr
    b, man = base.make_bundle(tmp_path, BLOCK + pr.samples())
    st = base.store(tmp_path, b)
    fs = st.load()
    assert dnsf.check_filterset(fs, min_entries=10) == []
    broken = base.gz(BLOCK + ["wikipedia.org"])                     # an everyday name blocked
    rep = st.update(fetcher(pack(man, "2026.1018.1", {"pax-block": broken})), bases=[BASE],
                    canary=lambda f: dnsf.check_filterset(f, min_entries=10))
    assert not rep["changed"] and rep["canary"]
    assert any("restricted name" in x or "everyday" in x for x in rep["canary"])


class FakeTamper:
    def __init__(self):
        self.events = []

    def append(self, kind, detail):
        self.events.append((kind, detail))


def test_guard_rolls_back_a_pack_that_fails_the_canary_in_use(tmp_path, monkeypatch):
    import pax_guard as pg
    b, man = base.make_bundle(tmp_path, BLOCK)
    st = base.store(tmp_path, b)
    st.update(fetcher(pack(man, "2026.1018.1", {"pax-block": base.gz(BLOCK + ["one.example"])})),
              bases=[BASE])
    urls = pack(man, "2026.1019.1", {"pax-block": base.gz(BLOCK + ["two.example"])})
    monkeypatch.setattr(fl, "PACK_BASES", [BASE])
    import dns_forwarder as dnsf
    monkeypatch.setattr(dnsf, "check_filterset", lambda fs, **k: [])       # passes before the swap
    loads = []
    fwd = types.SimpleNamespace(primary_upstreams=[object()], filters=None,
                                last_canary={"ok": False, "failures": ["a known restricted name was not blocked"]})

    def load_filters():
        fwd.filters = st.load()
        loads.append(fwd.filters.info["version"])
    g = types.SimpleNamespace(filter_store=st, forwarder=fwd, tamper_log=FakeTamper(),
                              sys=types.SimpleNamespace(fetch=lambda url, timeout=0: urls[url]),
                              _load_filters=load_filters)
    orig = st.update
    st.update = lambda fetch, canary=None: orig(fetch, bases=[BASE], canary=canary)
    rep = pg.Guard.update_lists_now(g)
    assert rep["rolled_back"] and loads == ["2026.1019.1", "2026.1018.1"]
    assert g.tamper_log.events[0][0] == "filters:pack_rolled_back"
    assert "2026.1019.1" in st.refused_versions()


def test_guard_logs_a_refused_pack_to_the_tamper_log(tmp_path, monkeypatch):
    import pax_guard as pg
    import dns_forwarder as dnsf
    b, man = base.make_bundle(tmp_path, BLOCK)
    st = base.store(tmp_path, b)
    urls = pack(man, "2026.1019.1", {"pax-block": base.gz(BLOCK + ["two.example"])})
    monkeypatch.setattr(dnsf, "check_filterset", lambda fs, **k: ["an everyday name was blocked (x)"])
    g = types.SimpleNamespace(filter_store=st, forwarder=None, tamper_log=FakeTamper(),
                              sys=types.SimpleNamespace(fetch=lambda url, timeout=0: urls[url]),
                              _load_filters=lambda: None)
    orig = st.update
    st.update = lambda fetch, canary=None: orig(fetch, bases=[BASE], canary=canary)
    rep = pg.Guard.update_lists_now(g)
    assert not rep["changed"]
    assert g.tamper_log.events and g.tamper_log.events[0][0] == "filters:pack_refused"


def test_bundled_lists_and_pack_channel_defaults():
    man = json.loads((GUARD / "filters" / "filters.json").read_text())
    assert fl.version_key(man["version"]) >= (2026, 1017, 1)
    assert fl.PACK_BASES[0].endswith("/releases/download/filter-pack/")
    assert "@filter-packs/" in fl.PACK_BASES[1]
    assert fl.UPDATE_INTERVAL == 6 * 3600
    # every block list in the bundle can be checked by a pack (floors present)
    for lid, item in man["lists"].items():
        assert item.get("min_entries") and item.get("max_drop") is not None, lid


def test_a_newer_pack_with_the_same_lists_takes_the_version_only(tmp_path):
    b, man = base.make_bundle(tmp_path, BLOCK)
    st = base.store(tmp_path, b)
    same = base.gz(BLOCK)
    urls = pack(man, "2026.1018.300", {"pax-block": same})
    calls = []
    rep = st.update(lambda u: calls.append(u) or urls[u], bases=[BASE], canary=lambda fs: ["not needed"])
    assert rep["ok"] and rep["taken"] and rep["changed"] == []
    assert calls == [BASE + fl.PACK_MANIFEST]                 # nothing downloaded
    assert st.load().info["version"] == "2026.1018.300" and st.pack_status()["origin"] == "pack"
    assert st.update(fetcher(urls), bases=[BASE]).get("up_to_date")


def test_pin_filter_key_tool(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("pin", REPO / "tools" / "pin-filter-key.py")
    pin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pin)
    p = tmp_path / "pax_signing.py"
    p.write_text((GUARD / "pax_signing.py").read_text())
    pin.pin("AB" * 32, p)
    assert 'FILTER_PUBLIC_KEYS_HEX = [\n    "' + "ab" * 32 + '",\n]' in p.read_text()
    with pytest.raises(SystemExit):
        pin.pin("xyz", p)
