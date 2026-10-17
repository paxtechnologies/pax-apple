# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.19 nightly filter workflow (lists/loop): homepage verdicts, packs (assemble,
sign, verify), the gates (floors, known-good, Tranco top 10k with held-back
entries, the paired benchmark), state and the encoded scoreboard. No network."""
import gzip
import json
import re
import sys
from pathlib import Path

import pytest

LOOP = Path(__file__).resolve().parents[1]
REPO = LOOP.parents[1]
sys.path.insert(0, str(LOOP))
import loop_util as lu  # noqa: E402
import bench  # noqa: E402
import build  # noqa: E402
import ed25519  # noqa: E402
import filter_lists as fl  # noqa: E402
import homepage  # noqa: E402
import pack  # noqa: E402
import pax_restricted as pr  # noqa: E402
import pax_signing  # noqa: E402
import run as loop  # noqa: E402

SEED = bytes(range(7, 39))
PUB = ed25519.public_key(SEED)
WORD = sorted(pr.data()["lookup_rule"]["words"])[0]


@pytest.fixture
def test_key(monkeypatch):
    monkeypatch.setattr(pax_signing, "FILTER_PUBLIC_KEYS_HEX", [PUB.hex()])
    import base64
    return base64.b64encode(SEED).decode()


# ------------------------------------------------------------- homepage
def test_homepage_verdicts():
    v = homepage.verdict
    assert v({"st": 200, "title": "Welcome", "rta": True}) == "adult"
    assert v({"st": 200, "title": "Home", "rating": True}) == "adult"
    assert v({"st": 200, "title": f"Free {WORD} videos", "adl": 3}) == "adult"
    assert v({"st": 200, "title": "Free web proxy - unblock any site"}) == "proxy"
    assert v({"st": 200, "title": "Residential proxies for scraping"}) == "other"
    assert v({"st": 200, "title": "This domain is for sale", "rta": True}) == "down"
    assert v({"st": 404, "title": "x"}) == "down"
    assert v({"st": 0, "err": "timeout"}) == "down"
    assert v({"st": 200, "title": "BBC - Home"}) == "other"


def test_homepage_check_is_rate_limited_and_never_raises():
    calls = []

    def fake(name, timeout):
        calls.append(name)
        if name == "boom.example":
            raise RuntimeError("x")
        return {"st": 200, "title": "Proxy list" if name.startswith("p") else "Hello"}
    out = homepage.check(["p1.example", "a.example", "boom.example", "p1.example"], qps=8, fetcher=fake)
    assert out == {"p1.example": "proxy", "a.example": "other", "boom.example": "down"}
    assert sorted(calls) == ["a.example", "boom.example", "p1.example"]


# ----------------------------------------------------------------- packs
def lists_fixture():
    m = pack.bundled_manifest()["lists"]
    return {"pax-block": lu.gz_bytes(["a.example", "b.example"]),
            "pax-bypass": lu.gz_bytes(["p.example"]),
            "pax-nrd": lu.gz_bytes(["n.example"]),
            "pax-allow": b"evil.example\n"}, m


def test_pack_assemble_sign_and_verify(tmp_path, test_key):
    lists, m = lists_fixture()
    payload = pack.assemble(tmp_path, lists, "2026.1018.300", {"code": "abc"})
    assert set(payload["lists"]) == {"pax-block", "pax-bypass", "pax-nrd"}      # never the allowlist
    item = payload["lists"]["pax-block"]
    assert item["object"] == f"pax-block-{lu.sha256(lists['pax-block'])[:16]}.txt.gz"
    assert re.match(fl._OBJECT, item["object"])
    assert item["restricted"] is True and item["min_entries"] == m["pax-block"]["min_entries"]
    doc = pack.sign(tmp_path, test_key)
    assert doc["payload"]["schema"] == fl.PACK_SCHEMA
    assert pack.verify(json.loads((tmp_path / fl.PACK_MANIFEST).read_text()), tmp_path)["version"] == "2026.1018.300"
    (tmp_path / item["object"]).write_bytes(b"tampered")
    with pytest.raises(ValueError):
        pack.verify(doc, tmp_path)


def test_signing_with_a_key_that_does_not_match_the_pinned_one_fails(tmp_path, test_key):
    import base64
    lists, _ = lists_fixture()
    pack.assemble(tmp_path, lists, "2026.1018.300")
    with pytest.raises(pax_signing.SignatureError):
        pack.sign(tmp_path, base64.b64encode(bytes(32)).decode())
    with pytest.raises(SystemExit):
        pack.sign(tmp_path, "")
    assert not (tmp_path / fl.PACK_MANIFEST).exists()


def test_a_pack_built_here_is_taken_by_the_guard(tmp_path, test_key, monkeypatch):
    """End to end: run.py's pack format is what filter_lists.FilterStore accepts."""
    sys.path.insert(0, str(REPO / "guard" / "tests"))
    import test_v08_lists as base
    b, man = base.make_bundle(tmp_path, base.BLOCK)
    out = tmp_path / "out"
    new_block = base.gz(base.BLOCK + ["fresh.example"])
    monkeypatch.setattr(pack, "bundled_manifest", lambda: man)
    pack.assemble(out, {"pax-block": new_block}, "2026.1018.300")
    pack.sign(out, test_key)
    st = base.store(tmp_path, b)
    urls = {base.BASE + p.name: p.read_bytes() for p in out.iterdir()}
    rep = st.update(lambda u: urls[u], bases=[base.BASE], canary=lambda fs: [])
    assert rep["changed"] == ["pax-block"] and st.load().blocked_by("fresh.example")


# ----------------------------------------------------------------- gates
class FakeDecider:
    def __init__(self, blocked=(), entries=None):
        self.b = set(blocked)
        self.entries = entries or {}

    def blocked(self, n):
        return n in self.b

    def list_entry(self, n):
        return self.entries.get(n, n)


def test_floor_failures(monkeypatch):
    man = {"lists": {"pax-block": {"file": "pax-block.txt.gz", "kind": "block", "format": "domains",
                                   "min_entries": 3, "max_drop": 0.1, "entries": 10}}}
    monkeypatch.setattr(pack, "bundled_manifest", lambda: man)
    ok = lu.gz_bytes([f"x{i}.example" for i in range(10)])
    assert loop.floor_failures({"pax-block": ok}, None) == []
    small = lu.gz_bytes(["a.example", "b.example"])
    assert "below the minimum" in loop.floor_failures({"pax-block": small}, None)[0]
    eight = lu.gz_bytes([f"x{i}.example" for i in range(8)])
    f = loop.floor_failures({"pax-block": eight}, {"lists": {"pax-block": {"entries": 9}}})
    assert any("bundled" in x for x in f)


def test_known_good_gate():
    uk = lu.gate_names("everyday-uk.txt")
    kg = lu.gate_names("known-good.txt")
    assert len(uk) == 57 and set(uk) <= set(kg) and len(kg) > 900
    fails, res = loop.gate_known_good(FakeDecider([uk[0]]))
    assert fails and res["uk57_blocked"] == 1 and res["encoded"] and uk[0] not in json.dumps(res)
    assert lu.decode_names(res["encoded"]) == [uk[0]]
    assert loop.gate_known_good(FakeDecider([]))[0] == []


def test_top10k_gate_confirms_holds_back_and_fails_on_code_rules(tmp_path):
    st = loop.State(tmp_path)
    top = [f"site{i}.example" for i in range(20)]
    new = FakeDecider(["site1.example", "site2.example", "site3.example"],
                      entries={"site3.example": "name-rule"})
    last = FakeDecider([])
    verdicts = {"site1.example": "adult", "site2.example": "other", "site3.example": "down"}
    res = loop.gate_top10k(new, last, top, st, lambda names: {n: verdicts[n] for n in names})
    assert res["confirmed"] == ["site1.example"]
    assert res["hold"] == {"site2.example"}
    assert res["code_rule"] == ["site3.example"] and res["fail"]
    assert st.checked["site2.example"][0] == "other" and "site2.example" in st.new_checked
    # a confirmed verdict is reused for 30 days without asking again
    asked = []
    res = loop.gate_top10k(FakeDecider(["site1.example"]), last, top, st, lambda n: asked.extend(n) or {})
    assert asked == [] and res["confirmed"] == ["site1.example"]
    big = [f"x{i}.example" for i in range(loop.MAX_NEW_TOP10K + 1)]
    assert "more than" in loop.gate_top10k(FakeDecider(big), last, big, st, lambda n: {})["fail"]


def test_paired_benchmark_and_regressions():
    ref = {f"a{i}": True for i in range(100)}
    names = list(ref)
    last = lambda d: int(d[1:]) < 90          # noqa: E731  90 blocked
    same = bench.paired(names, ref, last, last)
    assert same["losses"] == 0 and bench.regressions({"adult": same}) == []
    worse = bench.paired(names, ref, lambda d: int(d[1:]) < 85, last)
    assert worse["losses"] == 5 and bench.regressions({"adult": worse})
    within = bench.paired(names, ref, lambda d: int(d[1:]) < 88, last)
    assert bench.regressions({"adult": within}) == []          # 2 lost: within noise
    benign_ref = {f"b{i}": False for i in range(250)}
    fp = bench.paired(list(benign_ref), benign_ref, lambda d: d in ("b1", "b2", "b3"), lambda d: False)
    assert fp["new_fp"] == 3 and bench.regressions({"benign": fp})


def test_benchmark_run_offline_respects_budget_and_skips_seen(monkeypatch):
    src = "\n".join(f"0.0.0.0 h{i}.example" for i in range(50)).encode()
    blocked = {f"h{i}.example" for i in range(50)} | set(lu.gate_names("proxy-heldout.txt"))

    def ref_lookup(wire):
        q = wire[12:]
        labels, pos = [], 0
        while q[pos]:
            labels.append(q[pos + 1:pos + 1 + q[pos]].decode())
            pos += 1 + q[pos]
        n = ".".join(labels)
        return pr_answer(wire, nx=n in blocked)

    seen = {lu.name_hash("h0.example")}
    tranco = [f"t{i}.example" for i in range(20_000)]
    out = bench.run(lambda d: d in blocked, lambda d: d in blocked, tranco, seen, seed=1, qps=8, budget=1000,
                    adult_n=10, benign_n=5, proxy_n=5, fetch=lambda u: src,
                    ref_lookup=ref_lookup, neutral_lookup=lambda w: pr_answer(w))
    assert out["error"] is None and out["regressions"] == []
    assert "h0.example" not in out["sampled"] and len(out["sampled"]) == 10
    assert out["queries"]["reference"] == 20
    s = out["scores"]
    assert s["adult"]["n"] == 10 and s["adult"]["ref"] == 10 and s["benign"]["new_fp"] == 0
    out = bench.run(lambda d: True, lambda d: True, tranco, set(), seed=1, budget=3, adult_n=10, benign_n=5,
                    proxy_n=5, fetch=lambda u: src, ref_lookup=ref_lookup, neutral_lookup=lambda w: pr_answer(w))
    assert out["error"] and out["queries"]["reference"] == 3


def pr_answer(query: bytes, nx: bool = False) -> bytes:
    """A DNS answer to `query`: NXDOMAIN, or one A record."""
    import struct
    qid = query[:2]
    flags = 0x8183 if nx else 0x8180
    head = qid + struct.pack("!HHHHH", flags, 1, 0 if nx else 1, 0, 0)
    body = query[12:]
    if nx:
        return head + body
    return head + body + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, 9])


# ------------------------------------------------------- state + scoreboard
def test_state_roundtrip_and_hold_expiry(tmp_path):
    st = loop.State(tmp_path)
    st.record("a.example", "adult")
    old = tmp_path / "state" / "checked" / "20200101.json.gz"
    lu.save_json(old, {"old.example": ["other", "20200101"]})
    st.add_block.add("a.example")
    st.sample(["abc123"])
    st.held["h.example"] = lu.today()
    st.held["expired.example"] = "20200101"
    st.save()
    st2 = loop.State(tmp_path)
    assert st2.recent_verdict("a.example") == "adult" and "old.example" not in st2.checked
    assert not old.exists() and st2.sampled == ["abc123"]
    assert st2.add_block == {"a.example"} and st2.held_active() == {"h.example"}
    assert gzip.decompress((tmp_path / "state" / "verified-block.txt.gz").read_bytes()).startswith(b"#")


def test_scoreboard_keeps_names_encoded(tmp_path):
    r = {"version": "2026.1018.300", "ok": False, "last_version": "2026.1017.1",
         "failures": ["2 known-good sites would be blocked"],
         "known_good": {"uk57_blocked": 0, "known_good_blocked": 2,
                        "encoded": lu.encode_names(["secret-name.example"])},
         "top10k": {"new_blocks": 4, "held_back": 1, "encoded_held": lu.encode_names(["held.example"])},
         "bench": {"scores": {"adult": {"n": 10, "ref": 9, "new": 9, "last": 9}}, "queries": {"reference": 10}}}
    loop.write_scoreboard(tmp_path, r)
    loop.write_scoreboard(tmp_path, dict(r, version="2026.1019.300", ok=True, failures=[]))
    text = "".join(p.read_text() for p in (tmp_path / "scoreboard").iterdir())
    assert "secret-name" not in text and "held.example" not in text
    rows = (tmp_path / "scoreboard" / "history.csv").read_text().splitlines()
    assert rows[0].startswith("version,result") and len(rows) == 3 and ",published," in rows[2]
    assert "Not published because" not in (tmp_path / "scoreboard" / "latest.md").read_text()


def test_build_block_takes_checked_additions_and_held_back_entries(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for sid, (_u, _l, local) in build.SOURCES.items():
        lines = {"list_a": ["one.example", "www.two.example", "two.example", "sub.held.example", "held.example"],
                 "list_b": ["three.example"], "list_c": ["four.example"],
                 "hagezi_doh_vpn": ["vpn.example", "held.example"]}[sid]
        (src / local).parent.mkdir(parents=True, exist_ok=True)
        (src / local).write_text("\n".join(lines) + "\n")
    final, bypass, stats = build.build_block(src, extra_block=["added.example"], extra_bypass=["proxy.example"],
                                             remove=["held.example"])
    assert "added.example" in final and "proxy.example" in bypass
    assert "held.example" not in final and "sub.held.example" not in final and "held.example" not in bypass
    assert "two.example" in final and "www.two.example" not in final
    assert stats["loop_block_extra"] == 1 and stats["loop_bypass_extra"] == 1


def test_cli_limits():
    with pytest.raises(SystemExit):
        loop.main(["run", "--work", "w", "--state", "s", "--out", "o", "--qps", "20"])
    with pytest.raises(SystemExit):
        loop.main(["run", "--work", "w", "--state", "s", "--out", "o", "--ref-budget", "5000"])


# -------------------------------------------------------------- workflow
def test_workflow_shape():
    wf = (REPO / ".github" / "workflows" / "filter-loop.yml").read_text()
    assert "cron: \"0 3 * * *\"" in wf and "workflow_dispatch" in wf
    assert "secrets.PAX_FILTER_SIGNING_KEY" in wf and "PAX_UPDATE_SIGNING_KEY" not in wf
    assert "issues: write" in wf and "contents: write" in wf
    assert "filter-pack" in wf and "filter-packs" in wf and "filter-loop" in wf


def test_repo_text_keeps_the_reference_unnamed():
    files = list((REPO / "lists" / "loop").glob("*.py")) + [
        REPO / ".github" / "workflows" / "filter-loop.yml", REPO / "docs" / "FILTER_PACKS.md"]
    for f in files:
        low = f.read_text().lower()
        for word in ("cleanbrowsing", "nextdns", "covenant", "hardstop", "sage mobile"):
            assert word not in low, (f.name, word)
