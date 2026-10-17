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
    """The filter seed as the secret holds it (base64)."""
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
    assert v({"st": 200, "title": "Residential proxies for scraping"}) == "proxy"     # paid proxies bypass too
    assert v({"st": 200, "title": "Web scraping API for data teams"}) == "other"
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


def test_public_key_matches_derivation(test_key, monkeypatch, capsys):
    monkeypatch.setenv("PAX_FILTER_SIGNING_KEY", test_key)
    monkeypatch.delenv("PAX_UPDATE_SIGNING_KEY", raising=False)
    assert loop.main(["public-key"]) == 0
    assert capsys.readouterr().out.strip() == pax_signing.FILTER_PUBLIC_KEYS_HEX[0]


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


# ------------------------------------------------- v0.8.21 loop: web proxies
import proxy  # noqa: E402


def test_homepage_proxy_signals():
    v = homepage.verdict
    # parked pages recognised from the page itself (no title)
    assert v({"st": 200, "title": "", "park": True, "pxy": 5}) == "down"
    # a gambling page on an old proxy name is not a proxy
    assert v({"st": 200, "title": "Casino bonus - web proxy", "pxy": 9}) == "other"
    # the site's own name in the title is not evidence
    assert v({"st": 200, "title": "unblockweb.biz", "host": "unblockweb.biz"}) == "other"
    assert v({"st": 200, "title": "Unblock any site - unblockweb.biz", "host": "unblockweb.biz"}) == "proxy"
    # proxy engines, web VPN and mirror pages
    assert v({"st": 200, "title": "Home", "frame": 1}) == "proxy"
    assert v({"st": 200, "title": "Free Web VPN"}) == "proxy"
    assert v({"st": 200, "title": "Proxy mirrors for every site"}) == "proxy"
    assert v({"st": 200, "title": "Datacenter hosting and colocation", "frame": 0}) == "other"
    assert homepage.FRAME.search('<script src="/uv/uv.bundle.js"></script>')
    assert homepage.PARK_BODY.search('<script>window.onload=function(){window.location.href="/lander"}</script>')
    assert not homepage.FRAME.search("<p>Corrosion of metal pipes</p>")


def test_proxy_priority_brands_and_lookalikes():
    names = ["bakery.example", "freeproxyhub.example", "garden.co.uk", "unblock-now.example"]
    assert proxy.priority(names) == ["freeproxyhub.example", "unblock-now.example", "bakery.example", "garden.co.uk"]
    b = proxy.brands(["megaproxy.com", "megaproxy.net", "otherproxy.org", "bakery.com", "px.io"])
    assert b == ["megaproxy", "otherproxy"]
    look = proxy.lookalikes(["megaproxy"], known={"megaproxy.com"})
    assert "megaproxy.com" not in look and "megaproxy.net" in look and "megaproxy.co.uk" in look


def test_proxy_nrd_and_certificate_candidates(tmp_path):
    import datetime as dt
    today = dt.date(2026, 10, 18)
    (tmp_path / "2026-10-17.txt").write_text("fastproxy99.com\nbakery.com\nmy-unblocker.net\n")
    assert proxy.nrd_candidates(tmp_path, 3, today) == ["fastproxy99.com", "my-unblocker.net"]
    rows = json.dumps([{"name_value": "megaproxy.com\n*.megaproxy.net"}, {"name_value": "megaproxy.io"}]).encode()
    assert proxy.ct_names("megaproxy", fetch=lambda u, timeout=60: rows) == ["megaproxy.com", "megaproxy.io", "megaproxy.net"]

    def boom(u, timeout=60):
        raise OSError("down")
    assert proxy.ct_names("megaproxy", fetch=boom) == []
    assert proxy.ct_candidates(["a1proxy", "b1proxy"], 2, "20261018", fetch=lambda u, timeout=60: b"[]") == []


def test_proxy_dns_alive_uses_the_resolver():
    out = proxy.dns_alive(["a.example", "b.example"], resolver=lambda n: n == "a.example")
    assert out == {"a.example": True, "b.example": False}


def test_heldout_pool_parses_both_lists():
    import csv as _csv
    import io as _io
    import zipfile as _zip
    d = proxy.data()
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w") as z:
        s = _io.StringIO()
        w = _csv.writer(s)
        w.writerow(["url", "category_code"])
        w.writerow(["https://www.heldproxy.example/", d["heldout_proxy_a_category"]])
        w.writerow(["https://news.example/", "NEWS"])
        w.writerow(["http://1.2.3.4/", d["heldout_proxy_a_category"]])
        z.writestr("repo/lists/global.csv", s.getvalue())

    def fetch(u, timeout=180):
        return buf.getvalue() if u == d["heldout_proxy_a_url"] else b"# x\nmirror-two.example\n"
    assert proxy.heldout_pool(fetch) == ["heldproxy.example", "mirror-two.example"]


def test_proxy_gate_allows_no_net_loss():
    ref = {f"p{i}": True for i in range(100)}
    last = lambda d: int(d[1:]) < 90          # noqa: E731
    one_lost = bench.paired(list(ref), ref, lambda d: int(d[1:]) < 89, last)
    assert one_lost["losses"] == 1
    assert bench.regressions({"proxy": one_lost}) and bench.regressions({"proxy_fresh": one_lost})
    traded = bench.paired(list(ref), ref, lambda d: (int(d[1:]) < 89) or d == "p95", last)
    assert bench.regressions({"proxy_fresh": traded}) == []
    assert bench.regressions({"adult": one_lost}) == []        # adult keeps its noise allowance


def test_benchmark_fresh_proxies_and_dead_hand_names(monkeypatch):
    src = "\n".join(f"0.0.0.0 h{i}.example" for i in range(50)).encode()
    hand = lu.gate_names("proxy-heldout.txt")
    dead = set(hand[:3])
    pool = [f"fresh{i}.example" for i in range(30)]
    monkeypatch.setattr(proxy, "heldout_pool", lambda fetch=None: pool + hand[:2])

    def neutral(wire):
        q = wire[12:]
        labels, pos = [], 0
        while q[pos]:
            labels.append(q[pos + 1:pos + 1 + q[pos]].decode())
            pos += 1 + q[pos]
        return pr_answer(wire, nx=".".join(labels) in dead)
    labeller = lambda names: {n: ("proxy" if int(n[5:].split(".")[0]) % 2 == 0 else "other") for n in names}  # noqa: E731
    tranco = [f"t{i}.example" for i in range(20_000)]
    out = bench.run(lambda d: d.startswith("fresh"), lambda d: False, tranco, set(), seed=3, budget=1000,
                    adult_n=10, benign_n=5, proxy_fresh_n=8, fetch=lambda u: src,
                    ref_lookup=lambda w: pr_answer(w, nx=True), neutral_lookup=neutral, labeller=labeller)
    s = out["scores"]
    assert s["proxy"]["n"] == len(hand) - 3                       # names that no longer exist are left out
    assert s["proxy_fresh"]["n"] == 8 and s["proxy_fresh"]["new"] == 8 and s["proxy_fresh"]["gains"] == 8
    assert out["proxy_fresh"]["working_proxies"] == 8
    assert not any(r.startswith("proxy_fresh") for r in out["regressions"])


def test_scoreboard_migrates_history_header(tmp_path):
    sb = tmp_path / "scoreboard"
    sb.mkdir()
    (sb / "history.csv").write_text("version,result,proxy_n\n2026.1017.1537,published,77\n")
    r = {"version": "2026.1018.300", "ok": True, "failures": [], "discovery": {"lookalikes": 4},
         "bench": {"scores": {"proxy_fresh": {"n": 10, "ref": 9, "new": 9, "last": 8}}}}
    loop.write_scoreboard(tmp_path, r)
    rows = (sb / "history.csv").read_text().splitlines()
    assert rows[0] == ",".join(loop.HISTORY_FIELDS) and len(rows) == 3
    assert rows[1].startswith("2026.1017.1537,published,")
    assert "fresh held-out sample" in (sb / "latest.md").read_text()


def test_cli_limits_for_discovery():
    with pytest.raises(SystemExit):
        loop.main(["run", "--work", "w", "--state", "s", "--out", "o", "--verify-max", "9000"])
    with pytest.raises(SystemExit):
        loop.main(["run", "--work", "w", "--state", "s", "--out", "o", "--dns-max", "90000"])


def test_homepage_check_collects_links_of_proxy_pages_and_frontier_persists(tmp_path):
    def fake(name, timeout):
        if name == "dir.example":
            return {"st": 200, "title": "Proxy list", "links": ["p1.example", "p2.example"]}
        return {"st": 200, "title": "Bakery", "links": ["x.example"]}
    got: dict = {}
    homepage.check(["dir.example", "bakery.example"], qps=8, fetcher=fake, links_out=got)
    assert got == {"dir.example": ["p1.example", "p2.example"]}
    st = loop.State(tmp_path)
    st.frontier = ["p1.example", "p2.example", "p1.example"]
    st.save()
    assert loop.State(tmp_path).frontier == ["p1.example", "p2.example"]


# ------------------------------------------- round 2: VPN services, more sources
def test_candidate_verdict_vpn_services_and_not_proxies():
    cv = homepage.candidate_verdict
    # consumer VPN services count as bypass sites
    assert cv({"st": 200, "title": "Blast VPN — Browse Without Limits", "host": "blastvpn.org"}) == "proxy"
    assert cv({"st": 200, "title": "Лучший ВПН для России | BeeFreeVPN", "host": "beefreevpn.ru"}) == "proxy"
    # ... but not enterprise gateways, VPN detection or words that only contain "vpn"
    # (round 6: VPN review / comparison pages now count, see the round 6 test)
    assert cv({"st": 200, "title": "SSL VPN Portal - Log in", "host": "vpn.example.com"}) == "other"
    assert cv({"st": 200, "title": "Free transparent PNG images", "host": "favpng.example"}) == "other"
    assert cv({"st": 200, "title": "Secure VPN Solutions for Business", "host": "corpvpn.example"}) == "other"
    # pages that use "proxy" for something else
    assert cv({"st": 200, "title": "Email Security | NoSpamProxy", "host": "nospamproxy.example", "pxy": 6}) == "other"
    assert cv({"st": 200, "title": "Charles Web Debugging Proxy", "host": "charles.example"}) == "other"
    assert cv({"st": 200, "title": "Proxy Server Free Fire APK Download", "host": "ff.example", "pxy": 90}) == "other"
    assert cv({"st": 200, "title": "FunBlock", "host": "funblocks.example"}) == "other"
    # proxy code on the page still wins, and real proxies stay proxies
    assert cv({"st": 200, "title": "Unblocked Games", "host": "g.example", "frame": 2}) == "proxy"
    assert cv({"st": 200, "title": "Free Web Proxy - Unblock Websites", "host": "p.example", "pxy": 9}) == "proxy"
    # the benchmark's labeller is unchanged
    assert homepage.verdict({"st": 200, "title": "Blast VPN — Browse Without Limits", "host": "blastvpn.org"}) == "other"


def test_tranco_and_github_candidates():
    top = ["google.com"] * 3 + ["bakery.com", "megaproxy.net", "fastvpn.ru", "unblock-it.org"]
    assert proxy.tranco_candidates(top, start=3) == ["megaproxy.net", "fastvpn.ru", "unblock-it.org"]
    page = json.dumps({"items": [
        {"name": "someone.github.io", "homepage": ""},
        {"name": "uv-app", "homepage": "https://my-uv.vercel.app/"},
        {"name": "x", "homepage": "discord.gg/abc"},
        {"name": "y", "homepage": "https://docs.example.org"},
        {"name": "z", "homepage": "www.proxysite.example"}]}).encode()
    got = proxy.github_candidates(fetch=lambda url: page, pages=1, pause=0)
    assert got == ["someone.github.io", "my-uv.vercel.app", "proxysite.example"]

    def boom(url):
        raise OSError("rate limited")
    assert proxy.github_candidates(fetch=boom, pages=1, pause=0) == []


def test_github_candidates_read_readme_links():
    search = json.dumps({"items": [{"full_name": "a/uv", "name": "uv", "homepage": "", "updated_at": "2026-10-17"}]}).encode()
    readme = b"Official links: https://mirror-one.example/ and [two](https://www.mirror-two.example/x) https://github.com/a/uv"

    def fake(url):
        return readme if url.endswith("/readme") else search
    assert proxy.github_candidates(fetch=fake, pages=1, pause=0) == ["mirror-one.example", "mirror-two.example"]
    assert proxy.readme_hosts("see http://a.example and https://b.example/path") == ["a.example", "b.example"]


def test_ut1_vpn_category_parses_and_survives_errors():
    import io as _io
    import tarfile as _tar
    buf = _io.BytesIO()
    with _tar.open(fileobj=buf, mode="w:gz") as tf:
        data = b"fastvpn.example\nwww.othervpn.example\n10.0.0.1\nfastvpn.example\n"
        ti = _tar.TarInfo("vpn/domains")
        ti.size = len(data)
        tf.addfile(ti, _io.BytesIO(data))
    assert proxy.ut1_vpn(fetch=lambda url: buf.getvalue()) == ["fastvpn.example", "othervpn.example"]

    def boom(url):
        raise OSError("down")
    assert proxy.ut1_vpn(fetch=boom) == []


def test_candidate_verdict_round4_weak_evidence_and_bot_checks():
    cv = homepage.candidate_verdict
    # a few proxy words in the body and nothing in the title: not enough
    assert cv({"st": 200, "title": "Find IP Address Country Location", "host": "ip.example", "pxy": 4}) == "other"
    assert cv({"st": 200, "title": "Tips for hiding your identity online", "host": "h.example", "pxy": 8}) == "proxy"
    assert cv({"st": 200, "title": "Pirate Bay mirror", "host": "tpb.example", "pxy": 3}) == "proxy"
    assert cv({"st": 200, "title": "Home", "host": "big.example", "pxy": 40}) == "proxy"
    # a bot check says nothing either way
    assert cv({"st": 200, "title": "Just a moment...", "host": "p.example", "pxy": 0}) == "down"
    assert cv({"st": 200, "title": "Security Check Required", "host": "p.example"}) == "down"


def test_recheck_bypass_drops_only_pages_that_are_now_something_else(tmp_path):
    st = loop.State(tmp_path)
    st.add_bypass = {"still.example", "gone.example", "repurposed.example"}
    verdicts = {"still.example": "proxy", "gone.example": "down", "repurposed.example": "other"}
    dropped = loop.recheck_bypass(st, 8, n=10, checker=lambda names: {n: verdicts[n] for n in names})
    assert dropped == ["repurposed.example"]
    assert st.add_bypass == {"still.example", "gone.example"}
    assert st.checked["repurposed.example"][0] == "other"


# ------------------------------------------- round 5: curated lists, Chrome top sites
def test_curated_lists_parse_every_format_and_survive_errors():
    plain = "# header\nfast-proxy.example\n0.0.0.0 hosts-style.example\n||adblock-style.example^\n" \
            "www.web-vpn.example # note\ndns.resolver.example\n10.0.0.1\n*.wild.example\n"
    assert proxy.parse_curated(plain, "domains") == ["fast-proxy.example", "hosts-style.example",
                                                     "adblock-style.example", "web-vpn.example", "wild.example"]
    links = json.dumps({"links": ["https://a.mirror.example/", "b.mirror.example", 7]})
    assert proxy.parse_curated(links, "json-links") == ["a.mirror.example", "b.mirror.example"]
    assert proxy.parse_curated("not json", "json-links") == []
    src = (("one", "https://x.example/1", "domains", "CC0-1.0"), ("two", "https://x.example/2", "domains", "CC0-1.0"))

    def fetch(url):
        if url.endswith("2"):
            raise OSError("down")
        return b"proxy-one.example\n"
    assert proxy.curated_candidates(fetch, src) == {"one": ["proxy-one.example"], "two": []}
    # every curated source has an id, a url, a known format and an open licence
    for sid, url, fmt, lic in proxy.curated():
        assert url.startswith("https://") and fmt in ("domains", "json-links")
        assert lic in ("Unlicense", "CC0-1.0", "Apache-2.0", "MIT", "GPL-3.0", "CC-BY-4.0", "CC-BY-SA-4.0")
    # a curated list never comes from the held-out lists
    held = {proxy.data()["heldout_proxy_a_url"], proxy.data()["heldout_proxy_b_url"]}
    owners = {u.split("/")[3].lower() for u in held if "githubusercontent" in u or "github.com" in u}
    for _sid, url, _f, _l in proxy.curated():
        assert url not in held and url.split("/")[3].lower() not in owners


def test_chrome_top_sites_candidates():
    import datetime as _dt
    import gzip as _gz
    assert proxy.crux_months(_dt.date(2026, 10, 17)) == ["202609", "202608", "202607"]
    assert proxy.crux_months(_dt.date(2026, 1, 3), back=2) == ["202512", "202511"]
    csv = "origin,rank\nhttps://www.fastproxy.example,1000\nhttps://news.example,1000\n" \
          "https://lk.somevpn.example,5000\nhttp://10.0.0.1,5000\n"

    def fetch(url, timeout=None):
        if "/global/202609" in url or "/country/gb/202608" in url:
            return _gz.compress(csv.encode())
        raise OSError("404")
    got = proxy.crux_candidates(fetch, countries=("gb", "us"), today=_dt.date(2026, 10, 17))
    assert got == ["fastproxy.example", "lk.somevpn.example"]


def test_candidate_verdict_round5_unblock_alone_is_not_a_proxy():
    cv = homepage.candidate_verdict
    assert cv({"st": 200, "title": "Drain Services | Unblock Cumbria", "host": "unblockc.example"}) == "other"
    assert cv({"st": 200, "title": "Blocks Without Boundaries for WordPress | Unblock", "host": "uwp.example"}) == "other"
    assert cv({"st": 200, "title": "Speed Stars Unblocked", "host": "ss.example"}) == "other"
    assert cv({"st": 200, "title": "Government VPN Access - Secure Network", "host": "vpn.gov.example"}) == "other"
    # proxy words, proxy code or many proxy words still count
    assert cv({"st": 200, "title": "Unblockit - Proxies to access blocked sites", "host": "u.example"}) == "proxy"
    assert cv({"st": 200, "title": "Unblock", "host": "u2.example", "frame": True}) == "proxy"
    assert cv({"st": 200, "title": "Unblock any website free", "host": "u3.example"}) == "proxy"
    assert cv({"st": 200, "title": "SpotVPN - fast VPN", "host": "spotvpn.example"}) == "proxy"


def test_chrome_rotation_and_majestic_candidates():
    import datetime as _dt
    days = [(_dt.date(2026, 10, 1) + _dt.timedelta(d)).isoformat() for d in range(12)]
    seen = set()
    for d in days:
        r = proxy.crux_rotation(d)
        assert len(r) == proxy.CRUX_ROTATING_PER_NIGHT and set(r) <= set(proxy.CRUX_ROTATING)
        seen |= set(r)
    assert seen == set(proxy.CRUX_ROTATING)
    assert not set(proxy.CRUX_ROTATING) & set(proxy.CRUX_COUNTRIES)
    csv = "GlobalRank,TldRank,Domain,TLD\n1,1,topproxy.example,example\n2,2,fastproxy.example,example\n" \
          "3,3,news.example,example\n4,4,myvpn.example,example\n"
    assert proxy.majestic_candidates(fetch=lambda url, timeout=None: csv.encode(), start=1) == [
        "fastproxy.example", "myvpn.example"]

    def boom(url, timeout=None):
        raise OSError("down")
    assert proxy.majestic_candidates(fetch=boom) == []


def test_round6_policy_unblocked_games_and_vpn_reviews_are_bypass():
    """Decided 2026-10-17: unblocked-games pages and VPN review / affiliate pages are
    bypass sites; paid proxy networks stay proxies."""
    cv = homepage.candidate_verdict
    for title, host in [("Slope Unblocked Games - Play Free", "slope.example"),
                        ("Unblocked Games 76", "ug76.example"),
                        ("Cookie Clicker Unblocked", "cc.example"),
                        ("Unblocked Classroom 6x", "c6x.example"),
                        ("The Unblocked Initiative", "p2pgames.example"),
                        ("Best VPNs compared: reviews 2026", "vpnreviews.example"),
                        ("The Best VPN Services of 2026 | Compare Top VPN Providers", "top10bestvpn.example"),
                        ("Residential Proxies | Rotating Proxy Provider", "resi.example")]:
        assert cv({"st": 200, "title": title, "host": host}) == "proxy", title
    # still not bypass: games without "unblocked", "unblocked" without games, questions,
    # news, gambling on an old games name, the site's name alone, publishers, sunblock
    for title, host in [("Coolmath Games - Free Online Games", "coolmathgames.com"),
                        ("Poki - Free Online Games - Play Now!", "poki.com"),
                        ("Unblocked Games for school", "poki.com"),
                        ("Speed Stars Unblocked", "ss.example"),
                        ("Fortnite Unblocked? Play a Free Battle Royale Instead", "fn.example"),
                        ("Tech Unblockedgames - Games Related Tech News", "tech.example"),
                        ("Unblocked games news tracker", "t.example"),
                        ("BeonBet Casino | Slots Unblocked Games", "bb.example"),
                        ("Home | slope-unblocked-10x.example", "slope-unblocked-10x.example"),
                        ("Buy Sunblock / Sunscreen - play safe", "sunblock.example"),
                        ("Context for agentic software development | Unblocked", "getunblocked.example"),
                        ("Unblock Drains - play area plumbing", "drains.example")]:
        assert cv({"st": 200, "title": title, "host": host}) == "other", title
    # the benchmark's labeller is unchanged
    assert homepage.verdict({"st": 200, "title": "Best VPNs compared: reviews 2026", "host": "vpnreviews.example"}) == "other"


def test_round6_policy_recheck_of_old_other_verdicts(tmp_path, monkeypatch):
    st = loop.State(tmp_path)
    st.checked = {"unblocked-games76.example": ["other", "20261017"],
                  "topvpnrate.example": ["other", "20261017"],
                  "bakery.example": ["other", "20261017"],
                  "unblockedgames.example": ["other", "20261018"],
                  "freevpn.example": ["down", "20261017"]}
    monkeypatch.setattr(lu, "days_since", lambda d: 1)
    assert st.recent_verdict("unblocked-games76.example") is None
    assert st.recent_verdict("topvpnrate.example") is None
    assert st.recent_verdict("bakery.example") == "other"
    assert st.recent_verdict("unblockedgames.example") == "other"
    assert st.recent_verdict("freevpn.example") == "down"
