# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.6 YouTube Restricted Mode switch on the Mac.

On by default. Off: only YouTube's own names skip the rewrite and are asked of
CleanBrowsing's Adult filter, then AdGuard Family (which restricts again: never
open), else SERVFAIL. Google/Bing SafeSearch, the user's blocks and every list
stay. Both directions are immediate (no wait, no partner email, by the
maintainer's decision), survive updates (state/settings.json) and are written
to the tamper log."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dns_forwarder as d  # noqa: E402
import filter_lists as fl  # noqa: E402
import pax_guard as pg  # noqa: E402
from domain_matcher import SmallSuffixSet  # noqa: E402
from test_v08_dns import FakeUpstream, ask, filters  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402

RULES = fl.parse_safesearch((Path(__file__).resolve().parents[2] / "lists" / "safesearch_rules.csv").read_text())
YT = sorted(d.YOUTUBE_NAMES)


def fwd(restricted=True, fail=(), block=()):
    main = FakeUpstream("cb-family", fail="cb-family" in fail, ip=b"\x0a\x00\x00\x01")
    ag = FakeUpstream("AdGuard Family", fail="ag" in fail, ip=b"\x0a\x00\x00\x02")
    adult = FakeUpstream("cb-adult", fail="cb-adult" in fail, ip=b"\x0a\x00\x00\x03")
    f = d.Forwarder([main, ag], fl.FilterSet([], SmallSuffixSet([]), RULES),
                    d.Policy(blocked=list(block), youtube_restricted=restricted),
                    youtube_upstreams=[adult, ag])
    return f, main, ag, adult


def test_names_match_the_safesearch_rules_and_the_profile():
    youtube_rules = {h for h, t in RULES.items() if t == "restrict.youtube.com"}
    assert youtube_rules == set(d.YOUTUBE_NAMES)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "profile"))
    import make_profile
    assert set(make_profile.YOUTUBE_NAMES) == set(d.YOUTUBE_NAMES)


def test_on_by_default_rewrites_youtube():
    f, main, ag, adult = fwd()
    assert d.Policy().youtube_restricted is True
    for name in YT:
        rc, ans = ask(f, name)
        assert ans[0][1] == d.QTYPE_CNAME and d.read_name(ans[0][4], 0)[0] == "restrict.youtube.com", name
    assert adult.calls == []


def test_off_sends_only_youtube_names_to_the_adult_filter():
    f, main, ag, adult = fwd(restricted=False)
    for name in YT:
        rc, ans = ask(f, name)
        assert rc == 0 and ans[0][4] == b"\x0a\x00\x00\x03", name          # answered by CleanBrowsing Adult
    assert sorted(d.Query(q).name for q in adult.calls) == YT
    # Google and Bing SafeSearch are untouched.
    for host, target in (("www.google.com", "forcesafesearch.google.com"), ("www.bing.com", "strict.bing.com")):
        rc, ans = ask(f, host)
        assert d.read_name(ans[0][4], 0)[0] == target
    # Everything else still goes to CleanBrowsing Family, and other YouTube-ish names aren't freed.
    for other in ("example.com", "music.youtube.com.evil.example", "i.ytimg.com"):
        ask(f, other)
    assert all(d.Query(q).name not in d.YOUTUBE_NAMES for q in main.calls)
    assert len(adult.calls) == len(YT)
    assert f.active == "cb-family"                       # Home still shows the main filter


def test_off_still_honours_blocks():
    f, *_ = fwd(restricted=False, block=["youtube.com"])
    rc, ans = ask(f, "www.youtube.com")
    assert ans[0][4] == b"\x00\x00\x00\x00"


def test_off_falls_back_to_adguard_family_then_servfail_never_open():
    f, main, ag, adult = fwd(restricted=False, fail=("cb-adult",))
    rc, ans = ask(f, "www.youtube.com")
    assert rc == 0 and ans[0][4] == b"\x0a\x00\x00\x02"       # AdGuard Family (restricts it again)
    assert main.calls == []                                     # never an unfiltered resolver
    f, main, ag, adult = fwd(restricted=False, fail=("cb-adult", "ag", "cb-family"))
    rc, ans = ask(f, "www.youtube.com")
    assert rc == d.RCODE_SERVFAIL


def test_without_a_youtube_chain_youtube_stays_restricted():
    main = FakeUpstream("cb-family")
    f = d.Forwarder([main], fl.FilterSet([], SmallSuffixSet([]), RULES), d.Policy(youtube_restricted=False))
    rc, ans = ask(f, "www.youtube.com")
    assert d.read_name(ans[0][4], 0)[0] == "restrict.youtube.com"


def test_switching_flushes_the_cache():
    f, main, ag, adult = fwd(restricted=False)
    ask(f, "www.youtube.com")
    f.set_policy(d.Policy(youtube_restricted=True))
    rc, ans = ask(f, "www.youtube.com")
    assert d.read_name(ans[0][4], 0)[0] == "restrict.youtube.com"


def test_default_youtube_chain_reuses_pinned_addresses():
    ups = d.default_upstreams()
    chain = d.youtube_upstreams(ups)
    assert chain[0].url == "https://doh.cleanbrowsing.org/doh/adult-filter/"
    assert chain[0].host == ups[0].host and set(chain[0].ips) <= set(ups[0].ips)
    assert chain[1] is ups[1] and chain[1].name.startswith("AdGuard Family")
    f = d.Forwarder(ups, None, youtube_upstreams=chain)
    assert set(f.pinned_ips()) == {ip for u in ups for ip in u.ips}    # pf allows nothing new


def test_guard_switch_is_immediate_logged_and_survives(tmp_path):
    g, s = local_guard(tmp_path)
    assert g.handle_request({"cmd": "settings.get"}, 501)["settings"]["youtube_restricted"] is True
    r = g.handle_request({"cmd": "settings.set", "youtube_restricted": False}, 501)
    assert r["ok"] and r["settings"]["youtube_restricted"] is False
    assert g.forwarder_policy().youtube_restricted is False
    events = [e for e in g.tamper_log.entries() if e["kind"] == "setting:youtube_restricted"]
    assert events[-1]["detail"] == {"from": True, "to": False, "uid": 501}
    assert g.tamper_log.verify()[0]
    # No wait and nothing sent: no request, no partner message queued.
    assert not g.blocklist.view().get("requests")
    # A new Guard (restart or update) reads it back from state/.
    g2 = pg.Guard(g.cfg, s, state_dir=tmp_path / "PaxGuard" / "state", quarantine_dir=tmp_path / "q")
    assert g2.youtube_restricted is False
    assert json.loads(s.read(str(tmp_path / "PaxGuard" / "state" / "settings.json")))["youtube_restricted"] is False
    r = g2.handle_request({"cmd": "settings.set", "youtube_restricted": True}, 501)
    assert r["settings"]["youtube_restricted"] is True and g2.status_summary()["settings"]["youtube_restricted"]


def test_guard_switch_refuses_bad_values_and_profile_dns(tmp_path):
    g, s = local_guard(tmp_path)
    assert g.handle_request({"cmd": "settings.set", "youtube_restricted": "no"}, 501)["ok"] is False
    assert g.handle_request({"cmd": "settings.set"}, 501)["ok"] is False
    g2, _ = local_guard(tmp_path / "p", dns_mode="profile")
    r = g2.handle_request({"cmd": "settings.set", "youtube_restricted": False}, 501)
    assert r["code"] == "PAX-DNS-011" and g2.youtube_restricted is True
    assert g2.settings_view()["youtube_available"] is False


def test_set_up_choice_is_the_default_until_the_switch_is_used(tmp_path):
    g, s = local_guard(tmp_path, youtube_restricted_default=False)
    assert g.youtube_restricted is False
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"youtube_restricted_default": False}))
    assert pg.GuardConfig.load(cfg).youtube_restricted_default is False
    assert pg.GuardConfig().youtube_restricted_default is True
