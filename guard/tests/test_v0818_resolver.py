# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.18: Pax's own filter is the default resolver path. After Pax decides, an
allowed lookup goes to the primary (malware-only) chain, then the family chain,
else SERVFAIL. The family chain takes every lookup when the user turned on the
extra family layer, and automatically when Pax's filter fails a check (lists
missing or too small, the decision code throwing or slow, the canary self-test).
It switches back only when the canary passes again. Never open."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
import dns_forwarder as d  # noqa: E402
import filter_lists as fl  # noqa: E402
import guard_config as gc  # noqa: E402
import pax_restricted as pr  # noqa: E402
from domain_matcher import SmallSuffixSet, SuffixMatcher  # noqa: E402

from test_v08_dns import FakeUpstream, ask  # noqa: E402


def good_filters(block=(), safesearch=None):
    return fl.FilterSet([SuffixMatcher.from_domains(list(block))], SmallSuffixSet([]), safesearch or {},
                        restricted=[SuffixMatcher.from_domains(list(pr.samples()) + ["listed.test"])],
                        name_rules=[pr.lookup_rule()])


def make(filters=None, policy=None, prim_fail=False, fam_fail=False, events=None):
    prim = [FakeUpstream("q9", fail=prim_fail, ip=b"\x09\x09\x09\x09"),
            FakeUpstream("cfs", fail=prim_fail, ip=b"\x01\x01\x01\x02")]
    fam = [FakeUpstream("fam1", fail=fam_fail, ip=b"\x05\x05\x05\x05"),
           FakeUpstream("fam2", fail=fam_fail, ip=b"\x06\x06\x06\x06")]
    ev = events if events is not None else []
    fwd = d.Forwarder(fam, filters=None, policy=policy, log=lambda m: None, primary_upstreams=prim,
                      canary_min_entries=1, on_fallback=lambda on, why: ev.append((on, why)))
    if filters is not None:
        fwd.set_filters(filters)
    return fwd, prim, fam


def first_ip(fwd, name):
    rc, ans = ask(fwd, name)
    return rc, (ans[0][4] if ans else None)


def test_healthy_filter_uses_primary_chain_and_still_blocks_locally():
    fwd, prim, fam = make(good_filters(block=["proxy.test"]))
    assert fwd.last_canary["ok"] and fwd.status()["filter_mode"] == "pax"
    assert first_ip(fwd, "example.org") == (0, b"\x09\x09\x09\x09")
    assert not fam[0].calls
    for name in ["listed.test", "www." + pr.samples()[0], "proxy.test"]:
        rc, ans = ask(fwd, name)
        assert ans[0][4] == b"\x00\x00\x00\x00"           # decided locally, never forwarded
    assert len(prim[0].calls) == 1


def test_primary_down_goes_to_family_then_servfail():
    fwd, prim, fam = make(good_filters(), prim_fail=True)
    assert first_ip(fwd, "example.org") == (0, b"\x05\x05\x05\x05")
    fwd2, _, _ = make(good_filters(), prim_fail=True, fam_fail=True)
    rc, _ = ask(fwd2, "example.org")
    assert rc == d.RCODE_SERVFAIL


def test_family_layer_routes_everything_to_family_chain():
    fwd, prim, fam = make(good_filters(), policy=d.Policy(family_layer=True))
    assert first_ip(fwd, "example.org")[1] == b"\x05\x05\x05\x05"
    assert not prim[0].calls and fwd.status()["filter_mode"] == "family-layer"


def test_empty_lists_fall_back_at_once_and_never_use_primary():
    ev = []
    fwd, prim, fam = make(fl.empty_filterset(), events=ev)
    assert fwd.status()["filter_mode"] == "fallback" and ev and ev[0][0] is True
    assert first_ip(fwd, "example.org")[1] == b"\x05\x05\x05\x05"
    assert not prim[0].calls and not prim[1].calls
    # good lists again: the canary passes and the primary chain is back
    fwd.set_filters(good_filters())
    assert fwd.status()["filter_mode"] == "pax" and ev[-1][0] is False
    assert first_ip(fwd, "example.org")[1] == b"\x09\x09\x09\x09"


def test_lists_loading_use_family_chain_not_servfail_not_primary():
    fwd, prim, fam = make(None)
    assert first_ip(fwd, "example.org")[1] == b"\x05\x05\x05\x05"
    assert not prim[0].calls


def test_canary_fails_when_a_sample_is_missing_or_rule_broken():
    f = fl.FilterSet([], SmallSuffixSet([]), {}, restricted=[SuffixMatcher.from_domains(["other.test"])],
                     name_rules=[pr.lookup_rule()])
    fwd, prim, fam = make(f)
    assert not fwd.last_canary["ok"] and fwd.fallback_reason.startswith("canary")
    f2 = fl.FilterSet([], SmallSuffixSet([]), {}, restricted=[SuffixMatcher.from_domains(list(pr.samples()))])
    fwd2, _, _ = make(f2)            # no name rule
    assert any("name rule" in x for x in fwd2.last_canary["failures"])


def test_canary_fails_when_everyday_name_blocked():
    fwd, _, _ = make(good_filters(block=["wikipedia.org"]))
    assert any("everyday" in x for x in fwd.last_canary["failures"])
    assert fwd.status()["filter_mode"] == "fallback"


def test_decide_error_falls_back_for_that_query_and_after():
    fwd, prim, fam = make(good_filters())
    real = fwd.decide

    def boom(name, policy=None):
        raise RuntimeError("broken")
    fwd.decide = boom
    assert first_ip(fwd, "example.org")[1] == b"\x05\x05\x05\x05"
    assert fwd.status()["filter_mode"] == "fallback"
    fwd.decide = real
    first_ip(fwd, "example.net")
    assert not prim[0].calls                               # still in the fallback
    fwd.canary()
    assert fwd.status()["filter_mode"] == "pax"


def test_fallback_still_blocks_what_pax_decides():
    fwd, _, fam = make(good_filters())
    fwd.enter_fallback("test")
    rc, ans = ask(fwd, "listed.test")
    assert ans[0][4] == b"\x00\x00\x00\x00" and not fam[0].calls


def test_safesearch_rewrite_is_local_on_primary_path():
    fwd, prim, fam = make(good_filters(safesearch={"www.google.com": "forcesafesearch.google.com"}))
    rc, ans = ask(fwd, "www.google.com")
    assert ans[0][1] == d.QTYPE_CNAME
    assert d.Query(prim[0].calls[-1]).name == "forcesafesearch.google.com"


def test_youtube_unrestricted_on_primary_path_skips_rewrite():
    ss = {"www.youtube.com": "restrict.youtube.com"}
    fwd, prim, fam = make(good_filters(safesearch=ss), policy=d.Policy(youtube_restricted=False))
    rc, ans = ask(fwd, "www.youtube.com")
    assert ans[0][4] == b"\x09\x09\x09\x09"
    fwd2, prim2, _ = make(good_filters(safesearch=ss))
    rc, ans = ask(fwd2, "www.youtube.com")
    assert ans[0][1] == d.QTYPE_CNAME                     # Restricted Mode on: rewritten


def test_status_and_ips():
    fwd, prim, fam = make(good_filters())
    st = fwd.status()
    assert {u["role"] for u in st["upstreams"]} == {"primary", "family"}
    assert st["canary"]["ok"] is True
    assert fwd.primary_ips() == ["192.0.2.1"]


def test_without_primary_chain_old_behaviour_kept():
    fam = [FakeUpstream("fam1", ip=b"\x05\x05\x05\x05")]
    fwd = d.Forwarder(fam, filters=None, log=lambda m: None)
    rc, _ = ask(fwd, "example.org")
    assert rc == d.RCODE_SERVFAIL                        # lists loading: closed
    assert fwd.status()["filter_mode"] == "family"


def test_builtin_primary_chain_is_quad9_dot_then_cloudflare_security():
    ups = d.primary_upstreams()
    assert isinstance(ups[0], d.DotUpstream) and ups[0].host == "dns.quad9.net"
    assert isinstance(ups[1], d.DohUpstream) and ups[1].host == "security.cloudflare-dns.com"
    assert "9.9.9.9" in ups[0].ips and "1.1.1.2" in ups[1].ips


def test_canary_names_are_encoded_not_plain():
    src = (Path(__file__).resolve().parents[1] / "dns_forwarder.py").read_text()
    for name in pr.samples():
        assert name not in src


def test_pf_primary_root_only_and_blocked_without_user_match():
    rules = gc.pf_rules(allow_ips=["185.0.0.1"], local_dns=True, primary_ips=["9.9.9.9", "1.1.1.2"])
    assert "table <pax_primary> const { 1.1.1.2 9.9.9.9 }" in rules
    assert "to <pax_primary> port { 443 853 } user root" in rules
    lines = rules.splitlines()
    assert lines.index(next(x for x in lines if "<pax_primary> port" in x)) < \
        lines.index(next(x for x in lines if x.startswith("block drop out quick proto { tcp udp } from any to any port 853")))
    doh = next((x for x in lines if x.startswith("table <pax_doh>")), "")
    assert "9.9.9.9" not in doh and "1.1.1.2" not in doh
    open_rules = gc.pf_rules(allow_ips=["185.0.0.1"], local_dns=True, primary_ips=["9.9.9.9"],
                             root_only_upstream=False)
    assert "block drop out quick proto { tcp udp } from any to <pax_primary>" in open_rules
    assert "pass out quick proto tcp from any to <pax_primary>" not in open_rules


def test_dot_upstream_rejects_non_tls_url():
    import pytest
    with pytest.raises(ValueError):
        d.DotUpstream("x", "https://dns.quad9.net", ["9.9.9.9"])
    assert struct.calcsize("!H") == 2
