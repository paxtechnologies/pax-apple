# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0 local DNS forwarder: wire format, decisions, failover order, SERVFAIL
when every upstream is down (never unfiltered), SafeSearch rewrites, the
matcher, and a real UDP/TCP round trip on a high port. v0.8.1: restricted
lists and categories are blocked even when the name has an exception."""
import socket
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import dns_forwarder as d  # noqa: E402
import filter_lists as fl  # noqa: E402
from domain_matcher import SmallSuffixSet, SuffixMatcher, collapse, reverse_name  # noqa: E402


# ------------------------------------------------------------------ helpers
def answer_for(query: bytes, ip: bytes = b"\x5d\xb8\xd7\x0e", ttl: int = 600, rcode: int = 0) -> bytes:
    q = d.Query(query)
    hdr = struct.pack("!HHHHHH", 0, 0x8180 | rcode, 1, 0 if rcode else 1, 0, 0)
    rr = b"" if rcode else b"\xc0\x0c" + struct.pack("!HHIH", q.qtype, 1, ttl, len(ip)) + ip
    return hdr + q.question + rr


class FakeUpstream:
    def __init__(self, name, fail=False, ip=b"\x01\x02\x03\x04"):
        self.name, self.url, self.host = name, f"https://{name}.example/dns-query", f"{name}.example"
        self.fail, self.ip = fail, ip
        self.healthy = True
        self.last_error = ""
        self.calls = []
        self.ips = ["192.0.2.1"]
        self.trusted_time = None

    def query(self, wire):
        self.calls.append(wire)
        if self.fail:
            raise d.DNSError(f"{self.name} down")
        q = d.Query(wire)
        ip = self.ip if q.qtype == d.QTYPE_A else b"\x20\x01" + b"\x00" * 13 + b"\x01"
        return answer_for(wire, ip)


def filters(block=(), allow=(), safesearch=None, nrd=(), restricted=()):
    """`block` and `nrd` here are lists an exception may free; `restricted` ones it never frees."""
    return fl.FilterSet([SuffixMatcher.from_domains(list(block)), SmallSuffixSet(nrd)],
                        SmallSuffixSet(allow), safesearch or {},
                        restricted=[SuffixMatcher.from_domains(list(restricted))])


def ask(fwd, name, qtype=d.QTYPE_A, qid=0x4242):
    resp = fwd.handle(d.build_query(name, qtype, qid))
    assert struct.unpack("!H", resp[:2])[0] == qid
    return d.parse_answers(resp)


# ------------------------------------------------------------------ matcher
def test_matcher_suffix_match_and_tld_entries():
    m = SuffixMatcher.from_domains(["example.com", "tldone", "tldtwo", "co.cc", "a.b.c.org", "zz-top.net"])
    assert m.match("example.com") == "example.com"
    assert m.match("deep.sub.EXAMPLE.com.") == "example.com"
    assert m.match("notexample.com") is None          # label boundary, not substring
    assert m.match("anything.tldone") == "tldone"     # single-label (TLD) entries honoured
    assert m.match("foo.tldtwo") == "tldtwo"
    assert m.match("site.co.cc") == "co.cc"
    assert m.match("b.c.org") is None and m.match("x.a.b.c.org") == "a.b.c.org"
    assert m.match("zz-top.net") and not m.match("zz.net")
    assert "tldone" in m and "example.org" not in m


def test_matcher_collapse_and_roundtrip():
    names = ["a.example.com", "example.com", "b.a.example.com", "other.org"]
    assert sorted(collapse(names)) == ["example.com", "other.org"]
    m = SuffixMatcher.from_domains([f"site{i}.example{i % 97}.com" for i in range(5000)] + ["tld"])
    m2 = SuffixMatcher.from_bytes(m.to_bytes())
    assert len(m2) == len(m) == 5001
    for i in (0, 1, 31, 32, 33, 4999):
        assert m2.match(f"www.site{i}.example{i % 97}.com")
    assert m2.match("site1.example2.com") is None
    assert m2.match("x.tld") == "tld"


def test_matcher_rejects_damaged_file():
    data = bytearray(SuffixMatcher.from_domains(["a.com", "b.com"]).to_bytes())
    data[-1] ^= 0xFF
    with pytest.raises(ValueError):
        SuffixMatcher.from_bytes(bytes(data))


def test_matcher_is_compact():
    names = [f"host{i}.zone{i % 1000}.example" for i in range(50_000)]
    m = SuffixMatcher.from_domains(names)
    plain = sum(len(n) + 1 for n in names)
    assert m.nbytes < plain           # front coding beats the plain text
    assert reverse_name("www.Example.com") == b"com.example.www"


# ---------------------------------------------------------------- decisions
def test_order_safesearch_then_user_then_allowlist_then_lists():
    f = filters(block=["vpn-brand.example", "tailscale.com", "falsepositive.com"], allow=["tailscale.com"],
                restricted=["restricted.example"], safesearch={"www.google.com": "forcesafesearch.google.com"})
    pol = d.Policy(blocked=["mine.example", "falsepositive.com"], exceptions=["falsepositive.com", "www.google.com"],
                   categories=["pbs.twimg.com"])
    fwd = d.Forwarder([FakeUpstream("cb")], f, pol)
    assert fwd.decide("www.google.com") == ("rewrite", "forcesafesearch.google.com")   # exception can't skip SafeSearch
    assert fwd.decide("falsepositive.com") == ("forward", "exception")
    assert fwd.decide("x.mine.example")[0] == "block"
    assert fwd.decide("pbs.twimg.com")[0] == "block"
    assert fwd.decide("login.tailscale.com") == ("forward", "allowlist")
    assert fwd.decide("cdn.vpn-brand.example") == ("block", "list:vpn-brand.example")
    assert fwd.decide("cdn.restricted.example") == ("block", "restricted:restricted.example")
    assert fwd.decide("example.org") == ("forward", "")


def test_exception_never_frees_restricted_lists_or_categories():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
    import pax_restricted as pr
    rule = pr.parse_rule_file("tomp4\n")
    kw_name = f"free-{pr.keywords()[0]}.example"
    f = filters(block=["vpn-brand.example"], restricted=["restricted.example"],
                safesearch={"www.google.com": "forcesafesearch.google.com"})
    pol = d.Policy(exceptions=["restricted.example", "vpn-brand.example", "converter.example", "clip-tomp4.example",
                               kw_name, "www.google.com", "remote.example"],
                   categories=["remote.example"], restricted=["converter.example"], restricted_rules=[rule],
                   never_except=pr.RestrictedCheck())
    up = FakeUpstream("cb")
    fwd = d.Forwarder([up], f, pol)
    assert fwd.decide("restricted.example") == ("block", "restricted:restricted.example")
    assert fwd.decide("www.restricted.example")[0] == "block"
    assert fwd.decide("converter.example") == ("block", "restricted:category")
    assert fwd.decide("clip-tomp4.example") == ("block", "restricted:category")
    # A benign false positive (VPN/proxy list, a Pax category) is freed after the wait,
    # and still goes upstream (CleanBrowsing / AdGuard), never unfiltered.
    assert fwd.decide("vpn-brand.example") == ("forward", "exception")
    assert fwd.decide("remote.example") == ("forward", "exception")
    # The name rule: the exception is ignored (plain upstream lookup, which filters it).
    assert fwd.decide(kw_name) == ("forward", "")
    assert fwd.decide("www.google.com")[0] == "rewrite"
    rc, ans = ask(fwd, "restricted.example")
    assert ans[0][4] == b"\x00\x00\x00\x00" and up.calls == []
    ask(fwd, "vpn-brand.example")
    assert len(up.calls) == 1


def test_blocked_answers_zero_address_and_nodata():
    fwd = d.Forwarder([FakeUpstream("cb")], filters(block=["bad.example"]))
    rc, ans = ask(fwd, "www.bad.example", d.QTYPE_A)
    assert rc == 0 and ans[0][1] == d.QTYPE_A and ans[0][4] == b"\x00\x00\x00\x00"
    rc, ans = ask(fwd, "bad.example", d.QTYPE_AAAA)
    assert ans[0][4] == b"\x00" * 16
    rc, ans = ask(fwd, "bad.example", 16)       # TXT: NODATA
    assert rc == 0 and ans == []
    assert fwd.stats["blocked"] == 3


def test_safesearch_rewrite_cname_plus_addresses():
    up = FakeUpstream("cb", ip=b"\xd8\xef\x26\x78")       # 216.239.38.120
    rules = fl.parse_safesearch((Path(__file__).resolve().parents[2] / "lists" / "safesearch_rules.csv").read_text())
    assert len(rules) == 385
    fwd = d.Forwarder([up], fl.FilterSet([], SmallSuffixSet([]), rules))
    for host, target in [("www.google.co.uk", "forcesafesearch.google.com"), ("google.de", "forcesafesearch.google.com"),
                         ("youtube.com", "restrict.youtube.com"), ("m.youtube.com", "restrict.youtube.com"),
                         ("youtubei.googleapis.com", "restrict.youtube.com"),
                         ("www.youtube-nocookie.com", "restrict.youtube.com"),
                         ("bing.com", "strict.bing.com"), ("www.bing.com", "strict.bing.com"),
                         ("duckduckgo.com", "safe.duckduckgo.com")]:
        rc, ans = ask(fwd, host)
        assert rc == 0
        assert ans[0][1] == d.QTYPE_CNAME and d.read_name(ans[0][4], 0)[0] == target, host
        assert ans[1][0] == target and ans[1][4] == b"\xd8\xef\x26\x78"
    # the upstream was asked for the safe name, not the original
    assert d.Query(up.calls[0]).name == "forcesafesearch.google.com"
    rc, ans = ask(fwd, "www.google.com", d.QTYPE_HTTPS)   # no HTTPS record: browsers use A/AAAA
    assert rc == 0 and ans == []
    assert fwd.decide("mail.google.com")[0] == "forward"   # only the listed hosts


# ---------------------------------------------------------------- failover
def test_primary_first_then_fallback_on_failure():
    cb, ag = FakeUpstream("cb"), FakeUpstream("adguard", ip=b"\x05\x06\x07\x08")
    logs = []
    fwd = d.Forwarder([cb, ag], filters(), log=logs.append)
    rc, ans = ask(fwd, "example.org")
    assert ans[0][4] == b"\x01\x02\x03\x04" and len(cb.calls) == 1 and not ag.calls
    assert fwd.active == "cb"
    cb.fail = True
    rc, ans = ask(fwd, "example.net")
    assert ans[0][4] == b"\x05\x06\x07\x08"
    assert fwd.active == "adguard" and not cb.healthy
    assert any("PAX-DNS-003" in l for l in logs)
    # while CleanBrowsing is marked down, AdGuard is asked first
    ag.calls.clear()
    cb.calls.clear()
    ask(fwd, "example.com")
    assert ag.calls and not cb.calls
    # the health check brings CleanBrowsing back to the front
    cb.fail = False
    fwd.health_check()
    assert cb.healthy and fwd.active == "cb"


def test_servfail_when_every_upstream_fails_never_unfiltered():
    cb, ag = FakeUpstream("cb", fail=True), FakeUpstream("adguard", fail=True)
    logs = []
    fwd = d.Forwarder([cb, ag], filters(), log=logs.append)
    resp = fwd.handle(d.build_query("example.org", d.QTYPE_A, 7))
    rcode, ans = d.parse_answers(resp)
    assert rcode == d.RCODE_SERVFAIL and ans == []
    assert any("PAX-DNS-004" in l for l in logs)
    # SafeSearch names fail closed too (no CNAME without the safe address)
    fwd2 = d.Forwarder([FakeUpstream("cb", fail=True)],
                       fl.FilterSet([], SmallSuffixSet([]), {"www.google.com": "forcesafesearch.google.com"}))
    assert d.parse_answers(fwd2.handle(d.build_query("www.google.com", d.QTYPE_A, 8)))[0] == d.RCODE_SERVFAIL
    assert fwd.health_check()["all_down"] is True and fwd.active is None


def test_servfail_until_lists_are_loaded():
    fwd = d.Forwarder([FakeUpstream("cb")], None)
    assert d.parse_answers(fwd.handle(d.build_query("example.org", 1, 9)))[0] == d.RCODE_SERVFAIL
    fwd.set_filters(filters())
    assert d.parse_answers(fwd.handle(d.build_query("example.org", 1, 9)))[0] == 0


def test_only_doh_upstreams_and_default_order():
    assert [u[0] for u in d.DEFAULT_UPSTREAMS] == ["CleanBrowsing Family", "AdGuard Family"]
    assert d.DEFAULT_UPSTREAMS[0][1] == "https://doh.cleanbrowsing.org/doh/family-filter/"
    assert d.DEFAULT_UPSTREAMS[1][1] == "https://family.adguard-dns.com/dns-query"
    with pytest.raises(ValueError):
        d.DohUpstream("plain", "http://1.1.1.1/dns-query", ["1.1.1.1"])


def test_cache_serves_repeat_and_keeps_query_id():
    up = FakeUpstream("cb")
    fwd = d.Forwarder([up], filters())
    ask(fwd, "example.org", qid=1)
    ask(fwd, "example.org", qid=2)
    assert len(up.calls) == 1
    fwd.flush()
    ask(fwd, "example.org", qid=3)
    assert len(up.calls) == 2


def nx_with_soa(query: bytes, soa_ttl=3600, minimum=120) -> bytes:
    q = d.Query(query)
    hdr = struct.pack("!HHHHHH", 0, 0x8183, 1, 0, 1, 0)
    rdata = d.encode_name("ns.example") + d.encode_name("host.example") + struct.pack("!IIIII", 1, 2, 3, 4, minimum)
    soa = d.encode_name("example") + struct.pack("!HHIH", d.QTYPE_SOA, 1, soa_ttl, len(rdata)) + rdata
    return hdr + q.question + soa


def test_cache_respects_ttl_and_ages_it(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(d, "monotonic_continuous", lambda: clock["t"])
    up = FakeUpstream("cb")
    fwd = d.Forwarder([up], filters())
    up.query = lambda wire: (up.calls.append(wire), answer_for(wire, ttl=120))[1]
    ask(fwd, "example.org")
    clock["t"] += 100
    rc, ans = ask(fwd, "example.org")
    assert len(up.calls) == 1 and ans[0][3] == 20            # served from cache, TTL aged
    clock["t"] += 21
    ask(fwd, "example.org")
    assert len(up.calls) == 2                                # expired with its TTL
    assert fwd.stats["cache_hits"] == 1


def test_negative_cache_uses_soa_minimum_and_skips_servfail(monkeypatch):
    clock = {"t": 0.0}
    monkeypatch.setattr(d, "monotonic_continuous", lambda: clock["t"])
    up = FakeUpstream("cb")
    up.query = lambda wire: (up.calls.append(wire), nx_with_soa(wire, minimum=120))[1]
    fwd = d.Forwarder([up], filters())
    assert ask(fwd, "nope.example")[0] == d.RCODE_NXDOMAIN
    clock["t"] += 119
    ask(fwd, "nope.example")
    assert len(up.calls) == 1
    clock["t"] += 2
    ask(fwd, "nope.example")
    assert len(up.calls) == 2
    assert d.cache_ttl(nx_with_soa(d.build_query("x.example", 1), soa_ttl=99999, minimum=99999)) == d.NEG_MAX_TTL
    assert d.cache_ttl(answer_for(d.build_query("x.example", 1), ttl=999999)) == d.MAX_TTL
    assert d.cache_ttl(answer_for(d.build_query("x.example", 1), ttl=0)) == 0
    assert d.cache_ttl(answer_for(d.build_query("x.example", 1), rcode=2)) == 0
    up.query = lambda wire: (up.calls.append(wire), answer_for(wire, rcode=2))[1]
    ask(fwd, "flaky.example")
    ask(fwd, "flaky.example")
    assert len([c for c in up.calls if d.Query(c).name == "flaky.example"]) == 2


def test_malformed_and_truncation():
    fwd = d.Forwarder([FakeUpstream("cb")], filters())
    bad = struct.pack("!HHHHHH", 5, 0x0100, 2, 0, 0, 0)
    resp = fwd.handle(bad)
    assert resp[3] & 0x0F == d.RCODE_FORMERR
    assert fwd.handle(b"\x00") is None
    q = d.Query(d.build_query("example.org", 1, 3))
    big = d.make_blocked(q) + b"\x00" * 600
    t = d.truncate_for_udp(q, big)
    assert t[2] & 0x02 and len(t) < 512


def test_compressed_names_and_pointer_loops():
    msg = b"\x00" * 12 + b"\x03www\x07example\x03com\x00" + b"\xc0\x10"
    assert d.read_name(msg, 12) == ("www.example.com", 29)
    assert d.read_name(msg, 29)[0] == "example.com"
    loop = b"\x00" * 12 + b"\xc0\x0c"
    with pytest.raises(d.DNSError):
        d.read_name(loop, 12)


def test_trusted_time_from_date_header():
    up = d.DohUpstream("cb", "https://doh.cleanbrowsing.org/doh/family-filter/", ["192.0.2.1"])
    up._record_date("Thu, 15 Oct 2026 15:00:00 GMT")
    fwd = d.Forwarder([up], filters())
    t = fwd.trusted_now()
    assert t is not None and abs(t - 1792076400) < 5


# ------------------------------------------------------------- real socket
def test_udp_and_tcp_server_round_trip():
    fwd = d.Forwarder([FakeUpstream("cb")], filters(block=["blocked.example"]))
    srv = d.DNSServer(fwd, host="127.0.0.1", port=0, log=lambda m: None)
    srv.start()
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3)
        u.sendto(d.build_query("blocked.example", 1, 77), ("127.0.0.1", srv.port))
        data, _ = u.recvfrom(4096)
        assert d.parse_answers(data)[1][0][4] == b"\x00\x00\x00\x00"
        t = socket.create_connection(("127.0.0.1", srv.port), timeout=3)
        q = d.build_query("example.org", 1, 78)
        t.sendall(struct.pack("!H", len(q)) + q)
        n = struct.unpack("!H", t.recv(2))[0]
        resp = t.recv(n)
        assert d.parse_answers(resp)[1][0][4] == b"\x01\x02\x03\x04"
        t.close()
    finally:
        srv.stop()


def test_user_block_beats_safesearch_rewrite():
    """v0.8.3: blocking a search engine yourself blocks it outright."""
    f = filters(safesearch={"bing.com": "strict.bing.com", "www.bing.com": "strict.bing.com",
                            "www.google.com": "forcesafesearch.google.com"})
    pol = d.Policy(blocked=["bing.com"], exceptions=[])
    fwd = d.Forwarder([FakeUpstream("cb")], f, pol)
    assert fwd.decide("bing.com") == ("block", "your blocked sites")
    assert fwd.decide("www.bing.com") == ("block", "your blocked sites")
    assert fwd.decide("www.google.com") == ("rewrite", "forcesafesearch.google.com")
