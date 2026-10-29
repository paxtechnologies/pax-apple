# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.36 faster browsing: serve-stale and prefetch for allowed answers only, hedged
upstream requests inside one chain, one upstream lookup per name at a time, the cache
kept across list changes (every lookup is decided again first), pipelined DNS-over-TLS
connections that are replaced when idle and dropped when silent, the network-change
reset, keep-warm, and the /etc/hosts work remembered between cycles.

Protection rules checked here: a blocked name is never answered from the cache, an
answer is never served stale on the family-filter route, a hedge never leaves the
query's chain, and everything still fails closed (SERVFAIL)."""
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import dns_forwarder as d  # noqa: E402
import filter_lists as fl  # noqa: E402
import guard_config as gc  # noqa: E402
from domain_matcher import SmallSuffixSet, SuffixMatcher  # noqa: E402


def answer_for(query: bytes, ip: bytes = b"\x01\x02\x03\x04", ttl: int = 120, rcode: int = 0) -> bytes:
    q = d.Query(query)
    hdr = struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8180 | rcode, 1, 0 if rcode else 1, 0, 0)
    rr = b"" if rcode else b"\xc0\x0c" + struct.pack("!HHIH", q.qtype, 1, ttl,
                                                    len(ip) if q.qtype == d.QTYPE_A else 16) + (
        ip if q.qtype == d.QTYPE_A else b"\x20\x01" + b"\x00" * 13 + b"\x01")
    return hdr + q.question + rr


class Up:
    def __init__(self, name, delay=0.0, fail=False, ttl=120, rcode=0, ip=b"\x01\x02\x03\x04"):
        self.name, self.url, self.host = name, f"https://{name}.example/dns-query", f"{name}.example"
        self.delay, self.fail, self.ttl, self.rcode, self.ip = delay, fail, ttl, rcode, ip
        self.healthy, self.last_error, self.ips, self.trusted_time = True, "", ["192.0.2.1"], None
        self.calls = []
        self.lock = threading.Lock()

    def query(self, wire):
        with self.lock:
            self.calls.append(d.Query(wire).name)
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise d.DNSError(f"{self.name} down")
        return answer_for(wire, self.ip, self.ttl, self.rcode)


def filters(block=(), safesearch=None):
    return fl.FilterSet([SuffixMatcher.from_domains(list(block))], SmallSuffixSet([]), safesearch or {},
                        restricted=[SuffixMatcher.from_domains([])])


def pax_fwd(primary, family, **kw):
    """A forwarder on Pax's own route (primary chain healthy, canary not run)."""
    f = d.Forwarder(family, filters(kw.pop("block", ())), primary_upstreams=primary, log=lambda m: None, **kw)
    assert f.pax_filter_ok
    return f


def ask(fwd, name, qtype=d.QTYPE_A, qid=0x1111, policy=None):
    resp = fwd.handle(d.build_query(name, qtype, qid), policy)
    assert struct.unpack("!H", resp[:2])[0] == qid
    return d.parse_answers(resp)


def wait_for(cond, secs=3.0):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture
def clock(monkeypatch):
    c = {"t": 1000.0}
    monkeypatch.setattr(d, "monotonic_continuous", lambda: c["t"])
    return c


# ------------------------------------------------------------ serve-stale
def test_stale_allowed_answer_is_served_short_and_refreshed(clock):
    q9 = Up("quad9", ttl=60)
    f = pax_fwd([q9], [Up("cb")])
    ask(f, "news.example")
    clock["t"] += 61                                  # expired
    rc, ans = ask(f, "news.example")
    assert rc == 0 and ans and ans[0][3] <= d.STALE_TTL
    assert f.stats["stale_served"] == 1
    assert wait_for(lambda: len(q9.calls) == 2)     # refreshed in the background
    assert wait_for(lambda: f._cache_get(("news.example", 1, False, False, False)) is not None)


def test_never_stale_after_stale_max_or_for_negative_answers(clock):
    q9 = Up("quad9", ttl=60)
    f = pax_fwd([q9], [Up("cb")])
    ask(f, "old.example")
    clock["t"] += 61 + d.STALE_MAX
    ask(f, "old.example")
    assert len(q9.calls) == 2 and f.stats["stale_served"] == 0
    nx = Up("quad9", rcode=3)
    f2 = pax_fwd([nx], [Up("cb")])
    assert ask(f2, "nope.example")[0] == d.RCODE_NXDOMAIN
    clock["t"] += d.NEG_TTL + 1
    ask(f2, "nope.example")
    assert len(nx.calls) == 2 and f2.stats["stale_served"] == 0


def test_no_ipv6_answer_may_be_served_stale_too(clock):
    """NODATA (NOERROR, no records: e.g. a site without IPv6) is safe to reuse: it carries no address."""
    q9 = Up("quad9")
    q9.query = lambda wire: (q9.calls.append(d.Query(wire).name),
                             answer_for(wire)[:6] + b"\x00\x00" + answer_for(wire)[8:12] + d.Query(wire).question)[1]
    f = pax_fwd([q9], [Up("cb")])
    rc, ans = ask(f, "v4only.example", qtype=d.QTYPE_AAAA)
    assert rc == 0 and ans == []
    clock["t"] += d.NEG_TTL + 1
    rc, ans = ask(f, "v4only.example", qtype=d.QTYPE_AAAA)
    assert rc == 0 and ans == [] and f.stats["stale_served"] == 1


def test_a_name_blocked_since_is_never_served_from_cache(clock):
    q9 = Up("quad9", ttl=60)
    f = pax_fwd([q9], [Up("cb")])
    ask(f, "later-blocked.example")
    f.set_policy(d.Policy(blocked=["later-blocked.example"]))
    _, ans = ask(f, "later-blocked.example")
    assert ans[0][4] == b"\x00\x00\x00\x00"           # fresh entry ignored: blocked
    clock["t"] += 61
    _, ans = ask(f, "later-blocked.example")
    assert ans[0][4] == b"\x00\x00\x00\x00"           # stale entry ignored: blocked
    # and the lists: a new filter set that blocks it wins over the cache too
    f.set_policy(d.Policy())
    clock["t"] -= 61
    f.set_filters(filters(block=["later-blocked.example"]))
    _, ans = ask(f, "later-blocked.example")
    assert ans[0][4] == b"\x00\x00\x00\x00"
    assert len(q9.calls) == 1


def test_no_stale_answers_on_the_family_route(clock):
    cb = Up("cb", ttl=60)
    f = d.Forwarder([cb], filters(), primary_upstreams=[Up("quad9")], log=lambda m: None)
    fam = d.Policy(family_layer=True)
    ask(f, "site.example", policy=fam)
    clock["t"] += 61
    ask(f, "site.example", policy=fam)
    assert len(cb.calls) == 2 and f.stats["stale_served"] == 0
    # fallback: everything on the family route, cache emptied on the switch
    f.enter_fallback("test")
    ask(f, "site.example")
    assert len(cb.calls) == 3


def test_prefetch_refreshes_a_popular_name_before_it_expires(clock):
    q9 = Up("quad9", ttl=100)
    f = pax_fwd([q9], [Up("cb")])
    ask(f, "popular.example")
    ask(f, "popular.example")                         # 2nd ask, plenty of TTL left: no refresh
    assert len(q9.calls) == 1
    clock["t"] += 95                                  # last 10 % of its TTL
    ask(f, "popular.example")
    assert wait_for(lambda: len(q9.calls) == 2) and f.stats["prefetched"] == 1


def test_list_changes_keep_allowed_answers_but_drop_rewrites():
    q9 = Up("quad9")
    ss = {"www.google.com": "forcesafesearch.google.com"}
    f = d.Forwarder([Up("cb")], filters(safesearch=ss), primary_upstreams=[q9], log=lambda m: None)
    ask(f, "kept.example")
    ask(f, "www.google.com")
    f.set_filters(filters(safesearch={"www.google.com": "safe2.google.com"}))
    ask(f, "kept.example")
    rc, ans = ask(f, "www.google.com")
    assert d.read_name(ans[0][4], 0)[0] == "safe2.google.com"
    assert q9.calls.count("kept.example") == 1
    f.set_policy(d.Policy(blocked=["other.example"]))      # user list change: cache kept
    ask(f, "kept.example")
    assert q9.calls.count("kept.example") == 1
    f.set_policy(d.Policy(blocked=["other.example"], family_layer=True))   # route change: emptied
    assert len(f._cache) == 0


# ------------------------------------------------------------ hedging
def test_a_slow_first_upstream_is_hedged_within_the_chain():
    slow, fast, fam = Up("quad9", delay=1.5), Up("cloudflare"), Up("cb")
    f = pax_fwd([slow, fast], [fam])
    t0 = time.monotonic()
    rc, ans = ask(f, "hedge.example")
    took = time.monotonic() - t0
    assert rc == 0 and took < d.HEDGE_DEFAULT + 0.4
    assert fast.calls == ["hedge.example"] and fam.calls == []      # strictly in chain order
    assert f.stats["hedged"] == 1 and slow.healthy                 # slow isn't "down"


def test_an_upstream_failing_after_the_hedge_won_is_still_marked_down():
    """Port 853 blocked on some networks: Quad9 times out after the hedge answered. It must
    still go to the back of the chain, or every lookup would wait for the hedge."""
    q9, cf = Up("quad9", delay=0.6, fail=True), Up("cloudflare")
    f = pax_fwd([q9, cf], [])
    ask(f, "first.example")
    assert wait_for(lambda: not q9.healthy)
    t0 = time.monotonic()
    ask(f, "second.example")
    assert time.monotonic() - t0 < 0.2 and q9.calls == ["first.example"]


def test_hedges_never_leave_the_family_route():
    primary, cb, ag = Up("quad9"), Up("cb", delay=1.0), Up("adguard")
    f = d.Forwarder([cb, ag], filters(), primary_upstreams=[primary], log=lambda m: None)
    ask(f, "kid.example", policy=d.Policy(family_layer=True))
    assert primary.calls == [] and ag.calls == ["kid.example"]


def test_servfail_from_one_upstream_asks_the_next_and_fails_closed():
    sf, ok = Up("quad9", rcode=2), Up("cloudflare")
    f = pax_fwd([sf, ok], [])
    assert ask(f, "dnssec.example")[0] == 0 and ok.calls == ["dnssec.example"]
    f2 = pax_fwd([Up("quad9", rcode=2), Up("cloudflare", rcode=2)], [Up("cb", fail=True)])
    assert ask(f2, "broken.example")[0] == d.RCODE_SERVFAIL
    f3 = pax_fwd([Up("quad9", fail=True)], [Up("cb", fail=True)])
    assert ask(f3, "down.example")[0] == d.RCODE_SERVFAIL


def test_whole_chain_has_a_time_budget(monkeypatch):
    monkeypatch.setattr(d, "FORWARD_BUDGET", 0.6)
    f = pax_fwd([Up("quad9", delay=3)], [Up("cb", delay=3)])
    t0 = time.monotonic()
    assert ask(f, "slow.example")[0] == d.RCODE_SERVFAIL
    assert time.monotonic() - t0 < 1.5


def test_hedge_delay_adapts_within_bounds():
    f = pax_fwd([Up("quad9")], [])
    u = f.primary_upstreams[0]
    assert f.hedge_delay(u) == d.HEDGE_DEFAULT
    for _ in range(30):
        f._record_latency(u, 0.01)
    assert f.hedge_delay(u) == d.HEDGE_MIN
    for _ in range(30):
        f._record_latency(u, 2.0)
    assert f.hedge_delay(u) == d.HEDGE_MAX


# ------------------------------------------------------------ coalescing
def test_identical_lookups_in_flight_share_one_upstream_query():
    q9 = Up("quad9", delay=0.3)
    f = pax_fwd([q9], [])
    out = []

    def one(i):
        out.append(ask(f, "same.example", qid=100 + i)[0])
    ts = [threading.Thread(target=one, args=(i,)) for i in range(10)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert out == [0] * 10 and len(q9.calls) == 1 and f.stats["coalesced"] == 9


def test_cached_answer_echoes_the_askers_letter_case():
    f = pax_fwd([Up("quad9")], [])
    f.handle(d.build_query("case.example", 1, 1))
    resp = f.handle(d.build_query("CaSe.Example", 1, 2))
    assert d.read_name(resp, 12)[0] == "CaSe.Example"


# ------------------------------------------------------------ keep warm / reset
def test_keep_warm_only_while_browsing_and_when_idle(monkeypatch):
    q9 = Up("quad9")
    q9.warm_idle = lambda: 7.0
    f = pax_fwd([q9], [])
    assert f.keep_warm() is False                     # nothing looked up recently
    ask(f, "x.example")
    assert f.keep_warm() is True and q9.calls[-1] == d.HEALTH_NAME
    q9.warm_idle = lambda: 1.0
    assert f.keep_warm() is False                     # connection recently used


def test_reset_connections_reaches_every_upstream():
    hit = []
    a, b = Up("quad9"), Up("cb")
    a.reset = lambda: hit.append("a")
    b.reset = lambda: hit.append("b")
    f = pax_fwd([a], [b])
    f.reset_connections()
    assert sorted(hit) == ["a", "b"]


# ------------------------------------------------------------ pipelined DoT
class FakeDotServer:
    """Plain-TCP DNS server (RFC 7766 framing): answers each burst in REVERSE order,
    can close idle connections, stay silent, or answer the wrong question."""

    def __init__(self, idle_close=None, silent=False, wrong=False):
        self.idle_close, self.silent, self.wrong = idle_close, silent, wrong
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        c.settimeout(self.idle_close or 30)
        buf = b""
        try:
            while True:
                try:
                    chunk = c.recv(65536)
                except socket.timeout:
                    c.close()
                    return
                if not chunk:
                    return
                buf += chunk
                msgs = []
                while len(buf) >= 2 and len(buf) >= 2 + struct.unpack("!H", buf[:2])[0]:
                    n = struct.unpack("!H", buf[:2])[0]
                    msgs.append(buf[2:2 + n])
                    buf = buf[2 + n:]
                if self.silent:
                    continue
                time.sleep(0.02)                         # let a burst gather
                out = b""
                for m in reversed(msgs):
                    if self.wrong:
                        m = m[:2] + d.build_query("other.example", 1)[2:]
                    a = answer_for(m)
                    out += struct.pack("!H", len(a)) + a
                c.sendall(out)
        except OSError:
            return

    def close(self):
        self.sock.close()


def dot_for(server, timeout=1.0):
    up = d.DotUpstream("fake-dot", "tls://dns.fake.example", ["127.0.0.1"], timeout=timeout, port=server.port)

    def plain_open(ip):
        raw = socket.create_connection((ip, server.port), timeout)
        up.handshakes += 1
        return d._DotConn(ip, raw)
    up._open = plain_open
    return up


def test_dot_pipelines_many_queries_on_one_connection_out_of_order():
    srv = FakeDotServer()
    up = dot_for(srv)
    results = {}

    def one(i):
        w = d.build_query(f"n{i}.example", 1, 1000 + i)
        r = up.query(w)
        results[i] = (struct.unpack("!H", r[:2])[0], d.read_name(r, 12)[0])
    ts = [threading.Thread(target=one, args=(i,)) for i in range(20)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert results == {i: (1000 + i, f"n{i}.example") for i in range(20)}
    assert srv.connections <= d.DOT_MAX_CONNS and up.handshakes == srv.connections
    up.reset()
    srv.close()


def test_dot_replaces_idle_connections_and_survives_a_server_close(monkeypatch):
    monkeypatch.setattr(d, "DOT_IDLE_MAX", 0.3)
    srv = FakeDotServer(idle_close=0.6)
    up = dot_for(srv)
    up.query(d.build_query("a.example", 1, 1))
    time.sleep(0.4)                                   # past DOT_IDLE_MAX: not reused
    up.query(d.build_query("b.example", 1, 2))
    assert srv.connections == 2
    monkeypatch.setattr(d, "DOT_IDLE_MAX", 30)
    time.sleep(0.8)                                   # the server closed it under us
    r = up.query(d.build_query("c.example", 1, 3))    # retried on a new connection
    assert d.read_name(r, 12)[0] == "c.example" and srv.connections == 3
    up.reset()
    srv.close()


def test_dot_silent_connection_times_out_and_is_dropped():
    srv = FakeDotServer(silent=True)
    up = dot_for(srv, timeout=0.3)
    t0 = time.monotonic()
    with pytest.raises(d.DNSError):
        up.query(d.build_query("a.example", 1, 1))
    assert time.monotonic() - t0 < 1.0
    assert all(c.dead for cs in up._conns.values() for c in cs)
    up.reset()
    srv.close()


def test_dot_rejects_an_answer_to_another_question():
    srv = FakeDotServer(wrong=True)
    up = dot_for(srv, timeout=0.5)
    with pytest.raises(d.DNSError):
        up.query(d.build_query("a.example", 1, 1))
    up.reset()
    srv.close()


def test_real_server_round_trip_with_the_new_paths():
    f = pax_fwd([Up("quad9")], [Up("cb")], block=["blocked.example"])
    srv = d.DNSServer(f, host="127.0.0.1", port=0, log=lambda m: None)
    srv.start()
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3)
        for name, want in (("blocked.example", b"\x00\x00\x00\x00"), ("fine.example", b"\x01\x02\x03\x04")):
            u.sendto(d.build_query(name, 1, 9), ("127.0.0.1", srv.port))
            data, _ = u.recvfrom(4096)
            assert d.parse_answers(data)[1][0][4] == want
    finally:
        srv.stop()


# ------------------------------------------------------------ hosts work remembered
def test_hosts_domains_is_remembered_and_identical():
    ads = [f"ad{i}.example" for i in range(5000)]
    args = dict(ads=ads, allowlist=["ad7.example"], bypass_list=["vpn.example"], exceptions=[],
                restricted=["r.example"], categories=["c.example"], restricted_exact=["ad9.example"])
    gc._HOSTS_MEMO.clear()
    first = gc.hosts_domains(["mine.example"], **args)
    assert first == gc._hosts_domains(["mine.example"], **args)
    first.append("mutated.example")                   # callers get a copy
    again = gc.hosts_domains(["mine.example"], **args)
    assert "mutated.example" not in again and len(gc._HOSTS_MEMO) == 1
    changed = gc.hosts_domains(["mine.example", "new.example"], **args)
    assert "new.example" in changed and "www.new.example" in changed
    args2 = dict(args, exceptions=["vpn.example"])
    assert "vpn.example" not in gc.hosts_domains(["mine.example"], **args2)
