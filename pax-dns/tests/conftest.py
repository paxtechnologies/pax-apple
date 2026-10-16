# SPDX-License-Identifier: GPL-3.0-only
import sys
from pathlib import Path

import pytest
from dnslib import QTYPE, RR, A, AAAA, CNAME, DNSRecord

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pax_dns.config import DNSSettings  # noqa: E402
from pax_dns.lists import CategoryList  # noqa: E402
from pax_dns.policy import Store  # noqa: E402
from pax_dns.resolver import Resolver  # noqa: E402
from pax_dns.sources import Syncer  # noqa: E402
from pax_dns.upstream import UpstreamError  # noqa: E402

sys.path.insert(0, str(ROOT.parent / "common"))
import pax_restricted  # noqa: E402

TOKEN = "tok_" + "A" * 28            # 32 chars, URL-safe
OTHER = "tok_" + "B" * 28


class FakeUpstream:
    """Answers every query itself and records what it was sent."""

    def __init__(self, url="https://upstream.test/dns-query", ip="93.184.216.34", ttl=3600):
        self.url, self.ip, self.ttl = url, ip, ttl
        self.seen: list[DNSRecord] = []
        self.cnames: dict[str, str] = {}
        self.fail = False

    async def query(self, wire: bytes) -> bytes:
        q = DNSRecord.parse(wire)
        self.seen.append(q)
        if self.fail:
            raise UpstreamError("down")
        r = q.reply()
        name = str(q.q.qname)
        target = self.cnames.get(name.rstrip("."))
        if target:
            r.add_answer(RR(q.q.qname, QTYPE.CNAME, rdata=CNAME(target + "."), ttl=self.ttl))
            name = target + "."
        if q.q.qtype == QTYPE.A:
            r.add_answer(RR(name, QTYPE.A, rdata=A(self.ip), ttl=self.ttl))
        elif q.q.qtype == QTYPE.AAAA:
            r.add_answer(RR(name, QTYPE.AAAA, rdata=AAAA("2001:db8::1"), ttl=self.ttl))
        return bytes(r.pack())


def feed(block=(), allow=(), token=TOKEN, retire_at=None, full=True, account="acct1"):
    from pax_dns.policy import hash_token
    return {"seq": 1, "full": full, "accounts": [{
        "account_id": account, "tokens": [{"hash": hash_token(token), "retire_at": retire_at}],
        "block": list(block), "allow": list(allow)}]}


@pytest.fixture
def make_resolver():
    def _make(block=(), allow=(), category=(), **settings_kw):
        settings = DNSSettings(**settings_kw)
        store = Store()
        store.apply(feed(block, allow))
        syncer = Syncer(store, None, CategoryList.from_lines(category))
        up, allow_up = FakeUpstream(), FakeUpstream(url="https://allow.test/dns-query", ip="10.9.9.9")
        r = Resolver(settings, store, syncer, upstream=up, allow_upstream=allow_up)
        return r, up, allow_up
    return _make


@pytest.fixture(autouse=True)
def _no_network_restricted_check(monkeypatch):
    """The escrow server checks exception requests against CleanBrowsing
    (v0.8.1); in tests it asks a fake that blocks *.blocked-upstream.test."""
    sys.path.insert(0, str(ROOT.parent / "server"))
    from pax_server import restricted
    monkeypatch.setattr(restricted, "LOOKUP_OVERRIDE",
                        pax_restricted.fake_lookup(blocked=["blocked-upstream.test"]))
