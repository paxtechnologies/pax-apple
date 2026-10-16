# SPDX-License-Identifier: GPL-3.0-only
"""Wire-format resolver shared by the DoH app and the plain DNS server.

`Resolver.resolve(wire, token)` takes a DNS query in RFC 1035 wire format and
returns the reply in wire format. It never logs query names.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from dnslib import AAAA, CNAME, DNSRecord, EDNS0, QTYPE, RCODE, RR, SOA, A

from .config import DNSSettings
from .policy import Action, Decision, Store, UserLists, decide
from .sources import Syncer
from .upstream import AnswerCache, UpstreamError, make_upstream


class BadQuery(ValueError):
    """Not a parseable single-question DNS query."""


BLOCK_SOA_NAME = "blocked.paxmobile.org."


def parse_query(wire: bytes) -> DNSRecord:
    if not wire or len(wire) < 12 or len(wire) > 65535:
        raise BadQuery("DNS message must be 12..65535 bytes")
    try:
        rec = DNSRecord.parse(wire)
    except Exception as exc:  # dnslib raises several types
        raise BadQuery(f"unparseable DNS message: {exc}") from None
    if rec.header.qr:
        raise BadQuery("message is a response, not a query")
    if len(rec.questions) != 1:
        raise BadQuery("exactly one question is supported")
    return rec


def _edns(request: DNSRecord, reply: DNSRecord) -> None:
    if any(rr.rtype == QTYPE.OPT for rr in request.ar):
        reply.add_ar(EDNS0(udp_len=1232))


def blocked_reply(request: DNSRecord, mode: str, ttl: int) -> DNSRecord:
    q = request.q
    reply = request.reply()
    reply.header.aa = 0
    if mode == "nxdomain":
        reply.header.rcode = RCODE.NXDOMAIN
    elif q.qtype == QTYPE.A:
        reply.add_answer(RR(q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=ttl))
    elif q.qtype == QTYPE.AAAA:
        reply.add_answer(RR(q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=ttl))
    if not reply.rr:
        # NODATA / NXDOMAIN: an SOA lets resolvers negative-cache for `ttl` seconds.
        reply.add_auth(RR(q.qname, QTYPE.SOA, ttl=ttl, rdata=SOA(
            BLOCK_SOA_NAME, "hostmaster.paxmobile.org.", (1, 3600, 600, 86400, ttl))))
    _edns(request, reply)
    return reply


def error_reply(request: DNSRecord, rcode: int) -> DNSRecord:
    reply = request.reply()
    reply.header.rcode = rcode
    _edns(request, reply)
    return reply


def min_ttl(rec: DNSRecord, default: int) -> int:
    ttls = [rr.ttl for rr in rec.rr + rec.auth if rr.rtype != QTYPE.OPT]
    return min(ttls) if ttls else default


@dataclass
class Resolution:
    reply: DNSRecord
    decision: Decision

    @property
    def wire(self) -> bytes:
        return bytes(self.reply.pack())


class Resolver:
    def __init__(self, settings: DNSSettings, store: Store, syncer: Syncer,
                 upstream=None, allow_upstream=None, cache: Optional[AnswerCache] = None):
        self.settings = settings
        self.store = store
        self.syncer = syncer
        self.upstream = upstream or make_upstream(settings.upstream, settings.upstream_timeout)
        self.allow_upstream = allow_upstream or make_upstream(settings.allow_upstream,
                                                              settings.upstream_timeout)
        self.cache = cache if cache is not None else AnswerCache(settings.cache_size)

    def user_lists(self, token: Optional[str]) -> Optional[UserLists]:
        return self.store.lookup(token)

    async def _forward(self, upstream, request: DNSRecord) -> DNSRecord:
        q = request.q
        key = (getattr(upstream, "url", id(upstream)), str(q.qname).lower(), q.qtype, q.qclass)
        cached = self.cache.get(key)
        if cached is not None:
            cached.header.id = request.header.id
            return cached
        fwd = DNSRecord.parse(request.pack())
        fwd.header.id = 0  # RFC 8484 4.1: use ID 0 for cache friendliness
        data = await upstream.query(bytes(fwd.pack()))
        rec = DNSRecord.parse(data)
        if not rec.header.qr or len(rec.questions) != 1 or rec.q.qname != q.qname \
                or rec.q.qtype != q.qtype:
            raise UpstreamError("upstream answer does not match the question")
        for rr in rec.rr + rec.auth:
            if rr.rtype != QTYPE.OPT:
                rr.ttl = min(rr.ttl, self.settings.max_ttl)
        if rec.header.rcode in (RCODE.NOERROR, RCODE.NXDOMAIN):
            self.cache.put(key, rec, min_ttl(rec, self.settings.block_ttl))
        rec.header.id = request.header.id
        return rec

    def _cname_blocked(self, rec: DNSRecord, user: Optional[UserLists]) -> Optional[Decision]:
        """A CNAME chain that lands on a blocked name is blocked too."""
        for rr in rec.rr:
            if rr.rtype == QTYPE.CNAME and isinstance(rr.rdata, CNAME):
                target = str(rr.rdata.label)
                d = decide(target, user, self.syncer.category, self.syncer.builtin)
                if d.action.blocked:
                    return d
        return None

    async def resolve_record(self, request: DNSRecord, token: Optional[str]) -> Resolution:
        if request.header.opcode != 0:
            return Resolution(error_reply(request, RCODE.NOTIMP), Decision(Action.FORWARD))
        user = self.user_lists(token)
        qname = str(request.q.qname)
        d = decide(qname, user, self.syncer.category, self.syncer.builtin)
        if d.action.blocked:
            return Resolution(blocked_reply(request, self.settings.block_mode,
                                            self.settings.block_ttl), d)
        upstream = self.allow_upstream if d.action is Action.ALLOW else self.upstream
        try:
            rec = await self._forward(upstream, request)
        except (UpstreamError, Exception):  # noqa: BLE001 - fail closed, never unfiltered
            return Resolution(error_reply(request, RCODE.SERVFAIL), d)
        if True:   # v0.8.1: an exception's CNAME chain is checked too
            cd = self._cname_blocked(rec, user)
            if cd:
                return Resolution(blocked_reply(request, self.settings.block_mode,
                                                self.settings.block_ttl), cd)
        return Resolution(rec, d)

    async def resolve(self, wire: bytes, token: Optional[str]) -> Resolution:
        return await self.resolve_record(parse_query(wire), token)
