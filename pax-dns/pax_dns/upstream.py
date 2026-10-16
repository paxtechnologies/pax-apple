# SPDX-License-Identifier: GPL-3.0-only
"""Upstream forwarding (DoH or plain DNS) with a small shared answer cache."""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Optional
from urllib.parse import urlparse

import httpx
from dnslib import DNSRecord

DOH_CT = "application/dns-message"


class UpstreamError(Exception):
    pass


class DoHUpstream:
    def __init__(self, url: str, client: Optional[httpx.AsyncClient] = None, timeout: float = 4.0):
        if urlparse(url).scheme != "https":
            raise ValueError(f"DoH upstream must be https://, got {url!r}")
        self.url = url
        self.client = client or httpx.AsyncClient(timeout=timeout, http2=False)

    async def query(self, wire: bytes) -> bytes:
        try:
            r = await self.client.post(self.url, content=bytes(wire),
                                       headers={"Content-Type": DOH_CT, "Accept": DOH_CT})
        except httpx.HTTPError as exc:
            raise UpstreamError(f"{self.url}: {exc}") from exc
        if r.status_code != 200 or not r.headers.get("content-type", "").startswith(DOH_CT):
            raise UpstreamError(f"{self.url}: HTTP {r.status_code}")
        return r.content


class UDPUpstream:
    """udp://host[:port]; retries over TCP when the answer is truncated."""

    def __init__(self, url: str, timeout: float = 4.0):
        p = urlparse(url)
        if p.scheme != "udp" or not p.hostname:
            raise ValueError(f"plain DNS upstream must be udp://host[:port], got {url!r}")
        self.host, self.port, self.timeout = p.hostname, p.port or 53, timeout
        self.url = url

    def _query_sync(self, wire: bytes) -> bytes:
        q = DNSRecord.parse(wire)
        try:
            data = q.send(self.host, self.port, tcp=False, timeout=self.timeout)
            if DNSRecord.parse(data).header.tc:
                data = q.send(self.host, self.port, tcp=True, timeout=self.timeout)
        except OSError as exc:
            raise UpstreamError(f"{self.url}: {exc}") from exc
        return data

    async def query(self, wire: bytes) -> bytes:
        return await asyncio.to_thread(self._query_sync, wire)


def make_upstream(url: str, timeout: float = 4.0, client: Optional[httpx.AsyncClient] = None):
    if url.startswith("https://"):
        return DoHUpstream(url, client=client, timeout=timeout)
    if url.startswith("udp://"):
        return UDPUpstream(url, timeout=timeout)
    raise ValueError(f"unsupported upstream {url!r} (https://... DoH or udp://host)")


class AnswerCache:
    """LRU of upstream answers keyed by (upstream, qname, qtype, qclass).
    TTLs are aged on the way out. Shared by all users: the per-user decision is
    made before the cache is consulted, and CNAME checks after."""

    def __init__(self, size: int = 10000, clock=time.monotonic):
        self.size, self.clock = size, clock
        self._d: OrderedDict = OrderedDict()

    def get(self, key) -> Optional[DNSRecord]:
        item = self._d.get(key)
        if item is None:
            return None
        expires, stored, wire = item
        now = self.clock()
        if now >= expires:
            self._d.pop(key, None)
            return None
        self._d.move_to_end(key)
        rec = DNSRecord.parse(wire)
        elapsed = int(now - stored)
        for rr in rec.rr + rec.auth:
            rr.ttl = max(0, rr.ttl - elapsed)
        return rec

    def put(self, key, rec: DNSRecord, ttl: int) -> None:
        if self.size <= 0 or ttl <= 0:
            return
        now = self.clock()
        self._d[key] = (now + ttl, now, bytes(rec.pack()))
        self._d.move_to_end(key)
        while len(self._d) > self.size:
            self._d.popitem(last=False)
