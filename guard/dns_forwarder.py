# SPDX-License-Identifier: GPL-3.0-only
"""pax-guard's local DNS forwarder on 127.0.0.1:53 (v0.8.0). Standard library only.

Why a small Python forwarder inside pax-guard rather than a bundled one
(dnscrypt-proxy is ISC, CoreDNS Apache-2.0, Blocky Apache-2.0; all
GPL-compatible): every one of them is a Go binary of 10-30 MB that Pax would
have to build universal, sign and keep patched, and none does Pax's own policy
(user blocks, the wait-timed exceptions, the categories) without a plugin. Pax
already runs a root Python daemon, and a stub forwarder is a small, well-understood
job: parse one question, decide locally, otherwise send the query unchanged
over DoH (RFC 8484) and hand the answer back. It is covered by tests
(guard/tests/test_v08_dns.py) including failover and SERVFAIL. See docs/DNS.md.

For each query (v0.8.1 order):
  0. the user's blocked sites (not freed by an exception) -> blocked (v0.8.3)
  1. SafeSearch rewrite (exact host) -> CNAME to the safe host + its addresses
  2. restricted: the media converters (category and name rule) and, unless the
     Pax allowlist covers the name, the restricted lists (pax-block, pax-nrd,
     restricted plug-ins) -> blocked, even if the user has an exception
  3. the user's exceptions (freed after the wait) -> upstream, unless the
     restricted-content name rules match (then the exception is ignored)
  4. the user's blocked sites, Pax categories -> blocked (0.0.0.0 / ::)
  5. Pax allowlist (character.ai) -> upstream
  6. lists an exception may free (pax-bypass, other plug-ins) -> blocked
  7. upstream. v0.8.18: Pax's own filter is the default path. Steps 0-6 decide,
     then an allowed query goes to a fast resolver that filters only malware
     (Quad9 over DNS-over-TLS, then Cloudflare's security resolver over DoH),
     then the family-filter chain, else SERVFAIL. The family-filter chain
     (CleanBrowsing Family DoH, then AdGuard Family DoH) is used for everything
     when the user turns on the extra family layer (Advanced), or automatically
     when Pax's own filter can't be trusted: lists missing, empty or failing
     their checks, the decision code throwing or running slow, or a canary
     self-test failing (see Forwarder.canary). Never plain, unfiltered DNS.
     Without a primary chain (older callers, tests) the family chain is the
     only upstream, as before.
v0.8.6: with YouTube Restricted Mode switched off in Settings, step 1 skips the
rewrite for YouTube's own names only (YOUTUBE_NAMES), and step 7 asks
CleanBrowsing's Adult filter for them (it doesn't force Restricted Mode), then
AdGuard Family (which does: safe), else SERVFAIL. Steps 0 and 2-6 still apply.

Upstreams are reached at pinned IP addresses (TLS still checks the hostname),
so the forwarder never needs DNS to find its own resolvers; the pinned set is
refreshed through the upstream itself. A health check runs every minute and
the active upstream is reported in `status()` (shown on Home).
"""
from __future__ import annotations

import email.utils
import http.client
import os
import queue
import random
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

# --------------------------------------------------------------- constants
QTYPE_A, QTYPE_NS, QTYPE_CNAME, QTYPE_SOA, QTYPE_AAAA, QTYPE_OPT = 1, 2, 5, 6, 28, 41
QTYPE_SVCB, QTYPE_HTTPS = 64, 65
RCODE_NOERROR, RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NXDOMAIN, RCODE_REFUSED = 0, 1, 2, 3, 5
BLOCK_TTL = 300
NEG_TTL = 60            # negative answer with no SOA to say otherwise
NEG_MAX_TTL = 900       # cap for negative caching (RFC 2308 SOA minimum)
MAX_TTL = 3600          # cap for positive caching (upstream TTLs respected below it)
MAX_UDP_DEFAULT = 512
MAX_UDP_EDNS = 1232

# v0.8.36 faster browsing. Measured 29 Oct 2026 (bench: tools/dns-bench.py, docs/DNS.md "Speed"):
# Quad9 closes an idle DNS-over-TLS connection after about 10 s, a new TLS connection costs
# about 6 round trips against 1 for a kept-alive one, and Quad9 answers pipelined queries
# out of order on one connection.
STALE_MAX = 3600         # RFC 8767: an expired *allowed* answer may be served for up to an hour...
STALE_TTL = 30           # ...with this TTL, while a fresh copy is fetched in the background
PREFETCH_FRACTION = 0.1  # refresh a name asked at least PREFETCH_MIN_HITS times in its last 10 % of TTL
PREFETCH_MIN_HITS = 2
HEDGE_DEFAULT = 0.40     # ask the next upstream of the same chain when the first is this slow (s)...
HEDGE_MIN, HEDGE_MAX = 0.25, 0.80   # ...adapted to each upstream's measured latency, within these bounds
FORWARD_BUDGET = 4.0     # one lookup never waits longer than this for the whole chain (then SERVFAIL)
DOT_IDLE_MAX = 8.0       # a DoT connection idle this long is closed, not reused (Quad9 drops it ~10 s)
DOT_MAX_CONNS = 2        # pipelined DoT connections per resolver address
DOT_PIPELINE = 24        # in-flight queries on one DoT connection before a second one is opened
DOH_IDLE_MAX = 25.0      # an idle kept-alive DoH connection older than this is not reused
KEEPWARM_EVERY = 6.0     # while the Mac is browsing, keep the first upstream's connection warm...
KEEPWARM_WINDOW = 120.0  # ...for this long after the last lookup (one tiny query per KEEPWARM_EVERY)
# Names nearly every Mac looks up within minutes of starting; asked once after the lists load
# so the first pages after a restart or update don't wait. Nothing about the user is stored.
WARM_NAMES = ("apple.com", "www.apple.com", "icloud.com", "gateway.icloud.com", "configuration.apple.com",
              "gstatic.com", "www.gstatic.com", "fonts.gstatic.com", "fonts.googleapis.com", "ajax.googleapis.com",
              "www.googletagmanager.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
              "www.bbc.co.uk", "www.gov.uk", "en.wikipedia.org", "upload.wikimedia.org", "github.com",
              "www.amazon.co.uk", "m.media-amazon.com", "www.microsoft.com", "login.microsoftonline.com",
              "outlook.office.com", "accounts.google.com", "mail.google.com", "www.google.com", "www.youtube.com",
              "i.ytimg.com", "paxpeace.com", "api.paxpeace.com")

# Upstreams, in order. URLs from the project brief; AdGuard Family checked on
# adguard-dns.io 2026-10-15 (restricted content + SafeSearch). Addresses resolved
# 2026-10-15 (doh.cleanbrowsing.org A; family.adguard-dns.com A/AAAA).
CLEANBROWSING = ("CleanBrowsing Family", "https://doh.cleanbrowsing.org/doh/family-filter/",
                 ["185.228.168.10", "185.228.168.168"])
ADGUARD_FAMILY = ("AdGuard Family", "https://family.adguard-dns.com/dns-query",
                  ["94.140.14.15", "94.140.15.16", "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"])
DEFAULT_UPSTREAMS = [CLEANBROWSING, ADGUARD_FAMILY]
# v0.8.6 YouTube Restricted Mode switch. Both filtered upstreams force YouTube's
# Restricted Mode themselves (checked 2026-10-16: CleanBrowsing Family answers
# www.youtube.com with 216.239.38.119, restrictmoderate.youtube.com; AdGuard Family
# CNAMEs it there). CleanBrowsing's Adult filter, at the same address, leaves the
# YouTube names alone while still forcing Google and Bing SafeSearch and blocking
# restricted content. With the switch off, only the names below are asked of it, then
# of AdGuard Family (which puts Restricted Mode back: safe, never open), else SERVFAIL.
# Every other name keeps CleanBrowsing Family -> AdGuard Family -> SERVFAIL.
CLEANBROWSING_ADULT = ("CleanBrowsing Adult (YouTube names)", "https://doh.cleanbrowsing.org/doh/adult-filter/",
                       ["185.228.168.10", "185.228.168.168"])
# The hosts YouTube's DNS-based Restricted Mode covers (support.google.com/a/answer/6214622),
# plus the bare youtube.com and youtube-nocookie.com Pax also rewrites. Exact names only.
YOUTUBE_NAMES = frozenset({
    "youtube.com", "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com",
    "youtube-nocookie.com", "www.youtube-nocookie.com",
})
HEALTH_NAME = "example.com"
HEALTH_INTERVAL = 60

# v0.8.18: the primary chain, used once Pax's own lists and rules have decided.
# These resolvers filter malware and phishing only, never content, so every content
# decision is Pax's. Quad9's DoH answers HTTP/2 only (HTTP 505 to HTTP/1.1, checked
# 2026-10-17) and the forwarder is standard-library Python, so Quad9 is reached over
# DNS-over-TLS (RFC 7858, port 853) instead. Addresses from the providers' pages,
# checked 2026-10-17.
CLOUDFLARE_SECURITY = ("Cloudflare security", "https://security.cloudflare-dns.com/dns-query",
                       ["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"])
QUAD9_DOT = ("Quad9", "tls://dns.quad9.net",
             ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"])
# Quad9 first: in a 150-name test on 2026-10-17 its DoT answered in a median 17 ms
# against 59 ms for Cloudflare's security DoH (p95 388 ms vs 553 ms).
PRIMARY_UPSTREAMS = [QUAD9_DOT, CLOUDFLARE_SECURITY]
# v0.8.18 canary self-test: run on start, after every list change and every
# CANARY_INTERVAL seconds. A failure routes every query to the family chain at once;
# the primary chain comes back only after the canary passes again.
CANARY_INTERVAL = 180
CANARY_MIN_ENTRIES = 100_000         # the restricted lists hold well over a million
CANARY_TIMEOUT = 2.0                 # seconds for the whole self-test
DECIDE_SLOW = 0.5                    # one decision slower than this: fall back, re-test
CANARY_EVERYDAY = ("example.com", "wikipedia.org", "apple.com", "gov.uk", "bbc.co.uk",
                   # v0.8.19: a few more, since the canary also vets each new filter pack
                   "nhs.uk", "microsoft.com", "github.com", "paxpeace.com", "amazon.co.uk")


class DNSError(Exception):
    pass


def check_filterset(filters, min_entries: int = CANARY_MIN_ENTRIES) -> list:
    """v0.8.19: the canary self-test on a set of lists that isn't in use yet (a new
    filter pack, before it is swapped in). Returns the failures ([] = passed)."""
    fwd = Forwarder([], filters=filters, log=lambda m: None, canary_min_entries=min_entries)
    return list(fwd.canary().get("failures") or [])


# --------------------------------------------------------------- wire format
def read_name(msg: bytes, pos: int) -> tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (name, position after it)."""
    labels = []
    jumped = False
    end = pos
    hops = 0
    while True:
        if pos >= len(msg):
            raise DNSError("name runs past the message")
        n = msg[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise DNSError("bad pointer")
            ptr = ((n & 0x3F) << 8) | msg[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            hops += 1
            if hops > 30 or ptr >= len(msg):
                raise DNSError("pointer loop")
            pos = ptr
            continue
        if n > 63:
            raise DNSError("bad label")
        labels.append(msg[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(labels), (end if jumped else pos)


def encode_name(name: str) -> bytes:
    out = bytearray()
    for lab in name.strip(".").split("."):
        if lab:
            b = lab.encode("ascii", "ignore")[:63]
            out.append(len(b))
            out += b
    out.append(0)
    return bytes(out)


class Query:
    __slots__ = ("id", "flags", "qname", "qtype", "qclass", "raw", "question", "edns_size", "do_bit")

    def __init__(self, raw: bytes):
        if len(raw) < 12:
            raise DNSError("short message")
        self.raw = raw
        self.id, self.flags, qd, an, ns, ar = struct.unpack("!HHHHHH", raw[:12])
        if self.flags & 0x8000:
            raise DNSError("not a query")
        if qd != 1:
            raise DNSError("exactly one question supported")
        self.qname, pos = read_name(raw, 12)
        if pos + 4 > len(raw):
            raise DNSError("short question")
        self.qtype, self.qclass = struct.unpack("!HH", raw[pos:pos + 4])
        self.question = raw[12:pos + 4]
        self.edns_size = 0
        self.do_bit = False
        pos += 4
        # Skip answer/authority (normally 0) to find an OPT record.
        try:
            for _ in range(an + ns + ar):
                _, pos = read_name(raw, pos)
                rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", raw[pos:pos + 10])
                if rtype == QTYPE_OPT:
                    self.edns_size = rclass
                    self.do_bit = bool(ttl & 0x8000)
                pos += 10 + rdlen
        except (DNSError, struct.error):
            pass

    @property
    def name(self) -> str:
        return self.qname.lower().rstrip(".")

    def max_udp(self) -> int:
        return max(MAX_UDP_DEFAULT, min(self.edns_size, 4096)) if self.edns_size else MAX_UDP_DEFAULT


def _header(q: Query, rcode: int, an: int, aa: bool = False) -> bytes:
    flags = 0x8000 | (q.flags & 0x0100) | 0x0080 | (0x0400 if aa else 0) | (rcode & 0xF)
    flags |= q.flags & 0x7800          # keep the opcode
    return struct.pack("!HHHHHH", q.id, flags, 1, an, 0, 0)


def make_error(q: Query, rcode: int) -> bytes:
    return _header(q, rcode, 0) + q.question


def make_servfail(q: Query) -> bytes:
    return make_error(q, RCODE_SERVFAIL)


def make_blocked(q: Query) -> bytes:
    """0.0.0.0 for A, :: for AAAA, NODATA for anything else (like /etc/hosts)."""
    if q.qtype == QTYPE_A:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_A, 1, BLOCK_TTL, 4) + b"\x00\x00\x00\x00"
        return _header(q, RCODE_NOERROR, 1, aa=True) + q.question + rr
    if q.qtype == QTYPE_AAAA:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_AAAA, 1, BLOCK_TTL, 16) + b"\x00" * 16
        return _header(q, RCODE_NOERROR, 1, aa=True) + q.question + rr
    return _header(q, RCODE_NOERROR, 0, aa=True) + q.question


def parse_answers(msg: bytes) -> tuple[int, list[tuple[str, int, int, int, bytes]]]:
    """(rcode, [(owner, type, class, ttl, rdata)]) of the answer section."""
    if len(msg) < 12:
        raise DNSError("short response")
    _id, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    pos = 12
    for _ in range(qd):
        _, pos = read_name(msg, pos)
        pos += 4
    out = []
    for _ in range(an):
        owner, pos = read_name(msg, pos)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
        pos += 10
        out.append((owner, rtype, rclass, ttl, msg[pos:pos + rdlen]))
        pos += rdlen
    return flags & 0xF, out


def _sections(msg: bytes):
    """Yield (ttl_offset, type, ttl, section) for every record after the question."""
    _id, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    pos = 12
    for _ in range(qd):
        _, pos = read_name(msg, pos)
        pos += 4
    for section, count in (("an", an), ("ns", ns), ("ar", ar)):
        for _ in range(count):
            _, pos = read_name(msg, pos)
            rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
            yield pos + 4, rtype, ttl, section, msg[pos + 10:pos + 10 + rdlen]
            pos += 10 + rdlen


def cache_ttl(msg: bytes) -> int:
    """How long an upstream answer may be cached: the smallest answer TTL (capped
    at MAX_TTL); for NXDOMAIN/NODATA the SOA's negative TTL (min of the SOA
    record's TTL and its MINIMUM field, RFC 2308), capped at NEG_MAX_TTL, else
    NEG_TTL. 0 = don't cache (SERVFAIL, malformed, TTL 0)."""
    try:
        rcode = struct.unpack("!H", msg[2:4])[0] & 0xF
        recs = list(_sections(msg))
    except (DNSError, struct.error):
        return 0
    if rcode not in (RCODE_NOERROR, RCODE_NXDOMAIN):
        return 0
    answers = [r for r in recs if r[3] == "an"]
    if rcode == RCODE_NOERROR and answers:
        return max(0, min(min(r[2] for r in answers), MAX_TTL))
    for _off, rtype, ttl, section, rdata in recs:
        if section == "ns" and rtype == QTYPE_SOA and len(rdata) >= 20:
            minimum = struct.unpack("!I", rdata[-4:])[0]
            return max(0, min(ttl, minimum, NEG_MAX_TTL))
    return NEG_TTL


def min_ttl(msg: bytes) -> int:
    return cache_ttl(msg)


def age_ttls(msg: bytes, elapsed: int) -> bytes:
    """The cached message with every TTL lowered by the seconds it sat in the
    cache (OPT records left alone), so clients never hold it past its TTL."""
    if elapsed <= 0:
        return msg
    out = bytearray(msg)
    try:
        for off, rtype, ttl, _section, _rdata in _sections(msg):
            if rtype != QTYPE_OPT:
                struct.pack_into("!I", out, off, max(0, ttl - elapsed))
    except (DNSError, struct.error):
        return msg
    return bytes(out)


def cap_ttls(msg: bytes, ttl: int) -> bytes:
    """v0.8.36: every TTL (OPT left alone) lowered to at most `ttl`: a stale answer served
    while it is refreshed (RFC 8767) is held by clients for STALE_TTL seconds only."""
    out = bytearray(msg)
    try:
        for off, rtype, old, _section, _rdata in _sections(msg):
            if rtype != QTYPE_OPT:
                struct.pack_into("!I", out, off, max(0, min(old, ttl)))
    except (DNSError, struct.error):
        return msg
    return bytes(out)


def is_positive(msg: bytes) -> bool:
    """NOERROR: addresses, or "no address of this type" (NODATA, e.g. no IPv6), the only
    answers ever served stale. NXDOMAIN, SERVFAIL and the rest never are."""
    return len(msg) >= 12 and (msg[3] & 0xF) == RCODE_NOERROR


def rcode_of(msg: bytes) -> int:
    return msg[3] & 0xF if len(msg) >= 12 else RCODE_SERVFAIL


def question_len(wire: bytes) -> int:
    """Length of the (single) question section, so an answer can be matched to its query."""
    _, pos = read_name(wire, 12)
    return pos + 4 - 12


def make_rewrite(q: Query, target: str, upstream_answer: bytes | None) -> bytes:
    """CNAME <qname> -> <target>, then the target's A/AAAA records (re-encoded,
    so no compression pointer from the upstream message is copied)."""
    rrs = [b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_CNAME, 1, BLOCK_TTL, len(encode_name(target)))
           + encode_name(target)]
    if upstream_answer and q.qtype in (QTYPE_A, QTYPE_AAAA):
        try:
            _, answers = parse_answers(upstream_answer)
        except (DNSError, struct.error):
            answers = []
        for _owner, rtype, rclass, ttl, rdata in answers:
            if rtype == q.qtype and rclass == 1:
                rrs.append(encode_name(target) + struct.pack("!HHIH", rtype, 1, min(ttl, BLOCK_TTL), len(rdata))
                           + rdata)
    return _header(q, RCODE_NOERROR, len(rrs)) + q.question + b"".join(rrs)


def build_query(name: str, qtype: int, qid: int = 0) -> bytes:
    return (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + encode_name(name)
            + struct.pack("!HH", qtype, 1))


def with_id(msg: bytes, qid: int) -> bytes:
    return struct.pack("!H", qid) + msg[2:]


def for_query(msg: bytes, q: "Query") -> bytes:
    """A cached or shared answer for this asker: its id, and its question exactly as it
    asked it (same name and type, possibly other letter case)."""
    out = struct.pack("!H", q.id) + msg[2:]
    n = len(q.question)
    if out[12:12 + n].lower() == q.question.lower() and out[12:12 + n] != q.question:
        out = out[:12] + q.question + out[12 + n:]
    return out


def truncate_for_udp(q: Query, resp: bytes) -> bytes:
    if len(resp) <= q.max_udp():
        return resp
    hdr = bytearray(resp[:12])
    hdr[2] |= 0x02                                  # TC
    struct.pack_into("!HHH", hdr, 6, 0, 0, 0)
    return bytes(hdr) + q.question


# --------------------------------------------------------------- upstreams
def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    for bundle in ("/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem"):
        if os.path.exists(bundle):
            try:
                ctx.load_verify_locations(cafile=bundle)
            except (OSError, ssl.SSLError):
                pass
    return ctx


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, 443, timeout=timeout, context=context)
        self._ip = ip
        self._ctx = context

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, 443), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


class DohUpstream:
    """RFC 8484 POST to one DoH server, at pinned addresses, keep-alive."""

    def __init__(self, name: str, url: str, ips: list[str], timeout: float = 2.5,
                 ssl_context: ssl.SSLContext | None = None, use_curl: bool = False):
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("DoH upstreams must be https:// URLs")
        self.name, self.url, self.host = name, url, parts.hostname
        self.path = parts.path or "/"
        self.ips = list(dict.fromkeys(ips))
        self.timeout = timeout
        self._ctx = ssl_context
        self._pool: list[_PinnedHTTPS] = []
        self._lock = threading.Lock()
        self.use_curl = use_curl
        self.healthy = True
        self.last_error = ""
        self.last_ok = 0.0
        self.trusted_time: tuple[float, float] | None = None   # (server epoch, local monotonic)

    def _context(self) -> ssl.SSLContext:
        if self._ctx is None:
            self._ctx = _ssl_context()
        return self._ctx

    def _take(self, ip: str) -> _PinnedHTTPS:
        stale = []
        conn = None
        now = time.monotonic()
        with self._lock:
            # v0.8.36: newest first, and never one idle past DOH_IDLE_MAX (the server has
            # probably closed it, which costs a failed request and a retry).
            for i in range(len(self._pool) - 1, -1, -1):
                c = self._pool[i]
                if now - getattr(c, "_pax_idle_since", now) > DOH_IDLE_MAX:
                    stale.append(self._pool.pop(i))
                elif conn is None and c._ip == ip:
                    conn = self._pool.pop(i)
        for c in stale:
            c.close()
        return conn or _PinnedHTTPS(self.host, ip, self.timeout, self._context())

    def _give(self, conn: _PinnedHTTPS) -> None:
        conn._pax_idle_since = time.monotonic()
        with self._lock:
            if len(self._pool) < 8:
                self._pool.append(conn)
                return
        conn.close()

    def reset(self) -> None:
        """v0.8.36: drop every kept-alive connection (the network changed)."""
        with self._lock:
            pool, self._pool = self._pool, []
        for c in pool:
            c.close()

    def _record_date(self, date_header: str | None) -> None:
        if not date_header:
            return
        try:
            when = email.utils.parsedate_to_datetime(date_header).timestamp()
        except (TypeError, ValueError):
            return
        self.trusted_time = (when, monotonic_continuous())

    def query(self, wire: bytes) -> bytes:
        body = with_id(wire, 0)          # RFC 8484 4.1: id 0 for cache friendliness
        errors = []
        for ip in self.ips:
            for attempt in range(2):     # a kept-alive connection may have gone stale
                try:
                    resp = self._curl(ip, body) if self.use_curl else self._python(ip, body)
                    self.last_ok = time.time()
                    return resp
                except ssl.SSLCertVerificationError as exc:
                    # Python's CA store can disagree with macOS: fall back to curl,
                    # which uses the system trust store. Still TLS, still verified.
                    errors.append(f"{ip}: certificate ({exc.reason})")
                    if not self.use_curl and os.path.exists("/usr/bin/curl"):
                        self.use_curl = True
                        continue
                    break
                except (OSError, http.client.HTTPException, DNSError) as exc:
                    errors.append(f"{ip}: {type(exc).__name__}")
                    if attempt == 0 and isinstance(exc, (http.client.RemoteDisconnected,
                                                         BrokenPipeError, ConnectionResetError)):
                        continue
                    break
        self.last_error = "; ".join(errors)[-300:]
        raise DNSError(f"{self.name}: {self.last_error}")

    def _python(self, ip: str, body: bytes) -> bytes:
        conn = self._take(ip)
        try:
            conn.request("POST", self.path, body=body, headers={
                "Content-Type": "application/dns-message", "Accept": "application/dns-message",
                "User-Agent": "pax-guard"})
            r = conn.getresponse()
            data = r.read()
            self._record_date(r.getheader("Date"))
            if r.status != 200 or not data:
                conn.close()
                raise DNSError(f"HTTP {r.status}")
            self._give(conn)
            return data
        except Exception:
            conn.close()
            raise

    def _curl(self, ip: str, body: bytes) -> bytes:
        host_ip = f"[{ip}]" if ":" in ip else ip
        args = ["/usr/bin/curl", "-sS", "--fail", "--max-time", str(self.timeout), "--proto", "=https",
                "--resolve", f"{self.host}:443:{host_ip}", "-H", "Content-Type: application/dns-message",
                "-H", "Accept: application/dns-message", "--data-binary", "@-", "-D", "/dev/stderr",
                self.url]
        try:
            r = subprocess.run(args, input=body, capture_output=True, timeout=self.timeout + 2)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("curl timed out") from exc
        if r.returncode != 0 or not r.stdout:
            raise DNSError(f"curl exit {r.returncode}")
        for line in r.stderr.decode("latin-1", "replace").splitlines():
            if line.lower().startswith("date:"):
                self._record_date(line.split(":", 1)[1].strip())
        return r.stdout


class _DotConn:
    """v0.8.36: one DNS-over-TLS connection carrying many queries at once (RFC 7766
    pipelining; Quad9 answers out of order). One I/O thread per connection does every
    read and write, because an SSL object must not be read and written from two threads.
    Each query gets an id unique on this connection; the answer must carry that id and
    the same question, or it is ignored."""

    def __init__(self, ip: str, sock):
        self.ip = ip
        self.sock = sock
        self.lock = threading.Lock()
        self.pending: dict = {}          # wire id -> [Event, answer | None, error | None]
        self.outbuf = bytearray()
        self.dead = False
        now = time.monotonic()
        self.opened = self.last_rx = self.last_tx = now
        self._wr, self._ww = socket.socketpair()
        self._wr.setblocking(False)
        self._ww.setblocking(False)
        sock.setblocking(False)
        threading.Thread(target=self._run, name=f"pax-dot-{ip}", daemon=True).start()

    # ------------------------------------------------------------ state
    def idle(self, now: float) -> float:
        return now - max(self.last_rx, self.last_tx)

    def usable(self, now: float) -> bool:
        return not self.dead and self.idle(now) < DOT_IDLE_MAX

    def load(self) -> int:
        return len(self.pending)

    def kill(self) -> None:
        with self.lock:
            if self.dead:
                return
            self.dead = True
        self._wake()

    def _wake(self) -> None:
        try:
            self._ww.send(b"x")
        except OSError:
            pass

    # ------------------------------------------------------------ query
    def ask(self, wire: bytes, timeout: float) -> bytes:
        qlen = question_len(wire)
        question = wire[12:12 + qlen].lower()
        slot = [threading.Event(), None, None]
        with self.lock:
            if self.dead:
                raise ConnectionResetError("connection closed")
            for _ in range(64):
                qid = random.getrandbits(16)
                if qid not in self.pending:
                    break
            else:
                raise DNSError("no free query id")
            self.pending[qid] = slot
            msg = struct.pack("!H", qid) + wire[2:]
            self.outbuf += struct.pack("!H", len(msg)) + msg
            sent = time.monotonic()
            self.last_tx = sent
        self._wake()
        if not slot[0].wait(timeout):
            with self.lock:
                self.pending.pop(qid, None)
                quiet = self.last_rx < sent
            if quiet:
                self.kill()              # nothing came back at all: a dead connection (sleep, NAT)
            raise TimeoutError("DoT answer timed out")
        if slot[2] is not None:
            raise slot[2]
        data = slot[1]
        if len(data) < 12 + qlen or data[12:12 + qlen].lower() != question:
            raise DNSError("answer for another question")
        return wire[:2] + data[2:]

    # ------------------------------------------------------------ I/O thread
    def _run(self) -> None:
        sock = self.sock
        inbuf = bytearray()
        err: Exception = ConnectionResetError("connection closed")
        try:
            while True:
                with self.lock:
                    if self.dead:
                        break
                    want_write = bool(self.outbuf)
                pending = getattr(sock, "pending", None)      # plain sockets in tests
                wait = 0 if pending and pending() else 1.0
                r, w, _ = select.select([sock, self._wr], [sock] if want_write else [], [], wait)
                if self._wr in r:
                    try:
                        while self._wr.recv(512):
                            pass
                    except (BlockingIOError, InterruptedError):
                        pass
                if sock in r or (pending and pending()):
                    while True:
                        try:
                            chunk = sock.recv(65536)
                        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                            break
                        if not chunk:
                            raise ConnectionResetError("closed by the resolver")
                        inbuf += chunk
                        if not (pending and pending()):
                            break
                    while len(inbuf) >= 2:
                        (n,) = struct.unpack("!H", inbuf[:2])
                        if len(inbuf) < 2 + n:
                            break
                        msg = bytes(inbuf[2:2 + n])
                        del inbuf[:2 + n]
                        self.last_rx = time.monotonic()
                        if len(msg) < 12:
                            continue
                        with self.lock:
                            slot = self.pending.pop(struct.unpack("!H", msg[:2])[0], None)
                        if slot is not None:
                            slot[1] = msg
                            slot[0].set()
                if want_write and sock in w:
                    with self.lock:
                        data = bytes(self.outbuf)
                    try:
                        sent = sock.send(data)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                        sent = 0
                    if sent:
                        with self.lock:
                            del self.outbuf[:sent]
        except (OSError, ValueError, ssl.SSLError) as exc:
            err = exc if isinstance(exc, OSError) else ConnectionResetError(str(exc))
        with self.lock:
            self.dead = True
            pending, self.pending = self.pending, {}
        for slot in pending.values():
            slot[2] = err if isinstance(err, OSError) else ConnectionResetError("closed")
            slot[0].set()
        for s in (sock, self._wr, self._ww):
            try:
                s.close()
            except OSError:
                pass


class DotUpstream:
    """v0.8.18: DNS-over-TLS (RFC 7858) to one resolver, at pinned addresses. Same
    interface as DohUpstream. v0.8.36: queries are pipelined over at most DOT_MAX_CONNS
    kept-alive connections per address (no new TLS handshake per query), a connection
    idle past DOT_IDLE_MAX is replaced rather than reused, and one that stops answering
    is dropped at once."""

    def __init__(self, name: str, url: str, ips: list[str], timeout: float = 2.5,
                 ssl_context: ssl.SSLContext | None = None, port: int = 853):
        parts = urlsplit(url)
        if parts.scheme != "tls" or not parts.hostname:
            raise ValueError("DoT upstreams must be tls:// URLs")
        self.name, self.url, self.host = name, url, parts.hostname
        self.port = parts.port or port
        self.ips = list(dict.fromkeys(ips))
        self.timeout = timeout
        self._ctx = ssl_context
        self._conns: dict = {}           # ip -> [_DotConn]
        self._openers: dict = {}         # ip -> Lock (one TLS handshake at a time)
        self._lock = threading.Lock()
        self.healthy = True
        self.last_error = ""
        self.last_ok = 0.0
        self.trusted_time: tuple[float, float] | None = None   # no Date header over DoT
        self.handshakes = 0

    def _context(self) -> ssl.SSLContext:
        if self._ctx is None:
            self._ctx = _ssl_context()
        return self._ctx

    def _open(self, ip: str) -> _DotConn:
        raw = socket.create_connection((ip, self.port), self.timeout) if ":" not in ip \
            else socket.create_connection((ip, self.port, 0, 0), self.timeout)
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            sock = self._context().wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise
        self.handshakes += 1
        return _DotConn(ip, sock)

    def _pick(self, ip: str):
        now = time.monotonic()
        drop = []
        with self._lock:
            live = []
            for c in self._conns.get(ip, []):
                (live if c.usable(now) else drop).append(c)
            self._conns[ip] = live
            best = min(live, key=lambda c: c.load()) if live else None
            pick = best if best is not None and (best.load() < DOT_PIPELINE
                                                  or len(live) >= DOT_MAX_CONNS) else None
        for c in drop:
            c.kill()
        return pick

    def _conn(self, ip: str) -> tuple[_DotConn, bool]:
        """(connection, opened_now) for `ip`: the least busy usable one, or a new one.
        One thread opens a connection at a time per address; the others wait for it and
        pipeline on it instead of each paying for its own TLS handshake."""
        pick = self._pick(ip)
        if pick is not None:
            return pick, False
        with self._lock:
            opener = self._openers.setdefault(ip, threading.Lock())
        with opener:
            pick = self._pick(ip)
            if pick is not None:
                return pick, False
            c = self._open(ip)
            with self._lock:
                self._conns.setdefault(ip, []).append(c)
        return c, True

    def warm_idle(self) -> float:
        """Seconds since the busiest live connection last carried anything (inf: none)."""
        now = time.monotonic()
        with self._lock:
            idles = [c.idle(now) for cs in self._conns.values() for c in cs if not c.dead]
        return min(idles) if idles else float("inf")

    def reset(self) -> None:
        with self._lock:
            conns, self._conns = [c for cs in self._conns.values() for c in cs], {}
        for c in conns:
            c.kill()

    def query(self, wire: bytes) -> bytes:
        errors = []
        for ip in self.ips:
            for attempt in range(2):     # a kept-alive connection may close under us: retry once
                fresh = False
                try:
                    conn, fresh = self._conn(ip)
                    data = conn.ask(wire, self.timeout)
                    self.last_ok = time.time()
                    return data
                except (OSError, DNSError, struct.error, ssl.SSLError) as exc:
                    errors.append(f"{ip}: {type(exc).__name__}")
                    if attempt == 0 and not fresh and isinstance(exc, (ConnectionResetError, BrokenPipeError,
                                                                       ConnectionAbortedError)):
                        continue
                    break
        self.last_error = "; ".join(errors)[-300:]
        raise DNSError(f"{self.name}: {self.last_error}")


def make_upstream(name: str, url: str, ips: list[str], timeout: float = 2.5):
    """DohUpstream for https://, DotUpstream for tls://."""
    if url.startswith("tls://"):
        return DotUpstream(name, url, ips, timeout=timeout)
    return DohUpstream(name, url, ips, timeout=timeout)


def monotonic_continuous() -> float:
    """A clock that keeps counting while the Mac sleeps and can't be set.
    macOS CLOCK_MONOTONIC continues during sleep (Python's time.monotonic()
    uses mach_absolute_time, which stops)."""
    clk = getattr(time, "CLOCK_MONOTONIC", None)
    if clk is not None:
        try:
            return time.clock_gettime(clk)
        except OSError:
            pass
    return time.monotonic()


# ---------------------------------------------------------------- policy
class Policy:
    """The user's own lists, kept by pax-guard (local blocklist or the server),
    plus the restricted categories an exception never frees (v0.8.1):
    `restricted` names (the media converters, suffix match), `restricted_rules`
    (objects with match(name) -> bool, e.g. the media-converter name rule) and
    `never_except` (a callable: True when an exception must be ignored, e.g. the
    restricted-content name rule and top-level domains)."""

    def __init__(self, blocked=(), exceptions=(), categories=(), restricted=(),
                 restricted_rules=(), never_except=None, youtube_restricted: bool = True,
                 family_layer: bool = False):
        from domain_matcher import SmallSuffixSet
        # v0.8.18: True = the user turned on the extra family-filter layer
        # (Advanced): allowed queries go to the family chain, not the primary one.
        self.family_layer = bool(family_layer)
        # v0.8.6: False = the user turned YouTube Restricted Mode off (Settings).
        self.youtube_restricted = bool(youtube_restricted)
        self.blocked = SmallSuffixSet(blocked)
        self.exceptions = SmallSuffixSet(exceptions)
        self.categories = SmallSuffixSet(categories)
        self.restricted = SmallSuffixSet(restricted)
        self.restricted_rules = list(restricted_rules)
        self.never_except = never_except


class Forwarder:
    def __init__(self, upstreams: list, filters=None, policy: Policy | None = None,
                 log=print, cache_size: int = 20_000, clock=time.time, youtube_upstreams: list | None = None,
                 primary_upstreams: list | None = None, canary_min_entries: int = CANARY_MIN_ENTRIES,
                 on_fallback=None, serve_stale: bool = True, prefetch: bool = True, hedge: bool = True):
        # `upstreams` is the family-filter chain. v0.8.18: `primary_upstreams` (the
        # malware-only resolvers) take allowed queries while Pax's own filter is
        # healthy; without them the family chain is the only one (as before 0.8.18).
        self.upstreams = upstreams
        self.primary_upstreams = list(primary_upstreams) if primary_upstreams else []
        self.canary_min_entries = canary_min_entries
        # on_fallback(entering: bool, reason: str): pax-guard writes it to the tamper log.
        self.on_fallback = on_fallback
        self.fallback_reason: str | None = None
        self.fallback_since: float | None = None
        self.last_canary: dict = {}
        self._canary_lock = threading.Lock()
        self._last_canary_at = 0.0
        # v0.8.6: the chain for YouTube's names while Restricted Mode is off. Without
        # one, they keep the normal chain (Restricted Mode stays on: safe).
        self.youtube_upstreams = list(youtube_upstreams) if youtube_upstreams else []
        self.filters = filters
        self.policy = policy or Policy()
        self.log = log
        self.clock = clock
        self._cache: OrderedDict = OrderedDict()
        self._cache_size = cache_size
        self._cache_lock = threading.Lock()
        self.ready = filters is not None
        self.active = upstreams[0].name if upstreams else None
        self.stats = {"queries": 0, "blocked": 0, "rewritten": 0, "servfail": 0, "cache_hits": 0,
                      "stale_served": 0, "prefetched": 0, "coalesced": 0, "hedged": 0, "upstream": {}}
        self._last_all_down_log = 0.0
        # v0.8.36 speed: serve-stale + prefetch for allowed answers, one upstream query per
        # name at a time, hedged requests within a chain, per-upstream latency.
        self.serve_stale = serve_stale
        self.prefetch = prefetch
        self.hedge = hedge
        self._upool = ThreadPoolExecutor(max_workers=64, thread_name_prefix="pax-dns-up")
        self._bgpool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pax-dns-refresh")
        self._inflight: dict = {}
        self._inflight_lock = threading.Lock()
        self._refreshing: set = set()
        self._latency: dict = {}          # upstream name -> (ewma seconds, mean deviation)
        self.last_query_at = float("-inf")  # never: monotonic() is uptime, can be < KEEPWARM_WINDOW after boot
        self._bg_started = False

    # -------------------------------------------------------- configuration
    def set_filters(self, filters) -> None:
        # v0.8.36: every lookup is decided again with the new lists before the cache is read,
        # so allowed answers can stay; only SafeSearch rewrites (whose target comes from the
        # lists) are dropped. Blocked answers are never cached.
        self.filters = filters
        self.ready = filters is not None
        self.flush(rewrites_only=True)
        if self.primary_upstreams:
            self.canary()                 # after every list change

    # ------------------------------------------------ v0.8.18 fallback + canary
    @property
    def pax_filter_ok(self) -> bool:
        """True when allowed queries may use the primary (malware-only) chain."""
        return bool(self.primary_upstreams) and self.ready and self.fallback_reason is None

    def enter_fallback(self, reason: str) -> None:
        """Route every query to the family chain at once (never open)."""
        first = self.fallback_reason is None
        self.fallback_reason = reason[:200]
        if first:
            self.fallback_since = time.time()
            self.flush()
            self.log(f"PAX-DNS-017 Pax's own filter failed a check ({reason}); every lookup now goes "
                     "to the family filter until the self-test passes again")
            if self.on_fallback:
                try:
                    self.on_fallback(True, self.fallback_reason)
                except Exception:  # noqa: BLE001 - logging never stops DNS
                    pass

    def leave_fallback(self) -> None:
        if self.fallback_reason is None:
            return
        was = self.fallback_reason
        self.fallback_reason, self.fallback_since = None, None
        self.flush()
        self.log(f"Pax's own filter passed its self-test again (was: {was}); back to the primary chain")
        if self.on_fallback:
            try:
                self.on_fallback(False, was)
            except Exception:  # noqa: BLE001
                pass

    def canary(self) -> dict:
        """Self-test of Pax's own filter: the lists are loaded and big enough, known
        restricted names (encoded in common/pax_restricted.py) are blocked by the lists
        and by the decision code, a made-up name only the name rule knows is blocked,
        and everyday names are allowed, all within CANARY_TIMEOUT. A failure enters the
        fallback at once; a pass leaves it. Returns the result (also in status())."""
        import pax_restricted as pr
        with self._canary_lock:
            t0 = time.monotonic()
            failures: list[str] = []
            f = self.filters
            clean = Policy()
            try:
                if f is None:
                    failures.append("lists not loaded")
                else:
                    if (f.info or {}).get("state") == "empty" or f.entries < self.canary_min_entries:
                        failures.append(f"lists too small ({f.entries} entries)")
                    for name in pr.samples():
                        if not any(m.match(name) for m in f.restricted):
                            failures.append("a known restricted name is missing from the lists")
                            break
                    for name in pr.samples():
                        if self.decide(name, clean)[0] != "block":
                            failures.append("a known restricted name was not blocked")
                            break
                    word = sorted(pr.data()["lookup_rule"]["words"])[0]
                    made_up = f"{word}-paxcanary{random.randint(10_000, 99_999)}.com"
                    if self.decide(made_up, clean)[0] != "block":
                        failures.append("the name rule did not block a test name")
                    for name in CANARY_EVERYDAY:
                        if self.decide(name, clean)[0] == "block":
                            failures.append(f"an everyday name was blocked ({name})")
                            break
            except Exception as exc:  # noqa: BLE001 - a throwing engine is a failure
                failures.append(f"decision code error ({type(exc).__name__})")
            took = time.monotonic() - t0
            if took > CANARY_TIMEOUT:
                failures.append(f"self-test too slow ({took:.2f}s)")
            self._last_canary_at = time.monotonic()
            self.last_canary = {"ok": not failures, "at": int(time.time()), "seconds": round(took, 3),
                                "failures": failures}
        if self.primary_upstreams:
            if failures:
                self.enter_fallback("canary: " + "; ".join(failures))
            else:
                self.leave_fallback()
        return self.last_canary

    def canary_due(self) -> bool:
        """Every CANARY_INTERVAL; every health check (a minute) while in the fallback."""
        every = HEALTH_INTERVAL - 1 if self.fallback_reason else CANARY_INTERVAL
        return time.monotonic() - self._last_canary_at >= every

    def set_policy(self, policy: Policy) -> None:
        # v0.8.36: the user's blocks and exceptions are applied by decide() before the cache
        # is read, so a list change keeps the cache. A change of route (extra family layer,
        # YouTube Restricted Mode) still empties it.
        old = self.policy
        self.policy = policy
        if (getattr(old, "family_layer", False) != getattr(policy, "family_layer", False)
                or getattr(old, "youtube_restricted", True) != getattr(policy, "youtube_restricted", True)):
            self.flush()

    def flush(self, rewrites_only: bool = False) -> None:
        with self._cache_lock:
            if rewrites_only:
                for key in [k for k in self._cache if len(k) > 3 and k[3]]:
                    del self._cache[key]
            else:
                self._cache.clear()

    # ------------------------------------------------------------- decision
    def decide(self, name: str, policy: Policy | None = None) -> tuple[str, str]:
        """("rewrite", target) | ("block", why) | ("forward", why).

        v0.8.8: `policy` overrides self.policy for this one query (the server's
        per-user DoH resolver shares one forwarder, its lists, cache and
        upstreams between users; the Mac passes nothing).

        An exception frees only what an exception may free: the user's own
        blocks, Pax's categories and the overridable lists. Restricted hits
        are blocked even when the name is on the exception list (v0.8.1)."""
        f = self.filters
        p = policy if policy is not None else self.policy
        # v0.8.3: the user's own blocks beat the SafeSearch rewrite, so a
        # search engine (bing.com, google.com…) can be blocked outright.
        # An exception never frees a SafeSearch host from its rewrite.
        if name in p.blocked and name not in p.exceptions:
            return "block", "your blocked sites"
        if f is not None:
            target = f.safesearch_target(name)
            if target and not self.youtube_unrestricted(name, p):
                return "rewrite", target
        if name in p.restricted or any(r.match(name) for r in p.restricted_rules):
            return "block", "restricted:category"
        pax_allowed = f is not None and f.allowed(name)
        if f is not None and not pax_allowed:
            hit = f.restricted_by(name)
            if hit:
                return "block", f"restricted:{hit}"
        if name in p.exceptions and not (p.never_except is not None and p.never_except(name)):
            return "forward", "exception"
        if name in p.blocked:
            return "block", "your blocked sites"
        if name in p.categories:
            return "block", "category"
        if f is not None:
            if pax_allowed:
                return "forward", "allowlist"
            hit = f.overridable_by(name)
            if hit:
                return "block", f"list:{hit}"
        return "forward", ""

    def youtube_unrestricted(self, name: str, policy: Policy | None = None) -> bool:
        """v0.8.6: a YouTube name while the user has Restricted Mode off. Only
        YouTube's rewrite is skipped: Google/Bing SafeSearch and every block stay.
        v0.8.18: with Pax's filter healthy the rewrite is local, so skipping it is
        enough (the primary chain leaves YouTube alone); otherwise it needs the
        YouTube chain, as before."""
        p = policy if policy is not None else self.policy
        return (not p.youtube_restricted and name in YOUTUBE_NAMES
                and bool(self.youtube_upstreams or (self.primary_upstreams and not self.family_route(p))))

    # ---------------------------------------------------------------- cache
    def _cache_lookup(self, key):
        """(answer, state): state "fresh", "prefetch" (fresh, but popular and about to
        expire: refresh it now) or "stale" (expired allowed answer, served with STALE_TTL
        while it is refreshed; RFC 8767). (None, None) on a miss."""
        with self._cache_lock:
            item = self._cache.get(key)
            if not item:
                return None, None
            expires, resp, stored, ttl, hits, positive = item
            now = monotonic_continuous()
            if now < expires:
                item[4] = hits + 1
                self._cache.move_to_end(key)
                self.stats["cache_hits"] = self.stats.get("cache_hits", 0) + 1
                state = "fresh"
                if (self.prefetch and hits + 1 >= PREFETCH_MIN_HITS
                        and expires - now <= max(1.0, ttl * PREFETCH_FRACTION)):
                    state = "prefetch"
                return age_ttls(resp, int(now - stored)), state
            # Stale only on Pax's own route (key[4] False): there every content decision is the
            # lists' and was just made again. On the family-filter route the upstream decides
            # content too, so its answers are never used past their TTL.
            if self.serve_stale and positive and not key[4] and now < expires + STALE_MAX:
                self._cache.move_to_end(key)
                self.stats["stale_served"] = self.stats.get("stale_served", 0) + 1
                return cap_ttls(resp, STALE_TTL), "stale"
            del self._cache[key]
        return None, None

    def _cache_get(self, key):
        """Fresh answers only (pre-0.8.36 behaviour; kept for callers and tests)."""
        resp, state = self._cache_lookup(key)
        return resp if state in ("fresh", "prefetch") else None

    def _cache_put(self, key, resp: bytes, ttl: int) -> None:
        if ttl <= 0:
            return
        with self._cache_lock:
            now = monotonic_continuous()
            old = self._cache.get(key)
            hits = old[4] if old else 0
            self._cache[key] = [now + ttl, resp, now, ttl, hits, is_positive(resp)]
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

    # -------------------------------------------------------------- upstream
    @staticmethod
    def _ordered(ups: list) -> list:
        return [u for u in ups if u.healthy] + [u for u in ups if not u.healthy]

    def ordered_upstreams(self) -> list:
        """The default chain: primary (when Pax's filter is healthy), then family."""
        if self.pax_filter_ok:
            return self._ordered(self.primary_upstreams) + self._ordered(self.upstreams)
        return self._ordered(self.upstreams)

    def family_route(self, policy: Policy | None = None) -> bool:
        """v0.8.18: does this query go to the family chain only?"""
        p = policy if policy is not None else self.policy
        return not self.pax_filter_ok or bool(getattr(p, "family_layer", False))

    def chain_for(self, policy: Policy | None, youtube: bool) -> list:
        if self.family_route(policy):
            return list(self.youtube_upstreams) if youtube else self._ordered(self.upstreams)
        if youtube:
            # Pax's filter decided; the primary chain doesn't touch YouTube, and the
            # YouTube chain's last resort puts Restricted Mode back on (safe).
            return self._ordered(self.primary_upstreams) + list(self.youtube_upstreams)
        return self._ordered(self.primary_upstreams) + self._ordered(self.upstreams)

    def hedge_delay(self, u) -> float:
        """How long to wait for `u` before also asking the next upstream of the same chain:
        its usual answer time plus four mean deviations, within HEDGE_MIN..HEDGE_MAX."""
        lat = self._latency.get(u.name)
        if not lat:
            return HEDGE_DEFAULT
        ewma, dev = lat
        return min(HEDGE_MAX, max(HEDGE_MIN, ewma + 4 * dev))

    def _record_latency(self, u, took: float) -> None:
        ewma, dev = self._latency.get(u.name, (took, took / 2))
        dev = 0.75 * dev + 0.25 * abs(took - ewma)
        ewma = 0.8 * ewma + 0.2 * took
        self._latency[u.name] = (ewma, dev)

    def _attempt(self, u, wire: bytes, results) -> None:
        """One upstream query. Health is recorded here, not by the caller, so an upstream
        that fails after a hedge already answered (port 853 blocked on a hotel network,
        say) is still marked down and moved to the back of the chain."""
        t0 = time.monotonic()
        try:
            resp = u.query(wire)
            if len(resp) < 12:
                raise DNSError("short answer")
        except Exception as exc:  # noqa: BLE001 - reported to forward()
            if u.healthy:
                u.healthy = False
                self.log(f"PAX-DNS-003 {u.name} failed ({exc}); trying the next upstream")
            results.put((u, None, exc, time.monotonic() - t0))
            return
        took = time.monotonic() - t0
        if not u.healthy:
            u.healthy = True
        self._record_latency(u, took)
        results.put((u, resp, None, took))

    def forward(self, wire: bytes, chain: list | None = None, note: bool = True) -> bytes | None:
        """The first good upstream answer, or None when every upstream failed.
        `chain` (v0.8.6 YouTube names, v0.8.18 per-query route) is tried in its
        own order instead of the default one.

        v0.8.36: upstreams are still asked strictly in chain order, but the next one is
        also asked when the current one hasn't answered within hedge_delay() (it carries
        on; the first good answer wins), when it fails, or when it answers SERVFAIL or
        REFUSED. Every upstream in a chain is a filtered resolver Pax already trusts for
        that query, so this is the same set of resolvers the pre-0.8.36 failover reached,
        only sooner. The whole chain gets FORWARD_BUDGET seconds."""
        ups = list(chain if chain else self.ordered_upstreams())
        results: queue.Queue = queue.Queue()
        deadline = time.monotonic() + FORWARD_BUDGET
        started = finished = 0
        fallback = None
        next_hedge = 0.0

        def start_next() -> None:
            nonlocal started, next_hedge
            u = ups[started]
            started += 1
            if started > 1:
                self.stats["hedged"] = self.stats.get("hedged", 0) + 1
            self._upool.submit(self._attempt, u, wire, results)
            next_hedge = time.monotonic() + (self.hedge_delay(u) if self.hedge else FORWARD_BUDGET)

        if ups:
            start_next()
        while ups:
            now = time.monotonic()
            if now >= deadline:
                break
            until = deadline if started >= len(ups) else min(deadline, next_hedge)
            try:
                u, resp, exc, took = results.get(timeout=max(0.0, until - now))
            except queue.Empty:
                if started < len(ups) and time.monotonic() >= next_hedge:
                    start_next()
                continue
            finished += 1
            if exc is None:
                if rcode_of(resp) in (RCODE_NOERROR, RCODE_NXDOMAIN):
                    if note:
                        self._note_active(u)
                    self.stats["upstream"][u.name] = self.stats["upstream"].get(u.name, 0) + 1
                    return resp
                if fallback is None:
                    fallback = resp            # SERVFAIL/REFUSED: the next one may know better
            if finished >= started:
                if started < len(ups):
                    start_next()
                else:
                    break
        if fallback is not None:
            return fallback
        now = time.time()
        if now - self._last_all_down_log > 60:
            self._last_all_down_log = now
            self.log("PAX-DNS-004 every filtered upstream failed: answering SERVFAIL (never unfiltered)")
        return None

    def _note_active(self, u) -> None:
        if self.active != u.name:
            self.log(f"DNS upstream now {u.name} (was {self.active})")
            self.active = u.name

    # ---------------------------------------------------------------- handle
    def handle(self, raw: bytes, policy: Policy | None = None) -> bytes | None:
        try:
            q = Query(raw)
        except (DNSError, struct.error):
            if len(raw) >= 12:
                hdr = bytearray(raw[:12])
                hdr[2] |= 0x80
                hdr[3] = (hdr[3] & 0xF0) | RCODE_FORMERR
                struct.pack_into("!HHHH", hdr, 4, 0, 0, 0, 0)
                return bytes(hdr)
            return None
        self.stats["queries"] += 1
        if not self.ready and not self.primary_upstreams:
            self.stats["servfail"] += 1
            return make_servfail(q)          # lists still loading: closed, not open
        if q.qclass != 1:
            return make_error(q, RCODE_REFUSED)
        name = q.name
        # v0.8.18: lists still loading (with a primary chain configured) = family
        # chain only; a throwing or slow decision = fallback for every lookup.
        t0 = time.monotonic()
        try:
            action, detail = self.decide(name, policy)
        except Exception as exc:  # noqa: BLE001 - never open: the family chain decides
            self.enter_fallback(f"decision code error ({type(exc).__name__})")
            if not self.primary_upstreams:
                self.stats["servfail"] += 1
                return make_servfail(q)
            action, detail = "forward", "fallback"
        took = time.monotonic() - t0
        if took > DECIDE_SLOW and self.primary_upstreams:
            self.enter_fallback(f"decision took {took:.2f}s")
        if action == "block":
            self.stats["blocked"] += 1
            return make_blocked(q)
        if action == "rewrite" and q.qtype in (QTYPE_HTTPS, QTYPE_SVCB):
            self.stats["rewritten"] += 1
            return _header(q, RCODE_NOERROR, 0) + q.question     # use A/AAAA instead
        family = self.family_route(policy)
        youtube = action == "forward" and self.youtube_unrestricted(name, policy)
        key = (name, q.qtype, q.do_bit, action == "rewrite", family) + (("youtube",) if youtube else ())
        self.last_query_at = time.monotonic()
        # Only reached for a lookup decide() allowed (or rewrote) just now, with the lists
        # in use: a blocked name never gets here and never has a cached answer.
        cached, state = self._cache_lookup(key)
        if cached is not None:
            if state != "fresh":
                self._refresh_later(key, raw, q, action, detail, policy, youtube, state)
            return for_query(cached, q)
        if action == "rewrite":
            self.stats["rewritten"] += 1
        resp = self._resolve_once(key, raw, q, action, detail, policy, youtube)
        if resp is None:
            self.stats["servfail"] += 1
            return make_servfail(q)
        return resp

    def _resolve(self, key, raw: bytes, q: Query, action: str, detail: str, policy, youtube: bool):
        """Ask upstream for an allowed (or rewritten) lookup and cache the answer.
        None = every upstream failed (the caller answers SERVFAIL, never unfiltered)."""
        if action == "rewrite":
            upstream = None
            if q.qtype in (QTYPE_A, QTYPE_AAAA):
                upstream = self.forward(build_query(detail, q.qtype, random.getrandbits(16)),
                                        self.chain_for(policy, False))
                if upstream is None:
                    return None
            resp = make_rewrite(q, detail, upstream)
            self._cache_put(key, resp, min(BLOCK_TTL, cache_ttl(upstream)) if upstream else BLOCK_TTL)
            return resp
        resp = self.forward(raw, self.chain_for(policy, youtube), note=not youtube)
        if resp is None:
            return None
        resp = with_id(resp, q.id)
        try:
            rcode, _ = parse_answers(resp)
        except (DNSError, struct.error):
            rcode = RCODE_SERVFAIL
        if rcode in (RCODE_NOERROR, RCODE_NXDOMAIN):
            self._cache_put(key, resp, cache_ttl(resp))     # TTL-respecting, negative too
        return resp

    def _resolve_once(self, key, raw: bytes, q: Query, action: str, detail: str, policy, youtube: bool):
        """v0.8.36: one upstream lookup per name at a time; a second asker of the same
        name (the browser and macOS often ask together) waits for the first one's answer."""
        with self._inflight_lock:
            slot = self._inflight.get(key)
            leader = slot is None
            if leader:
                slot = self._inflight[key] = [threading.Event(), None]
        if not leader:
            self.stats["coalesced"] = self.stats.get("coalesced", 0) + 1
            if slot[0].wait(FORWARD_BUDGET + 1.0) and slot[1] is not None:
                return for_query(slot[1], q)
            return self._resolve(key, raw, q, action, detail, policy, youtube)
        try:
            resp = self._resolve(key, raw, q, action, detail, policy, youtube)
            slot[1] = resp
            return resp
        finally:
            with self._inflight_lock:
                self._inflight.pop(key, None)
            slot[0].set()

    def _refresh_later(self, key, raw: bytes, q: Query, action: str, detail: str, policy, youtube: bool,
                       state: str) -> None:
        """Fetch a fresh copy of a stale or about-to-expire allowed answer in the background."""
        with self._inflight_lock:
            if key in self._refreshing or key in self._inflight:
                return
            self._refreshing.add(key)
        if state == "prefetch":
            self.stats["prefetched"] = self.stats.get("prefetched", 0) + 1

        def run() -> None:
            try:
                self._resolve_once(key, raw, q, action, detail, policy, youtube)
            except Exception:  # noqa: BLE001 - a failed refresh keeps the old answer until STALE_MAX
                pass
            finally:
                with self._inflight_lock:
                    self._refreshing.discard(key)
        try:
            self._bgpool.submit(run)
        except RuntimeError:              # shutting down
            with self._inflight_lock:
                self._refreshing.discard(key)

    # ------------------------------------------------------- warm + keep warm
    def warm(self, names=WARM_NAMES) -> int:
        """v0.8.36: look up a few names almost every Mac needs (A and AAAA), through the
        normal path (decided, rewritten, cached), so the first pages after a restart don't
        wait. Returns how many answers were cached."""
        n = 0
        for name in names:
            for qtype in (QTYPE_A, QTYPE_AAAA):
                try:
                    resp = self.handle(build_query(name, qtype, random.getrandbits(16)))
                    n += 1 if resp and rcode_of(resp) == RCODE_NOERROR else 0
                except Exception:  # noqa: BLE001
                    pass
        return n

    def keep_warm(self) -> bool:
        """While the Mac has looked something up in the last KEEPWARM_WINDOW seconds, send
        the first upstream of the default chain one tiny query when its connection has been
        idle KEEPWARM_EVERY seconds, so a pause in browsing doesn't cost a new TLS handshake
        (Quad9 closes idle connections after ~10 s). True when a query was sent."""
        if time.monotonic() - self.last_query_at > KEEPWARM_WINDOW:
            return False
        first = next((u for u in self.ordered_upstreams() if u.healthy), None)
        idle = getattr(first, "warm_idle", None)
        if first is None or idle is None or idle() < KEEPWARM_EVERY:
            return False
        try:
            first.query(build_query(HEALTH_NAME, QTYPE_A, random.getrandbits(16)))
            return True
        except Exception:  # noqa: BLE001 - the next real lookup hedges past it
            return False

    def start_background(self, warm: bool = True) -> None:
        """pax-guard: the keep-warm loop, and the warm-up once the lists are in."""
        if self._bg_started:
            return
        self._bg_started = True

        def loop() -> None:
            warmed = False
            while True:
                try:
                    if warm and not warmed and self.ready:
                        warmed = True
                        self.warm()
                    self.keep_warm()
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(2.0)
        threading.Thread(target=loop, name="pax-dns-warm", daemon=True).start()

    def reset_connections(self) -> None:
        """v0.8.36: the network changed: kept-alive upstream connections belong to the old
        one, so drop them instead of waiting for each to time out."""
        for u in self.all_upstreams():
            r = getattr(u, "reset", None)
            if r is not None:
                try:
                    r()
                except Exception:  # noqa: BLE001
                    pass

    # ---------------------------------------------------------------- health
    def health_check(self) -> dict:
        probe = build_query(HEALTH_NAME, QTYPE_A, random.getrandbits(16))
        if self.primary_upstreams and self.canary_due():
            self.canary()
        for u in self.primary_upstreams + list(self.upstreams):
            try:
                resp = u.query(probe)
                rcode, _ = parse_answers(resp)
                ok = rcode in (RCODE_NOERROR, RCODE_NXDOMAIN)
            except Exception as exc:  # noqa: BLE001
                ok = False
                u.last_error = str(exc)[-200:]
            if ok != u.healthy:
                self.log(f"DNS upstream {u.name} is {'back' if ok else 'down'}")
            u.healthy = ok
        first = next((u for u in self.ordered_upstreams() if u.healthy), None)
        if first:
            self._note_active(first)
        elif self.active is not None:
            self.log("PAX-DNS-004 no filtered upstream answers the health check; DNS answers SERVFAIL")
            self.active = None
        return self.status()

    def refresh_pinned_ips(self) -> None:
        """Re-resolve each upstream's hostname through a working upstream and
        add the answers to its pinned set (built-in addresses are kept)."""
        for u in self.all_upstreams():
            found = []
            for qtype in (QTYPE_A, QTYPE_AAAA):
                resp = self.forward(build_query(u.host, qtype, random.getrandbits(16)))
                if not resp:
                    continue
                try:
                    _, answers = parse_answers(resp)
                except (DNSError, struct.error):
                    continue
                for _o, rtype, _c, _t, rdata in answers:
                    if rtype == QTYPE_A and len(rdata) == 4:
                        found.append(socket.inet_ntop(socket.AF_INET, rdata))
                    elif rtype == QTYPE_AAAA and len(rdata) == 16:
                        found.append(socket.inet_ntop(socket.AF_INET6, rdata))
            # A filtering upstream may answer a resolver's own name with a block
            # address; never pin one of those (v0.8.18).
            found = [ip for ip in found if ip not in ("0.0.0.0", "::") and not ip.startswith("146.112.61.")]
            u.ips = list(dict.fromkeys(u.ips + found))[:8]

    def trusted_now(self, max_age: float = 24 * 3600) -> float | None:
        """Time from the upstreams' TLS-protected Date headers, if recent."""
        best = None
        mono = monotonic_continuous()
        for u in self.primary_upstreams + list(self.upstreams):
            if u.trusted_time:
                when, at = u.trusted_time
                if 0 <= mono - at <= max_age:
                    est = when + (mono - at)
                    best = est if best is None else max(best, est)
        return best

    def status(self) -> dict:
        allu = self.primary_upstreams + list(self.upstreams)
        if not self.primary_upstreams:
            mode = "family"
        elif self.fallback_reason or not self.ready:
            mode = "fallback"
        elif getattr(self.policy, "family_layer", False):
            mode = "family-layer"
        else:
            mode = "pax"
        return {
            "active": self.active,
            "ready": self.ready,
            # v0.8.18: "pax" (Pax's filter + primary chain), "family-layer" (the user's
            # Advanced choice), "fallback" (Pax's filter failed a check), "family" (no
            # primary chain configured).
            "filter_mode": mode,
            "fallback_reason": self.fallback_reason,
            "fallback_since": self.fallback_since,
            "canary": dict(self.last_canary),
            "all_down": not any(u.healthy for u in allu),
            "upstreams": [{"name": u.name, "url": u.url, "healthy": u.healthy,
                           "role": "primary" if u in self.primary_upstreams else "family",
                           "last_error": u.last_error[-120:],
                           # v0.8.36: usual answer time and TLS handshakes, for "is it slow?"
                           "latency_ms": (round(self._latency[u.name][0] * 1000, 1)
                                          if u.name in self._latency else None),
                           "handshakes": getattr(u, "handshakes", None),
                           "via_curl": bool(getattr(u, "use_curl", False))} for u in allu],
            "cache": {"entries": len(self._cache), "size": self._cache_size},
            "stats": dict(self.stats, upstream=dict(self.stats["upstream"])),
            "lists": (self.filters.info if self.filters is not None else {}),
        }

    def all_upstreams(self) -> list:
        out = list(self.primary_upstreams) + list(self.upstreams)
        for u in self.youtube_upstreams:
            if all(u is not x for x in out):
                out.append(u)
        return out

    def pinned_ips(self) -> list[str]:
        return sorted({ip for u in self.all_upstreams() for ip in u.ips})

    def primary_ips(self) -> list[str]:
        """v0.8.18: the malware-only resolvers' addresses (pf: root only, always)."""
        return sorted({ip for u in self.primary_upstreams for ip in u.ips})

    def family_ips(self) -> list[str]:
        prim = set(self.primary_ips())
        return [ip for ip in self.pinned_ips() if ip not in prim]


def default_upstreams(timeout: float = 2.5) -> list[DohUpstream]:
    return [DohUpstream(n, url, ips, timeout=timeout) for n, url, ips in DEFAULT_UPSTREAMS]


def primary_upstreams(timeout: float = 2.5) -> list:
    """v0.8.18: Quad9 (DoT), then Cloudflare's security resolver (DoH)."""
    return [make_upstream(n, url, ips, timeout=timeout) for n, url, ips in PRIMARY_UPSTREAMS]


def youtube_upstreams(upstreams: list, timeout: float = 2.5) -> list:
    """v0.8.6: CleanBrowsing Adult, then the AdGuard Family upstream already in
    `upstreams` (Restricted Mode back on, never unfiltered), for YouTube's names
    while the switch is off. Reaches the same addresses pf already allows."""
    n, url, ips = CLEANBROWSING_ADULT
    ag = [u for u in upstreams if u.name.startswith("AdGuard")]
    return [DohUpstream(n, url, ips, timeout=timeout)] + ag


# ---------------------------------------------------------------- servers
class DNSServer:
    """UDP + TCP on 127.0.0.1:53 (root binds the port). Threads only."""

    def __init__(self, forwarder: Forwarder, host: str = "127.0.0.1", port: int = 53, log=print):
        self.fwd = forwarder
        self.host, self.port = host, port
        self.log = log
        self.pool = ThreadPoolExecutor(max_workers=64, thread_name_prefix="pax-dns")
        self._udp: socket.socket | None = None
        self._tcp: socketserver.ThreadingTCPServer | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        fam = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self._udp = socket.socket(fam, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((self.host, self.port))
        self.port = self._udp.getsockname()[1]
        fwd = self.fwd

        class TCPHandler(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: D401
                self.request.settimeout(10)
                try:
                    while True:
                        hdr = _recv_exact(self.request, 2)
                        if not hdr:
                            return
                        (n,) = struct.unpack("!H", hdr)
                        msg = _recv_exact(self.request, n)
                        if not msg:
                            return
                        resp = fwd.handle(msg)
                        if resp is None:
                            return
                        self.request.sendall(struct.pack("!H", len(resp)) + resp)
                except OSError:
                    return

        class TCPServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
            address_family = fam

        self._tcp = TCPServer((self.host, self.port), TCPHandler)
        threading.Thread(target=self._udp_loop, name="pax-dns-udp", daemon=True).start()
        threading.Thread(target=self._tcp.serve_forever, name="pax-dns-tcp", daemon=True).start()
        self.log(f"DNS forwarder listening on {self.host}:{self.port}")

    def _udp_loop(self) -> None:
        assert self._udp is not None
        while not self._stop.is_set():
            try:
                data, addr = self._udp.recvfrom(4096)
            except OSError:
                if self._stop.is_set():
                    return
                continue
            self.pool.submit(self._answer_udp, data, addr)

    def _answer_udp(self, data: bytes, addr) -> None:
        try:
            resp = self.fwd.handle(data)
            if resp is None:
                return
            try:
                q = Query(data)
                resp = truncate_for_udp(q, resp)
            except (DNSError, struct.error):
                pass
            self._udp.sendto(resp, addr)
        except Exception as exc:  # noqa: BLE001 - one bad packet never stops the server
            self.log(f"DNS answer error: {type(exc).__name__}")

    def stop(self) -> None:
        self._stop.set()
        if self._tcp:
            self._tcp.shutdown()
            self._tcp.server_close()
        if self._udp:
            self._udp.close()
        self.pool.shutdown(wait=False)


def _recv_exact(sock, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
