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
  5. Pax allowlist (tailscale.com, character.ai) -> upstream
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
import random
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
CANARY_EVERYDAY = ("example.com", "wikipedia.org", "apple.com", "gov.uk", "bbc.co.uk")


class DNSError(Exception):
    pass


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
        with self._lock:
            for i, c in enumerate(self._pool):
                if c._ip == ip:
                    return self._pool.pop(i)
        return _PinnedHTTPS(self.host, ip, self.timeout, self._context())

    def _give(self, conn: _PinnedHTTPS) -> None:
        with self._lock:
            if len(self._pool) < 8:
                self._pool.append(conn)
                return
        conn.close()

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


class DotUpstream:
    """v0.8.18: DNS-over-TLS (RFC 7858) to one resolver, at pinned addresses, with
    kept-alive connections. Same interface as DohUpstream."""

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
        self._pool: list[tuple[str, ssl.SSLSocket]] = []
        self._lock = threading.Lock()
        self.healthy = True
        self.last_error = ""
        self.last_ok = 0.0
        self.trusted_time: tuple[float, float] | None = None   # no Date header over DoT

    def _context(self) -> ssl.SSLContext:
        if self._ctx is None:
            self._ctx = _ssl_context()
        return self._ctx

    def _take(self, ip: str):
        with self._lock:
            for i, (pip, sock) in enumerate(self._pool):
                if pip == ip:
                    return self._pool.pop(i)[1]
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        raw = socket.create_connection((ip, self.port), self.timeout) if fam == socket.AF_INET \
            else socket.create_connection((ip, self.port, 0, 0), self.timeout)
        return self._context().wrap_socket(raw, server_hostname=self.host)

    def _give(self, ip: str, sock) -> None:
        with self._lock:
            if len(self._pool) < 8:
                self._pool.append((ip, sock))
                return
        sock.close()

    def query(self, wire: bytes) -> bytes:
        errors = []
        for ip in self.ips:
            for attempt in range(2):     # a kept-alive connection may have gone stale
                sock = None
                try:
                    sock = self._take(ip)
                    sock.settimeout(self.timeout)
                    sock.sendall(struct.pack("!H", len(wire)) + wire)
                    hdr = _recv_exact(sock, 2)
                    if not hdr:
                        raise ConnectionResetError("closed")
                    (n,) = struct.unpack("!H", hdr)
                    data = _recv_exact(sock, n)
                    if not data or len(data) < 12 or data[:2] != wire[:2]:
                        raise DNSError("bad answer")
                    self._give(ip, sock)
                    self.last_ok = time.time()
                    return data
                except (OSError, DNSError, struct.error) as exc:
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError:
                            pass
                    errors.append(f"{ip}: {type(exc).__name__}")
                    if attempt == 0 and isinstance(exc, (ConnectionResetError, BrokenPipeError)):
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
                 log=print, cache_size: int = 10_000, clock=time.time, youtube_upstreams: list | None = None,
                 primary_upstreams: list | None = None, canary_min_entries: int = CANARY_MIN_ENTRIES,
                 on_fallback=None):
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
                      "upstream": {}}
        self._last_all_down_log = 0.0

    # -------------------------------------------------------- configuration
    def set_filters(self, filters) -> None:
        self.filters = filters
        self.ready = filters is not None
        self.flush()
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
        self.policy = policy
        self.flush()

    def flush(self) -> None:
        with self._cache_lock:
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
    def _cache_get(self, key):
        with self._cache_lock:
            item = self._cache.get(key)
            if not item:
                return None
            expires, resp, stored = item
            now = monotonic_continuous()
            if now >= expires:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            self.stats["cache_hits"] = self.stats.get("cache_hits", 0) + 1
        return age_ttls(resp, int(now - stored))

    def _cache_put(self, key, resp: bytes, ttl: int) -> None:
        if ttl <= 0:
            return
        with self._cache_lock:
            now = monotonic_continuous()
            self._cache[key] = (now + ttl, resp, now)
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

    def forward(self, wire: bytes, chain: list | None = None, note: bool = True) -> bytes | None:
        """The first good upstream answer, or None when every upstream failed.
        `chain` (v0.8.6 YouTube names, v0.8.18 per-query route) is tried in its
        own order instead of the default one."""
        for u in (chain if chain else self.ordered_upstreams()):
            try:
                resp = u.query(wire)
                if len(resp) < 12:
                    raise DNSError("short answer")
                if not u.healthy:
                    u.healthy = True
                if note:
                    self._note_active(u)
                self.stats["upstream"][u.name] = self.stats["upstream"].get(u.name, 0) + 1
                return resp
            except Exception as exc:  # noqa: BLE001 - try the next one
                if u.healthy:
                    u.healthy = False
                    self.log(f"PAX-DNS-003 {u.name} failed ({exc}); trying the next upstream")
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
        family = self.family_route(policy)
        key = (name, q.qtype, q.do_bit, action == "rewrite", family)
        cached = self._cache_get(key)
        if cached is not None:
            return with_id(cached, q.id)
        if action == "rewrite":
            self.stats["rewritten"] += 1
            if q.qtype in (QTYPE_HTTPS, QTYPE_SVCB):
                return _header(q, RCODE_NOERROR, 0) + q.question     # use A/AAAA instead
            upstream = None
            if q.qtype in (QTYPE_A, QTYPE_AAAA):
                upstream = self.forward(build_query(detail, q.qtype, random.getrandbits(16)),
                                        self.chain_for(policy, False))
                if upstream is None:
                    self.stats["servfail"] += 1
                    return make_servfail(q)
            resp = make_rewrite(q, detail, upstream)
            self._cache_put(key, resp, min(BLOCK_TTL, cache_ttl(upstream)) if upstream else BLOCK_TTL)
            return resp
        youtube = action == "forward" and self.youtube_unrestricted(name, policy)
        if youtube:
            key = key + ("youtube",)
            cached = self._cache_get(key)
            if cached is not None:
                return with_id(cached, q.id)
        resp = self.forward(raw, self.chain_for(policy, youtube), note=not youtube)
        if resp is None:
            self.stats["servfail"] += 1
            return make_servfail(q)
        resp = with_id(resp, q.id)
        try:
            rcode, _ = parse_answers(resp)
        except (DNSError, struct.error):
            rcode = RCODE_SERVFAIL
        if rcode in (RCODE_NOERROR, RCODE_NXDOMAIN):
            self._cache_put(key, resp, cache_ttl(resp))     # TTL-respecting, negative too
        return resp

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
                           "last_error": u.last_error[-120:]} for u in allu],
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
        self.pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="pax-dns")
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
