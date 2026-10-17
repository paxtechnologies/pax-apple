# SPDX-License-Identifier: GPL-3.0-only
"""Pax's restricted-content rules (v0.8.1): one place every part of Pax asks
"is this a site Pax always blocks?". Standard library only.

Used by pax-guard (exception requests and the DNS forwarder), the escrow
server (iPhone/iPad exception requests), pax-dns and make_profile.py. pax-guard
ships a copy next to its own modules (build-dmg.sh, pax-guard-install.sh); the
others import it from common/ in the repo.

Pax is a recovery tool and the repo is meant to read calmly, so the words and
names these rules match are not kept in plain text. They live in `_DATA`
below: gzip-compressed JSON, base64-encoded, decoded at load time. To change
them:

    python3 common/pax_restricted.py --dump > /tmp/restricted.json   # edit it
    python3 common/pax_restricted.py --encode /tmp/restricted.json    # prints the new _DATA

(keep the decoded copy out of the repo). What the data holds:
  keywords / keyword_allow_words  the new-registration name rule (a keyword at a
                                  label edge; allow words are skipped)
  tlds                            single-label (whole top-level domain) entries
  hand_list                       Pax's hand-kept restricted sites (suffix match),
                                  also part of the pax-block build
  ios_fallback_sites              the iPhone web-filter fallback (make_profile.py)
  samples                         a few restricted sites for tests and hardware checks
  sources                         upstream list addresses whose names would read badly
  lookup_rule                     (v0.8.18) the name rule applied to every lookup:
                                  words, allow_words, exclude (LookupRule)
  bypass_rule                     (v0.8.18) web proxies by name: contains, labels,
                                  exclude (BypassNameRule; not restricted)
  homepage                        (v0.8.19) the homepage check the filter workflow
                                  uses on new candidates and new Tranco hits
                                  (lists/loop/homepage.py)
  sources.heldout_* / verify_* /  (v0.8.19) the filter workflow's held-out test
  reference_doh                   sources, verification sources and reference resolver

"Restricted" here means: blocked for everyone, and never released by an
exception. Media converters (pax-dns/lists/media-converters.txt) are treated the
same way; callers pass them in as extra sets and rules.

Exception requests are also checked against CleanBrowsing Family itself
(`upstream_blocked`): a site it blocks can't be excepted either. CleanBrowsing
answers a blocked name with NXDOMAIN (checked in the v1 DNS test), so
NXDOMAIN, 0.0.0.0 / :: and known block-page addresses count as blocked, and a
lookup that fails counts as blocked too (fail closed).
"""
from __future__ import annotations

import base64
import gzip
import json
import random
import re
import struct
import sys
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable, Optional

RESTRICTED_CODE = "PAX-DNS-010"
RESTRICTED_MESSAGE = "This site is in a category Pax always blocks, so it can't be allowed."
CLEANBROWSING_FAMILY_DOH = "https://doh.cleanbrowsing.org/doh/family-filter/"
# Block-page addresses some filtering resolvers answer with (none seen from
# CleanBrowsing Family, which answers NXDOMAIN).
BLOCK_PAGE_IPS = frozenset({"0.0.0.0", "::", "146.112.61.104", "146.112.61.105", "146.112.61.106",
                            "146.112.61.107", "146.112.61.108", "146.112.61.110"})

_DATA = """
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
"""


class RestrictedSite(Exception):
    """An exception request for a site Pax always blocks."""

    code = RESTRICTED_CODE

    def __init__(self, domain: str = "", reason: str = ""):
        super().__init__(RESTRICTED_MESSAGE)
        self.message = RESTRICTED_MESSAGE
        self.domain = domain
        self.reason = reason        # internal only (logs), never shown


# ------------------------------------------------------------------ the data
def decode_blob(blob: str) -> dict:
    return json.loads(gzip.decompress(base64.b64decode("".join(blob.split()))).decode("utf-8"))


def encode_blob(data: dict) -> str:
    raw = gzip.compress(json.dumps(data, sort_keys=True, separators=(",", ":")).encode(), 9, mtime=0)
    b64 = base64.b64encode(raw).decode()
    return "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))


@lru_cache(maxsize=1)
def data() -> dict:
    return decode_blob(_DATA)


def keywords() -> list[str]:
    return list(data()["keywords"])


def keyword_allow_words() -> list[str]:
    return list(data()["keyword_allow_words"])


def restricted_tlds() -> frozenset:
    return frozenset(data()["tlds"])


def hand_list() -> list[str]:
    return list(data()["hand_list"])


def ios_fallback_sites() -> list[str]:
    return list(data()["ios_fallback_sites"])


def samples() -> list[str]:
    return list(data()["samples"])


def source(key: str) -> str:
    return data()["sources"][key]


def homepage_patterns() -> dict:
    """v0.8.19: the homepage check's patterns (lists/loop/homepage.py)."""
    return dict(data()["homepage"])


# ------------------------------------------------------------------ the rules
def suffixes(name: str) -> list[str]:
    """www.a.example.com -> [www.a.example.com, a.example.com, example.com, com]."""
    labels = name.strip(".").lower().split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


class EdgeRule:
    """A word at a label edge: the start or end of a label, or next to "-" or a
    digit. `exact` words match a whole label only. `labels="first"` looks at the
    first label (the new-registration rule); `labels="all"` at every label but
    the last (the media-converter rule)."""

    def __init__(self, words: Iterable[str], allow_words: Iterable[str] = (),
                 exact: Iterable[str] = (), labels: str = "first"):
        words = [w for w in (x.strip().lower() for x in words) if w]
        kw = "|".join(map(re.escape, words)) or "(?!)"
        self._re = re.compile(rf"(?:^|[-0-9])(?:{kw})|(?:{kw})(?:$|[-0-9])")
        allow = sorted((w.strip().lower() for w in allow_words if w.strip()), key=len, reverse=True)
        self._allow = re.compile("|".join(map(re.escape, allow))) if allow else None
        self._exact = frozenset(w.strip().lower() for w in exact if w.strip())
        self.labels = labels

    def label_hit(self, label: str) -> bool:
        if label.startswith("xn--"):
            return False
        if label in self._exact:
            return True
        if self._allow:
            label = self._allow.sub("~", label)
        return bool(self._re.search(label))

    def match(self, name: str) -> bool:
        labels = name.strip(".").lower().split(".")
        if self.labels == "first":
            return self.label_hit(labels[0])
        return any(self.label_hit(lab) for lab in labels[:-1])


def name_rule() -> EdgeRule:
    """The new-registration keyword rule (first label, allow words skipped)."""
    return EdgeRule(keywords(), keyword_allow_words(), labels="first")


# Second-level labels under which the site's own name sits one label further
# left (example.co.uk, example.com.br). A small table instead of the full
# public suffix list: it only decides which label the name rules read.
_SECOND_LEVEL = frozenset({"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or", "go", "gob",
                           "nic", "ltd", "plc", "sch", "mil", "info", "biz", "nom", "gen", "firm",
                           "web", "ind", "in"})


def registrable_label(name: str) -> Optional[str]:
    """The label a site is registered under: www.example.co.uk -> "example".
    None for a single-label name."""
    labels = name.strip(".").lower().split(".")
    if len(labels) < 2 or not all(labels):
        return None
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return labels[-3]
    return labels[-2]


def _excluded(name: str, exclude: frozenset) -> bool:
    return any(s in exclude for s in suffixes(name))


class LookupRule:
    """v0.8.18: the restricted-content name rule applied to every lookup (not
    only new registrations). It reads the registrable label only (so a
    subdomain such as a CDN hash or a telemetry host is never judged by its
    own labels), counts a word only at the start or end of the label or next
    to "-" (not next to a digit, which random hashes hit), skips the allow
    words, and never matches a name in or under `exclude`. Tuned on the
    Tranco and Umbrella top 1M (2026-10-17): see docs/FILTER_LISTS.md."""

    def __init__(self, words: Iterable[str], allow_words: Iterable[str] = (), exclude: Iterable[str] = ()):
        words = [w for w in (x.strip().lower() for x in words) if w]
        kw = "|".join(map(re.escape, words)) or "(?!)"
        self._re = re.compile(rf"(?:^|-)(?:{kw})|(?:{kw})(?:$|-)")
        allow = sorted((w.strip().lower() for w in allow_words if w.strip()), key=len, reverse=True)
        self._allow = re.compile("|".join(map(re.escape, allow))) if allow else None
        self._exclude = frozenset(e.strip(".").lower() for e in exclude if e.strip("."))

    def label_hit(self, label: Optional[str]) -> bool:
        if not label or label.startswith("xn--"):
            return False
        if self._allow:
            label = self._allow.sub("~", label)
        return bool(self._re.search(label))

    def match(self, name: str) -> bool:
        name = name.strip(".").lower()
        if not name or _excluded(name, self._exclude):
            return False
        return self.label_hit(registrable_label(name))


class BypassNameRule:
    """v0.8.18: web proxies and proxy-list sites by name. A hit is a
    registrable label that contains one of `contains` or equals one of
    `labels`; names in or under `exclude` never match. Not restricted: an
    exception can free a hit, like the rest of the bypass category."""

    def __init__(self, contains: Iterable[str] = (), labels: Iterable[str] = (), exclude: Iterable[str] = ()):
        self._contains = tuple(w.strip().lower() for w in contains if w.strip())
        self._labels = frozenset(w.strip().lower() for w in labels if w.strip())
        self._exclude = frozenset(e.strip(".").lower() for e in exclude if e.strip("."))

    def match(self, name: str) -> bool:
        name = name.strip(".").lower()
        if not name or _excluded(name, self._exclude):
            return False
        label = registrable_label(name)
        if not label or label.startswith("xn--"):
            return False
        return label in self._labels or any(w in label for w in self._contains)


def lookup_rule() -> LookupRule:
    d = data().get("lookup_rule") or {}
    return LookupRule(d.get("words", ()), d.get("allow_words", ()), d.get("exclude", ()))


def bypass_name_rule() -> BypassNameRule:
    d = data().get("bypass_rule") or {}
    return BypassNameRule(d.get("contains", ()), d.get("labels", ()), d.get("exclude", ()))


def parse_rule_file(text: str) -> EdgeRule:
    """A media-converter rule file: one word per line, "=word" for a whole label."""
    words, exact = [], []
    for line in text.splitlines():
        s = line.strip().lower()
        if not s or s.startswith("#"):
            continue
        (exact if s.startswith("=") else words).append(s.lstrip("="))
    return EdgeRule(words, exact=exact, labels="all")


def parse_domain_file(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip().lower().rstrip(".")
        if s and "." in s and " " not in s:
            out.append(s)
    return out


# ----------------------------------------------------------------- checking
class RestrictedCheck:
    """Static checks (no network): the single-label TLDs, the hand list, the
    name rule on the site and every parent, plus whatever extra sets and rules
    the caller has (pax-guard's restricted lists, the media converters).

    `sets`: objects with `match(name)` returning a truthy hit, or containers
    of names (suffix-checked). `rules`: objects with `match(name) -> bool`."""

    def __init__(self, sets: Iterable = (), rules: Iterable = (), use_builtin: bool = True):
        self.sets = list(sets)
        self.rules = list(rules)
        self.use_builtin = use_builtin
        self._hand = frozenset(hand_list()) if use_builtin else frozenset()
        self._tlds = restricted_tlds() if use_builtin else frozenset()
        self._name_rule = name_rule() if use_builtin else None
        self._lookup_rule = lookup_rule() if use_builtin else None

    def reason(self, name: str) -> Optional[str]:
        name = name.strip(".").lower()
        if not name:
            return None
        sfx = suffixes(name)
        if sfx[-1] in self._tlds:
            return "tld"
        for s in sfx:
            if s in self._hand:
                return "hand-list"
            if self._name_rule is not None and "." in s and self._name_rule.match(s):
                return "name-rule"
        if self._lookup_rule is not None and self._lookup_rule.match(name):
            return "name-rule"
        for st in self.sets:
            m = getattr(st, "match", None)
            if m is not None:
                if m(name):
                    return "list"
            elif any(s in st for s in sfx):
                return "list"
        for r in self.rules:
            if r.match(name):
                return "rule"
        return None

    def __call__(self, name: str) -> bool:
        return self.reason(name) is not None


# ------------------------------------------------------- the upstream check
QTYPE_A, QTYPE_AAAA = 1, 28
RCODE_NOERROR, RCODE_NXDOMAIN = 0, 3


def build_query(name: str, qtype: int = QTYPE_A, qid: Optional[int] = None) -> bytes:
    qid = random.getrandbits(16) if qid is None else qid
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for lab in name.strip(".").split("."):
        b = lab.encode("idna") if lab else b""
        q += bytes([len(b)]) + b
    return q + b"\x00" + struct.pack("!HH", qtype, 1)


def _skip_name(msg: bytes, pos: int) -> int:
    while True:
        n = msg[pos]
        if n == 0:
            return pos + 1
        if n & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + n


def answer_addresses(msg: bytes) -> tuple[int, list[str]]:
    """(rcode, [A/AAAA addresses]) of a DNS response."""
    import socket
    if len(msg) < 12:
        raise ValueError("short answer")
    _id, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    pos = 12
    for _ in range(qd):
        pos = _skip_name(msg, pos) + 4
    out = []
    for _ in range(an):
        pos = _skip_name(msg, pos)
        rtype, _rc, _ttl, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
        pos += 10
        rdata = msg[pos:pos + rdlen]
        pos += rdlen
        if rtype == QTYPE_A and rdlen == 4:
            out.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == QTYPE_AAAA and rdlen == 16:
            out.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return flags & 0xF, out


def doh_lookup(url: str = CLEANBROWSING_FAMILY_DOH, timeout: float = 5.0) -> Callable[[bytes], bytes]:
    """A `lookup(wire) -> wire` that POSTs RFC 8484 DNS messages to `url`."""
    def lookup(wire: bytes) -> bytes:
        req = urllib.request.Request(url, data=wire, method="POST", headers={
            "Content-Type": "application/dns-message", "Accept": "application/dns-message",
            "User-Agent": "pax/0.8.22"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https URL)
            return r.read()
    return lookup


def upstream_blocked(name: str, lookup: Callable[[bytes], bytes]) -> tuple[bool, str]:
    """(blocked, why) for `name` according to the filtering resolver behind
    `lookup`. Fail closed: any error, SERVFAIL or REFUSED counts as blocked."""
    try:
        rcode, addrs = answer_addresses(lookup(build_query(name, QTYPE_A)))
    except Exception as exc:  # noqa: BLE001 - fail closed
        return True, f"lookup failed ({type(exc).__name__})"
    if rcode == RCODE_NXDOMAIN:
        return True, "nxdomain"
    if rcode != RCODE_NOERROR:
        return True, f"rcode {rcode}"
    if any(a in BLOCK_PAGE_IPS for a in addrs):
        return True, "block address"
    return False, "open"


def fake_lookup(blocked: Iterable[str] = (), failing: Iterable[str] = (),
                address: str = "93.184.216.34") -> Callable[[bytes], bytes]:
    """For tests: a `lookup(wire)` that answers NXDOMAIN (the way CleanBrowsing
    blocks) for names in or under `blocked`, raises OSError for names in or
    under `failing`, and otherwise answers one A record."""
    import socket
    blocked, failing = set(blocked), set(failing)

    def lookup(wire: bytes) -> bytes:
        labels, pos = [], 12
        while wire[pos]:
            n = wire[pos]
            labels.append(wire[pos + 1:pos + 1 + n].decode())
            pos += 1 + n
        qend = pos + 5
        name = ".".join(labels).lower()
        sfx = set(suffixes(name))
        if sfx & failing:
            raise OSError("upstream unreachable")
        qid = wire[:2]
        if sfx & blocked:
            return qid + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0) + wire[12:qend]
        rr = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_A, 1, 60, 4) + socket.inet_aton(address)
        return qid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + wire[12:qend] + rr
    return lookup


def check_exception(name: str, static: Optional[RestrictedCheck] = None,
                    lookup: Optional[Callable[[bytes], bytes]] = None) -> None:
    """Raise RestrictedSite unless an exception for `name` may be requested:
    not restricted by the static checks, and not blocked by the upstream filter
    (when `lookup` is given; a failed lookup refuses)."""
    static = static if static is not None else RestrictedCheck()
    why = static.reason(name)
    if why:
        raise RestrictedSite(name, why)
    if lookup is not None:
        blocked, why = upstream_blocked(name, lookup)
        if blocked:
            raise RestrictedSite(name, f"upstream: {why}")


def _main(argv: list[str]) -> int:
    if argv[:1] == ["--dump"]:
        print(json.dumps(data(), indent=1, sort_keys=True))
        return 0
    if len(argv) == 2 and argv[0] == "--encode":
        print(encode_blob(json.loads(Path(argv[1]).read_text())))
        return 0
    if argv[:1] == ["--sample"]:
        print("\n".join(samples()[:1] + ["restricted-check.paxpeace.com"]))
        return 0
    if len(argv) == 2 and argv[0] == "--source":
        print(source(argv[1]))
        return 0
    print("usage: pax_restricted.py --dump | --encode FILE | --sample | --source KEY", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
