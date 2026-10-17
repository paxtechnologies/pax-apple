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
H4sIAAAAAAACA61VzZKcOAx+lz6noZJMqpJ5la0UJWwBmjY2sUVDdyrvHglspnv2soc9IVnyp8/6
4/dpAG8bR4lPr/+cIlpLXJkwnj6daOznmOUXI34eXRViL6rFK4FniMV3opWulUcWeQHmCWy2QDQD
XTF0YY5h8RmAyVss4H14Uj0ufQyztykftMRmmBmzugyUJvFOg97tbgb4kWWO8P0y+4rDJKKcsgA6
5AOj+/HtHjyKgyrgk7sVC7Kjrvj1UZgVYmHE3hVL8O6mF7Mqmeupe9BsRZwl4hEtwYONODEwmadM
U9isiSMZRns2A5pLNcE6IZg97E/xDanpwLkWzKVJxJi0cFOIfpjbjLdeyWIoZFa/rkUcYEx8ZFqo
8NyWF93CrDBZU8P3LKcJ/KUF32cd1e9A4fXAH349WVThiMXaIvbvsd7ofi8IHjpHxW0MPGB0mMoD
MErmC2Up49eXSkKq4TygdCHlkvus7W34oUBPRdaOmGMLRz9o0ic9LVSD78FIsrLupIXfII1U0iO2
l8L31kXEB2cVgy31biPc7xhTKeAFb0uItpEahqVRcavgSNbKm3HdAdpItsddnoB6n4+DNNIuUkJW
MckAjCGqL67GzYmuu4OkLd8i5zYoR54MbI6TNFrSYZLPFjPNRcCVy0WMORjEkLnMaRcsFnCfTS1l
gY64KV+Xcd0F8d7DuxB3AaMWq7DQmK7ELvi6cIT3WKhkTOV6nFI2ZioPiT7mQ/t/zS/Ubkndoi27
9Yzqs91ymEwQSnI/SQz3f42X4slAC8HXk4x09T7n1fWzcpL1aDTY75NpG6GAjQ2DOA+yTNNrXYtW
GYfgW1mjiWQWpen1tAY7Oz535CRyre/P94egS/30aD5bnYePKFt/J26gccGA06DQ450aTVHFK787
zNE9cIqwVD2xZGZOGE3wLMnU59Y7QC3hzq2AXvR6qkcgXy/krIFoa0U/65TaoIb0GKk9qARK9l9E
2g9ENrt6Vt7VGU7jfCkXzIG3paP4vJuf8WyiauazgYk4yMrvYt06KM+w8h9zAeye+Up+g1V/3xaX
RfefU0S+k3GUouCeijfNj3ZPveGIFlpyKMusuX45/ZEt6fZe3qLm7Xp0s3b2zz9/AU574avPBwAA
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
            "User-Agent": "pax/0.8.17"})
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
