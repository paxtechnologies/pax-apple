# SPDX-License-Identifier: GPL-3.0-only
"""Domain validation and normalisation for the custom blocklist and allow-list.

`normalise_domain` turns what a person types ("https://Bad.Example/path",
"*.bücher.de", "bad.example.") into the registrable form Pax stores
("bad.example", "xn--bcher-kva.de"). An entry always covers the domain *and all
of its subdomains*, so a leading "*." is accepted and dropped. Everything else
that looks like a wildcard, an IP address, a bare TLD or a public suffix is
refused: an allow-list entry for "com" or "co.uk" would switch the filter off.

pax-dns ships a copy of this logic (pax-dns/pax_dns/domains.py) so it can be
deployed on its own; a test keeps the two identical.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import idna

MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

# Suffixes under which anyone can register a name. Blocking or allowing one of
# these would cover millions of unrelated sites, so they are refused. Not the
# full Public Suffix List (that would be a dependency and a moving target); the
# single-label rule below already refuses every TLD, and this covers the common
# two-label public suffixes.
PUBLIC_SUFFIXES = frozenset("""
co.uk org.uk me.uk ltd.uk plc.uk net.uk ac.uk gov.uk nhs.uk sch.uk
com.au net.au org.au edu.au gov.au id.au
co.nz org.nz net.nz govt.nz
co.jp ne.jp or.jp ac.jp go.jp
com.br net.br org.br gov.br
com.cn net.cn org.cn gov.cn
co.in net.in org.in gov.in firm.in
co.za org.za gov.za
com.mx org.mx gob.mx
co.kr or.kr go.kr
com.tr com.sg com.hk com.tw com.ar com.co com.pe com.ph com.my com.ng com.pk com.ua
com.es com.pt com.pl com.ru com.de com.fr com.it
github.io gitlab.io pages.dev vercel.app netlify.app herokuapp.com blogspot.com
web.app firebaseapp.com azurewebsites.net cloudfront.net appspot.com
workers.dev r2.dev s3.amazonaws.com
""".split())


class DomainError(ValueError):
    """The input is not a domain Pax will store."""


def normalise_domain(raw: str) -> str:
    """Return the canonical ASCII (IDNA/punycode) domain, or raise DomainError."""
    if not isinstance(raw, str):
        raise DomainError("domain must be text")
    s = raw.strip()
    if not s:
        raise DomainError("enter a website, for example example.com")
    if len(s) > 2048:
        raise DomainError("that is too long to be a website address")
    # Strip a scheme, userinfo, port, path, query and fragment.
    if _SCHEME_RE.match(s):
        parts = urlsplit(s)
        s = parts.netloc
    else:
        s = re.split(r"[/?#]", s, maxsplit=1)[0]
    s = s.rsplit("@", 1)[-1]
    if s.startswith("[") or s.count(":") > 1:
        raise DomainError("IP addresses can't be blocked by name; enter a website")
    s = s.split(":", 1)[0]
    s = s.strip().rstrip(".").lower()
    # "*.example.com" means the same as "example.com" (subdomains are always included).
    if s.startswith("*."):
        s = s[2:]
    if "*" in s:
        raise DomainError("wildcards aren't needed: example.com already covers every subdomain")
    if any(c.isspace() for c in s) or not s:
        raise DomainError("that doesn't look like a website address")
    try:
        ipaddress.ip_address(s)
    except ValueError:
        pass
    else:
        raise DomainError("IP addresses can't be blocked by name; enter a website")
    if re.fullmatch(r"[0-9.]+", s):
        raise DomainError("IP addresses can't be blocked by name; enter a website")
    try:
        ascii_name = idna.encode(s, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        # Some real hostnames have underscores or other characters IDNA 2008
        # refuses; fall back to a plain ASCII check before giving up.
        if s.isascii():
            ascii_name = s
        else:
            raise DomainError(f"that isn't a valid domain name ({exc})") from None
    ascii_name = ascii_name.lower().rstrip(".")
    if len(ascii_name) > MAX_DOMAIN_LENGTH:
        raise DomainError("domain names are at most 253 characters")
    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise DomainError("enter a full domain such as example.com, not a single word or TLD")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise DomainError(f"{label!r} isn't a valid part of a domain name")
    if labels[-1].isdigit():
        raise DomainError("that doesn't look like a website address")
    if ascii_name in PUBLIC_SUFFIXES:
        raise DomainError("that is a public suffix shared by many sites; enter a specific site")
    return ascii_name


def display_domain(ascii_name: str) -> str:
    """Unicode form for showing to people (xn--bcher-kva.de -> bücher.de)."""
    try:
        return idna.decode(ascii_name)
    except idna.IDNAError:
        return ascii_name


def suffixes(name: str):
    """'a.b.example.com' -> a.b.example.com, b.example.com, example.com, com."""
    labels = name.lower().rstrip(".").split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


def matches(name: str, domains) -> str | None:
    """The entry in `domains` that covers `name` (itself or a parent), if any."""
    for s in suffixes(name):
        if s in domains:
            return s
    return None
