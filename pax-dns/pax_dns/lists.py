# SPDX-License-Identifier: GPL-3.0-only
"""Category block lists (HaGeZi, OISD, Pax additions) and their parser.

Accepted line formats (one rule per line):
  example.com            plain domain (blocks it and all subdomains)
  *.example.com          wildcard (same meaning)
  0.0.0.0 example.com    hosts file (127.0.0.1 too; localhost entries skipped)
  ||example.com^         Adblock-style domain rule ($important allowed;
                         other $options and @@ exceptions are skipped)
Comments start with #, ! or ;. Invalid entries, IPs and public suffixes are
skipped, never fatal.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .domains import PUBLIC_SUFFIXES, DomainError, normalise_domain, suffixes

_FAST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}$")
_HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "::0"}
_SKIP_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
               "ip6-loopback", "0.0.0.0"}


def parse_line(line: str) -> Optional[str]:
    s = line.strip()
    if not s or s[0] in "#!;[":
        return None
    s = s.split(" #", 1)[0].split("\t#", 1)[0].strip()
    if s.startswith("@@"):
        return None
    if s.startswith("||"):
        s = s[2:]
        if "$" in s:
            s, opts = s.split("$", 1)
            if opts.strip() not in ("important", ""):
                return None
        s = s.rstrip("^|").strip()
        if "/" in s or "^" in s:
            return None
    else:
        parts = s.split()
        if len(parts) >= 2 and parts[0] in _HOSTS_IPS:
            s = parts[1]
        elif len(parts) != 1:
            return None
    s = s.lower().rstrip(".")
    if s.startswith("*."):
        s = s[2:]
    if s in _SKIP_HOSTS:
        return None
    if _FAST_RE.match(s):
        name = s
    else:
        try:
            name = normalise_domain(s)
        except DomainError:
            return None
    if name in PUBLIC_SUFFIXES or "." not in name:
        return None
    return name


def parse_lines(lines: Iterable[str]) -> set[str]:
    out = set()
    for line in lines:
        name = parse_line(line)
        if name:
            out.add(name)
    return out


def compact(domains: set[str]) -> set[str]:
    """Drop entries already covered by a parent entry (a.example.com under example.com)."""
    return {d for d in domains if not any(s in domains for s in list(suffixes(d))[1:])}


@dataclass
class CategoryList:
    """In-memory set of category-blocked domains, suffix-matched."""
    domains: frozenset = field(default_factory=frozenset)
    path: str = ""
    mtime: float = 0.0

    def __len__(self) -> int:
        return len(self.domains)

    def match(self, qname: str) -> Optional[str]:
        for s in suffixes(qname):
            if s in self.domains:
                return s
        return None

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "CategoryList":
        return cls(frozenset(parse_lines(lines)))

    @classmethod
    def load(cls, path: str) -> "CategoryList":
        with open(path, encoding="utf-8", errors="replace") as fh:
            cl = cls.from_lines(fh)
        cl.path, cl.mtime = path, os.path.getmtime(path)
        return cl

    def reload_if_changed(self) -> "CategoryList":
        if not self.path:
            return self
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return self  # keep the last good list
        if mtime == self.mtime:
            return self
        return CategoryList.load(self.path)


# v0.5: Pax's curated built-in categories, shipped in pax-dns/lists/ (and
# bundled for pax-guard on the Mac). "bypass" is always on; "remote_desktop" is
# on unless the user switched it off (after the wait). v0.8.1: "media_converters"
# (sites) and "media_converter_rule" (a name rule) are always on and, like the
# restricted-content category list, never freed by a user's exception.
# "remote_ai_browsers" (AI services that let the user control a remote computer
# or browser: ChatGPT, Manus) is the same: always on, never excepted.
LISTS_DIR = Path(__file__).resolve().parents[1] / "lists"
BUILTIN_FILES = {
    "bypass": LISTS_DIR / "cloud-pc-bypass.txt",
    "remote_desktop": LISTS_DIR / "remote-desktop.txt",
    "media_converters": LISTS_DIR / "media-converters.txt",
    "media_converter_rule": LISTS_DIR / "media-converter-keywords.txt",
    "remote_ai_browsers": LISTS_DIR / "remote-ai-browsers.txt",
}
RULE_CATEGORIES = ("media_converter_rule",)
RESTRICTED_BUILTIN = ("media_converters", "media_converter_rule", "remote_ai_browsers")


def _restricted_module():
    try:
        import pax_restricted  # type: ignore
    except ImportError:
        import sys
        sys.path.append(str(Path(__file__).resolve().parents[2] / "common"))
        import pax_restricted  # type: ignore
    return pax_restricted


@dataclass
class RuleList:
    """A name rule file (one word per line, "=word" for a whole label), matched
    at label edges like pax_restricted.EdgeRule. Same API as CategoryList."""
    rule: object = None
    path: str = ""
    mtime: float = 0.0

    def __len__(self) -> int:
        return 1 if self.rule is not None else 0

    def match(self, qname: str) -> Optional[str]:
        name = qname.lower().rstrip(".")
        return name if self.rule is not None and self.rule.match(name) else None

    @classmethod
    def load(cls, path: str) -> "RuleList":
        with open(path, encoding="utf-8", errors="replace") as fh:
            rule = _restricted_module().parse_rule_file(fh.read())
        return cls(rule, path, os.path.getmtime(path))

    def reload_if_changed(self) -> "RuleList":
        if not self.path:
            return self
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return self
        return self if mtime == self.mtime else RuleList.load(self.path)


def load_builtin(paths: dict[str, str]) -> dict:
    """{category: CategoryList | RuleList} from {category: path}; an empty path skips it."""
    return {name: (RuleList.load(path) if name in RULE_CATEGORIES else CategoryList.load(path))
            for name, path in paths.items() if path}
