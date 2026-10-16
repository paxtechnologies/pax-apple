# SPDX-License-Identifier: GPL-3.0-only
"""pax-dns settings, read from PAX_DNS_* environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass

from .lists import BUILTIN_FILES

# Verified 2026-10-12 on https://cleanbrowsing.org/filters/ (DoH rows).
# Family Filter: restricted content, proxy/VPN domains, mixed-content sites (Reddit),
# SafeSearch on Google/Bing/YouTube. DEV DEFAULT ONLY: the free tier is "for
# parents, not organizations" and throttled; production self-hosts category
# lists (HaGeZi / OISD, scripts/load_lists.py) and an unfiltered upstream.
CLEANBROWSING_FAMILY_DOH = "https://doh.cleanbrowsing.org/doh/family-filter/"
# Security Filter: malware/phishing only, no content filtering. Until v0.8.0 it
# answered names the user had allow-listed. v0.8.1: exceptions go through the
# Family Filter too (so the upstream's filtering always applies, and Pax refuses
# exceptions for anything it blocks); kept for anyone who sets it on purpose
# with PAX_DNS_ALLOW_UPSTREAM.
CLEANBROWSING_SECURITY_DOH = "https://doh.cleanbrowsing.org/doh/security-filter/"


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class DNSSettings:
    # Where everything not decided locally goes (the "category filter" upstream in
    # dev). https://... = DoH, udp://host[:port] = plain DNS.
    upstream: str = CLEANBROWSING_FAMILY_DOH
    # Where allow-listed names go (v0.8.1: the same filtered upstream by default;
    # an exception only frees Pax's own lists, never the upstream's filtering).
    allow_upstream: str = CLEANBROWSING_FAMILY_DOH
    # Merged category list (one domain per line), e.g. from scripts/load_lists.py.
    # Optional; reloaded when the file changes.
    category_file: str = ""
    # v0.5 built-in categories (Pax's curated lists, reloaded when they change).
    # Set the variable to an empty string to turn one off for this server.
    bypass_file: str = str(BUILTIN_FILES["bypass"])
    remote_desktop_file: str = str(BUILTIN_FILES["remote_desktop"])
    # v0.8.1 media converters (always on, never freed by an exception).
    media_converters_file: str = str(BUILTIN_FILES["media_converters"])
    media_converter_rule_file: str = str(BUILTIN_FILES["media_converter_rule"])
    # v0.8.1 remote AI browsers (ChatGPT, Manus): always on, never excepted.
    remote_ai_browsers_file: str = str(BUILTIN_FILES["remote_ai_browsers"])
    # "null" answers 0.0.0.0 / :: (and NODATA for other types); "nxdomain" answers NXDOMAIN.
    block_mode: str = "null"
    block_ttl: int = 60
    # Cap on TTLs of forwarded answers, so a site you block stops resolving on
    # devices within this many seconds even if they cached it.
    max_ttl: int = 300
    # Effective-list source: "sqlite:///path/to/pax.sqlite3" (shared DB, read-only),
    # "http(s)://escrow-server" (internal API, needs internal_key) or "" (none).
    source: str = ""
    internal_key: str = ""
    poll_seconds: float = 2.0
    cache_size: int = 10000
    upstream_timeout: float = 4.0
    # Serve /dns-query (no token): category filtering without custom lists.
    public_endpoint: bool = True

    @classmethod
    def from_env(cls) -> "DNSSettings":
        d = cls()
        mode = os.environ.get("PAX_DNS_BLOCK_MODE", d.block_mode).strip().lower()
        if mode not in ("null", "nxdomain"):
            raise ValueError("PAX_DNS_BLOCK_MODE must be 'null' or 'nxdomain'")
        return cls(
            upstream=os.environ.get("PAX_DNS_UPSTREAM", d.upstream),
            allow_upstream=os.environ.get("PAX_DNS_ALLOW_UPSTREAM", d.allow_upstream),
            category_file=os.environ.get("PAX_DNS_CATEGORY_FILE", d.category_file),
            bypass_file=os.environ.get("PAX_DNS_BYPASS_FILE", d.bypass_file),
            remote_desktop_file=os.environ.get("PAX_DNS_REMOTE_DESKTOP_FILE",
                                               d.remote_desktop_file),
            media_converters_file=os.environ.get("PAX_DNS_MEDIA_CONVERTERS_FILE", d.media_converters_file),
            media_converter_rule_file=os.environ.get("PAX_DNS_MEDIA_CONVERTER_RULE_FILE",
                                                     d.media_converter_rule_file),
            remote_ai_browsers_file=os.environ.get("PAX_DNS_REMOTE_AI_BROWSERS_FILE",
                                                   d.remote_ai_browsers_file),
            block_mode=mode,
            block_ttl=_int("PAX_DNS_BLOCK_TTL", d.block_ttl),
            max_ttl=_int("PAX_DNS_MAX_TTL", d.max_ttl),
            source=os.environ.get("PAX_DNS_SOURCE", d.source),
            internal_key=os.environ.get("PAX_INTERNAL_KEY", d.internal_key),
            poll_seconds=float(os.environ.get("PAX_DNS_POLL_SECONDS", d.poll_seconds)),
            cache_size=_int("PAX_DNS_CACHE_SIZE", d.cache_size),
            upstream_timeout=float(os.environ.get("PAX_DNS_UPSTREAM_TIMEOUT", d.upstream_timeout)),
            public_endpoint=_bool("PAX_DNS_PUBLIC_ENDPOINT", d.public_endpoint),
        )

    def builtin_paths(self) -> dict[str, str]:
        return {"bypass": self.bypass_file, "remote_desktop": self.remote_desktop_file,
                "media_converters": self.media_converters_file,
                "media_converter_rule": self.media_converter_rule_file,
                "remote_ai_browsers": self.remote_ai_browsers_file}
