# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1: sites Pax always blocks can't get an exception on the iPhone/iPad
path either.

An exception request is refused (HTTP 422, `restricted_site`, support code
PAX-DNS-010) before any wait starts or any email goes out when the site or a
parent is restricted content (common/pax_restricted.py), a media converter
(pax-dns/lists/media-converters.txt and its name rule), a remote AI browser
(pax-dns/lists/remote-ai-browsers.txt: ChatGPT, Manus), X's or Bluesky's media
servers (v0.8.13), or blocked by
CleanBrowsing Family itself. That last check is a DoH lookup to
`Settings.restricted_probe_url`; a lookup that fails refuses (fail closed).

v0.8.18: Pax's own filter is the default resolver path, so the check uses Pax's
own lists first (`lists_check`, the DoH resolver's loaded lists and name rules).
The outside lookup is only made when the account turned on the extra family
layer (Advanced; its lookups go through that filter, so its verdict should count
too) or when Pax's own lists can't answer (not loaded, or the filter is in its
fallback): then, as before, a failed lookup refuses.
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Callable, Optional

_REPO = Path(__file__).resolve().parents[2]
try:
    import pax_restricted as pr  # type: ignore  # deployed next to the server
except ImportError:
    sys.path.append(str(_REPO / "common"))
    import pax_restricted as pr  # type: ignore  # noqa: E402

# v0.8.13: same list as guard/guard_config.py ALWAYS_BLOCKED_MEDIA_NAMES (a test checks).
ALWAYS_BLOCKED_MEDIA_NAMES = ("pbs.twimg.com", "video.twimg.com", "ton.twimg.com",
                              "cdn.bsky.app", "video.bsky.app", "video.cdn.bsky.app", "gifs.bsky.app")

RESTRICTED_CODE = pr.RESTRICTED_CODE
RESTRICTED_MESSAGE = pr.RESTRICTED_MESSAGE

# Tests replace this with a fake `lookup(wire) -> wire`.
LOOKUP_OVERRIDE: Optional[Callable[[bytes], bytes]] = None


def _lists_dir() -> Path:
    return Path(os.environ.get("PAX_LISTS_DIR") or (_REPO / "pax-dns" / "lists"))


@lru_cache(maxsize=1)
def static_check() -> "pr.RestrictedCheck":
    d = _lists_dir()
    names, rules = set(), []
    try:
        names = set(pr.parse_domain_file((d / "media-converters.txt").read_text()))
        rules = [pr.parse_rule_file((d / "media-converter-keywords.txt").read_text())]
    except OSError:
        pass     # restricted content still checked; the upstream check still runs
    try:
        names |= set(pr.parse_domain_file((d / "remote-ai-browsers.txt").read_text()))
    except OSError:
        pass
    # v0.8.13: X's and Bluesky's media servers are always blocked; an exception for
    # one of them would never take effect, so it's refused up front too.
    names |= set(ALWAYS_BLOCKED_MEDIA_NAMES)
    return pr.RestrictedCheck(sets=[names], rules=rules)


def is_restricted(domain: str) -> bool:
    """No network: restricted content, media converters and remote AI browsers."""
    return static_check()(domain)


def check(domain: str, probe_url: str, lists_check: Optional[Callable[[str], Optional[bool]]] = None,
          family_layer: bool = False) -> None:
    """Raise pax_restricted.RestrictedSite when `domain` can't be excepted.
    `lists_check(domain)`: True = Pax's lists block it, False = they don't,
    None = Pax's filter can't answer right now (v0.8.18)."""
    verdict = None
    if lists_check is not None:
        try:
            verdict = lists_check(domain)
        except Exception:  # noqa: BLE001 - can't answer: the outside lookup decides
            verdict = None
    if verdict is True:
        raise pr.RestrictedSite(domain, "pax lists")
    if verdict is False and not family_layer:
        pr.check_exception(domain, static=static_check(), lookup=None)
        return
    lookup = LOOKUP_OVERRIDE or pr.doh_lookup(probe_url)
    pr.check_exception(domain, static=static_check(), lookup=lookup)
