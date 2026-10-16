# SPDX-License-Identifier: GPL-3.0-only
"""Small built-in deny-list for Apple's web content filter (DenyListURLs).

A backstop, not the filter: DNS (CleanBrowsing or pax-dns) does the real work.
These URLs keep the most-visited restricted sites blocked in Safari and in-app
web views even if DNS filtering is bypassed or a per-user resolver is
misconfigured. Apple caps DenyListURLs at 500 entries (shared with --block-url
and the media converters), so keep it small: 30 sites, each as https://site
and https://www.site.

The site names are kept encoded in common/pax_restricted.py (copied next to
this file in Pax.app) and decoded here.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent.parent / "common"))
import pax_restricted as _pr  # noqa: E402

_SITES = _pr.ios_fallback_sites()

FALLBACK_DENYLIST_URLS: list[str] = [
    url for site in _SITES for url in (f"https://{site}", f"https://www.{site}")
]
