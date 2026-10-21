# SPDX-License-Identifier: GPL-3.0-only
"""The locked iPhone/iPad profile, built by the same profile/make_profile.py the Mac runs
(called in-process here instead of as a script). Same choices as the Mac's default
set-up: DNS through Pax's own filter at <dns_base>/u/<token>/dns-query (with the
built-in fallback deny-list), YouTube Restricted Mode on, the removal password random and
never shown."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import paths


@dataclass
class Profile:
    data: bytes
    identifier: str
    removal_password: str

    def __repr__(self) -> str:      # never print the password
        return f"Profile(identifier={self.identifier!r}, bytes={len(self.data)})"


def generate(*, user_token: Optional[str], dns_base: Optional[str],
             blocked_sites: Optional[list[str]] = None, blocked_apps: Optional[list[str]] = None,
             youtube_restricted: bool = True) -> Profile:
    paths.add_shared_paths()
    import make_profile as mp

    resolver = mp.resolver_for(mp.DEFAULT_FILTER, None, user_token, dns_base if user_token else None)
    gp = mp.build_profile(mp.ProfileOptions(
        platform="ios",
        resolver_url=resolver,
        custom_app_blocks=list(blocked_apps or []),
        custom_url_blocks=list(blocked_sites or []),
        include_fallback_denylist=bool(user_token),   # CLI default with --user-token
        youtube_restricted=youtube_restricted,
    ))
    return Profile(gp.to_bytes(), gp.profile_identifier, gp.removal_password)
