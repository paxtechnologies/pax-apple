# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1: the iPhone/iPad web filter carries the top 60 media converters and
mirrors, stays within Apple's 500, and never permits a site Pax always blocks."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import make_profile as mp  # noqa: E402
import pax_restricted as pr  # noqa: E402  (make_profile put common/ on the path)


def webfilter(gp):
    return next(p for p in gp.profile["PayloadContent"] if p["PayloadType"] == "com.apple.webcontent-filter")


def test_ios_profile_has_converters_and_mirrors_within_500():
    gp = mp.build_profile(mp.ProfileOptions(include_fallback_denylist=True))
    deny = webfilter(gp)["DenyListURLs"]
    assert len(mp.IOS_CONVERTER_URLS) == 60 and len(set(mp.IOS_CONVERTER_URLS)) == 60
    for u in ("https://savefrom.net", "https://ssstik.io", "https://snaptik.app", "https://fxtwitter.com",
              "https://vxtwitter.com", "https://fixupx.com", "https://bskx.app", "https://rxddit.com"):
        assert u in deny, u
    assert len(deny) <= mp.MAX_DENYLIST_URLS
    mp.validate_profile(gp.profile, platform="ios")


def test_permitted_urls_are_checked_and_restricted_ones_refused():
    lookup = pr.fake_lookup(blocked=["blocked-upstream.com"], failing=["down-upstream.com"])
    ok = mp.build_profile(mp.ProfileOptions(permitted_urls=["https://school.example/maths"],
                                            upstream_lookup=lookup))
    assert webfilter(ok)["PermittedURLs"] == ["https://school.example/maths"]
    for url in (f"https://{pr.samples()[0]}", "https://reddit.com/r/x", "https://ssstik.io",
                f"https://site.{sorted(pr.restricted_tlds())[0]}", "https://blocked-upstream.com",
                "https://down-upstream.com"):
        with pytest.raises(mp.ProfileError) as e:
            mp.build_profile(mp.ProfileOptions(permitted_urls=[url], upstream_lookup=lookup))
        assert "PAX-DNS-010" in str(e.value), url


def test_core_filter_name_is_neutral():
    assert set(mp.FILTERS) == {"family", "core"}
