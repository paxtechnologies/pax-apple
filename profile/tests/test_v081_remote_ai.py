# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1 (project decision, 2026-10-15): remote AI browsers (ChatGPT, Manus).

iPhone/iPad: the domains are always in the web filter (WebKit only), the apps
are always in blockedAppBundleIDs (supervised), and the total stays within
Apple's 500. Mac: the domains are in every managed browser's block list, and
Chrome's URLBlocklist stays under its 1000-entry limit at the custom maximum."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_profile as mp  # noqa: E402
import mac_policies as mpol  # noqa: E402
import pax_restricted as pr  # noqa: E402
import remote_ai_browsers as rai  # noqa: E402
from test_mac_self_lock import CHROMIUMS, browser, build  # noqa: E402


def payload(gp, ptype):
    return next(p for p in gp.profile["PayloadContent"] if p["PayloadType"] == ptype)


def test_ios_lists():
    assert rai.IOS_REMOTE_AI_HOSTS == ["chatgpt.com", "chat.openai.com", "ios.chat.openai.com",
                                       "android.chat.openai.com", "desktop.chat.openai.com",
                                       "oaiusercontent.com", "oaistatic.com", "manus.im"]
    assert "openai.com" not in rai.IOS_REMOTE_AI_HOSTS
    assert "com.openai.chat" in rai.IOS_REMOTE_AI_APP_BUNDLE_IDS
    assert len(mp.IOS_REMOTE_AI_URLS) == 8


def test_ios_profile_blocks_the_app_and_the_domains_within_500():
    custom = [f"site{i}.example" for i in range(mp.MAX_CUSTOM_DENYLIST_URLS)]
    gp = mp.build_profile(mp.ProfileOptions(custom_url_blocks=custom, include_fallback_denylist=True))
    deny = payload(gp, "com.apple.webcontent-filter")["DenyListURLs"]
    assert len(deny) == mp.MAX_DENYLIST_URLS == 500
    assert set(mp.IOS_REMOTE_AI_URLS) <= set(deny)
    assert "https://openai.com" not in deny
    r = payload(gp, "com.apple.applicationaccess")
    assert "com.openai.chat" in r["blockedAppBundleIDs"] and "com.openai.chat" in r["blacklistedAppBundleIDs"]
    mp.validate_profile(gp.profile, platform="ios")


def test_ios_app_block_survives_custom_and_no_defaults():
    gp = mp.build_profile(mp.ProfileOptions(include_default_app_blocks=False, custom_app_blocks=["com.example.x"]))
    apps = payload(gp, "com.apple.applicationaccess")["blockedAppBundleIDs"]
    assert apps[0] == "com.example.x" and "com.openai.chat" in apps
    assert len(apps) == len(set(apps))


def test_permitted_urls_refuse_remote_ai():
    lookup = pr.fake_lookup()
    for url in ("https://chatgpt.com", "https://chat.openai.com/c/1", "https://files.oaiusercontent.com",
                "https://manus.im"):
        with pytest.raises(mp.ProfileError) as e:
            mp.build_profile(mp.ProfileOptions(permitted_urls=[url], upstream_lookup=lookup))
        assert "PAX-DNS-010" in str(e.value), url
    ok = mp.build_profile(mp.ProfileOptions(permitted_urls=["https://platform.openai.com/docs"],
                                            upstream_lookup=lookup))
    assert payload(ok, "com.apple.webcontent-filter")["PermittedURLs"] == ["https://platform.openai.com/docs"]


def test_mac_browsers_block_remote_ai():
    gp = build()
    for d in CHROMIUMS:
        bl = browser(gp, d)["URLBlocklist"]
        assert "chatgpt.com" in bl and "chat.openai.com" in bl and "manus.im" in bl
        assert "openai.com" not in bl
    wf = browser(gp, mpol.FIREFOX_DOMAIN)["WebsiteFilter"]["Block"]
    assert "*://chatgpt.com/*" in wf and "*://*.oaiusercontent.com/*" in wf


def test_chrome_url_blocklist_fits_with_max_custom_and_bypass():
    hosts = mpol.bypass_hosts()
    assert 200 <= len(hosts) <= 400                       # ~260 always-on bypass entries
    custom = [f"https://site{i}.example" for i in range(mp.MAX_DENYLIST_URLS)]
    gp = build(custom_url_blocks=custom)
    for d in CHROMIUMS:
        bl = browser(gp, d)["URLBlocklist"]
        assert len(bl) <= mpol.CHROME_URL_BLOCKLIST_MAX == 1000
        assert "site499.example" in bl and hosts[-1] in bl and "chatgpt.com" in bl


def test_chrome_url_blocklist_over_limit_is_refused():
    with pytest.raises(ValueError):
        mpol.chromium_policies(browser="chrome", doh_url=None, adblock=False,
                               custom_hosts=[f"s{i}.example" for i in range(1001)])


def test_remote_ai_hosts_fallback(tmp_path):
    assert mpol.remote_ai_hosts([tmp_path]) == rai.IOS_REMOTE_AI_HOSTS
