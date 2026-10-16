# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1 (project decision, 2026-10-15): remote AI browsers are always blocked on the Mac.

ChatGPT's "Work" cloud browser is a remote computer the user can take over,
which goes round the filter, so the whole service is blocked (Manus too): in
the DNS forwarder, in /etc/hosts and, for the desktop apps, by quarantine like
the unmanageable browsers. Exceptions are refused (PAX-DNS-010). openai.com
itself (docs, API) is not blocked."""
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent
sys.path.insert(0, str(GUARD))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(GUARD.parent / "common"))
import dns_forwarder as dnsf  # noqa: E402
import guard_config as gc  # noqa: E402
from test_guard import make_guard, remote  # noqa: E402
from test_v081_restricted import (MESSAGE, FakeCleanBrowsing, allow, bundled_filters,  # noqa: E402,F401
                                  guard_with)

CHATGPT = ["chatgpt.com", "chat.openai.com", "ios.chat.openai.com", "android.chat.openai.com",
           "desktop.chat.openai.com", "oaiusercontent.com", "oaistatic.com"]


def test_list_has_the_service_and_not_openai_com():
    names = gc.load_curated("remote_ai_browsers")
    for n in CHATGPT + ["manus.im"]:
        assert n in names, n
    assert "openai.com" not in names and "platform.openai.com" not in names
    assert "remote_ai_browsers" in gc.RESTRICTED_CATEGORIES


def test_hosts_block_has_remote_ai_even_with_an_exception(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote(allowed=["chatgpt.com", "openai.com"])
    g.cycle()
    hosts = s.files[gc.HOSTS_PATH]
    for n in CHATGPT + ["manus.im", "www.chatgpt.com", "cdn.oaistatic.com"]:
        assert f"0.0.0.0 {n}\n" in hosts, n
    assert "0.0.0.0 openai.com\n" not in hosts and "0.0.0.0 platform.openai.com\n" not in hosts


def test_forwarder_blocks_the_service_and_subdomains(tmp_path, bundled_filters):
    g = guard_with(tmp_path, bundled_filters, FakeCleanBrowsing())
    g.remote = {"blocked": [], "allowed": ["chatgpt.com", "openai.com", "manus.im"]}
    g.forwarder.set_policy(g.forwarder_policy())
    for name in CHATGPT + ["sdmntprwestus.oaiusercontent.com", "files.oaiusercontent.com",
                           "cdn.oaistatic.com", "www.chatgpt.com", "manus.im", "api.manus.im"]:
        assert g.forwarder.decide(name)[0] == "block", name
    # openai.com (docs, API) is not Pax's to block: the exception frees it, the upstream decides.
    for name in ("openai.com", "platform.openai.com", "api.openai.com"):
        assert g.forwarder.decide(name)[0] != "block", name


def test_exceptions_for_remote_ai_are_refused(tmp_path, bundled_filters):
    g = guard_with(tmp_path, bundled_filters, FakeCleanBrowsing())
    for domain in ("chatgpt.com", "www.chatgpt.com", "chat.openai.com", "ios.chat.openai.com",
                   "files.oaiusercontent.com", "manus.im"):
        assert allow(g, domain) == {"ok": False, "code": "PAX-DNS-010", "error": MESSAGE}, domain
    assert g.blocklist.view()["pending"] == []
    # openai.com itself can still get an exception (after the wait).
    r = allow(g, "platform.openai.com")
    assert r["ok"] and r["request"]["seconds_remaining"] > 0


@pytest.mark.parametrize("folder,bid", [
    ("ChatGPT.app", "com.openai.chat"), ("Whatever.app", "com.openai.chat"), ("ChatGPT.app", None),
    ("ChatGPT Atlas.app", None), ("Manus.app", None),
])
def test_remote_ai_apps_detected(folder, bid):
    hit = gc.is_bypass_app(folder, bid)
    assert hit is not None and hit in gc.REMOTE_AI_APPS


def test_remote_ai_apps_are_always_in_the_list():
    apps = gc.all_bypass_apps(include_browsers=False, include_vms=False)
    assert all(a in apps for a in gc.REMOTE_AI_APPS)
    assert gc.is_bypass_app("ChatGPT.app", "com.openai.chat", apps) is not None


def test_chatgpt_desktop_app_is_quarantined(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote()
    s.apps = {"/Applications/ChatGPT.app": "com.openai.chat"}
    g.cycle()
    assert s.moved and s.moved[0][0] == "/Applications/ChatGPT.app"
    assert "/Applications/ChatGPT.app" not in s.apps
