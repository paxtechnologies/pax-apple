# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1 (project decision, 2026-10-15): no iPhone/iPad exception for a remote AI browser
(ChatGPT, Manus): 422 restricted_site, PAX-DNS-010, no wait. openai.com itself
can still be excepted."""
from pax_server import restricted
from test_blocklist_api import HOUR, effective, env  # noqa: F401  (fixture)
from test_v081_restricted import _ask, _refused


def test_remote_ai_is_restricted_without_network():
    for d in ("chatgpt.com", "www.chatgpt.com", "chat.openai.com", "ios.chat.openai.com",
              "files.oaiusercontent.com", "oaistatic.com", "manus.im"):
        assert restricted.is_restricted(d), d
    assert not restricted.is_restricted("openai.com")
    assert not restricted.is_restricted("platform.openai.com")


def test_exception_requests_refused(env):
    for d in ("chatgpt.com", "chat.openai.com", "android.chat.openai.com", "oaiusercontent.com", "manus.im"):
        assert _refused(_ask(env, d)), d
    view = env.client.get("/v1/blocklist", headers=env.h).json()
    assert view["pending"] == [] and view["allowed"] == []


def test_openai_docs_can_still_be_excepted(env):
    assert _ask(env, "platform.openai.com").status_code == 202
    env.clock.advance(72 * HOUR)
    assert effective(env)[1] == ["platform.openai.com"]
