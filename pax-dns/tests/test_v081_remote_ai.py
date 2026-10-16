# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1 (project decision, 2026-10-15): remote AI browsers (ChatGPT, Manus) are always
blocked and never freed by an exception. openai.com itself is not blocked."""
from pax_dns.config import DNSSettings
from pax_dns.lists import BUILTIN_FILES, RESTRICTED_BUILTIN, load_builtin
from pax_dns.policy import Action, UserLists, decide

BUILTIN = load_builtin({k: str(v) for k, v in BUILTIN_FILES.items()})
AI = BUILTIN["remote_ai_browsers"]


def test_list_contents():
    names = set(AI.domains)
    for d in ("chatgpt.com", "chat.openai.com", "ios.chat.openai.com", "android.chat.openai.com",
              "desktop.chat.openai.com", "oaiusercontent.com", "oaistatic.com", "manus.im"):
        assert d in names, d
    assert "openai.com" not in names
    assert "remote_ai_browsers" in RESTRICTED_BUILTIN


def test_blocked_even_with_an_exception():
    user = UserLists(allow=frozenset({"chatgpt.com", "openai.com", "manus.im", "oaiusercontent.com"}))
    for q in ("chatgpt.com", "www.chatgpt.com", "chat.openai.com", "ios.chat.openai.com",
              "files.oaiusercontent.com", "cdn.oaistatic.com", "manus.im", "api.manus.im"):
        d = decide(q, user, None, BUILTIN)
        assert d.action is Action.BLOCK_CATEGORY and d.category == "remote_ai_browsers", q
        assert decide(q, None, None, BUILTIN).action is Action.BLOCK_CATEGORY, q


def test_openai_com_is_left_to_the_upstream():
    for q in ("openai.com", "platform.openai.com", "api.openai.com", "help.openai.com"):
        assert decide(q, None, None, BUILTIN).action is Action.FORWARD, q
    assert decide("platform.openai.com", UserLists(allow=frozenset({"openai.com"})), None,
                  BUILTIN).action is Action.ALLOW


def test_settings_env_override(monkeypatch, tmp_path):
    f = tmp_path / "ai.txt"
    f.write_text("example-ai.test\n")
    monkeypatch.setenv("PAX_DNS_REMOTE_AI_BROWSERS_FILE", str(f))
    paths = DNSSettings.from_env().builtin_paths()
    assert paths["remote_ai_browsers"] == str(f)
    assert load_builtin(paths)["remote_ai_browsers"].match("www.example-ai.test")
