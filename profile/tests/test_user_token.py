# SPDX-License-Identifier: GPL-3.0-only
"""v0.3: per-user pax-dns URL (--user-token) and the built-in fallback deny-list."""
import json
import plistlib
import subprocess
import sys
from pathlib import Path

import pytest

PROFILE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROFILE_DIR))

import make_profile as mp  # noqa: E402
from fallback_denylist import FALLBACK_DENYLIST_URLS  # noqa: E402

TOKEN = "Abc_def-GHIjklMNOpqrSTUvwx"  # 26 URL-safe chars


def by_type(profile):
    return {p["PayloadType"]: p for p in profile["PayloadContent"]}


def run(tmp_path, *args, env=None):
    out, esc = tmp_path / "p.mobileconfig", tmp_path / "e.json"
    proc = subprocess.run([sys.executable, str(PROFILE_DIR / "make_profile.py"), "--out", str(out),
                           "--escrow-out", str(esc), *args], capture_output=True, text=True,
                          env=env)
    return proc, out


def test_user_doh_url_default_and_custom_base(monkeypatch):
    monkeypatch.delenv("PAX_DNS_BASE", raising=False)
    assert mp.user_doh_url(TOKEN) == f"https://dns.paxpeace.com/u/{TOKEN}/dns-query"
    assert mp.user_doh_url(TOKEN, "https://dns.example.test/") == \
        f"https://dns.example.test/u/{TOKEN}/dns-query"
    assert mp.user_doh_url(TOKEN, "https://example.test/pax") == \
        f"https://example.test/pax/u/{TOKEN}/dns-query"
    monkeypatch.setenv("PAX_DNS_BASE", "https://staging-dns.example.test")
    assert mp.user_doh_url(TOKEN).startswith("https://staging-dns.example.test/u/")


@pytest.mark.parametrize("bad", ["", "short", "has space in it 1234567890", "a/b" * 10,
                                 "x" * 129, "tok%2Fen" + "a" * 20, "../" * 10])
def test_user_token_validation(bad):
    with pytest.raises(mp.ProfileError):
        mp.user_doh_url(bad)


@pytest.mark.parametrize("base", ["http://dns.example", "dns.example", "https://", "https://a.b/?x=1"])
def test_dns_base_must_be_https(base):
    with pytest.raises(mp.ProfileError):
        mp.user_doh_url(TOKEN, base)


def test_resolver_for_precedence():
    assert mp.resolver_for("core", None, TOKEN, "https://d.example") == \
        f"https://d.example/u/{TOKEN}/dns-query"
    with pytest.raises(mp.ProfileError):
        mp.resolver_for("family", "https://x.example/dns-query", TOKEN)


def test_mask_token_url():
    masked = mp.mask_token_url(f"https://dns.paxpeace.com/u/{TOKEN}/dns-query")
    assert TOKEN not in masked and masked.startswith("https://dns.paxpeace.com/u/Abc_")


def test_cli_ios_user_token(tmp_path, monkeypatch):
    proc, out = run(tmp_path, "--user-token", TOKEN, "--block-url", "mine.example")
    assert proc.returncode == 0, proc.stderr
    assert TOKEN not in proc.stdout and TOKEN not in proc.stderr
    meta = json.loads(proc.stdout)
    assert meta["per_user_dns"] is True
    profile = plistlib.loads(out.read_bytes())
    p = by_type(profile)
    assert p["com.apple.dnsSettings.managed"]["DNSSettings"]["ServerURL"] == \
        f"https://dns.paxpeace.com/u/{TOKEN}/dns-query"
    deny = p["com.apple.webcontent-filter"]["DenyListURLs"]
    assert deny[0] == "https://mine.example"           # custom blocks first
    assert set(FALLBACK_DENYLIST_URLS) <= set(deny)    # fallback kept in the profile
    assert len(deny) <= mp.MAX_DENYLIST_URLS
    mp.validate_profile(profile)


def test_cli_dns_base_flag(tmp_path):
    proc, out = run(tmp_path, "--user-token", TOKEN, "--dns-base", "https://dns.example.test")
    assert proc.returncode == 0, proc.stderr
    url = by_type(plistlib.loads(out.read_bytes()))["com.apple.dnsSettings.managed"]["DNSSettings"]
    assert url["ServerURL"] == f"https://dns.example.test/u/{TOKEN}/dns-query"


def test_cli_conflicts(tmp_path):
    assert run(tmp_path, "--user-token", TOKEN, "--filter", "core")[0].returncode == 2
    assert run(tmp_path, "--user-token", TOKEN, "--resolver-url", "https://a.b/q")[0].returncode == 2
    assert run(tmp_path, "--dns-base", "https://dns.example.test")[0].returncode == 2
    assert run(tmp_path, "--user-token", "bad token")[0].returncode == 2


def test_fallback_switches(tmp_path):
    proc, out = run(tmp_path, "--user-token", TOKEN, "--no-fallback-denylist")
    w = by_type(plistlib.loads(out.read_bytes()))["com.apple.webcontent-filter"]
    assert w["DenyListURLs"] == ([f"https://{h}" for h in mp.IOS_BUILTIN_DENY_HOSTS]   # v0.8 built-ins
                                 + mp.IOS_CONVERTER_URLS                                # + v0.8.1 converters
                                 + mp.IOS_REMOTE_AI_URLS)                               # + remote AI browsers
    proc, out = run(tmp_path, "--fallback-denylist")
    w = by_type(plistlib.loads(out.read_bytes()))["com.apple.webcontent-filter"]
    assert set(FALLBACK_DENYLIST_URLS) <= set(w["DenyListURLs"])


def test_fallback_respects_apple_limit():
    # v0.8.13: 361 custom + 11 media hosts (v0.8.1: 368 + 4) + 60 media converters + 8 remote AI
    # browsers + 60 fallback = Apple's 500.
    assert mp.MAX_CUSTOM_DENYLIST_URLS == 361
    custom = [f"site{i}.example" for i in range(mp.MAX_CUSTOM_DENYLIST_URLS)]
    gp = mp.build_profile(mp.ProfileOptions(custom_url_blocks=custom, include_fallback_denylist=True))
    deny = by_type(gp.profile)["com.apple.webcontent-filter"]["DenyListURLs"]
    assert len(deny) == mp.MAX_DENYLIST_URLS
    assert deny[:len(custom)] == [f"https://{c}" for c in custom]
    assert set(mp.IOS_CONVERTER_URLS) <= set(deny) and set(FALLBACK_DENYLIST_URLS) <= set(deny)
    assert set(mp.IOS_REMOTE_AI_URLS) <= set(deny)
    with pytest.raises(mp.ProfileError):
        mp.build_profile(mp.ProfileOptions(custom_url_blocks=custom + ["one-more.example"]))


def test_fallback_list_is_small_and_valid():
    assert 0 < len(FALLBACK_DENYLIST_URLS) <= 100
    assert len(set(FALLBACK_DENYLIST_URLS)) == len(FALLBACK_DENYLIST_URLS)
    assert all(u.startswith("https://") for u in FALLBACK_DENYLIST_URLS)


def test_macos_user_token_dns_only(tmp_path):
    proc, out = run(tmp_path, "--macos", "--user-token", TOKEN)
    assert proc.returncode == 0, proc.stderr
    profile = plistlib.loads(out.read_bytes())
    p = by_type(profile)
    assert set(p) == {"com.apple.dnsSettings.managed", "com.apple.profileRemovalPassword"}
    assert p["com.apple.dnsSettings.managed"]["DNSSettings"]["ServerURL"] == \
        f"https://dns.paxpeace.com/u/{TOKEN}/dns-query"
    mp.validate_profile(profile, platform="macos")
