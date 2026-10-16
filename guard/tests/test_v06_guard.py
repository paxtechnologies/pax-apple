# SPDX-License-Identifier: GPL-3.0-only
"""v0.6 pax-guard: X stays readable, its image and video servers are blocked.
v0.8.13: X and Bluesky media are always blocked (no switch, no exception)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import guard_config as gc  # noqa: E402
from test_guard import ad_list, make_guard, remote  # noqa: E402

CFG_URL = "https://pax.example.org/v1/guard/config"


def test_x_media_blocked_but_x_itself_reachable(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls[CFG_URL] = remote(blocked=[])
    s.urls[gc.ADS_LIST_URL] = ad_list()
    s.profiles_out = "attribute: profileIdentifier: org.paxpeace.pax.macos-selflock.abc"
    g.cycle()
    hosts = s.files[gc.HOSTS_PATH]
    for name in ("pbs.twimg.com", "video.twimg.com", "ton.twimg.com"):
        assert f"0.0.0.0 {name}" in hosts
    for name in ("x.com", "twitter.com", "abs.twimg.com", "api.x.com"):
        assert f"0.0.0.0 {name}\n" not in hosts + "\n"


def test_x_media_never_freed_by_an_exception_v0813(tmp_path):
    # v0.8.13: X and Bluesky media are always blocked; an exception doesn't free them
    # (before 0.8.13 a waited exception did).
    g, s = make_guard(tmp_path)
    s.urls[CFG_URL] = remote(blocked=[], allowed=["pbs.twimg.com", "twimg.com", "bsky.app"])
    s.urls[gc.ADS_LIST_URL] = ad_list()
    s.profiles_out = "attribute: profileIdentifier: org.paxpeace.pax.macos-selflock.abc"
    g.cycle()
    hosts = s.files[gc.HOSTS_PATH]
    for name in gc.ALWAYS_BLOCKED_MEDIA_NAMES:
        assert f"0.0.0.0 {name}" in hosts


def test_pax_dns_additions_list_x_media():
    add = (HERE.parents[1] / "pax-dns" / "lists" / "pax-additions.txt").read_text()
    lines = [l.strip() for l in add.splitlines() if l.strip() and not l.startswith("#")]
    assert {"pbs.twimg.com", "video.twimg.com", "ton.twimg.com"} <= set(lines)


def test_old_x_media_off_set_up_is_forced_on_v0813(tmp_path):
    # v0.8.13 migration: a Mac set up with "X images and video" off blocks them after updating.
    import json
    import pax_guard as pg
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"server_url": "https://pax.example.org/", "x_media_default": False,
                                    "bluesky_media_default": False}))
    cfg = pg.GuardConfig.load(cfg_path)
    assert cfg.media_forced_on is True and not hasattr(pg.GuardConfig(), "x_media_default")
    assert pg.GuardConfig().media_forced_on is False
    g, s = make_guard(tmp_path / "g")
    g.cfg = cfg
    g.cfg.profile_identifier = "org.paxpeace.pax.macos-selflock.abc"
    s.urls[CFG_URL] = remote(blocked=[])
    s.urls[gc.ADS_LIST_URL] = ad_list()
    s.profiles_out = "attribute: profileIdentifier: org.paxpeace.pax.macos-selflock.abc"
    g.cycle()
    hosts = s.files[gc.HOSTS_PATH]
    for name in gc.ALWAYS_BLOCKED_MEDIA_NAMES:
        assert f"0.0.0.0 {name}" in hosts


# ------------------------------------------------ v0.7.0 Bluesky media
BSKY = ["cdn.bsky.app", "video.bsky.app", "video.cdn.bsky.app", "gifs.bsky.app"]


def test_bluesky_media_list_is_exactly_the_maintainers():
    assert gc.BLUESKY_MEDIA_NAMES == BSKY


def test_bluesky_media_blocked_but_text_site_reachable(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls[CFG_URL] = remote(blocked=[])
    s.urls[gc.ADS_LIST_URL] = ad_list()
    s.profiles_out = "attribute: profileIdentifier: org.paxpeace.pax.macos-selflock.abc"
    g.cycle()
    hosts = s.files[gc.HOSTS_PATH]
    for name in BSKY:
        assert f"0.0.0.0 {name}" in hosts
    for name in ("bsky.app", "www.bsky.app", "bsky.social", "public.api.bsky.app"):
        assert f"0.0.0.0 {name}\n" not in hosts + "\n"


def test_pax_dns_additions_list_bluesky_media():
    lines = [l.strip() for l in (HERE.parent.parent / "pax-dns" / "lists" / "pax-additions.txt").read_text().splitlines()]
    assert set(BSKY) <= set(lines)
    assert "bsky.app" not in lines
