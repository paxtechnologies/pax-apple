# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.13 (replaces the v0.8.12 "Safer social media" tests): pictures and video on
X and Bluesky are always blocked on a Mac, whatever the set-up said or the server
sends. pax-guard no longer reports them as settings, settings.set refuses to turn
them off (PAX-DNS-016) and changes nothing else in that request, and YouTube
Restricted Mode still switches at once both ways."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import guard_config as gc  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402


def test_settings_no_longer_report_x_or_bluesky(tmp_path):
    g, _ = local_guard(tmp_path)
    view = g.handle_request({"cmd": "settings.get"}, 501)["settings"]
    assert "x_media" not in view and "bluesky_media" not in view
    assert view["youtube_restricted"] is True
    assert g.x_media_blocked is True and g.bluesky_media_blocked is True


def test_settings_set_refuses_turning_x_or_bluesky_off(tmp_path):
    g, _ = local_guard(tmp_path)
    for req in ({"x_media": False}, {"bluesky_media": False},
                {"youtube_restricted": False, "x_media": False}):
        r = g.handle_request({"cmd": "settings.set", **req}, 501)
        assert r["ok"] is False and r["code"] == "PAX-DNS-016", req
    # Refused as a whole: YouTube didn't change either.
    assert g.youtube_restricted is True
    assert g.x_media_blocked is True and g.bluesky_media_blocked is True
    # YouTube on its own still switches at once.
    r = g.handle_request({"cmd": "settings.set", "youtube_restricted": False}, 501)
    assert r["ok"] and r["settings"]["youtube_restricted"] is False


def test_server_value_cannot_turn_media_off(tmp_path):
    g, _ = local_guard(tmp_path)
    g.remote = {"x_media": False, "bluesky_media": False}
    assert g.x_media_blocked is True and g.bluesky_media_blocked is True
    pol = g.forwarder_policy()
    for name in gc.ALWAYS_BLOCKED_MEDIA_NAMES:
        assert name in pol.restricted


def test_media_survive_an_exception_in_the_forwarder(tmp_path):
    g, _ = local_guard(tmp_path)
    g.remote = {"blocked": [], "allowed": ["twimg.com", "pbs.twimg.com", "bsky.app"]}
    import dns_forwarder as dnsf
    f = dnsf.Forwarder([], policy=g.forwarder_policy(), log=lambda m: None)
    for name in gc.ALWAYS_BLOCKED_MEDIA_NAMES:
        assert f.decide(name)[0] == "block", name
    assert f.decide("bsky.app")[0] == "forward"


def test_always_blocked_list_is_x_plus_bluesky():
    assert gc.ALWAYS_BLOCKED_MEDIA_NAMES == gc.X_MEDIA_NAMES + gc.BLUESKY_MEDIA_NAMES
    assert "x.com" not in gc.ALWAYS_BLOCKED_MEDIA_NAMES and "bsky.app" not in gc.ALWAYS_BLOCKED_MEDIA_NAMES
