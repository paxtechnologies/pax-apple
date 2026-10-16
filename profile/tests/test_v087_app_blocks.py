# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.7: the user's own blocked iPhone apps go into blockedAppBundleIDs (set-up
only), checked: Apple's own apps and password managers are never blocked, at most
200 of the user's own (Pax's own list doesn't count), typos refused."""
import json
import plistlib
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import app_blocks  # noqa: E402
import make_profile as mp  # noqa: E402


def apps_in(gp):
    p = next(x for x in gp.profile["PayloadContent"] if x["PayloadType"] == "com.apple.applicationaccess")
    return p["blockedAppBundleIDs"]


def test_chosen_apps_join_paxs_own():
    gp = mp.build_profile(mp.ProfileOptions(custom_app_blocks=["com.example.game", "com.example.chat"]))
    apps = apps_in(gp)
    assert "com.example.game" in apps and "com.example.chat" in apps
    assert "com.nordvpn.NordVPN" in apps and "com.openai.chat" in apps
    assert len(apps) == len(set(apps))


@pytest.mark.parametrize("bid", ["com.apple.Preferences", "com.apple.mobilephone", "com.8bit.bitwarden",
                                 "com.1password.1password", "org.paxpeace.pax"])
def test_never_blocked(bid):
    with pytest.raises(mp.AppBlockProfileError) as e:
        mp.build_profile(mp.ProfileOptions(custom_app_blocks=[bid]))
    assert e.value.code == "PAX-PROFILE-004"


@pytest.mark.parametrize("bid", ["not a bundle", "example", "com..x", "D4D2433BGC", ""])
def test_typos_refused(bid):
    with pytest.raises(mp.ProfileError):
        mp.build_profile(mp.ProfileOptions(custom_app_blocks=[bid]))


def test_cap_counts_only_the_users_own():
    own = [f"com.example.a{i}" for i in range(app_blocks.MAX_CUSTOM_APP_BLOCKS)]
    gp = mp.build_profile(mp.ProfileOptions(custom_app_blocks=own + app_blocks.pax_blocked_ids()))
    assert len(apps_in(gp)) >= app_blocks.MAX_CUSTOM_APP_BLOCKS
    with pytest.raises(mp.AppBlockProfileError):
        mp.build_profile(mp.ProfileOptions(custom_app_blocks=own + ["com.example.one-more"]))


def test_bypass_app_chosen_with_defaults_off_is_kept():
    gp = mp.build_profile(mp.ProfileOptions(include_default_app_blocks=False,
                                            custom_app_blocks=["com.nordvpn.NordVPN"]))
    assert "com.nordvpn.NordVPN" in apps_in(gp)


def test_cli_prints_the_app_code(tmp_path, capsys):
    rc = mp.main(["--out", str(tmp_path / "p"), "--escrow-out", str(tmp_path / "e"),
                  "--block-app", "com.apple.Preferences"])
    assert rc == 2
    assert "PAX-PROFILE-004" in capsys.readouterr().err
    rc = mp.main(["--out", str(tmp_path / "p"), "--escrow-out", str(tmp_path / "e"),
                  "--block-app", "com.example.game"])
    assert rc == 0
    prof = plistlib.loads((tmp_path / "p").read_bytes())
    assert "com.example.game" in apps_in(type("G", (), {"profile": prof}))
    assert json.loads((tmp_path / "e").read_text())


def test_picker_rows():
    rows = app_blocks.app_rows({
        "b": {"CFBundleIdentifier": "com.example.b", "CFBundleName": "beta"},
        "a": {"CFBundleIdentifier": "com.example.a", "CFBundleDisplayName": "Alpha", "CFBundleShortVersionString": "1"},
        "k": {"CFBundleIdentifier": "com.example.k", "CFBundleDisplayName": "KeePass Touch"},
        "x": "garbage",
    })
    assert [r["name"] for r in rows] == ["Alpha", "beta", "KeePass Touch", "x"]
    assert rows[2]["can_block"] is False and rows[2]["why_not"] == "a password manager"
    assert rows[0]["version"] == "1"
