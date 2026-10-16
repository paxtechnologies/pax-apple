# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.6 YouTube Restricted Mode in the generated profiles.

iPhone/iPad: DNS goes straight to CleanBrowsing Family DoH, which forces
Restricted Mode for YouTube's names (checked 2026-10-16: www.youtube.com ->
216.239.38.119, restrictmoderate.youtube.com). Switching CleanBrowsing's filter
would loosen everything else (Adult doesn't block proxies, VPNs or mixed-content
sites), so "off" keeps the Family filter and only lets YouTube's own names skip
the encrypted DNS (Apple's per-domain OnDemandRules: EvaluateConnection +
NeverConnect). On (the default) the profile is exactly as before.

Mac self-lock with local DNS: pax-guard's switch decides, so the browser policy
no longer pins ForceYouTubeRestrict (it would override the switch)."""
import json
import plistlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import make_profile as mp  # noqa: E402

NAMES = {"youtube.com", "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
         "youtube.googleapis.com", "youtube-nocookie.com", "www.youtube-nocookie.com"}


def dns(profile):
    return next(p for p in profile["PayloadContent"] if p["PayloadType"] == "com.apple.dnsSettings.managed")


def test_iphone_default_is_unchanged():
    p = mp.build_profile(mp.ProfileOptions(platform="ios")).profile
    d = dns(p)
    assert "OnDemandRules" not in d
    assert d["DNSSettings"]["ServerURL"] == mp.CLEANBROWSING_FAMILY_DOH and d["ProhibitDisablement"] is True


def test_iphone_off_only_lets_youtube_names_skip_the_filter():
    on = mp.build_profile(mp.ProfileOptions(platform="ios", profile_uuid="A" * 8 + "-AAAA-AAAA-AAAA-" + "A" * 12,
                                            removal_password="x" * 24)).profile
    off = mp.build_profile(mp.ProfileOptions(platform="ios", youtube_restricted=False,
                                             profile_uuid="A" * 8 + "-AAAA-AAAA-AAAA-" + "A" * 12,
                                             removal_password="x" * 24)).profile
    d = dns(off)
    assert d["DNSSettings"]["ServerURL"] == mp.CLEANBROWSING_FAMILY_DOH     # still Family for everything else
    assert d["ProhibitDisablement"] is True and "AllowFailover" not in d["DNSSettings"]
    assert d["OnDemandRules"] == [{"Action": "EvaluateConnection", "ActionParameters": [
        {"Domains": sorted(NAMES, key=mp.YOUTUBE_NAMES.index), "DomainAction": "NeverConnect"}]}]
    assert set(d["OnDemandRules"][0]["ActionParameters"][0]["Domains"]) == NAMES
    # Nothing else differs: same web filter, app blocks, removal password.
    strip = lambda prof: [{k: v for k, v in x.items() if k not in ("PayloadUUID", "OnDemandRules")}  # noqa: E731
                          for x in prof["PayloadContent"]]
    assert strip(on) == strip(off)
    plistlib.loads(plistlib.dumps(off))


def test_mac_self_lock_local_dns_leaves_youtube_to_pax_guard():
    p = mp.build_profile(mp.ProfileOptions(platform="macos", self_lock=True, mac_dns="local")).profile
    chrome = [x for x in p["PayloadContent"] if x["PayloadType"] == "com.apple.ManagedClient.preferences"]
    blobs = json.dumps([x["PayloadContent"] for x in chrome], default=str)
    assert "ForceYouTubeRestrict" not in blobs
    assert "ForceGoogleSafeSearch" in blobs                       # SafeSearch stays forced


def test_mac_self_lock_profile_dns_keeps_the_policy_unless_off():
    on = mp.build_profile(mp.ProfileOptions(platform="macos", self_lock=True, mac_dns="profile")).profile
    assert '"ForceYouTubeRestrict": 2' in json.dumps([x.get("PayloadContent") for x in on["PayloadContent"]],
                                                       default=str)
    off = mp.build_profile(mp.ProfileOptions(platform="macos", self_lock=True, mac_dns="profile",
                                             youtube_restricted=False)).profile
    assert "ForceYouTubeRestrict" not in json.dumps([x.get("PayloadContent") for x in off["PayloadContent"]],
                                                     default=str)
    assert dns(off)["OnDemandRules"][0]["ActionParameters"][0]["DomainAction"] == "NeverConnect"


def test_cli_flag(tmp_path, capsys):
    out, esc = tmp_path / "p.mobileconfig", tmp_path / "e.json"
    assert mp.main(["--out", str(out), "--escrow-out", str(esc), "--no-youtube-restricted"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["youtube_restricted"] is False
    assert "OnDemandRules" in dns(plistlib.loads(out.read_bytes()))
    assert mp.main(["--out", str(out), "--escrow-out", str(esc)]) == 0
    assert json.loads(capsys.readouterr().out)["youtube_restricted"] is True
    assert "OnDemandRules" not in dns(plistlib.loads(out.read_bytes()))
