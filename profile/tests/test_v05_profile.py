# SPDX-License-Identifier: GPL-3.0-only
"""v0.5 Mac profile: Pax Image Blur (Firefox local XPI, Chromium via a store ID
once one exists) and the always-on bypass list in URLBlocklist / WebsiteFilter."""
import json
import plistlib
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PROFILE_DIR = HERE.parent
sys.path.insert(0, str(PROFILE_DIR))
sys.path.insert(0, str(HERE))

import make_profile as mp  # noqa: E402
import mac_policies as mpol  # noqa: E402
from test_mac_self_lock import CHROMIUMS, browser, build  # noqa: E402

CWS_ID = "abcdefghijklmnopabcdefghijklmnop"
EDGE_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"


def test_placeholders_are_empty_until_listings_exist():
    assert mpol.BLUR_CHROME_WEBSTORE_ID == "" and mpol.BLUR_EDGE_ADDONS_ID == ""
    assert mpol.BLUR_FIREFOX_XPI_URL == "file:///Library/PaxGuard/extensions/pax-image-blur.xpi"


def test_firefox_force_installs_local_xpi_in_private_windows_too():
    ff = browser(build(image_blur=True), mpol.FIREFOX_DOMAIN)["ExtensionSettings"]
    assert ff[mpol.BLUR_FIREFOX_ID] == {"installation_mode": "force_installed",
                                        "install_url": mpol.BLUR_FIREFOX_XPI_URL,
                                        "private_browsing": True}
    assert ff["*"]["installation_mode"] == "blocked"


def test_no_chromium_blur_without_store_id():
    gp = build(image_blur=True)
    for d in CHROMIUMS:
        p = browser(gp, d)
        assert "ExtensionInstallForcelist" not in p   # v0.6.1: nothing force-installed


def test_chromium_blur_with_store_ids():
    gp = build(image_blur=True, blur_chrome_id=CWS_ID)
    for d in (mpol.CHROME_DOMAIN, mpol.BRAVE_DOMAIN, mpol.CHROMIUM_DOMAIN, mpol.EDGE_DOMAIN):
        p = browser(gp, d)
        assert f"{CWS_ID};{mpol.CHROME_UPDATE_URL}" in p["ExtensionInstallForcelist"]
        assert CWS_ID in p["ExtensionInstallAllowlist"]
        es = p["ExtensionSettings"][CWS_ID]
        assert es["installation_mode"] == "force_installed"
        assert es["blocked_permissions"] == ["proxy", "vpnProvider"]
    edge = browser(build(image_blur=True, blur_chrome_id=CWS_ID, blur_edge_id=EDGE_ID), mpol.EDGE_DOMAIN)
    assert f"{EDGE_ID};{mpol.EDGE_UPDATE_URL}" in edge["ExtensionInstallForcelist"]
    assert CWS_ID not in edge["ExtensionInstallAllowlist"]


def test_blur_off_and_bad_ids():
    gp = build(image_blur=False, blur_chrome_id=CWS_ID)
    assert mpol.BLUR_FIREFOX_ID not in browser(gp, mpol.FIREFOX_DOMAIN)["ExtensionSettings"]
    assert CWS_ID not in browser(gp, mpol.CHROME_DOMAIN)["ExtensionInstallAllowlist"]
    with pytest.raises(mp.ProfileError):
        build(image_blur=True, blur_chrome_id="not-an-id")


def test_bypass_list_in_browser_blocklists():
    gp = build()
    hosts = mpol.bypass_hosts()
    assert "sensepc.com" in hosts and "browserling.com" in hosts and len(hosts) > 40
    for d in CHROMIUMS:
        bl = browser(gp, d)["URLBlocklist"]
        assert "sensepc.com" in bl and "chrome://flags" in bl
        assert "anydesk.com" not in bl          # remote desktop is switchable: not in the profile
    wf = browser(gp, mpol.FIREFOX_DOMAIN)["WebsiteFilter"]["Block"]
    assert "*://sensepc.com/*" in wf and "*://*.sensepc.com/*" in wf
    # v0.8.1: without the bypass list, only the always-on remote AI browsers remain.
    wf_off = browser(build(block_bypass_sites=False), mpol.FIREFOX_DOMAIN)["WebsiteFilter"]["Block"]
    assert "*://chatgpt.com/*" in wf_off and "*://sensepc.com/*" not in wf_off
    assert len(browser(gp, mpol.CHROME_DOMAIN)["URLBlocklist"]) < 1000   # Chrome's documented cap


def test_bypass_hosts_missing_dir(tmp_path):
    assert mpol.bypass_hosts([tmp_path]) == []


def test_cli_blur_is_opt_in(tmp_path, monkeypatch):
    """v0.6: Pax Image Blur ('Pax Max') is off unless --image-blur."""
    out = tmp_path / "mac.mobileconfig"
    env = {"PATH": "/usr/bin:/bin", "PAX_BLUR_CHROME_ID": CWS_ID}
    r = subprocess.run([sys.executable, str(PROFILE_DIR / "make_profile.py"), "--self-lock",
                        "--out", str(out)], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["image_blur"] is False
    r = subprocess.run([sys.executable, str(PROFILE_DIR / "make_profile.py"), "--self-lock",
                        "--image-blur", "--out", str(out)], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["image_blur"] is True
    prof = plistlib.loads(out.read_bytes())
    found = [p for p in prof["PayloadContent"] if mpol.CHROME_DOMAIN in p.get("PayloadContent", {})]
    s = found[0]["PayloadContent"][mpol.CHROME_DOMAIN]["Forced"][0]["mcx_preference_settings"]
    assert f"{CWS_ID};{mpol.CHROME_UPDATE_URL}" in s["ExtensionInstallForcelist"]
    r = subprocess.run([sys.executable, str(PROFILE_DIR / "make_profile.py"), "--self-lock",
                        "--image-blur", "--no-image-blur", "--out", str(out)], capture_output=True, text=True)
    assert json.loads(r.stdout)["image_blur"] is False
