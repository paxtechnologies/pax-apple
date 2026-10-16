# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.12: Pax Max switchable after set-up. With --image-blur-switchable the Mac
profile installs Pax Image Blur in Firefox whatever was chosen (pax-guard then
tells it whether to blur); Chromium browsers still follow --image-blur."""
import json
import plistlib
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE_DIR = HERE.parent
sys.path.insert(0, str(PROFILE_DIR))
sys.path.insert(0, str(HERE))

import mac_policies as mpol  # noqa: E402
from test_mac_self_lock import CHROMIUMS, browser, build  # noqa: E402

CWS_ID = "abcdefghijklmnopabcdefghijklmnop"


def test_switchable_installs_firefox_blur_even_when_off():
    gp = build(image_blur=False, image_blur_switchable=True, blur_chrome_id=CWS_ID)
    ff = browser(gp, mpol.FIREFOX_DOMAIN)["ExtensionSettings"]
    assert ff[mpol.BLUR_FIREFOX_ID]["installation_mode"] == "force_installed"
    for d in CHROMIUMS:                                    # Chromium has no off signal: not installed
        assert "ExtensionInstallForcelist" not in browser(gp, d)


def test_not_switchable_keeps_the_old_rule():
    ff = browser(build(image_blur=False), mpol.FIREFOX_DOMAIN)["ExtensionSettings"]
    assert mpol.BLUR_FIREFOX_ID not in ff


def test_cli_flag(tmp_path):
    out = tmp_path / "mac.mobileconfig"
    r = subprocess.run([sys.executable, str(PROFILE_DIR / "make_profile.py"), "--self-lock",
                        "--image-blur-switchable", "--out", str(out)], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin"})
    assert r.returncode == 0, r.stderr
    info = json.loads(r.stdout)
    assert info["image_blur"] is False and info["image_blur_switchable"] is True
    prof = plistlib.loads(out.read_bytes())
    assert mpol.BLUR_FIREFOX_ID in json.dumps(prof["PayloadContent"], default=str)
