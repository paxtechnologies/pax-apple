#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check that every bundle ID in bypass_apps.py still resolves on the App Store.

Uses Apple's public iTunes Lookup API: https://itunes.apple.com/lookup?bundleId=<id>
Prints one line per app; exits 1 if any bundle ID no longer resolves.
"""
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bypass_apps import DEFAULT_BYPASS_APPS  # noqa: E402
from remote_ai_browsers import IOS_REMOTE_AI_APPS  # noqa: E402


def main(country: str = "gb") -> int:
    missing = 0
    for bid, name, reason in DEFAULT_BYPASS_APPS + IOS_REMOTE_AI_APPS:
        url = "https://itunes.apple.com/lookup?" + urllib.parse.urlencode(
            {"bundleId": bid, "country": country})
        with urllib.request.urlopen(url, timeout=15) as r:
            results = json.load(r).get("results", [])
        if results:
            print(f"ok       {bid:45} {results[0].get('trackName')}")
        else:
            missing += 1
            print(f"MISSING  {bid:45} (was: {name}, {reason})")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
