# SPDX-License-Identifier: GPL-3.0-only
"""Media converters and media mirrors for the iPhone/iPad web filter (v0.8.1).

The full category (pax-dns/lists/media-converters.txt, ~250 sites plus a name
rule) is enforced by DNS: pax-dns and pax-guard. Apple's built-in web filter
takes at most 500 DenyListURLs in total, so the profile carries only these 60:
the most visited converters in the Tranco top 1M (2026-10-15), then the X,
Bluesky, Reddit, Instagram and TikTok media mirrors. One https URL each (the
filter matches by URL prefix). See docs/FILTER_LISTS.md for the trade-off with
the custom block cap.
"""
from __future__ import annotations

IOS_CONVERTER_HOSTS: list[str] = [
    "savefrom.net",
    "fdown.net",
    "sotwe.com",
    "ssstik.io",
    "snaptik.app",
    "fastdl.app",
    "indown.io",
    "twstalker.com",
    "sssinstagram.com",
    "twittervideodownloader.com",
    "fdownloader.net",
    "snapsave.app",
    "ssstwitter.com",
    "savefrom.co.id",
    "y2mate.gs",
    "igram.world",
    "snaptube.com",
    "musicaldown.com",
    "snaptik.net",
    "imginn.com",
    "nitter.net",
    "xcancel.com",
    "x2twitter.com",
    "savetik.co",
    "snaptik.kim",
    "snaptiktt.com",
    "cobalt.tools",
    "www-y2mate.com",
    "ssyoutube.com",
    "savethevideo.com",
    "y2mate.is",
    "keepvid.com",
    "tikwm.com",
    "snaptik.fi",
    "x-downloader.com",
    "savefromins.com",
    "dirpy.com",
    "savetwitter.net",
    "snaptik.sbs",
    "9xbuddy.site",
    "snapsave.io",
    "getindevice.com",
    "tiksave.io",
    "videodownloader.site",
    "savett.cc",
    "snaptik.vn",
    "savefrom.app",
    "vww-y2mate.com",
    "fxtwitter.com",
    "fixupx.com",
    "vxtwitter.com",
    "fixvx.com",
    "twittpr.com",
    "bskx.app",
    "fxbsky.app",
    "vxbsky.app",
    "rxddit.com",
    "vxreddit.com",
    "ddinstagram.com",
    "vxtiktok.com",
]

IOS_CONVERTER_URLS: list[str] = [f"https://{h}" for h in IOS_CONVERTER_HOSTS]
