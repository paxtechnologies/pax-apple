# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1: the media-converter category (sites + name rule), always on and
never freed by an exception."""
import pax_restricted

from pax_dns.lists import BUILTIN_FILES, CategoryList, RuleList, load_builtin, parse_line
from pax_dns.policy import Action, UserLists, decide

BUILTIN = load_builtin({k: str(v) for k, v in BUILTIN_FILES.items()})
CONV = BUILTIN["media_converters"]
RULE = BUILTIN["media_converter_rule"]

# Pax's UK false-positive set from the v1/v2 DNS tests: the rule must stay at 0 here.
UK_SET = [
    "bbc.co.uk", "bbc.com", "nhs.uk", "gov.uk", "hmrc.gov.uk", "dvla.gov.uk", "parliament.uk", "police.uk",
    "theguardian.com", "telegraph.co.uk", "thetimes.co.uk", "independent.co.uk", "dailymail.co.uk",
    "thesun.co.uk", "mirror.co.uk", "sky.com", "news.sky.com", "itv.com", "channel4.com", "ft.com",
    "economist.com", "barclays.co.uk", "hsbc.co.uk", "lloydsbank.com", "natwest.com", "santander.co.uk",
    "nationwide.co.uk", "monzo.com", "starlingbank.com", "halifax.co.uk", "tesco.com", "sainsburys.co.uk",
    "asda.com", "morrisons.com", "waitrose.com", "ocado.com", "argos.co.uk", "johnlewis.com",
    "marksandspencer.com", "boots.com", "currys.co.uk", "amazon.co.uk", "ebay.co.uk", "rightmove.co.uk",
    "zoopla.co.uk", "autotrader.co.uk", "nationalrail.co.uk", "tfl.gov.uk", "trainline.com", "royalmail.com",
    "bt.com", "virginmedia.com", "ucas.com", "justgiving.com", "moneysavingexpert.com", "which.co.uk",
    "deliveroo.co.uk",
]


def test_list_has_broad_coverage_and_what_the_maintainer_named():
    names = set(CONV.domains)
    assert len(names) >= 150
    for d in ("savefrom.net", "ssstwitter.com", "sstwitter.com", "twittervideodownloader.com", "twdown.net",
              "twitsave.com", "x2twitter.com", "savetwitter.net", "snapsave.app", "snaptik.app", "ssstik.io",
              "tikmate.app", "savetik.co", "y2mate.com", "ssyoutube.com", "yt1s.com", "9xbuddy.com",
              "keepvid.com", "fdown.net", "getfvid.com", "savevideo.me", "redditsave.com", "rapidsave.com",
              "viddit.red", "sssinstagram.com", "igram.world", "snapinsta.app", "fastdl.app", "saveig.app",
              "cobalt.tools", "loader.to", "tweeload.com", "getmyfb.com",
              # media mirrors and embed fixers
              "fxtwitter.com", "fixupx.com", "vxtwitter.com", "fixvx.com", "twittpr.com", "nitter.net",
              "xcancel.com", "bskx.app", "fxbsky.app", "rxddit.com", "vxreddit.com"):
        assert d in names, d
    assert CONV.match("en.savefrom.net") == "savefrom.net"


def test_name_rule_positive_and_negative():
    for hit in ("ssstwitter.example", "my-twittervideo.example", "twitterdownloader.example",
                "best-videodownloader.example", "tiktokdownload.example", "instadownload2.example",
                "savetwitter.example", "redditvideo.example", "redditsave.example", "youtubetomp4.example",
                "nitter.example", "x.nitter.example"):
        assert RULE.match(hit), hit
    for miss in ("download.mozilla.org", "apps.apple.com", "knitter.example", "twitter.com", "x.com",
                 "youtube.com", "reddit-help.example", "videos.example", "bigdownload.example",
                 "atomp3.example", "tomp4"):
        assert not RULE.match(miss), miss
    for d in UK_SET:
        assert not RULE.match(d) and not CONV.match(d), d


def test_rule_file_is_clean():
    words = [l.strip() for l in BUILTIN_FILES["media_converter_rule"].read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    assert len(words) == len(set(words)) >= 15
    assert all(w.lstrip("=").isalnum() for w in words)


def test_converters_are_never_freed_by_an_exception():
    user = UserLists(allow=frozenset({"ssstik.io", "vxtwitter.com", "clip-tomp4.example"}))
    for name in ("ssstik.io", "www.ssstik.io", "vxtwitter.com", "clip-tomp4.example"):
        d = decide(name, user, None, BUILTIN)
        assert d.action is Action.BLOCK_CATEGORY and d.category.startswith("media_converter"), name


def test_every_list_entry_parses_and_profile_hosts_are_listed():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "profile"))
    import media_converters
    names = set(CONV.domains)
    assert len(media_converters.IOS_CONVERTER_HOSTS) == 60
    assert all(h in names for h in media_converters.IOS_CONVERTER_HOSTS)
    assert all(parse_line(d) == d for d in names)


def test_restricted_check_uses_converters():
    chk = pax_restricted.RestrictedCheck(sets=[CONV], rules=[RULE.rule])
    assert chk("www.y2mate.com") and chk("ssstwitter.example") and not chk("example.com")
