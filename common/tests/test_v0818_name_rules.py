# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.18: the name rule applied to every lookup (LookupRule) and the web-proxy
name rule (BypassNameRule). Matched words are read from common/pax_restricted.py
at run time, never written here."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import pax_restricted as pr  # noqa: E402

RULE = pr.lookup_rule()
WORDS = pr.data()["lookup_rule"]["words"]
W = WORDS[0]


def test_data_sections_present():
    d = pr.data()
    assert d["lookup_rule"]["words"] and d["lookup_rule"]["allow_words"]
    assert d["bypass_rule"]["contains"] and d["bypass_rule"]["labels"]
    # An exception request is refused for anything the lookup rule blocks.
    chk = pr.RestrictedCheck()
    for w in WORDS:
        assert chk.reason(f"{w}-site.example") is not None, w


def test_registrable_label():
    assert pr.registrable_label("www.example.co.uk") == "example"
    assert pr.registrable_label("a.b.example.com") == "example"
    assert pr.registrable_label("example.com.br") == "example"
    assert pr.registrable_label("example.com") == "example"
    assert pr.registrable_label("com") is None
    assert pr.registrable_label("") is None


def test_every_word_at_each_edge():
    for w in WORDS:
        assert RULE.match(f"{w}tube.example"), w            # start of the label
        assert RULE.match(f"www.free{w}.example"), w        # end of the label
        assert RULE.match(f"best-{w}-clips.example"), w     # next to a hyphen
        assert RULE.match(f"www.{w}.co.uk"), w               # ccTLD second level


def test_not_in_the_middle_or_next_to_a_digit():
    assert not RULE.match(f"ab{W}cd.example")
    # Random hashes (CDN and telemetry names) put words next to digits.
    assert not RULE.match(f"d3ug{W}05crldn.example")
    assert not RULE.match(f"x9{W}7.example")


def test_only_the_registrable_label_is_read():
    # A subdomain label is never judged on its own (CDN, telemetry, test hosts).
    assert not RULE.match(f"{W}.cdn.example.com")
    assert not RULE.match(f"datasec-km{W}-sg.example.com")
    assert RULE.match(f"cdn.{W}site.example")


def test_allow_words_and_exclusions():
    allow = pr.data()["lookup_rule"]["allow_words"]
    hits = [a for a in allow if RULE.label_hit(a)]
    assert hits == [], hits
    for name in pr.data()["lookup_rule"]["exclude"]:
        assert not RULE.match(name)
        assert not RULE.match("www." + name)


def test_everyday_sites_are_not_matched():
    for name in ("bbc.co.uk", "nhs.uk", "gov.uk", "essex.gov.uk", "sussex.ac.uk", "middlesex.gov.uk",
                 "camden.gov.uk", "cambridge.org", "expedia.com", "sensex.example", "unisex.example",
                 "tesco.com", "amazon.co.uk", "github.com", "proxy.golang.org"):
        assert not RULE.match(name), name


def test_restricted_check_uses_the_lookup_rule():
    chk = pr.RestrictedCheck()
    assert chk.reason(f"www.{W}tube.example") == "name-rule"
    assert chk.reason("bbc.co.uk") is None


def test_bypass_name_rule():
    b = pr.bypass_name_rule()
    d = pr.data()["bypass_rule"]
    for w in d["contains"]:
        assert b.match(f"free{w}now.example"), w
        assert b.match(f"www.{w}.co.uk"), w
    for lab in d["labels"]:
        assert b.match(f"{lab}.example"), lab
        assert not b.match(f"{lab}.corp.example.com"), lab   # a subdomain label never counts
    for name in d["exclude"]:
        assert not b.match(name)
    for name in ("proxy.golang.org", "haproxy.org", "envoyproxy.io", "bbc.co.uk", "proxyvote.com"):
        assert not b.match(name), name
