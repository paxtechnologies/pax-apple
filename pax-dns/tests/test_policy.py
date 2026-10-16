# SPDX-License-Identifier: GPL-3.0-only
from conftest import OTHER, TOKEN, feed

import pax_restricted

from pax_dns.lists import CategoryList, RuleList
from pax_dns.policy import Action, Store, UserLists, decide

CAT = CategoryList.from_lines(["restricted.example", "*.blocked-example.test"])


def test_order_category_then_allow_then_block_then_forward():
    user = UserLists(block=frozenset({"custom.example", "restricted.example"}),
                     allow=frozenset({"news.example", "custom.example"}))
    # allow beats the user's own block
    assert decide("custom.example", user, CAT).action is Action.ALLOW
    assert decide("www.news.example", user, CAT).action is Action.ALLOW
    # v0.8.1: the restricted category list comes first
    assert decide("restricted.example", user, CAT).action is Action.BLOCK_CATEGORY
    assert decide("x.blocked-example.test", user, CAT).action is Action.BLOCK_CATEGORY
    assert decide("example.org", user, CAT).action is Action.FORWARD


def test_subdomains_and_lookalikes():
    user = UserLists(block=frozenset({"bad.example"}))
    assert decide("bad.example", user, None).action is Action.BLOCK_CUSTOM
    assert decide("a.b.bad.example.", user, None).matched == "bad.example"
    assert decide("notbad.example", user, None).action is Action.FORWARD
    assert decide("bad.example.evil.net", user, None).action is Action.FORWARD
    assert decide("BAD.Example", user, None).action is Action.BLOCK_CUSTOM


def test_exception_never_frees_the_restricted_category():
    allowed = UserLists(allow=frozenset({"restricted.example"}))
    assert decide("restricted.example", allowed, CAT).action is Action.BLOCK_CATEGORY
    assert decide("www.restricted.example", allowed, CAT).action is Action.BLOCK_CATEGORY
    assert decide("restricted.example", None, CAT).action is Action.BLOCK_CATEGORY


def test_exception_never_frees_media_converters_but_frees_bypass():
    conv = CategoryList.from_lines(["converter-example.test"])
    rule = RuleList(pax_restricted.parse_rule_file("tomp4\n=nitter\n"))
    bypass = CategoryList.from_lines(["cloudpc.example"])
    builtin = {"bypass": bypass, "media_converters": conv, "media_converter_rule": rule}
    user = UserLists(allow=frozenset({"converter-example.test", "clip-tomp4.example", "nitter.example",
                                      "cloudpc.example"}))
    for name in ("converter-example.test", "a.converter-example.test", "clip-tomp4.example", "nitter.example"):
        assert decide(name, user, None, builtin).action is Action.BLOCK_CATEGORY, name
    assert decide("cloudpc.example", user, None, builtin).action is Action.ALLOW
    assert decide("cloudpc.example", None, None, builtin).category == "bypass"
    assert decide("knitter.example", None, None, builtin).action is Action.FORWARD


def test_exception_ignored_for_restricted_name_rule():
    name = f"free-{pax_restricted.keywords()[0]}.example"
    user = UserLists(allow=frozenset({name, "news.example"}))
    # not in any list here, so it goes upstream, but as a plain lookup, not an exception
    assert decide(name, user, None).action is Action.FORWARD
    assert decide("news.example", user, None).action is Action.ALLOW


def test_store_lookup_unknown_malformed_and_retired_tokens():
    now = [1000.0]
    s = Store(clock=lambda: now[0])
    s.apply(feed(block=["a.com"], retire_at=2000))
    assert s.lookup(TOKEN).block == {"a.com"}
    assert s.lookup(OTHER) is None
    assert s.lookup("short") is None
    assert s.lookup("../../etc/passwd" + "x" * 20) is None
    assert s.lookup(None) is None
    now[0] = 2000
    assert s.lookup(TOKEN) is None  # retired: falls back to category filtering


def test_store_incremental_and_full_updates():
    s = Store()
    s.apply(feed(block=["a.com"]))
    s.apply(feed(block=["b.com"], token=OTHER, account="acct2", full=False))
    assert s.lookup(TOKEN).block == {"a.com"} and s.lookup(OTHER).block == {"b.com"}
    # account 1 rotates: old token disappears, lists replaced
    s.apply(feed(block=["c.com"], token=OTHER[:-1] + "C", account="acct1", full=False))
    assert s.lookup(TOKEN) is None
    assert s.lookup(OTHER[:-1] + "C").block == {"c.com"}
    # full snapshot drops accounts not present
    s.apply(feed(block=["z.com"], full=True))
    assert s.lookup(OTHER) is None and s.lookup(TOKEN).block == {"z.com"}
    assert len(s) == 1
