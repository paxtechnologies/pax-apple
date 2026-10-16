# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1: an exception can never unblock a site Pax always blocks.

pax-guard refuses the request (PAX-DNS-010, no wait, no partner email) when the
site or a parent is restricted content (bundled lists, top-level domains, the
name rule, the hand list), a media converter, or blocked by CleanBrowsing
Family itself; a CleanBrowsing lookup that fails refuses too. Real restricted
names come from common/pax_restricted.py, decoded at run time."""
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent
sys.path.insert(0, str(GUARD))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(GUARD.parent / "common"))
import dns_forwarder as dnsf  # noqa: E402
import filter_lists as fl  # noqa: E402
import local_blocklist as lb  # noqa: E402
import pax_restricted as pr  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402
from test_v08_partner import H, World  # noqa: E402

MESSAGE = "This site is in a category Pax always blocks, so it can't be allowed."


class FakeCleanBrowsing:
    name, url, host = "CleanBrowsing Family", "https://cb.example/dns-query", "cb.example"

    def __init__(self, blocked=(), failing=()):
        self.query = pr.fake_lookup(blocked=blocked, failing=failing)
        self.healthy, self.ips, self.last_error, self.trusted_time = True, [], "", None


@pytest.fixture(scope="module")
def bundled_filters(tmp_path_factory):
    return fl.FilterStore(tmp_path_factory.mktemp("lists-state"), bundled_dir=GUARD / "filters", plugin_dirs=[],
                          compile_in_subprocess=False, log=lambda m: None).load()


def guard_with(tmp_path, filters, cb):
    g, s = local_guard(tmp_path)
    g.forwarder = dnsf.Forwarder([cb], filters, g.forwarder_policy(), log=lambda m: None)
    return g


def allow(g, domain):
    return g.handle_request({"cmd": "blocklist.allow", "domain": domain}, 501)


def test_restricted_sites_are_refused_before_any_wait(tmp_path, bundled_filters):
    g = guard_with(tmp_path, bundled_filters, FakeCleanBrowsing(blocked=["blocked-upstream.com"],
                                                                failing=["down-upstream.com"]))
    tld = sorted(pr.restricted_tlds())[0]
    for domain in (pr.samples()[1],                     # bundled pax-block (local list)
                   "www." + pr.samples()[1],             # a parent counts
                   "restricted-check.paxpeace.com",      # hand list
                   f"anything.{tld}",                    # whole top-level domain
                   f"{pr.keywords()[0]}-site.com",       # name rule
                   "ssstik.io", "en.savefrom.net",       # media converters
                   "my-twittervideo.com",                # media-converter name rule
                   "blocked-upstream.com",               # CleanBrowsing Family blocks it (mocked)
                   "down-upstream.com"):                 # CleanBrowsing can't be asked: fail closed
        r = allow(g, domain)
        assert r == {"ok": False, "code": "PAX-DNS-010", "error": MESSAGE}, (domain, r)
    v = g.blocklist.view()
    assert v["pending"] == [] and v["allowed"] == []


def test_benign_false_positive_is_still_allowed_after_the_wait(tmp_path, bundled_filters):
    cb = FakeCleanBrowsing()
    g = guard_with(tmp_path, bundled_filters, cb)
    # On the VPN/proxy list (an exception may free it), not on any restricted list.
    assert bundled_filters.overridable_by("nordvpn.com") and not bundled_filters.restricted_by("nordvpn.com")
    r = allow(g, "nordvpn.com")
    assert r["ok"] and r["request"]["seconds_remaining"] > 0
    g.sys.t += 73 * 3600
    assert "allow nordvpn.com" in g.blocklist.apply_due()
    g.remote = {"blocked": [], "allowed": g.blocklist.allowed()}
    g.forwarder.set_policy(g.forwarder_policy())
    assert g.forwarder.decide("nordvpn.com") == ("forward", "exception")


def test_decide_blocks_restricted_even_with_an_exception(tmp_path, bundled_filters):
    g = guard_with(tmp_path, bundled_filters, FakeCleanBrowsing())
    g.remote = {"blocked": [], "allowed": [pr.samples()[1], "ssstik.io", "restricted-check.paxpeace.com"]}
    g.forwarder.set_policy(g.forwarder_policy())
    for name in (pr.samples()[1], "ssstik.io", "restricted-check.paxpeace.com"):
        assert g.forwarder.decide(name)[0] == "block", name


def test_no_partner_email_for_a_refused_request(tmp_path):
    w = World(tmp_path)
    sent_before = len(w.mail.sent)

    def refuse(d):
        raise pr.RestrictedSite(d, "test")
    bl = lb.LocalBlocklist(tmp_path / "bl.json", wait_seconds=lambda: 24 * H, clock=lambda: w.wall,
                           partner=w.esc.partner, restricted_check=refuse, restricted_static=lambda d: False)
    with pytest.raises(lb.BlocklistError) as e:
        bl.request_allow("somewhere.example")
    assert e.value.code == "PAX-DNS-010" and e.value.message == MESSAGE
    assert len(w.mail.sent) == sent_before and bl.view()["pending"] == []
    assert w.esc.partner.flush() == []


def test_a_waiting_exception_that_became_restricted_is_refused_when_due(tmp_path):
    now = [1_800_000_000]
    restricted = set()
    bl = lb.LocalBlocklist(tmp_path / "bl.json", wait_seconds=lambda: 72 * H, clock=lambda: now[0],
                           restricted_check=lambda d: None, restricted_static=lambda d: d in restricted)
    bl.request_allow("later.example")
    restricted.add("later.example")
    now[0] += 73 * H
    assert bl.apply_due() == [] and bl.allowed() == [] and bl.view()["pending"] == []
