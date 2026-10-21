# SPDX-License-Identifier: GPL-3.0-only
import json
import plistlib

import make_profile as mp
from pax_windows import profile_maker

TOKEN = "Abcdefghijklmnopqrstuv_-12"


def payloads(data):
    p = plistlib.loads(data)
    return p, {x["PayloadType"]: x for x in p["PayloadContent"]}


def test_same_profile_as_the_mac_default(tmp_path):
    prof = profile_maker.generate(user_token=TOKEN, dns_base="https://dns.paxpeace.com")
    p, by = payloads(prof.data)
    assert p["PayloadRemovalDisallowed"] is True
    assert prof.identifier.startswith("org.paxpeace.pax.ios.") and p["PayloadIdentifier"] == prof.identifier
    assert by["com.apple.dnsSettings.managed"]["DNSSettings"]["ServerURL"] == \
        f"https://dns.paxpeace.com/u/{TOKEN}/dns-query"
    assert by["com.apple.profileRemovalPassword"]["RemovalPassword"] == prof.removal_password
    assert prof.removal_password not in repr(prof)
    # The Mac app runs the CLI with --user-token --dns-base; same payloads and lists.
    out, esc = tmp_path / "p.mobileconfig", tmp_path / "e.json"
    assert mp.main(["--platform", "ios", "--out", str(out), "--escrow-out", str(esc),
                    "--user-token", TOKEN, "--dns-base", "https://dns.paxpeace.com"]) == 0
    _, cli = payloads(out.read_bytes())
    assert sorted(cli) == sorted(by)
    assert cli["com.apple.webcontent-filter"]["DenyListURLs"] == by["com.apple.webcontent-filter"]["DenyListURLs"]
    assert cli["com.apple.applicationaccess"] == by["com.apple.applicationaccess"] or \
        cli["com.apple.applicationaccess"]["blockedAppBundleIDs"] == by["com.apple.applicationaccess"]["blockedAppBundleIDs"]
    assert json.loads(esc.read_text())["profile_identifier"].startswith("org.paxpeace.pax.ios.")


def test_sites_go_into_the_web_filter():
    prof = profile_maker.generate(user_token=TOKEN, dns_base="https://dns.paxpeace.com",
                                  blocked_sites=["example.org"])
    _, by = payloads(prof.data)
    assert by["com.apple.webcontent-filter"]["DenyListURLs"][0] == "https://example.org"


def test_direct_filter_without_token():
    prof = profile_maker.generate(user_token=None, dns_base=None)
    _, by = payloads(prof.data)
    assert by["com.apple.dnsSettings.managed"]["DNSSettings"]["ServerURL"] == mp.CLEANBROWSING_FAMILY_DOH
