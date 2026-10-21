# SPDX-License-Identifier: GPL-3.0-only
import hashlib

from pax_windows import choices as ch


def test_presets_and_default_match_the_mac():
    assert ch.WAIT_PRESETS == (1, 3, 7) and ch.DEFAULT_WAIT_DAYS == 3
    assert ch.WaitLimits.standard().presets() == [1, 3, 7]
    assert ch.WaitLimits.legacy_server().presets() == [3, 7]      # pre-0.8.9 server: no 24 hours
    assert [ch.choice_title(d) for d in (1, 3, 7)] == ["1 day", "3 days", "7 days"]
    assert ch.duration_days(1) == "24 hours" and ch.duration_days(3) == "3 days"


def test_wait_limits_from_health():
    w = ch.WaitLimits.from_health({"wait_limits": {"min_wait_seconds": 86400, "max_wait_seconds": 365 * 86400}})
    assert w.day_range == (1, 365) and w.allows(1) and not w.allows(366)
    assert ch.WaitLimits.from_health({}) == ch.WaitLimits.legacy_server()
    assert ch.WaitLimits.from_health({"wait_limits": {"min_wait_seconds": 0, "max_wait_seconds": 5}}) \
        == ch.WaitLimits.legacy_server()
    assert ch.WaitLimits.from_health(None) == ch.WaitLimits.legacy_server()
    assert ch.WaitLimits(36 * 3600, 365 * 86400).day_range == (2, 365)       # rounds up
    assert ch.WaitLimits.legacy_server().clamp(1) == 3 and ch.WaitLimits.standard().clamp(999) == 365


def test_custom_days():
    w = ch.WaitLimits.standard()
    assert ch.parse_custom_days("14", w) == 14
    assert ch.parse_custom_days(" 365 ", w) == 365
    for bad in ("", "0", "366", "2.5", "-3", "abc", "1e3"):
        assert ch.parse_custom_days(bad, w) is None, bad


def test_agreement_is_the_mac_sentence():
    # mac-app/Sources/Pax/Views/SetupFlowView.swift (v0.8.30)
    assert ch.agreement_text("iPhone", 3) == ("I'm 18 or over, and this iPhone is mine or my child's. "
                                              "I understand that turning Pax off takes my turn-off wait (3 days).")
    assert ch.agreement_text("iPad", 1).endswith("turn-off wait (24 hours).")
    assert "this iPad is mine or my child's" in ch.agreement_text("iPad", 7)


def test_device_word():
    assert ch.device_word("iPad13,4") == "iPad"
    assert ch.device_word("iPhone15,2") == "iPhone"
    assert ch.device_word(None) == "iPhone"


def test_emails_and_codes():
    assert ch.email_looks_valid("a@b.co") and ch.email_looks_valid(" alex@example.org ")
    for bad in ("", None, "a@b", "ab.co", "a b@c.d", "@b.co"):
        assert not ch.email_looks_valid(bad), bad
    assert ch.code_looks_valid("123456") and ch.code_looks_valid("123 456")
    assert not ch.code_looks_valid("12345") and not ch.code_looks_valid("abcdef")


def test_hardware_id_matches_the_mac_formula():
    udid = "00008110-001A2B3C4D5E801E"
    expected = hashlib.sha256(("pax-hw-v1:" + udid.lower()).encode()).hexdigest()
    assert ch.hardware_id(udid) == expected
    assert ch.hardware_id("  " + udid.upper() + "\n") == expected
    assert ch.hardware_id("") is None and ch.hardware_id(None) is None


def test_ready_to_protect():
    c = ch.SetupChoices()
    assert c.ready_to_protect(False) == ["find_my", "backup", "agreement"]
    c.find_my_confirmed_off, c.agreed = True, True
    assert c.ready_to_protect(True) == []
    assert c.ready_to_protect(False) == ["backup"]
    c.backup_confirmed = True
    assert c.ready_to_protect(False) == []


def test_defaults_match_the_mac():
    c = ch.SetupChoices()
    assert c.trial is True and c.support_release is True and c.forbid_pairing is False
    assert c.dns_base == "https://dns.paxpeace.com" and c.youtube_restricted is True
