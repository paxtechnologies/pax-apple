# SPDX-License-Identifier: GPL-3.0-only
"""The order is the safety (see pax_windows/flow.py): supervision confirmed before
anything is escrowed, escrow before the profile is installed, the supervision key
destroyed on every path."""
import plistlib

import pytest

from pax_windows import choices as ch
from pax_windows.account import EmailAccount
from pax_windows.flow import SetupFailed, SetupSession, for_pc
from pax_windows.helper import DemoHelperRunner, HelperFailed


class Escrow:
    def __init__(self, journal):
        self.j = journal
        self.token = None
        self.device = None

    def account_summary(self):
        return {}

    def register_account(self, email):
        self.j.append("account")
        return {"token": "T"}

    def set_wait(self, d):
        self.j.append(f"wait:{d}")

    def set_partner(self, e):
        self.j.append("partner")

    def block_site(self, d):
        self.j.append("site")

    def set_dns_settings(self, yt):
        self.j.append("dns_settings")

    def dns_info(self):
        return {"token": "Abcdefghijklmnopqrstuv_-12"}

    def register_device(self, **kw):
        self.j.append("escrow")
        self.device = kw
        return {"device_id": "d1"}


class Runner(DemoHelperRunner):
    def __init__(self, journal, **kw):
        super().__init__(**kw)
        self.j = journal
        self.fail_install = False

    def run(self, args, stdin=None, on_event=None):
        self.j.append(args[0])
        if args[0] == "install-profile" and self.fail_install:
            raise HelperFailed("silent_failed", "Silent install failed")
        return super().run(args, stdin, on_event)


def make(tmp_path, ios="27.2", healthy=True):
    j = []
    s = SetupSession(Runner(j, ios=ios), Escrow(j), tmp_path, dns_health=lambda b: healthy, sleep=lambda s: None)
    c = ch.SetupChoices(find_my_confirmed_off=True, backup_confirmed=True, agreed=True,
                        partner_email="friend@example.org", blocked_sites=["example.org"])
    return s, c, j


def run_to_supervised(s, c):
    d = s.find_devices()[0]
    pre = s.preflight(d, c)
    assert pre.ok and pre.mode
    s.start(d, pre, c)
    states = []
    while (st := s.connect_once(d)) != "paired":
        states.append(st)
    s.confirm(d, c)
    return d, states


def test_full_live_path_order(tmp_path):
    s, c, j = make(tmp_path, ios="27.2")
    assert s.ensure_account(EmailAccount("a@b.co"), c).state == "ready"
    d, states = run_to_supervised(s, c)
    assert states == ["not_found", "not_found", "trust_requested"]
    assert s.mode == "live" and "live-configure" in j
    assert s.lock_and_escrow(d, c) == "installed"
    assert j.index("account") < j.index("wait:3") < j.index("partner") < j.index("list")
    assert j.index("status") < j.index("escrow") < j.index("install-profile") < j.index("profiles")
    assert not s.identity.private_key.exists()
    # The password escrowed is the one inside the profile that went to the phone.
    prof = plistlib.loads(s.runner.installed_profiles[0])
    pw = next(p for p in prof["PayloadContent"] if p["PayloadType"] == "com.apple.profileRemovalPassword")
    assert s.escrow.device["removal_password"] == pw["RemovalPassword"]
    assert s.escrow.device["trial"] is True and s.escrow.device["support_release"] is True
    assert s.escrow.device["hardware_id"] == ch.hardware_id(d.udid)
    assert s.escrow.device["profile_identifier"] == prof["PayloadIdentifier"]


def test_restored_path_has_no_live_configure(tmp_path):
    s, c, j = make(tmp_path, ios="26.1")
    d, _ = run_to_supervised(s, c)
    assert s.mode == "restored" and "live-configure" not in j


def test_not_supervised_means_nothing_escrowed(tmp_path):
    s, c, j = make(tmp_path)
    d = s.find_devices()[0]
    s.start(d, s.preflight(d, c), c)
    s.runner.supervised_after_restore = False
    with pytest.raises(SetupFailed) as e:
        s.confirm(d, c)
    assert e.value.code == "PAX-IOS-007"
    with pytest.raises(SetupFailed):
        s.lock_and_escrow(d, c)
    assert "escrow" not in j and "install-profile" not in j
    assert not s.identity.private_key.exists()


def test_filter_down_means_nothing_escrowed(tmp_path):
    s, c, j = make(tmp_path, healthy=False)
    d, _ = run_to_supervised(s, c)
    with pytest.raises(SetupFailed) as e:
        s.lock_and_escrow(d, c)
    assert e.value.code == "PAX-DNS-012" and "escrow" not in j
    assert not s.identity.private_key.exists()


def test_install_failure_after_escrow_still_destroys_the_key(tmp_path):
    s, c, j = make(tmp_path)
    d, _ = run_to_supervised(s, c)
    s.runner.fail_install = True
    with pytest.raises(SetupFailed) as e:
        s.lock_and_escrow(d, c)
    assert e.value.code == "PAX-IOS-010"
    assert j.index("escrow") < j.index("install-profile")
    assert not s.identity.private_key.exists()


def test_preflight_blocking_stops_before_the_phone(tmp_path):
    s, c, j = make(tmp_path)
    c.backup_confirmed = False
    d = s.find_devices()[0]
    pre = s.preflight(d, c)
    assert not pre.ok and pre.blocking
    with pytest.raises(SetupFailed) as e:
        s.start(d, pre, c)
    assert e.value.code == "PAX-IOS-011" and "seed-restore" not in j and s.identity is None


def test_trust_is_never_polled():
    assert SetupSession.poll_again("not_found") and SetupSession.poll_again("locked")
    assert not SetupSession.poll_again("trust_requested") and not SetupSession.poll_again("denied")


def test_helper_messages_say_pc():
    assert for_pc("This Mac isn't trusted by the iPhone yet.") == "This PC isn't trusted by the iPhone yet."


def test_code_sent_stops_before_the_wait(tmp_path):
    s, c, j = make(tmp_path)

    class Existing(EmailAccount):
        def ensure(self, escrow):
            from pax_windows.account import AccountResult
            return AccountResult("code_sent", self.email)
    assert s.ensure_account(Existing("a@b.co"), c).state == "code_sent"
    assert j == []


def test_support_codes_exist():
    import re
    from pathlib import Path

    import pax_errors
    for f in (Path(__file__).resolve().parents[1] / "pax_windows").glob("*.py"):
        for code in re.findall(r"PAX-[A-Z]+-\d{3}", f.read_text(encoding="utf-8")):
            assert code in pax_errors.BY_CODE, (f.name, code)
