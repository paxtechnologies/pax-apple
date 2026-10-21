# SPDX-License-Identifier: GPL-3.0-only
import json

import pytest

from pax_windows.account import EmailAccount
from pax_windows.escrow import EscrowClient, EscrowError, dns_healthy


class Fake:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, dict(headers), json.loads(body) if body else None))
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        status, obj = a
        return status, json.dumps(obj).encode() if obj is not None else b""


def test_requests_match_the_mac_client():
    f = Fake([(201, {"account_id": "a", "token": "T"}), (200, {}), (200, {}), (201, {"device_id": "d"})])
    c = EscrowClient("https://api.example", transport=f)
    c.token = c.register_account("alex@example.org")["token"]
    c.set_wait(3)
    c.set_partner("friend@example.org")
    c.register_device(name="Alex's iPhone", platform="ios", profile_identifier="org.paxpeace.pax.ios.x",
                      removal_password="p" * 30, support_release=True, trial=True, hardware_id="h" * 64)
    m = [(x[0], x[1]) for x in f.calls]
    assert m == [("POST", "https://api.example/v1/accounts"), ("PUT", "https://api.example/v1/accounts/me/wait"),
                 ("PUT", "https://api.example/v1/accounts/me/partner"), ("POST", "https://api.example/v1/devices")]
    assert "Authorization" not in f.calls[0][2]
    assert f.calls[1][2]["Authorization"] == "Bearer T" and f.calls[1][3] == {"wait_days": 3}
    assert f.calls[3][3] == {"name": "Alex's iPhone", "platform": "ios",
                             "profile_identifier": "org.paxpeace.pax.ios.x", "removal_password": "p" * 30,
                             "support_release": True, "trial": True, "hardware_id": "h" * 64}
    assert f.calls[0][2]["User-Agent"].startswith("PaxWindowsSetup/")


def test_trial_needs_a_hardware_id():
    f = Fake([(201, {"device_id": "d"})])
    EscrowClient("https://x", token="T", transport=f).register_device(
        name="n", platform="ios", profile_identifier="org.paxpeace.pax.ios.y", removal_password="p" * 30,
        support_release=False, trial=True, hardware_id=None)
    assert "trial" not in f.calls[0][3] and f.calls[0][3]["support_release"] is False


def test_errors():
    f = Fake([(409, {"error": "exists", "message": "That email has an account."}), OSError("down"),
              (500, None)])
    c = EscrowClient("https://x", transport=f)
    with pytest.raises(EscrowError) as e:
        c.register_account("a@b.co")
    assert e.value.status == 409 and e.value.code == "exists"
    with pytest.raises(EscrowError) as e:
        c.health()
    assert e.value.status == 0 and e.value.code == "network"
    with pytest.raises(EscrowError) as e:
        c.health()
    assert e.value.code == "http_500"


def test_wait_limits_fall_back_like_the_mac():
    c = EscrowClient("https://x", transport=Fake([OSError("x")]))
    assert c.wait_limits().presets() == [3, 7]
    c = EscrowClient("https://x", transport=Fake([(200, {"wait_limits": {"min_wait_seconds": 86400,
                                                                          "max_wait_seconds": 86400 * 30}})]))
    assert c.wait_limits().day_range == (1, 30)


def test_dns_healthy():
    assert dns_healthy("https://dns.example/", Fake([(200, {"ok": True})]))
    assert not dns_healthy("https://dns.example", Fake([(200, {"ok": False})]))
    assert not dns_healthy("https://dns.example", Fake([(502, None)]))
    assert not dns_healthy("https://dns.example", Fake([OSError("x")]))
    f = Fake([(200, {"ok": True})])
    dns_healthy("https://dns.example/", f)
    assert f.calls[0][1] == "https://dns.example/health"


def test_email_account_new():
    f = Fake([(201, {"account_id": "a", "token": "NEW"})])
    c = EscrowClient("https://x", transport=f)
    assert EmailAccount("a@b.co").ensure(c).state == "ready" and c.token == "NEW"


def test_email_account_existing_uses_a_code():
    f = Fake([(409, {"error": "exists"}), (202, {"sent": True}), (200, {"account_id": "a", "token": "SIGNED"})])
    c = EscrowClient("https://x", transport=f)
    acct = EmailAccount("a@b.co")
    r = acct.ensure(c)
    assert r.state == "code_sent" and r.sent_to == "a@b.co" and c.token is None
    acct.code = "123 456"
    assert acct.ensure(c).state == "ready" and c.token == "SIGNED"
    assert f.calls[-1][3] == {"email": "a@b.co", "code": "123456", "label": "Windows PC"}


def test_email_account_saved_token():
    f = Fake([(200, {"email": "a@b.co"})])
    c = EscrowClient("https://x", token="OLD", transport=f)
    assert EmailAccount("").ensure(c).state == "ready" and c.token == "OLD"
    f = Fake([(401, {"error": "unauthorized"}), (201, {"account_id": "a", "token": "NEW"})])
    c = EscrowClient("https://x", token="STALE", transport=f)
    assert EmailAccount("a@b.co").ensure(c).state == "ready" and c.token == "NEW"
