# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.5: sign-up rate limit per client IP, a global daily email budget
(account-holder emails dropped before partner alerts; partner alerts fail
closed), one welcome per address per day, best-effort welcome email, and stale
grace / removal requests lapsing on their own."""
import pytest
from fastapi.testclient import TestClient

from test_escrow_api import PW, FakeClock, make_device, past_grace  # noqa: F401
from pax_server import __version__
from pax_server.config import DAY, HOUR, Settings
from pax_server.crypto import generate_key_b64
from pax_server.limits import client_ip, is_loopback
from pax_server.main import create_app
from pax_server.notify import MemoryEmailSender

PARTNER = "friend@example.org"


class FlakySender(MemoryEmailSender):
    """Records what was sent; raises for addresses in `down`."""

    def __init__(self):
        super().__init__()
        self.down: set[str] = set()

    def send(self, email):
        if email.to in self.down:
            raise OSError("smtp down")
        super().send(email)


def build(tmp_path, peer=("testclient", 50000), **overrides):
    clock, mail = FakeClock(), FlakySender()
    settings = Settings(db_path=str(tmp_path / "pax.sqlite3"), server_key_b64=generate_key_b64(),
                        **overrides)
    app = create_app(settings, clock=clock, sender=mail)

    class Env:
        pass

    e = Env()
    e.client = TestClient(app, client=peer)
    e.clock, e.mail, e.settings, e.app = clock, mail, settings, app
    e.escrow = app.state.escrow
    return e


@pytest.fixture
def env(tmp_path):
    return build(tmp_path)


def signup(env, email, xff=None):
    headers = {"X-Forwarded-For": xff} if xff else {}
    return env.client.post("/v1/accounts", json={"email": email}, headers=headers)


def account(env, email="me@example.com", partner=None):
    r = signup(env, email)
    assert r.status_code == 201, r.text
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    if partner:
        assert env.client.put("/v1/accounts/me/partner", headers=h, json={"email": partner}).status_code == 200
    return h


def removal(env, h, dev):
    return env.client.get(f"/v1/devices/{dev}", headers=h).json()["removal_request"]


# ------------------------------------------------------------------ version
def test_version_is_085(env):
    assert __version__ == "0.8.19"
    assert env.client.get("/v1/health").json()["version"] == "0.8.19"


# ---------------------------------------------------------------- client IP
def test_client_ip_trusts_forwarded_for_only_from_localhost():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("203.0.113.9") and not is_loopback("testclient") and not is_loopback(None)
    # From Caddy on this machine: the last entry is the address Caddy saw.
    assert client_ip("127.0.0.1", "198.51.100.7") == "198.51.100.7"
    assert client_ip("127.0.0.1", "10.9.9.9, 198.51.100.7") == "198.51.100.7"
    assert client_ip("::1", "2001:db8::5") == "2001:db8::5"
    assert client_ip("127.0.0.1", "198.51.100.7:4433") == "198.51.100.7"
    assert client_ip("127.0.0.1", "[2001:db8::5]:4433") == "2001:db8::5"
    assert client_ip("127.0.0.1", "198.51.100.7, junk") == "198.51.100.7"
    assert client_ip("127.0.0.1", "junk") == "127.0.0.1"
    assert client_ip("127.0.0.1", None) == "127.0.0.1"
    # From anywhere else the header is ignored: it could be forged.
    assert client_ip("203.0.113.9", "198.51.100.7") == "203.0.113.9"
    assert client_ip(None, "198.51.100.7") == "unknown"


# ------------------------------------------------------------ sign-up limit
def test_signup_limited_per_hour_then_per_day(env):
    for i in range(5):
        assert signup(env, f"u{i}@example.com").status_code == 201
    r = signup(env, "u5@example.com")
    assert r.status_code == 429
    assert r.json()["error"] == "rate_limited" and r.json()["pax_code"] == "PAX-ESCROW-006"
    # Nothing was created or emailed for the refused one.
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 5
    assert env.mail.kinds_to("u5@example.com") == []
    n = 5
    for _ in range(3):
        env.clock.advance(HOUR + 1)
        for _ in range(5):
            assert signup(env, f"u{n}@example.com").status_code == 201
            n += 1
    env.clock.advance(HOUR + 1)
    r = signup(env, f"u{n}@example.com")          # 20 in the last day
    assert r.status_code == 429 and "today" in r.json()["message"]
    env.clock.advance(DAY)
    assert signup(env, f"u{n}@example.com").status_code == 201


def test_signup_attempts_count_even_when_refused_as_duplicates(env):
    assert signup(env, "same@example.com").status_code == 201
    for _ in range(4):
        assert signup(env, "same@example.com").status_code == 409
    assert signup(env, "other@example.com").status_code == 429


def test_forwarded_for_from_localhost_separates_clients(tmp_path):
    env = build(tmp_path, peer=("127.0.0.1", 41000))
    for i in range(5):
        assert signup(env, f"a{i}@example.com", xff="198.51.100.1").status_code == 201
    assert signup(env, "a5@example.com", xff="198.51.100.1").status_code == 429
    # Another visitor behind the same proxy is counted separately.
    assert signup(env, "b0@example.com", xff="198.51.100.2").status_code == 201
    # A client can't dodge the limit by adding its own entries in front.
    assert signup(env, "a6@example.com", xff="1.2.3.4, 198.51.100.1").status_code == 429


def test_forwarded_for_from_elsewhere_is_ignored(tmp_path):
    env = build(tmp_path, peer=("203.0.113.50", 41000))
    for i in range(5):
        assert signup(env, f"c{i}@example.com", xff=f"198.51.100.{i}").status_code == 201
    assert signup(env, "c5@example.com", xff="198.51.100.99").status_code == 429


def test_signup_limits_can_be_switched_off(tmp_path):
    env = build(tmp_path, signup_per_ip_hour=0, signup_per_ip_day=0)
    for i in range(30):
        assert signup(env, f"d{i}@example.com").status_code == 201


def test_signup_settings_from_env(monkeypatch):
    monkeypatch.setenv("PAX_SIGNUP_PER_IP_HOUR", "2")
    monkeypatch.setenv("PAX_SIGNUP_PER_IP_DAY", "7")
    monkeypatch.setenv("PAX_MAIL_DAILY_CAP", "80")
    monkeypatch.setenv("PAX_ACCOUNT_MAIL_DAILY_CAP", "50")
    s = Settings.from_env()
    assert (s.signup_per_ip_hour, s.signup_per_ip_day, s.mail_daily_cap, s.account_mail_daily_cap) == (2, 7, 80, 50)
    d = Settings()
    assert d.mail_daily_cap < 100 and d.account_mail_daily_cap < d.mail_daily_cap
    assert d.grace_seconds == HOUR


# --------------------------------------------------- welcome is best-effort
def test_welcome_failure_still_creates_the_account(env):
    env.mail.down.add("me@example.com")
    r = signup(env, "me@example.com")
    assert r.status_code == 201, r.text
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    assert env.client.get("/v1/accounts/me", headers=h).json()["email"] == "me@example.com"
    kinds = [e["kind"] for e in env.escrow.db.all("SELECT kind FROM events")]
    assert "account_registered" in kinds and "welcome_not_sent" in kinds
    # A retry is a duplicate, not a second account.
    assert signup(env, "me@example.com").status_code == 409


def test_one_welcome_per_address_per_day(env):
    assert signup(env, "me@example.com").status_code == 201
    assert env.mail.kinds_to("me@example.com") == ["welcome"]
    esc = env.escrow
    assert esc._mail("me@example.com", "welcome", "Welcome to Pax", "again") is False
    assert esc._mail("ME@example.com ", "welcome", "Welcome to Pax", "again") is False
    assert env.mail.kinds_to("me@example.com") == ["welcome"]
    env.clock.advance(DAY + 1)
    assert esc._mail("me@example.com", "welcome", "Welcome to Pax", "later") is True


def test_failed_welcome_does_not_block_a_later_one(env):
    env.mail.down.add("me@example.com")
    assert env.escrow._mail("me@example.com", "welcome", "Welcome to Pax", "x") is False
    env.mail.down.clear()
    assert env.escrow._mail("me@example.com", "welcome", "Welcome to Pax", "x") is True


# ------------------------------------------------------------- mail budget
def _fill(env, n, tier):
    for i in range(n):
        env.escrow.limits.finish(env.escrow.limits.reserve(f"x{i}@example.net", "filler", tier)[0], True)


def test_account_emails_stop_first_and_partner_alerts_continue(env):
    h = account(env, partner=PARTNER)
    dev = make_device(env, h)
    past_grace(env)
    _fill(env, env.settings.account_mail_daily_cap - env.escrow.limits.sent_today(), "account")
    before_me = len(env.mail.kinds_to("me@example.com"))
    r = env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    assert r.status_code == 201, r.text
    assert "removal_requested" in env.mail.kinds_to(PARTNER)          # partner still told
    assert len(env.mail.kinds_to("me@example.com")) == before_me     # account copy dropped
    assert env.escrow.limits.sent_today() <= env.settings.mail_daily_cap


def test_budget_never_exceeded_and_partner_alert_fails_closed(env):
    h = account(env, partner=PARTNER)
    dev = make_device(env, h)
    past_grace(env)
    _fill(env, env.settings.mail_daily_cap - env.escrow.limits.sent_today(), "partner")
    assert env.escrow.limits.sent_today() == env.settings.mail_daily_cap
    r = env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    assert r.status_code == 503
    assert r.json()["error"] == "partner_unreachable" and r.json()["pax_code"] == "PAX-ESCROW-010"
    assert removal(env, h, dev) is None                                # no countdown started
    assert env.escrow.limits.sent_today() == env.settings.mail_daily_cap
    # A day later the budget is back and the request works.
    env.clock.advance(DAY + 1)
    assert env.client.post(f"/v1/devices/{dev}/removal-request", headers=h).status_code == 201
    assert removal(env, h, dev)["status"] == "pending"


def test_signups_still_work_when_the_budget_is_spent(env):
    _fill(env, env.settings.mail_daily_cap, "partner")
    r = signup(env, "late@example.com")
    assert r.status_code == 201
    assert env.mail.kinds_to("late@example.com") == []


# ------------------------------------------------------- partner fail-closed
def test_partner_email_failure_starts_nothing(env):
    h = account(env, partner=PARTNER)
    dev = make_device(env, h)
    past_grace(env)
    env.mail.down.add(PARTNER)
    r = env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    assert r.status_code == 503 and r.json()["pax_code"] == "PAX-ESCROW-010"
    assert removal(env, h, dev) is None
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 3 + 1})
    assert r.status_code == 200                                        # increase: no email needed
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 3})
    assert r.status_code == 503
    assert env.client.get("/v1/accounts/me", headers=h).json()["pending_wait_seconds"] is None
    r = env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "new@example.org"})
    assert r.status_code == 503
    assert env.client.get("/v1/accounts/me", headers=h).json()["pending_partner_email"] is None
    r = env.client.post(f"/v1/devices/{dev}/emergency", headers=h, json={"reason": "a real emergency here"})
    assert r.status_code == 503
    assert removal(env, h, dev) is None
    assert env.escrow.db.one("SELECT last_emergency_at FROM accounts")[0] is None   # allowance kept


def test_reveal_needs_the_partner_told_first(env):
    h = account(env, partner=PARTNER)
    dev = make_device(env, h)
    past_grace(env)
    assert env.client.post(f"/v1/devices/{dev}/removal-request", headers=h).status_code == 201
    env.clock.advance(env.settings.default_wait_seconds + 1)
    env.mail.down.add(PARTNER)
    r = env.client.post(f"/v1/devices/{dev}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 503 and "removal_password" not in r.json()
    assert env.escrow.db.one("SELECT released_at FROM devices")[0] is None
    assert removal(env, h, dev)["status"] == "pending"
    env.mail.down.clear()
    r = env.client.post(f"/v1/devices/{dev}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 200 and r.json()["removal_password"] == PW
    assert "password_revealed" in env.mail.kinds_to(PARTNER)


def test_cancel_never_waits_on_email(env):
    h = account(env, partner=PARTNER)
    dev = make_device(env, h)
    past_grace(env)
    assert env.client.post(f"/v1/devices/{dev}/removal-request", headers=h).status_code == 201
    env.mail.down.add(PARTNER)
    r = env.client.post(f"/v1/devices/{dev}/removal-request/cancel", headers=h)
    assert r.status_code == 200 and r.json()["removal_request"] is None


def test_blocklist_removal_fails_closed(env):
    h = account(env, partner=PARTNER)
    assert env.client.post("/v1/blocklist", headers=h, json={"domain": "example.net"}).status_code == 201
    env.mail.down.add(PARTNER)
    r = env.client.post("/v1/blocklist/remove", headers=h, json={"domain": "example.net"})
    assert r.status_code == 503
    assert env.client.get("/v1/blocklist", headers=h).json().get("pending", []) == []
    assert env.escrow.db.one("SELECT COUNT(*) FROM blocklist_requests")[0] == 0


def test_account_email_failure_never_blocks_an_action(env):
    h = account(env)                                                   # no partner
    dev = make_device(env, h)
    past_grace(env)
    env.mail.down.add("me@example.com")
    assert env.client.post(f"/v1/devices/{dev}/removal-request", headers=h).status_code == 201
    assert removal(env, h, dev)["status"] == "pending"


def test_relay_partner_failure_is_503_and_not_counted(env):
    h = account(env)
    env.mail.down.add(PARTNER)
    body = {"kind": "removal_requested", "subject": "s", "body": "b", "partner_email": PARTNER}
    r = env.client.post("/v1/notify", headers=h, json=body)
    assert r.status_code == 503 and r.json()["pax_code"] == "PAX-ESCROW-010"
    assert env.escrow.db.one("SELECT COUNT(*) FROM events WHERE kind='notify_relayed'")[0] == 0
    env.mail.down.clear()
    assert env.client.post("/v1/notify", headers=h, json=body).status_code == 202
    # The account holder's copy is best-effort.
    env.mail.down.add("me@example.com")
    assert env.client.post("/v1/notify", headers=h, json=body).status_code == 202


# -------------------------------------------------------- stale requests
def test_grace_request_lapses_when_grace_ends(env):
    h = account(env)
    dev = make_device(env, h)
    rr = env.client.post(f"/v1/devices/{dev}/removal-request", headers=h).json()["removal_request"]
    assert rr["kind"] == "grace" and rr["can_reveal"]
    assert rr["expires_at"] == env.escrow.db.one("SELECT installed_at FROM devices")[0] + HOUR
    past_grace(env)
    assert removal(env, h, dev) is None
    assert env.escrow.db.one("SELECT status FROM removal_requests")[0] == "lapsed"
    r = env.client.post(f"/v1/devices/{dev}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 410
    # A new request now takes the full wait.
    rr = env.client.post(f"/v1/devices/{dev}/removal-request", headers=h).json()["removal_request"]
    assert rr["kind"] == "standard" and not rr["can_reveal"]


def test_grace_request_can_be_confirmed_within_the_hour(env):
    h = account(env)
    dev = make_device(env, h)
    env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    env.clock.advance(HOUR - 60)
    r = env.client.post(f"/v1/devices/{dev}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 200 and r.json()["removal_password"] == PW


def test_sweep_lapses_without_anyone_looking(env):
    h = account(env)
    dev = make_device(env, h)
    env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    assert env.escrow.lapse_due() == 0
    past_grace(env)
    assert env.escrow.lapse_due() == 1
    assert env.escrow.db.one("SELECT status FROM removal_requests")[0] == "lapsed"
    assert env.escrow.db.one("SELECT COUNT(*) FROM events WHERE kind='removal_lapsed'")[0] == 1
    assert env.escrow.lapse_due() == 0


def test_sweep_lapses_standard_requests_after_the_reveal_window(env):
    h = account(env)
    dev = make_device(env, h)
    past_grace(env)
    env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    env.clock.advance(env.settings.default_wait_seconds + env.settings.reveal_window_seconds - 10)
    assert env.escrow.lapse_due() == 0
    env.clock.advance(20)
    assert env.escrow.lapse_due() == 1


def test_old_grace_request_from_a_longer_grace_period_lapses(env):
    """A request made on day 2 of the old 7-day grace period (expires_at a week
    out) lapses now that the grace period is an hour."""
    h = account(env)
    dev = make_device(env, h)
    esc = env.escrow
    now = env.clock.now()
    esc.db.execute("UPDATE devices SET installed_at=?", (now - 2 * DAY,))
    esc.db.execute("INSERT INTO removal_requests(id, device_id, kind, status, created_at, unlock_at, expires_at) "
                   "VALUES ('old', ?, 'grace', 'pending', ?, ?, ?)", (dev, now - DAY, now - DAY, now + 6 * DAY))
    assert removal(env, h, dev) is None
    r = env.client.post(f"/v1/devices/{dev}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 410


def test_revealed_grace_request_can_still_be_shown_again(env):
    h = account(env)
    dev = make_device(env, h)
    env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    assert env.client.post(f"/v1/devices/{dev}/removal-request/confirm", headers=h,
                           json={"confirm": True}).status_code == 200
    past_grace(env)
    assert env.escrow.lapse_due() == 0
    assert env.escrow.db.one("SELECT status FROM removal_requests")[0] == "revealed"


def test_emergency_in_grace_closes_with_the_grace_period(env):
    h = account(env)
    dev = make_device(env, h)
    r = env.client.post(f"/v1/devices/{dev}/emergency", headers=h, json={"reason": "a real emergency here"})
    assert r.status_code == 201 and r.json()["removal_request"]["can_reveal"]
    past_grace(env)
    assert removal(env, h, dev) is None
