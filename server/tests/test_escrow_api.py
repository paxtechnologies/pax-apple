# SPDX-License-Identifier: GPL-3.0-only
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pax_server.config import DAY, HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402
from verified_signup import verified_signup  # noqa: E402  (v0.8.32)

PW = "abcde-fghjk-mnpqr-stuvw-xyz23-45678"
T0 = 1_800_000_000  # fixed start time (2027-01-15)


class FakeClock:
    def __init__(self, t: int = T0):
        self.t = t

    def now(self) -> int:
        return self.t

    def advance(self, seconds: int) -> None:
        self.t += seconds


@pytest.fixture
def env(tmp_path):
    clock, mail = FakeClock(), MemoryEmailSender()
    settings = Settings(db_path=str(tmp_path / "pax.sqlite3"), server_key_b64=generate_key_b64())
    app = create_app(settings, clock=clock, sender=mail)
    client = TestClient(app)

    class Env:
        pass

    e = Env()
    e.client, e.clock, e.mail, e.settings = client, clock, mail, settings
    return e


def make_account(env, email="user@example.com"):
    r = verified_signup(env.client, email)
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def make_device(env, h, name="Alex's iPhone"):
    r = env.client.post("/v1/devices", headers=h, json={
        "name": name, "platform": "ios",
        "profile_identifier": "org.paxpeace.pax.ios.test", "removal_password": PW})
    assert r.status_code == 201, r.text
    return r.json()["device_id"]


def past_grace(env):
    env.clock.advance(env.settings.grace_seconds + 1)


# ------------------------------------------------------------------ accounts
def test_health_and_crisis_lines(env):
    assert env.client.get("/v1/health").json()["ok"] is True
    lines = env.client.get("/v1/crisis-lines").json()["crisis_lines"]
    contacts = " ".join(c["contact"] for c in lines)
    assert "116 123" in contacts and "988" in contacts


def test_register_account_and_auth(env):
    h = make_account(env)
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["email"] == "user@example.com"
    assert me["wait_seconds"] == 72 * HOUR
    assert env.client.get("/v1/accounts/me").status_code == 401
    assert env.client.get("/v1/accounts/me", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert env.client.post("/v1/accounts", json={"email": "USER@example.com"}).status_code == 409


# ------------------------------------------------------------------- storage
def test_password_encrypted_at_rest(env):
    h = make_account(env)
    make_device(env, h)
    raw = Path(env.settings.db_path).read_bytes()
    assert PW.encode() not in raw
    con = sqlite3.connect(env.settings.db_path)
    blob = con.execute("SELECT password_ct FROM devices").fetchone()[0]
    assert PW.encode() not in blob and len(blob) > len(PW)
    tok = con.execute("SELECT token_hash FROM accounts").fetchone()[0]
    assert not tok.startswith("pax_")  # only the hash is stored


def test_device_records_install_time_and_grace(env):
    h = make_account(env)
    did = make_device(env, h)
    d = env.client.get(f"/v1/devices/{did}", headers=h).json()
    assert d["installed_at"] == T0
    assert d["grace_until"] == T0 + 3600
    assert d["in_grace_period"] is True
    assert "removal_password" not in d


def test_devices_are_scoped_to_account(env):
    h1 = make_account(env, "a@example.com")
    h2 = make_account(env, "b@example.com")
    did = make_device(env, h1)
    assert env.client.get(f"/v1/devices/{did}", headers=h2).status_code == 404
    assert env.client.post(f"/v1/devices/{did}/removal-request", headers=h2).status_code == 404


# ----------------------------------------------------------------- wait time
def test_wait_increase_is_immediate(env):
    h = make_account(env)
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 10}).json()
    assert r["wait_seconds"] == 10 * DAY
    assert r["pending_wait_seconds"] is None


def test_wait_decrease_waits_out_current_wait(env):
    h = make_account(env)
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 10})
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 4}).json()
    assert r["wait_seconds"] == 10 * DAY
    assert r["pending_wait_seconds"] == 4 * DAY
    assert r["pending_wait_effective_at"] == T0 + 10 * DAY
    env.clock.advance(10 * DAY - 1)
    assert env.client.get("/v1/accounts/me", headers=h).json()["wait_seconds"] == 10 * DAY
    env.clock.advance(1)
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["wait_seconds"] == 4 * DAY and me["pending_wait_seconds"] is None


def test_increase_cancels_pending_decrease(env):
    h = make_account(env)
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 3})  # same as default
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 30})
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 5})
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 40}).json()
    assert r["wait_seconds"] == 40 * DAY and r["pending_wait_seconds"] is None


# v0.8.9: the minimum is 24 hours everywhere (was 3 days on the server).
@pytest.mark.parametrize("body", [{"wait_hours": 23}, {"wait_days": 366}, {"wait_hours": 1},
                                  {}, {"wait_days": 3, "wait_hours": 72}])
def test_wait_bounds(env, body):
    h = make_account(env)
    assert env.client.put("/v1/accounts/me/wait", headers=h, json=body).status_code in (400, 422)


def test_wait_hours_accepted(env):
    h = make_account(env)
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_hours": 100}).json()
    assert r["wait_seconds"] == 100 * HOUR


# ------------------------------------------------------------------- removal
def test_grace_period_removal_is_immediate(env):
    h = make_account(env)
    did = make_device(env, h)
    env.clock.advance(50 * 60)
    r = env.client.post(f"/v1/devices/{did}/removal-request", headers=h).json()
    assert r["removal_request"]["kind"] == "grace"
    assert r["removal_request"]["can_reveal"] is True
    rv = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                         json={"confirm": True})
    assert rv.status_code == 200 and rv.json()["removal_password"] == PW


def test_standard_removal_full_flow(env):
    h = make_account(env)
    env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "partner@example.com"})
    did = make_device(env, h)
    past_grace(env)
    r = env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    assert r.status_code == 201
    rr = r.json()["removal_request"]
    assert rr["kind"] == "standard" and rr["seconds_remaining"] == 72 * HOUR
    assert "removal_requested" in env.mail.kinds_to("partner@example.com")
    assert "removal_requested" in env.mail.kinds_to("user@example.com")

    # Too early
    env.clock.advance(72 * HOUR - 1)
    early = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                            json={"confirm": True})
    assert early.status_code == 425
    assert "removal_password" not in early.text and PW not in early.text

    # Needs a separate confirm
    env.clock.advance(1)
    no = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                         json={"confirm": False})
    assert no.status_code == 400

    ok = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                         json={"confirm": True})
    assert ok.status_code == 200 and ok.json()["removal_password"] == PW
    assert "password_revealed" in env.mail.kinds_to("partner@example.com")
    # No email ever carries the password.
    assert all(PW not in m.body and PW not in m.subject for m in env.mail.outbox)

    d = env.client.get(f"/v1/devices/{did}", headers=h).json()
    assert d["released_at"] is not None
    # Re-fetch within the window is idempotent; new requests are refused.
    again = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                            json={"confirm": True})
    assert again.json()["removal_password"] == PW
    assert env.client.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 409


def test_request_uses_wait_at_request_time(env):
    h = make_account(env)
    did = make_device(env, h)
    past_grace(env)
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 30})
    rr = env.client.post(f"/v1/devices/{did}/removal-request", headers=h).json()["removal_request"]
    assert rr["seconds_remaining"] == 30 * DAY


def test_pending_decrease_does_not_shorten_request(env):
    h = make_account(env)
    did = make_device(env, h)
    past_grace(env)
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 30})
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 3})
    rr = env.client.post(f"/v1/devices/{did}/removal-request", headers=h).json()["removal_request"]
    assert rr["seconds_remaining"] == 30 * DAY


def test_duplicate_request_conflict(env):
    h = make_account(env)
    did = make_device(env, h)
    past_grace(env)
    env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    r = env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    assert r.status_code == 409 and r.json()["removal_request"]["status"] == "pending"


def test_cancel_request(env):
    h = make_account(env)
    env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "partner@example.com"})
    did = make_device(env, h)
    past_grace(env)
    env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    r = env.client.post(f"/v1/devices/{did}/removal-request/cancel", headers=h)
    assert r.status_code == 200 and r.json()["removal_request"] is None
    assert "removal_cancelled" in env.mail.kinds_to("partner@example.com")
    env.clock.advance(100 * DAY)
    assert env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                           json={"confirm": True}).status_code == 404
    assert env.client.post(f"/v1/devices/{did}/removal-request/cancel", headers=h).status_code == 404


def test_unconfirmed_request_lapses(env):
    h = make_account(env)
    did = make_device(env, h)
    past_grace(env)
    env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    env.clock.advance(72 * HOUR + env.settings.reveal_window_seconds + 1)
    r = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                        json={"confirm": True})
    assert r.status_code == 410
    # A fresh request starts a fresh full wait.
    rr = env.client.post(f"/v1/devices/{did}/removal-request", headers=h).json()["removal_request"]
    assert rr["seconds_remaining"] == 72 * HOUR


def test_confirm_without_request(env):
    h = make_account(env)
    did = make_device(env, h)
    assert env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                           json={"confirm": True}).status_code == 404


# ------------------------------------------------------------------- partner
def test_first_partner_immediate(env):
    h = make_account(env)
    r = env.client.put("/v1/accounts/me/partner", headers=h,
                       json={"email": "partner@example.com"}).json()
    assert r["partner_email"] == "partner@example.com"
    assert "partner_added" in env.mail.kinds_to("partner@example.com")


def test_cannot_partner_self(env):
    h = make_account(env)
    assert env.client.put("/v1/accounts/me/partner", headers=h,
                          json={"email": "user@example.com"}).status_code == 400


def test_partner_change_subject_to_wait(env):
    h = make_account(env)
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 5})
    env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "old@example.com"})
    r = env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "new@example.com"}).json()
    assert r["partner_email"] == "old@example.com"
    assert r["pending_partner_email"] == "new@example.com"
    assert r["pending_partner_effective_at"] == T0 + 5 * DAY
    assert "partner_change_requested" in env.mail.kinds_to("old@example.com")
    env.clock.advance(5 * DAY)
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["partner_email"] == "new@example.com" and me["pending_partner_email"] is None
    assert "partner_added" in env.mail.kinds_to("new@example.com")


def test_partner_removal_subject_to_wait_and_cancellable(env):
    h = make_account(env)
    env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "p@example.com"})
    r = env.client.put("/v1/accounts/me/partner", headers=h, json={"email": None}).json()
    assert r["partner_email"] == "p@example.com" and r["pending_partner_email"] == ""
    # Old partner still gets notified of removal requests during the wait.
    did = make_device(env, h)
    env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    assert "removal_requested" in env.mail.kinds_to("p@example.com")
    # Re-asserting the partner cancels the pending removal.
    r = env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "p@example.com"}).json()
    assert r["pending_partner_email"] is None
    env.clock.advance(10 * DAY)
    assert env.client.get("/v1/accounts/me", headers=h).json()["partner_email"] == "p@example.com"


def test_partner_told_about_wait_decrease(env):
    h = make_account(env)
    env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "p@example.com"})
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 20})
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 3})
    assert "wait_decrease_requested" in env.mail.kinds_to("p@example.com")


# ----------------------------------------------------------------- emergency
def test_emergency_release_cooloff_and_crisis_lines(env):
    h = make_account(env)
    env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "p@example.com"})
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 60})
    did = make_device(env, h)
    past_grace(env)
    r = env.client.post(f"/v1/devices/{did}/emergency", headers=h,
                        json={"reason": "Phone needs to be wiped for a repair today"})
    assert r.status_code == 201
    body = r.json()
    assert body["removal_request"]["kind"] == "emergency"
    assert body["removal_request"]["seconds_remaining"] == 24 * HOUR
    assert "116 123" in body["message"] and "988" in body["message"]
    auto = [m for m in env.mail.outbox if m.kind == "emergency_auto_reply"]
    assert auto and "116 123" in auto[0].body and "988" in auto[0].body
    assert "emergency_requested" in env.mail.kinds_to("p@example.com")

    env.clock.advance(24 * HOUR)
    ok = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                         json={"confirm": True})
    assert ok.status_code == 200 and ok.json()["removal_password"] == PW


def test_emergency_shortens_existing_request(env):
    h = make_account(env)
    env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 30})
    did = make_device(env, h)
    past_grace(env)
    env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    r = env.client.post(f"/v1/devices/{did}/emergency", headers=h,
                        json={"reason": "Genuine emergency, need the phone reset"}).json()
    assert r["removal_request"]["seconds_remaining"] == 24 * HOUR


def test_emergency_rate_limited(env):
    h = make_account(env)
    d1 = make_device(env, h, "iPhone")
    d2 = make_device(env, h, "iPad")
    past_grace(env)
    assert env.client.post(f"/v1/devices/{d1}/emergency", headers=h,
                           json={"reason": "first emergency reason here"}).status_code == 201
    env.clock.advance(30 * DAY)
    r = env.client.post(f"/v1/devices/{d2}/emergency", headers=h,
                        json={"reason": "second emergency reason here"})
    assert r.status_code == 429
    assert "crisis_lines" in r.json()
    env.clock.advance(61 * DAY)
    assert env.client.post(f"/v1/devices/{d2}/emergency", headers=h,
                           json={"reason": "third emergency reason here"}).status_code == 201


def test_emergency_requires_reason(env):
    h = make_account(env)
    did = make_device(env, h)
    r = env.client.post(f"/v1/devices/{did}/emergency", headers=h, json={"reason": "help"})
    assert r.status_code == 400 and "crisis_lines" in r.json()


def test_emergency_cooloff_configurable(tmp_path):
    clock, mail = FakeClock(), MemoryEmailSender()
    s = Settings(db_path=str(tmp_path / "x.db"), server_key_b64=generate_key_b64(),
                 emergency_cooloff_seconds=2 * HOUR)
    c = TestClient(create_app(s, clock=clock, sender=mail))
    tok = verified_signup(c, "u@example.com").json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    did = c.post("/v1/devices", headers=h, json={"name": "i", "platform": "ios",
                 "profile_identifier": "x.y.z", "removal_password": PW}).json()["device_id"]
    clock.advance(8 * DAY)
    r = c.post(f"/v1/devices/{did}/emergency", headers=h,
               json={"reason": "need it now please, emergency"}).json()
    assert r["removal_request"]["seconds_remaining"] == 2 * HOUR


# -------------------------------------------------------------------- crypto
def test_ciphertext_bound_to_device(env):
    from pax_server.crypto import SecretBox
    box = SecretBox(env.settings.server_key_b64)
    ct = box.encrypt(PW, aad="device-a")
    assert box.decrypt(ct, aad="device-a") == PW
    with pytest.raises(Exception):
        box.decrypt(ct, aad="device-b")


def test_missing_server_key_refuses_to_start(tmp_path):
    with pytest.raises(Exception):
        create_app(Settings(db_path=str(tmp_path / "y.db"), server_key_b64=""))


# ---------------------------------------------------------- v0.7.0 support codes
def test_error_bodies_carry_pax_support_codes(env):
    h = make_account(env)
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 366})
    assert r.status_code == 400 and r.json()["pax_code"] == "PAX-ESCROW-002"
    r = env.client.get("/v1/accounts/me", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401 and r.json()["pax_code"] == "PAX-ESCROW-001"
