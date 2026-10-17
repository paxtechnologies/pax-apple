# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.18 trial day on the server (iPhone and iPad escrow, and Macs on the server path).

A genuinely new set-up (the app sends trial=true and a hashed hardware ID) can be
turned off with no wait for 24 hours; the partner is still emailed first. The day
counts from the account's and the hardware's FIRST trial start, so setting up again,
a new account on the same phone, or an older client never gets a fresh one."""
import pytest

from test_escrow_api import PW
from test_v085_limits import PARTNER, account, build

H, D = 3600, 86400
HW = "ab" * 32          # what the app sends: hex SHA-256 of the ECID / hardware UUID


@pytest.fixture
def env(tmp_path):
    return build(tmp_path)


def device(env, h, trial=True, hw=HW, support=True):
    body = {"name": "Test iPhone", "platform": "ios", "profile_identifier": "org.paxpeace.pax.ios.test",
            "removal_password": PW, "support_release": support}
    if trial is not None:
        body["trial"] = trial
    if hw is not None:
        body["hardware_id"] = hw
    r = env.client.post("/v1/devices", headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def status(env, h, dev):
    return env.client.get(f"/v1/devices/{dev}", headers=h).json()


def request(env, h, dev):
    return env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)


def test_new_setup_gets_a_trial_day(env):
    h = account(env)
    d = device(env, h)
    now = env.clock.now()
    assert d["trial"] == {"active": True, "until": now + D, "ended_at": None}
    assert d["in_grace_period"] and d["grace_until"] == now + D
    env.clock.advance(20 * H)
    r = request(env, h, d["device_id"])
    assert r.status_code == 201, r.text
    rr = r.json()["removal_request"]
    assert rr["kind"] == "trial" and rr["seconds_remaining"] == 0 and rr["can_reveal"]
    c = env.client.post(f"/v1/devices/{d['device_id']}/removal-request/confirm", headers=h, json={"confirm": True})
    assert c.status_code == 200 and c.json()["removal_password"] == PW


def test_after_the_day_the_wait_applies(env):
    h = account(env)
    d = device(env, h)
    env.clock.advance(D + 1)
    st = status(env, h, d["device_id"])
    assert st["trial"]["active"] is False and not st["in_grace_period"]
    rr = request(env, h, d["device_id"]).json()["removal_request"]
    assert rr["kind"] == "standard" and rr["seconds_remaining"] == env.settings.default_wait_seconds


def test_trial_request_lapses_at_the_end_of_the_day(env):
    h = account(env)
    d = device(env, h)
    env.clock.advance(23 * H)
    request(env, h, d["device_id"])
    env.clock.advance(2 * H)
    assert env.escrow.lapse_due() == 1
    assert status(env, h, d["device_id"])["removal_request"] is None


def test_partner_emailed_first_and_fail_closed(env):
    h = account(env, partner=PARTNER)
    d = device(env, h)
    env.mail.down.add(PARTNER)
    r = request(env, h, d["device_id"])
    assert r.status_code == 503 and status(env, h, d["device_id"])["removal_request"] is None
    env.mail.down.clear()
    r = request(env, h, d["device_id"])
    assert r.status_code == 201
    assert any(m.to == PARTNER and m.kind == "removal_requested" for m in env.mail.outbox)
    assert "trial day" in [m for m in env.mail.outbox if m.to == PARTNER][-1].body


def test_older_app_or_no_hardware_id_gets_no_trial(env):
    h = account(env)
    assert device(env, h, trial=None, hw=None)["trial"] is None           # older app
    h2 = account(env, email="two@example.com")
    assert device(env, h2, trial=True, hw=None)["trial"] is None           # no hardware ID
    h3 = account(env, email="three@example.com")
    assert device(env, h3, trial=True, hw="not-hex!")["trial"] is None


def test_setting_up_again_only_gets_the_rest_of_the_first_day(env):
    h = account(env)
    first = device(env, h)
    env.clock.advance(10 * H)
    again = device(env, h)
    assert again["trial"]["until"] == first["trial"]["until"]
    env.clock.advance(2 * D)
    assert device(env, h)["trial"] is None


def test_a_new_account_on_the_same_phone_gets_no_new_trial(env):
    h = account(env)
    device(env, h)
    env.clock.advance(2 * D)
    h2 = account(env, email="fresh@example.com")
    assert device(env, h2)["trial"] is None
    # That attempt started the fresh account's own day with the phone's old start,
    # so another phone on it gets nothing either.
    assert device(env, h2, hw="cd" * 32)["trial"] is None


def test_an_existing_account_from_before_gets_no_trial(env):
    h = account(env)
    device(env, h, trial=None, hw=None)          # set up before 0.8.18
    env.clock.advance(5 * D)
    assert device(env, h, hw="ef" * 32)["trial"] is None


def test_existing_devices_are_migrated_without_a_trial(tmp_path):
    """A 0.8.17 database: the new columns arrive empty, so no existing device or
    account ever gets a trial day."""
    import sqlite3
    from pax_server.db import Database
    path = tmp_path / "old.sqlite3"
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL, wait_seconds INTEGER NOT NULL, pending_wait_seconds INTEGER,
            pending_wait_effective INTEGER, partner_email TEXT, pending_partner_email TEXT,
            pending_partner_effective INTEGER, last_emergency_at INTEGER);
        CREATE TABLE devices (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, name TEXT NOT NULL,
            platform TEXT NOT NULL, profile_identifier TEXT NOT NULL, password_ct BLOB NOT NULL,
            installed_at INTEGER NOT NULL, released_at INTEGER);
        INSERT INTO accounts VALUES ('a', 'me@example.com', 'h', 1, 259200, NULL, NULL, NULL, NULL, NULL, NULL);
        INSERT INTO devices VALUES ('d', 'a', 'Old iPhone', 'ios', 'p', x'00', 1, NULL);
    """)
    c.commit()
    c.close()
    db = Database(str(path))
    d = db.one("SELECT * FROM devices WHERE id='d'")
    assert d["trial_until"] is None and d["trial_ended_at"] is None and d["support_release"] == 0
    assert db.one("SELECT trial_started_at FROM accounts WHERE id='a'")["trial_started_at"] is None


def test_start_my_wait_now(env):
    h = account(env)
    d = device(env, h)
    env.clock.advance(2 * H)
    request(env, h, d["device_id"])
    r = env.client.post(f"/v1/devices/{d['device_id']}/trial/end", headers=h)
    assert r.status_code == 200, r.text
    st = r.json()
    assert st["trial"]["active"] is False and st["trial"]["ended_at"] == env.clock.now()
    assert st["removal_request"] is None and not st["in_grace_period"]
    rr = request(env, h, d["device_id"]).json()["removal_request"]
    assert rr["kind"] == "standard" and rr["seconds_remaining"] == env.settings.default_wait_seconds
    assert env.client.post(f"/v1/devices/{d['device_id']}/trial/end", headers=h).status_code == 200


def test_support_release_on_is_instant_in_trial_partner_first(env):
    h = account(env, partner=PARTNER)
    d = device(env, h, support=False)
    env.mail.down.add(PARTNER)
    r = env.client.put(f"/v1/devices/{d['device_id']}/support-release", headers=h, json={"allowed": True})
    assert r.status_code == 503
    assert status(env, h, d["device_id"])["support_release"]["allowed"] is False
    env.mail.down.clear()
    r = env.client.put(f"/v1/devices/{d['device_id']}/support-release", headers=h, json={"allowed": True})
    assert r.status_code == 200
    assert r.json()["support_release"] == {"allowed": True, "pending_on_at": None}


def test_support_release_on_after_trial_takes_the_wait(env):
    h = account(env)
    d = device(env, h, support=False)
    env.client.post(f"/v1/devices/{d['device_id']}/trial/end", headers=h)
    r = env.client.put(f"/v1/devices/{d['device_id']}/support-release", headers=h, json={"allowed": True})
    sr = r.json()["support_release"]
    assert sr["allowed"] is False and sr["pending_on_at"] == env.clock.now() + env.settings.default_wait_seconds


def test_support_release_default_on_for_new_setups(env):
    """Unchanged since 0.8.15: the app sends its set-up choice (on by default)."""
    h = account(env)
    assert device(env, h)["support_release"]["allowed"] is True


def test_trial_can_be_turned_off_on_a_server(tmp_path):
    env = build(tmp_path, trial_seconds=0)
    h = account(env)
    assert device(env, h)["trial"] is None


def test_emergency_in_trial_has_no_cooling_off(env):
    h = account(env)
    d = device(env, h)
    env.clock.advance(5 * H)
    r = env.client.post(f"/v1/devices/{d['device_id']}/emergency", headers=h,
                        json={"reason": "I need this phone for work right now"})
    assert r.status_code == 201
    assert r.json()["removal_request"]["can_reveal"]
