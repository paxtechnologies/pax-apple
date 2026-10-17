# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.15 verified support release on the server (iPhone and iPad escrow).

POST /v1/devices/{id}/support-release/redeem takes a one-time code from Pax
support for that device: switch on, signature, device, expiry and nonce checked,
partner emailed FIRST (503 otherwise, nothing released, code still usable), then
the password is released to the owner at once. PUT /v1/devices/{id}/support-release
turns the switch off at once, or on after the wait with the partner told first.
Devices registered before 0.8.15 (or by an older app) stay off."""
import sqlite3
import sys
from pathlib import Path

import pytest

from test_escrow_api import PW
from test_v085_limits import PARTNER, account, build

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "guard"))
import ed25519  # noqa: E402
import support_code as sc  # noqa: E402

SEED = b"\x07" * 32
PUB = ed25519.public_key(SEED)


@pytest.fixture(autouse=True)
def test_key(monkeypatch):
    monkeypatch.setattr(sc, "SUPPORT_PUBLIC_KEYS_HEX", [PUB.hex()])


@pytest.fixture
def env(tmp_path):
    return build(tmp_path)


def device(env, h, support=True, send_flag=True):
    body = {"name": "Test iPhone", "platform": "ios",
            "profile_identifier": "org.paxpeace.pax.ios.test", "removal_password": PW}
    if send_flag:
        body["support_release"] = support
    r = env.client.post("/v1/devices", headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def code(env, support_id, lifetime=24 * 3600, issued=None):
    return sc.issue(SEED, support_id, issued if issued is not None else env.clock.now(), lifetime=lifetime)


def redeem(env, h, dev_id, c):
    return env.client.post(f"/v1/devices/{dev_id}/support-release/redeem", headers=h, json={"code": c})


def events(env, kind):
    return [r["detail"] for r in env.escrow.db.all("SELECT detail FROM events WHERE kind=? ORDER BY id", (kind,))]


def test_status_shows_support_id_and_switch(env):
    h = account(env)
    d = device(env, h)
    assert sc.normalise_support_id(d["support_id"]) == d["support_id"]
    assert d["support_release"] == {"allowed": True, "pending_on_at": None}


def test_older_app_registers_with_the_switch_off(env):
    h = account(env)
    d = device(env, h, send_flag=False)
    assert d["support_release"]["allowed"] is False


def test_code_releases_at_once_partner_first(env):
    h = account(env, partner=PARTNER)
    d = device(env, h)
    env.client.post(f"/v1/devices/{d['device_id']}/removal-request", headers=h)   # a wait already running
    before = len(env.mail.outbox)
    r = redeem(env, h, d["device_id"], code(env, d["support_id"]))
    assert r.status_code == 200, r.text
    assert r.json()["removal_password"] == PW
    sent = env.mail.outbox[before:]
    assert sent[0].to == PARTNER and sent[0].kind == "support_release_used"     # the partner first
    st = env.client.get(f"/v1/devices/{d['device_id']}", headers=h).json()
    assert st["released_at"] is not None
    assert events(env, "support_release_used")


def test_wrong_device(env):
    h = account(env)
    a, b = device(env, h), device(env, h)
    r = redeem(env, h, a["device_id"], code(env, b["support_id"]))
    assert r.status_code == 403 and r.json()["error"] == "support_code_wrong_device"
    assert r.json()["pax_code"] == "PAX-ESCROW-014"
    assert events(env, "support_code_refused") == ["PAX-ESCROW-014"]


def test_bad_signature_and_malformed(env):
    h = account(env)
    d = device(env, h)
    forged = sc.issue(b"\x09" * 32, d["support_id"], env.clock.now())
    r = redeem(env, h, d["device_id"], forged)
    assert r.status_code == 403 and r.json()["pax_code"] == "PAX-ESCROW-013"
    r = redeem(env, h, d["device_id"], "PAXS-ABCDE-FGHIJ-KLMNO")
    assert r.status_code == 400 and r.json()["pax_code"] == "PAX-ESCROW-012"


def test_expired(env):
    h = account(env)
    d = device(env, h)
    c = code(env, d["support_id"], lifetime=3600)
    env.clock.advance(3601)
    r = redeem(env, h, d["device_id"], c)
    assert r.status_code == 410 and r.json()["pax_code"] == "PAX-ESCROW-015"


def test_reused_nonce(env):
    h = account(env)
    d = device(env, h)
    c = code(env, d["support_id"])
    assert redeem(env, h, d["device_id"], c).status_code == 200
    r = redeem(env, h, d["device_id"], c)
    assert r.status_code in (409,)   # used (checked before "already released")
    assert r.json()["pax_code"] == "PAX-ESCROW-016"


def test_switch_off_rejects_every_code(env):
    h = account(env)
    d = device(env, h, support=False)
    r = redeem(env, h, d["device_id"], code(env, d["support_id"]))
    assert r.status_code == 403 and r.json()["pax_code"] == "PAX-ESCROW-017"
    assert env.client.get(f"/v1/devices/{d['device_id']}", headers=h).json()["released_at"] is None


def test_off_is_immediate_on_waits_with_partner_told(env):
    h = account(env, partner=PARTNER)
    d = device(env, h)
    dev = d["device_id"]
    r = env.client.put(f"/v1/devices/{dev}/support-release", headers=h, json={"allowed": False})
    assert r.json()["support_release"]["allowed"] is False
    assert redeem(env, h, dev, code(env, d["support_id"])).json()["pax_code"] == "PAX-ESCROW-017"
    before = len(env.mail.outbox)
    r = env.client.put(f"/v1/devices/{dev}/support-release", headers=h, json={"allowed": True})
    sr = r.json()["support_release"]
    wait = env.client.get("/v1/accounts/me", headers=h).json()["wait_seconds"]
    assert sr["allowed"] is False and sr["pending_on_at"] == env.clock.now() + wait
    assert env.mail.outbox[before].to == PARTNER and env.mail.outbox[before].kind == "support_release_on_requested"
    env.clock.advance(wait - 1)
    assert env.client.get(f"/v1/devices/{dev}", headers=h).json()["support_release"]["allowed"] is False
    env.clock.advance(1)
    assert env.client.get(f"/v1/devices/{dev}", headers=h).json()["support_release"]["allowed"] is True
    assert redeem(env, h, dev, code(env, d["support_id"])).status_code == 200


def test_turning_on_fails_closed(env):
    h = account(env, partner=PARTNER)
    d = device(env, h, support=False)
    env.mail.down.add(PARTNER)
    r = env.client.put(f"/v1/devices/{d['device_id']}/support-release", headers=h, json={"allowed": True})
    assert r.status_code == 503 and r.json()["pax_code"] == "PAX-ESCROW-010"
    st = env.client.get(f"/v1/devices/{d['device_id']}", headers=h).json()["support_release"]
    assert st == {"allowed": False, "pending_on_at": None}


def test_partner_email_failure_blocks_the_release(env):
    h = account(env, partner=PARTNER)
    d = device(env, h)
    c = code(env, d["support_id"])
    env.mail.down.add(PARTNER)
    r = redeem(env, h, d["device_id"], c)
    assert r.status_code == 503 and r.json()["pax_code"] == "PAX-ESCROW-018"
    assert "removal_password" not in r.json()
    assert env.client.get(f"/v1/devices/{d['device_id']}", headers=h).json()["released_at"] is None
    env.mail.down.clear()
    assert redeem(env, h, d["device_id"], c).status_code == 200      # the code wasn't used up


def test_only_the_owner_can_redeem(env):
    h = account(env)
    d = device(env, h)
    other = account(env, email="someone@example.com")
    r = redeem(env, other, d["device_id"], code(env, d["support_id"]))
    assert r.status_code == 404


def test_rate_limited(env):
    h = account(env)
    d = device(env, h)
    for _ in range(10):
        redeem(env, h, d["device_id"], "PAXS-ABCDE-FGHIJ-KLMNO")
    r = redeem(env, h, d["device_id"], code(env, d["support_id"]))
    assert r.status_code == 429 and r.json()["pax_code"] == "PAX-ESCROW-019"


def test_migration_keeps_old_devices_off(tmp_path):
    """A 0.8.14 database: devices has no support columns. Opening it with 0.8.15
    adds them OFF, gives each device a support ID on first read, and never turns
    the switch on."""
    env = build(tmp_path)
    h = account(env)
    d = device(env, h)
    env.escrow.db.close()
    db = sqlite3.connect(tmp_path / "pax.sqlite3")
    db.execute("ALTER TABLE devices DROP COLUMN support_pending_on")
    db.execute("ALTER TABLE devices DROP COLUMN support_release")
    db.execute("ALTER TABLE devices DROP COLUMN support_id")
    db.commit()
    db.close()
    env2 = build(tmp_path)
    st = env2.client.get(f"/v1/devices/{d['device_id']}", headers=h).json()
    assert st["support_release"]["allowed"] is False and st["support_id"]
    assert env2.client.get(f"/v1/devices/{d['device_id']}", headers=h).json()["support_id"] == st["support_id"]
    build(tmp_path)                                    # a restart runs the migration again: still off
    env3 = build(tmp_path)
    st = env3.client.get(f"/v1/devices/{d['device_id']}", headers=h).json()
    assert st["support_release"]["allowed"] is False
    r = redeem(env3, h, d["device_id"], code(env3, st["support_id"]))
    assert r.json()["pax_code"] == "PAX-ESCROW-017"
