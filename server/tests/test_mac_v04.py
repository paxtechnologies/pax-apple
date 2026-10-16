# SPDX-License-Identifier: GPL-3.0-only
"""v0.4: 'mac' device type (self-locked Mac), 1-day test wait via env, adblock setting."""
import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pax_server.config import DAY, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.db import Database  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402

from test_escrow_api import FakeClock, make_account  # noqa: E402

ADMIN_PW = "Ab3dE5gH7jK9mN2pQ4sT6vW8yZ1bC3dF"  # 32 chars, like paxadmin's


def _env(tmp_path, **settings):
    clock, mail = FakeClock(), MemoryEmailSender()
    s = Settings(db_path=str(tmp_path / "pax.sqlite3"), server_key_b64=generate_key_b64(),
                 **settings)
    client = TestClient(create_app(s, clock=clock, sender=mail))

    class E:
        pass
    e = E()
    e.client, e.clock, e.mail, e.settings = client, clock, mail, s
    return e


def _mac(e, h):
    r = e.client.post("/v1/devices", headers=h, json={
        "name": "Alex's MacBook Pro", "platform": "mac",
        "profile_identifier": "org.paxpeace.pax.macos-selflock.test",
        "removal_password": ADMIN_PW})
    assert r.status_code == 201, r.text
    return r.json()


def test_mac_device_type_accepted_and_released_after_wait(tmp_path):
    e = _env(tmp_path, grace_seconds=0)
    h = make_account(e)
    d = _mac(e, h)
    assert d["platform"] == "mac"
    did = d["device_id"]
    assert e.client.get(f"/v1/devices/{did}", headers=h).json()["platform"] == "mac"
    r = e.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    assert r.status_code == 201
    assert r.json()["removal_request"]["seconds_remaining"] == 3 * DAY
    r = e.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 425
    e.clock.advance(3 * DAY)
    r = e.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 200 and r.json()["removal_password"] == ADMIN_PW


def test_mac_grace_period_releases_immediately(tmp_path):
    e = _env(tmp_path)
    h = make_account(e)
    did = _mac(e, h)["device_id"]
    e.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    r = e.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.json()["removal_password"] == ADMIN_PW


def test_unknown_platform_still_rejected(tmp_path):
    e = _env(tmp_path)
    h = make_account(e)
    r = e.client.post("/v1/devices", headers=h, json={
        "name": "x", "platform": "windows", "profile_identifier": "abc", "removal_password": ADMIN_PW})
    assert r.status_code == 422


def test_production_minimum_is_24_hours(tmp_path):
    """v0.8.9: one minimum everywhere (24 h, as on a Mac's own key); was 3 days."""
    e = _env(tmp_path)
    h = make_account(e)
    assert e.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 1}).status_code == 200
    assert e.client.put("/v1/accounts/me/wait", headers=h, json={"wait_hours": 23}).status_code == 400
    assert Settings().min_wait_seconds == DAY


def test_one_day_wait_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PAX_MIN_WAIT_SECONDS", str(DAY))
    monkeypatch.setenv("PAX_DEFAULT_WAIT_SECONDS", str(DAY))
    monkeypatch.setenv("PAX_GRACE_SECONDS", "0")
    s = Settings.from_env()
    assert s.min_wait_seconds == DAY and s.default_wait_seconds == DAY
    e = _env(tmp_path, min_wait_seconds=s.min_wait_seconds,
             default_wait_seconds=s.default_wait_seconds, grace_seconds=0)
    h = make_account(e)
    me = e.client.get("/v1/accounts/me", headers=h).json()
    assert me["wait_seconds"] == DAY and me["limits"]["min_wait_seconds"] == DAY
    r = e.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 1})
    assert r.status_code == 200 and r.json()["wait_seconds"] == DAY
    did = _mac(e, h)["device_id"]
    rr = e.client.post(f"/v1/devices/{did}/removal-request", headers=h).json()["removal_request"]
    assert rr["seconds_remaining"] == DAY
    e.clock.advance(DAY)
    r = e.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.json()["removal_password"] == ADMIN_PW


def test_adblock_setting_defaults_on_and_toggles(tmp_path):
    e = _env(tmp_path)
    h = make_account(e)
    assert e.client.get("/v1/accounts/me", headers=h).json()["adblock"] is True
    r = e.client.put("/v1/accounts/me/adblock", headers=h, json={"enabled": False})
    assert r.status_code == 200 and r.json()["adblock"] is False
    assert e.client.get("/v1/accounts/me", headers=h).json()["adblock"] is False
    assert e.client.put("/v1/accounts/me/adblock", headers=h, json={"enabled": True}).json()["adblock"]


def test_old_database_gets_adblock_column(tmp_path):
    path = tmp_path / "old.sqlite3"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, "
                "token_hash TEXT NOT NULL, created_at INTEGER NOT NULL, wait_seconds INTEGER NOT NULL, "
                "pending_wait_seconds INTEGER, pending_wait_effective INTEGER, partner_email TEXT, "
                "pending_partner_email TEXT, pending_partner_effective INTEGER, last_emergency_at INTEGER)")
    con.execute("INSERT INTO accounts(id,email,token_hash,created_at,wait_seconds) VALUES ('a','a@b.c','h',0,1)")
    con.commit()
    con.close()
    db = Database(str(path))
    assert db.one("SELECT adblock FROM accounts WHERE id='a'")["adblock"] == 1


def test_guard_token_reads_lists_and_nothing_else(tmp_path):
    e = _env(tmp_path, grace_seconds=0)
    h = make_account(e)
    did = _mac(e, h)["device_id"]
    gt = e.client.post(f"/v1/devices/{did}/guard-token", headers=h).json()["guard_token"]
    g = {"X-Pax-Guard-Token": gt}
    e.client.post("/v1/blocklist", headers=h, json={"domain": "reddit.com"})
    cfg = e.client.get("/v1/guard/config", headers=g).json()
    assert cfg["blocked"] == ["reddit.com"] and cfg["adblock"] is True and cfg["released"] is False
    # removal still waiting: still blocked
    e.client.post("/v1/blocklist/remove", headers=h, json={"domain": "reddit.com"})
    assert e.client.get("/v1/guard/config", headers=g).json()["blocked"] == ["reddit.com"]
    e.clock.advance(e.settings.blocklist_delay_seconds)
    assert e.client.get("/v1/guard/config", headers=g).json()["blocked"] == []
    # the guard token is not an account token
    assert e.client.get("/v1/accounts/me", headers={"Authorization": f"Bearer {gt}"}).status_code == 401
    assert e.client.post(f"/v1/devices/{did}/removal-request",
                         headers={"Authorization": f"Bearer {gt}"}).status_code == 401
    assert e.client.get("/v1/guard/config", headers={"X-Pax-Guard-Token": "nope"}).status_code == 401
    assert e.client.get("/v1/guard/config").status_code == 401


def test_guard_sees_release_and_adblock_off(tmp_path):
    e = _env(tmp_path)  # grace period: no wait
    h = make_account(e)
    did = _mac(e, h)["device_id"]
    g = {"X-Pax-Guard-Token": e.client.post(f"/v1/devices/{did}/guard-token", headers=h).json()["guard_token"]}
    e.client.put("/v1/accounts/me/adblock", headers=h, json={"enabled": False})
    assert e.client.get("/v1/guard/config", headers=g).json()["adblock"] is False
    e.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    e.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert e.client.get("/v1/guard/config", headers=g).json()["released"] is True


def test_guard_token_only_for_mac(tmp_path):
    e = _env(tmp_path)
    h = make_account(e)
    r = e.client.post("/v1/devices", headers=h, json={
        "name": "iPhone", "platform": "ios", "profile_identifier": "abc", "removal_password": ADMIN_PW})
    did = r.json()["device_id"]
    assert e.client.post(f"/v1/devices/{did}/guard-token", headers=h).status_code == 400


def test_local_reveal_script(tmp_path, capsys, monkeypatch):
    import importlib.util
    e = _env(tmp_path)
    h = make_account(e)
    did = _mac(e, h)["device_id"]
    spec = importlib.util.spec_from_file_location(
        "local_reveal", Path(__file__).resolve().parents[1] / "scripts" / "local_reveal.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setenv("PAX_SERVER_KEY", e.settings.server_key_b64)
    assert mod.main(["--db", e.settings.db_path]) == 0
    assert did in capsys.readouterr().out
    assert mod.main(["--db", e.settings.db_path, "--device", did]) == 0
    assert capsys.readouterr().out.strip() == ADMIN_PW
