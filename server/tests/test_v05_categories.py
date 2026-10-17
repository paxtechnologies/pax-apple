# SPDX-License-Identifier: GPL-3.0-only
"""v0.5: built-in categories. "bypass" is always on; "remote_desktop" is on by
default, turning it off waits like a removal (cancellable, partner told), and
turning it on is immediate. pax-guard and pax-dns both see the effective value."""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pax_server.config import HOUR  # noqa: E402
from pax_server.db import Database  # noqa: E402

from test_escrow_api import make_account  # noqa: E402
from test_mac_v04 import _env, _mac  # noqa: E402


def _cat(e, h, cid):
    r = e.client.get("/v1/categories", headers=h)
    assert r.status_code == 200, r.text
    return next(c for c in r.json()["categories"] if c["id"] == cid)


def _guard(e, h):
    d = _mac(e, h)
    g = e.client.post(f"/v1/devices/{d['device_id']}/guard-token", headers=h).json()["guard_token"]
    return {"X-Pax-Guard-Token": g}


def test_defaults_on_and_bypass_cannot_be_turned_off(tmp_path):
    e = _env(tmp_path)
    h = make_account(e)
    assert _cat(e, h, "bypass")["enabled"] is True
    assert _cat(e, h, "bypass")["can_turn_off"] is False
    assert _cat(e, h, "remote_desktop")["enabled"] is True
    r = e.client.put("/v1/categories/bypass", headers=h, json={"enabled": False})
    assert r.status_code == 409
    assert e.client.put("/v1/categories/nope", headers=h, json={"enabled": False}).status_code == 404
    assert e.client.get("/v1/accounts/me", headers=h).json()["block_remote_desktop"] is True


def test_turning_remote_desktop_off_waits_and_notifies_partner(tmp_path):
    e = _env(tmp_path, blocklist_delay_seconds=72 * HOUR)
    h = make_account(e)
    e.client.put("/v1/accounts/me/partner", headers=h, json={"email": "partner@example.com"})
    gh = _guard(e, h)
    r = e.client.put("/v1/categories/remote-desktop", headers=h, json={"enabled": False})
    assert r.status_code == 202, r.text
    req = r.json()["request"]
    assert req["action"] == "remote_desktop_off" and req["seconds_remaining"] == 72 * HOUR
    # still blocked while waiting, for the API, pax-guard and the pax-dns feed
    assert _cat(e, h, "remote_desktop")["enabled"] is True
    assert _cat(e, h, "remote_desktop")["pending"]["request_id"] == req["request_id"]
    assert e.client.get("/v1/guard/config", headers=gh).json()["categories"]["remote_desktop"] is True
    # a second request is refused
    assert e.client.put("/v1/categories/remote_desktop", headers=h,
                        json={"enabled": False}).status_code == 409
    assert "blocklist_remote_desktop_off_requested" in e.mail.kinds_to("partner@example.com")
    e.clock.advance(72 * HOUR)
    assert _cat(e, h, "remote_desktop")["enabled"] is False
    assert e.client.get("/v1/guard/config", headers=gh).json()["categories"] == {
        "bypass": True, "remote_desktop": False, "family_layer": False}


def test_cancel_and_turn_back_on_is_immediate(tmp_path):
    e = _env(tmp_path)
    h = make_account(e)
    rid = e.client.put("/v1/categories/remote_desktop", headers=h,
                       json={"enabled": False}).json()["request"]["request_id"]
    r = e.client.post(f"/v1/blocklist/requests/{rid}/cancel", headers=h)
    assert r.status_code == 200, r.text
    e.clock.advance(1000 * HOUR)
    assert _cat(e, h, "remote_desktop")["enabled"] is True
    # off for real, then on again: no wait
    e.client.put("/v1/categories/remote_desktop", headers=h, json={"enabled": False})
    e.clock.advance(1000 * HOUR)
    assert _cat(e, h, "remote_desktop")["enabled"] is False
    r = e.client.put("/v1/categories/remote_desktop", headers=h, json={"enabled": True})
    assert r.status_code == 200 and _cat(e, h, "remote_desktop")["enabled"] is True


def test_turning_on_cancels_a_pending_off(tmp_path):
    e = _env(tmp_path)
    h = make_account(e)
    e.client.put("/v1/categories/remote_desktop", headers=h, json={"enabled": False})
    e.client.put("/v1/categories/remote_desktop", headers=h, json={"enabled": True})
    assert _cat(e, h, "remote_desktop")["pending"] is None
    e.clock.advance(1000 * HOUR)
    assert _cat(e, h, "remote_desktop")["enabled"] is True


def test_dns_feed_carries_remote_desktop(tmp_path):
    e = _env(tmp_path, internal_api_key="k" * 32)
    h = make_account(e)
    e.client.get("/v1/dns", headers=h)
    feed = e.client.get("/internal/v1/dns/changes?since=0", headers={"X-Pax-Internal-Key": "k" * 32})
    assert feed.json()["accounts"][0]["categories"] == {"remote_desktop": True, "family_layer": False}


def test_old_database_gets_remote_desktop_column(tmp_path):
    path = tmp_path / "old.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, "
                 "token_hash TEXT NOT NULL, created_at INTEGER NOT NULL, wait_seconds INTEGER NOT NULL, "
                 "pending_wait_seconds INTEGER, pending_wait_effective INTEGER, partner_email TEXT, "
                 "pending_partner_email TEXT, pending_partner_effective INTEGER, last_emergency_at INTEGER)")
    conn.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) "
                 "VALUES ('a', 'x@example.com', 'h', 0, 1)")
    conn.commit()
    conn.close()
    db = Database(str(path))
    row = db.one("SELECT adblock, block_remote_desktop FROM accounts WHERE id='a'")
    assert row["adblock"] == 1 and row["block_remote_desktop"] == 1


def test_v0818_family_layer_off_by_default_on_instant_off_waits(tmp_path):
    e = _env(tmp_path, blocklist_delay_seconds=72 * HOUR)
    h = make_account(e)
    gh = _guard(e, h)
    assert _cat(e, h, "family_layer")["enabled"] is False
    r = e.client.put("/v1/categories/family_layer", headers=h, json={"enabled": True})
    assert r.status_code == 200, r.text
    assert _cat(e, h, "family_layer")["enabled"] is True
    assert e.client.get("/v1/guard/config", headers=gh).json()["categories"]["family_layer"] is True
    r = e.client.put("/v1/categories/family_layer", headers=h, json={"enabled": False})
    assert r.status_code == 202 and r.json()["request"]["action"] == "family_layer_off"
    assert _cat(e, h, "family_layer")["enabled"] is True
    e.clock.advance(72 * HOUR)
    assert _cat(e, h, "family_layer")["enabled"] is False
