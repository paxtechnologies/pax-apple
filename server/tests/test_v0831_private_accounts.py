# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.31: private (device-only) accounts for the iPhone app's one-tap set-up.

* POST /v1/accounts/device -> 201 {account_id, token, private: true}; no email column
  value, no email of any kind; the same per-IP sign-up limit as POST /v1/accounts.
* who(acct) = display_name -> email -> "Someone using Pax" in every email that names
  the holder; PUT /v1/accounts/me/partner {from_name} sets display_name.
* PUT /v1/devices/{id}/escrow replaces a device's escrowed secret (409 while released,
  retired, or a removal request / emergency release is open).
* accounts.email becomes nullable through a one-time, idempotent table rebuild.
"""
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "guard"))
sys.path.insert(0, str(ROOT.parent / "pax-dns"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pax_server.config import DAY, HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64, hash_token as hash_account_token  # noqa: E402
from pax_server.db import SCHEMA, Database  # noqa: E402
from pax_server.doh import Policies  # noqa: E402
from pax_server.escrow import Escrow  # noqa: E402
from pax_server.main import create_app  # noqa: E402

from test_v085_limits import FlakySender, build  # noqa: E402
from test_v0826_device_state import PW  # noqa: E402

import ed25519  # noqa: E402
import support_code as sc  # noqa: E402

PW2 = "paxios1.second-secret-0123456789abcdef"
FRIEND = "friend@example.org"


def private(env, label="iPhone app", xff=None):
    headers = {"X-Forwarded-For": xff} if xff else {}
    r = env.client.post("/v1/accounts/device", json={"label": label}, headers=headers)
    assert r.status_code == 201, r.text
    b = r.json()
    return b["account_id"], {"Authorization": f"Bearer {b['token']}"}


def device(env, h, name="iPhone", platform="ios", support=False):
    r = env.client.post("/v1/devices", headers=h, json={
        "name": name, "platform": platform, "profile_identifier": "org.paxpeace.pax.appstore.t",
        "removal_password": PW, "support_release": support})
    assert r.status_code == 201, r.text
    return r.json()["device_id"]


def all_text(env):
    return [(m.to, m.subject, m.body) for m in env.mail.outbox]


def assert_no_none(env):
    for to, subject, body in all_text(env):
        assert to and "None" not in to
        assert "None" not in subject and "None" not in body, (subject, body)


def events(env, kind):
    return env.escrow.db.all("SELECT * FROM events WHERE kind=? ORDER BY id", (kind,))


@pytest.fixture
def env(tmp_path):
    return build(tmp_path)


# ------------------------------------------------------------- private account
def test_create_private_account(env):
    r = env.client.post("/v1/accounts/device", json={"label": "iPhone app"})
    assert r.status_code == 201
    b = r.json()
    assert set(b) == {"account_id", "token", "private"} and b["private"] is True
    assert b["token"].startswith("pax_") and len(b["account_id"]) == 32
    h = {"Authorization": f"Bearer {b['token']}"}
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["email"] is None and me["private"] is True and me["display_name"] is None
    assert me["account_id"] == b["account_id"]
    assert me["wait_seconds"] == env.settings.default_wait_seconds
    row = env.escrow.db.one("SELECT email, token_hash FROM accounts WHERE id=?", (b["account_id"],))
    assert row["email"] is None and row["token_hash"] != b["token"]
    assert env.mail.outbox == []                       # no welcome, no code, nothing
    assert [e["detail"] for e in events(env, "account_registered")] == ["private: iPhone app"]
    # The wait goes up at once, as the app does right after.
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 7})
    assert r.status_code == 200 and r.json()["wait_seconds"] == 7 * DAY
    assert env.mail.outbox == []


def test_body_is_optional_and_label_is_bounded(env):
    assert env.client.post("/v1/accounts/device").status_code == 201
    assert env.client.post("/v1/accounts/device", json={}).status_code == 201
    assert env.client.post("/v1/accounts/device", json={"label": "x" * 101}).status_code == 422
    # A label with control characters is accepted but not stored.
    r = env.client.post("/v1/accounts/device", json={"label": "bad\nlabel"})
    assert r.status_code == 201
    assert events(env, "account_registered")[-1]["detail"] == "private"


def test_email_account_still_reports_private_false(env):
    r = env.client.post("/v1/accounts", json={"email": "Me@Example.com"})
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["email"] == "me@example.com" and me["private"] is False


def test_many_private_accounts_and_email_stays_unique(tmp_path):
    env = build(tmp_path, signup_per_ip_hour=0, signup_per_ip_day=0)
    ids = {private(env)[0] for _ in range(4)}
    assert len(ids) == 4
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts WHERE email IS NULL")[0] == 4
    assert env.client.post("/v1/accounts", json={"email": "a@example.com"}).status_code == 201
    r = env.client.post("/v1/accounts", json={"email": "a@example.com"})
    assert r.status_code == 409
    with pytest.raises(sqlite3.IntegrityError):
        env.escrow.db.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) "
                              "VALUES ('dup', 'a@example.com', 'h', 0, 1)")


def test_same_per_ip_limit_as_email_signup(env):
    for _ in range(3):
        private(env)
    assert env.client.post("/v1/accounts", json={"email": "a@example.com"}).status_code == 201
    assert env.client.post("/v1/accounts", json={"email": "b@example.com"}).status_code == 201
    r = env.client.post("/v1/accounts/device", json={"label": "iPhone app"})   # 6th in the hour
    assert r.status_code == 429
    assert r.json()["error"] == "rate_limited" and r.json()["pax_code"] == "PAX-ESCROW-006"
    assert env.client.post("/v1/accounts", json={"email": "c@example.com"}).status_code == 429
    env.clock.advance(HOUR + 1)
    assert env.client.post("/v1/accounts/device").status_code == 201


def test_limit_counts_per_client_behind_the_proxy(tmp_path):
    env = build(tmp_path, peer=("127.0.0.1", 50000))
    for _ in range(5):
        private(env, xff="198.51.100.7")
    assert env.client.post("/v1/accounts/device", headers={"X-Forwarded-For": "198.51.100.7"}).status_code == 429
    private(env, xff="198.51.100.8")


def test_sign_in_by_email_never_reaches_a_private_account(env):
    private(env)
    r = env.client.post("/v1/accounts/signin/start", json={"email": "none@example.com"})
    assert r.status_code == 202 and env.mail.outbox == []
    assert env.escrow.db.one("SELECT COUNT(*) FROM signin_codes")[0] == 0


def test_unknown_routes_keep_fastapi_404_and_pax_404s_carry_error(env):
    aid, h = private(env)
    r = env.client.put("/v1/devices/nope/escrow", headers=h, json={"removal_password": PW2})
    assert r.status_code == 404 and r.json()["error"] == "not_found"
    r = env.client.post("/v1/accounts/nothing-here")
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}


# --------------------------------------------------------------------- who()
def test_who_order():
    assert Escrow.who({"display_name": "Sam", "email": "s@example.com"}) == "Sam"
    assert Escrow.who({"display_name": None, "email": "s@example.com"}) == "s@example.com"
    assert Escrow.who({"display_name": "", "email": None}) == "Someone using Pax"
    assert Escrow.who({"display_name": None, "email": None}, mid=True) == "someone using Pax"
    assert Escrow.who({"email": None}) == "Someone using Pax"          # a row without the column
    assert Escrow.who({"display_name": "bad\nname", "email": None}) == "Someone using Pax"


def test_partner_with_from_name_and_every_email_uses_it(env):
    aid, h = private(env)
    did = device(env, h)
    r = env.client.put("/v1/accounts/me/partner", headers=h, json={"email": FRIEND, "from_name": "  Sam  "})
    assert r.status_code == 200
    assert r.json()["partner_email"] == FRIEND and r.json()["display_name"] == "Sam"
    env.clock.advance(2 * HOUR)
    c = env.client
    assert c.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 7}).status_code == 200
    assert c.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 3}).status_code == 200      # decrease
    assert c.post("/v1/blocklist", headers=h, json={"domain": "example.net"}).status_code == 201
    assert c.post("/v1/blocklist/remove", headers=h, json={"domain": "example.net"}).status_code == 202
    req = c.get("/v1/blocklist", headers=h).json()["pending"][0]
    assert c.post(f"/v1/blocklist/requests/{req['request_id']}/cancel", headers=h).status_code == 200
    assert c.put(f"/v1/devices/{did}/support-release", headers=h, json={"allowed": True}).status_code == 200
    assert c.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 201
    assert c.post(f"/v1/devices/{did}/removal-request/cancel", headers=h).status_code == 200
    assert c.post(f"/v1/devices/{did}/emergency", headers=h, json={"reason": "a real emergency here"}).status_code == 201
    env.clock.advance(DAY + 60)
    assert c.post(f"/v1/devices/{did}/removal-request/confirm", headers=h,
                  json={"confirm": True}).status_code == 200
    assert c.put("/v1/accounts/me/partner", headers=h, json={"email": "other@example.org"}).status_code == 200
    kinds = env.mail.kinds_to(FRIEND)
    for k in ("partner_added", "wait_decrease_requested", "blocklist_unblock_requested",
              "blocklist_unblock_cancelled", "support_release_on_requested", "removal_requested",
              "removal_cancelled", "emergency_requested", "password_revealed", "partner_change_requested"):
        assert k in kinds, (k, kinds)
    to_friend = [m for m in env.mail.outbox if m.to == FRIEND]
    assert all(m.body.startswith("Sam ") or " Sam " in m.body for m in to_friend), [m.body for m in to_friend]
    # Nothing ever goes to the holder (no address), and no "None" anywhere.
    assert {m.to for m in env.mail.outbox} <= {FRIEND, "other@example.org"}
    assert_no_none(env)


def test_without_a_name_emails_say_someone_using_pax(env):
    aid, h = private(env)
    did = device(env, h)
    assert env.client.put("/v1/accounts/me/partner", headers=h, json={"email": FRIEND}).status_code == 200
    env.clock.advance(2 * HOUR)
    assert env.client.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 201
    bodies = [m.body for m in env.mail.outbox if m.to == FRIEND]
    assert bodies[0].startswith("Someone using Pax has made you their Pax accountability partner")
    assert bodies[1].startswith("Someone using Pax asked to turn Pax off on iPhone")
    assert_no_none(env)


def test_applied_blocklist_change_and_partner_change_after_wait(env):
    aid, h = private(env)
    c = env.client
    assert c.put("/v1/accounts/me/partner", headers=h, json={"email": FRIEND}).status_code == 200
    assert c.post("/v1/blocklist", headers=h, json={"domain": "example.net"}).status_code == 201
    assert c.post("/v1/blocklist/remove", headers=h, json={"domain": "example.net"}).status_code == 202
    assert c.put("/v1/accounts/me/partner", headers=h, json={"email": "new@example.org"}).status_code == 200
    env.clock.advance(env.settings.max_wait_seconds)
    env.app.state.blocklist.apply_due()
    assert c.get("/v1/accounts/me", headers=h).json()["partner_email"] == "new@example.org"
    applied = [m for m in env.mail.outbox if m.kind == "blocklist_unblock_applied"]
    assert applied and applied[0].body.startswith("For someone using Pax: ")
    added = [m for m in env.mail.outbox if m.to == "new@example.org" and m.kind == "partner_added"]
    assert added and added[0].body.startswith("Someone using Pax has made you")
    assert_no_none(env)


def test_support_release_email_names_the_holder(env, monkeypatch):
    seed = b"\x09" * 32
    monkeypatch.setattr(sc, "SUPPORT_PUBLIC_KEYS_HEX", [ed25519.public_key(seed).hex()])
    aid, h = private(env)
    assert env.client.put("/v1/accounts/me/partner", headers=h, json={"email": FRIEND}).status_code == 200
    did = device(env, h, support=True)
    sid = env.client.get(f"/v1/devices/{did}", headers=h).json()["support_id"]
    code = sc.issue(seed, sid, env.clock.now(), lifetime=24 * 3600)
    r = env.client.post(f"/v1/devices/{did}/support-release/redeem", headers=h, json={"code": code})
    assert r.status_code == 200, r.text
    used = [m for m in env.mail.outbox if m.kind == "support_release_used"]
    assert len(used) == 1 and used[0].to == FRIEND        # the holder has no address
    assert "Pax support checked an emergency with someone using Pax and" in used[0].body
    assert_no_none(env)


def test_from_name_validation(env):
    aid, h = private(env)
    put = lambda body: env.client.put("/v1/accounts/me/partner", headers=h, json=body)  # noqa: E731
    for bad in ("x" * 41, "Sam\nSmith", "Sam\rX", "Sam\tX", "Sam\u202eX", "Sam\u2028X", "Sam\x00",
                "see https://evil.example", "www.evil.example"):
        r = put({"email": FRIEND, "from_name": bad})
        assert r.status_code == 422, bad
    assert env.escrow.db.one("SELECT partner_email FROM accounts WHERE id=?", (aid,))[0] is None
    assert put({"email": FRIEND, "from_name": "  " + "y" * 40 + "  "}).json()["display_name"] == "y" * 40
    assert put({"email": FRIEND, "from_name": "Zoë-Anne O'Neill"}).json()["display_name"] == "Zoë-Anne O'Neill"
    assert put({"email": FRIEND}).json()["display_name"] == "Zoë-Anne O'Neill"          # left out: unchanged
    assert put({"email": FRIEND, "from_name": None}).json()["display_name"] == "Zoë-Anne O'Neill"
    assert put({"email": FRIEND, "from_name": "   "}).json()["display_name"] is None    # "": cleared
    assert len(events(env, "display_name_set")) == 2 and len(events(env, "display_name_cleared")) == 1
    assert all(e["detail"] is None for e in events(env, "display_name_set"))           # the name isn't logged


def test_own_partner_check_only_with_an_email(env):
    r = env.client.post("/v1/accounts", json={"email": "me@example.com"})
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    r = env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "ME@example.com"})
    assert r.status_code == 400 and "own" in r.json()["message"]
    aid, hp = private(env)
    assert env.client.put("/v1/accounts/me/partner", headers=hp, json={"email": FRIEND}).status_code == 200


def test_email_account_with_a_name_uses_the_name(env):
    r = env.client.post("/v1/accounts", json={"email": "me@example.com"})
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    env.client.put("/v1/accounts/me/partner", headers=h, json={"email": FRIEND, "from_name": "Ruth"})
    m = [m for m in env.mail.outbox if m.to == FRIEND][0]
    assert m.body.startswith("Ruth has made you") and "me@example.com" not in m.body


# ------------------------------------------------------------- escrow replace
def _reveal(env, h, did):
    r = env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    assert r.status_code == 201, r.text
    env.clock.advance(r.json()["removal_request"]["seconds_remaining"] + 60)
    r = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 200, r.text
    return r.json()["removal_password"]


def test_escrow_replace_ok_and_revealed_later(env):
    aid, h = private(env)
    did = device(env, h)
    before = env.escrow.db.one("SELECT password_ct FROM devices WHERE id=?", (did,))[0]
    r = env.client.put(f"/v1/devices/{did}/escrow", headers=h, json={"removal_password": PW2})
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["device_id"] == did and b["released"] is False and b["removal_request"] is None
    after = env.escrow.db.one("SELECT password_ct FROM devices WHERE id=?", (did,))[0]
    assert after != before and PW2.encode() not in after
    ev = events(env, "escrow_replaced")
    assert len(ev) == 1 and ev[0]["device_id"] == did and ev[0]["detail"] is None
    assert not env.escrow.db.one("SELECT COUNT(*) FROM events WHERE detail LIKE ?", (f"%{PW2}%",))[0]
    assert env.mail.outbox == []
    env.clock.advance(2 * HOUR)
    assert _reveal(env, h, did) == PW2


def test_escrow_replace_is_bound_to_the_device(env):
    aid, h = private(env)
    a, b = device(env, h, "A"), device(env, h, "B")
    assert env.client.put(f"/v1/devices/{a}/escrow", headers=h, json={"removal_password": PW2}).status_code == 200
    db = env.escrow.db
    # A ciphertext moved to another device row doesn't decrypt (aad = device id).
    ct = db.one("SELECT password_ct FROM devices WHERE id=?", (a,))[0]
    with pytest.raises(Exception):
        env.escrow.box.decrypt(ct, aad=b)
    assert env.escrow.box.decrypt(ct, aad=a) == PW2


def test_escrow_replace_validation_and_auth(env):
    aid, h = private(env)
    did = device(env, h)
    url = f"/v1/devices/{did}/escrow"
    assert env.client.put(url, headers=h, json={"removal_password": "x" * 19}).status_code == 422
    assert env.client.put(url, headers=h, json={"removal_password": "x" * 257}).status_code == 422
    assert env.client.put(url, headers=h, json={}).status_code == 422
    r = env.client.put(url, json={"removal_password": PW2})
    assert r.status_code == 401 and r.json()["error"] == "unauthorized"
    other_aid, other = private(env)
    r = env.client.put(url, headers=other, json={"removal_password": PW2})
    assert r.status_code == 404 and r.json()["error"] == "not_found"
    assert env.escrow.box.decrypt(env.escrow.db.one("SELECT password_ct FROM devices WHERE id=?", (did,))[0],
                                  aad=did) == PW


def test_escrow_replace_refused_while_a_request_is_open(env):
    aid, h = private(env)
    did = device(env, h)
    env.clock.advance(2 * HOUR)
    assert env.client.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 201
    r = env.client.put(f"/v1/devices/{did}/escrow", headers=h, json={"removal_password": PW2})
    assert r.status_code == 409
    b = r.json()
    assert b["error"] == "conflict" and b["reason"] == "removal_request_open"
    assert b["removal_request"]["kind"] == "standard"
    r = env.client.post(f"/v1/devices/{did}/emergency", headers=h, json={"reason": "a real emergency here"})
    assert r.status_code == 201
    r = env.client.put(f"/v1/devices/{did}/escrow", headers=h, json={"removal_password": PW2})
    assert r.status_code == 409 and r.json()["reason"] == "emergency_open"
    assert [e["detail"] for e in events(env, "escrow_replace_refused")] == ["removal_request_open",
                                                                            "emergency_open"]
    assert not events(env, "escrow_replaced")
    # The request reveals the secret it was made for.
    env.clock.advance(DAY + 60)
    r = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.json()["removal_password"] == PW


def test_escrow_replace_after_cancel_works(env):
    aid, h = private(env)
    did = device(env, h)
    env.clock.advance(2 * HOUR)
    env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    env.client.post(f"/v1/devices/{did}/removal-request/cancel", headers=h)
    assert env.client.put(f"/v1/devices/{did}/escrow", headers=h,
                          json={"removal_password": PW2}).status_code == 200


def test_escrow_replace_refused_once_released_or_retired(env):
    aid, h = private(env)
    did = device(env, h)
    env.clock.advance(2 * HOUR)
    _reveal(env, h, did)
    r = env.client.put(f"/v1/devices/{did}/escrow", headers=h, json={"removal_password": PW2})
    assert r.status_code == 409 and r.json()["reason"] == "released"
    assert env.client.post(f"/v1/devices/{did}/retire", headers=h).status_code == 200
    r = env.client.put(f"/v1/devices/{did}/escrow", headers=h, json={"removal_password": PW2})
    assert r.status_code == 409 and r.json()["reason"] == "retired"


def test_escrow_replace_in_the_grace_hour_request(env):
    """A no-wait request in the first hour is still an open request: refused."""
    aid, h = private(env)
    did = device(env, h)
    assert env.client.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 201
    r = env.client.put(f"/v1/devices/{did}/escrow", headers=h, json={"removal_password": PW2})
    assert r.status_code == 409 and r.json()["reason"] == "removal_request_open"


# ------------------------------------------------------------- delete account
def test_delete_private_account_sends_nothing(env):
    aid, h = private(env)
    did = device(env, h)
    env.client.put("/v1/accounts/me/partner", headers=h, json={"email": FRIEND, "from_name": "Sam"})
    env.clock.advance(2 * HOUR)
    _reveal(env, h, did)
    sent_before = len(env.mail.outbox)
    r = env.client.delete("/v1/accounts/me", headers=h)
    assert r.status_code == 204 and r.content == b""
    assert len(env.mail.outbox) == sent_before          # no confirmation (no address); partner not told
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts WHERE id=?", (aid,))[0] == 0
    assert env.client.get("/v1/accounts/me", headers=h).status_code == 401
    assert_no_none(env)


def test_delete_private_account_refused_while_protected(env):
    aid, h = private(env)
    device(env, h)
    r = env.client.delete("/v1/accounts/me", headers=h)
    assert r.status_code == 409 and r.json()["error"] == "devices_still_protected"


# ---------------------------------------------------------- DNS feed / dns2
def test_dns_feed_and_replica_with_a_private_account(tmp_path):
    import hashlib
    key = "k" * 40
    env = build(tmp_path, replica_key_sha256=(hashlib.sha256(key.encode()).hexdigest(),))
    aid, h = private(env)
    c = env.client
    dns = c.get("/v1/dns", headers=h).json()["token"]
    assert c.post("/v1/blocklist", headers=h, json={"domain": "example.net"}).status_code == 201
    feed = env.app.state.blocklist.changes(0)
    mine = [a for a in feed["accounts"] if a["account_id"] == aid]
    assert len(mine) == 1 and mine[0]["block"] == ["example.net"] and mine[0]["tokens"]
    assert "email" not in repr(feed)
    # What dns2 reads (the replica endpoint) and does with it (Policies).
    r = c.get("/v1/replica/dns/changes?since=0", headers={"X-Pax-Replica-Key": key})
    assert r.status_code == 200
    assert [a["block"] for a in r.json()["accounts"] if a["account_id"] == aid] == [["example.net"]]
    replica = Policies()
    replica.apply(dict(r.json(), full=True))
    assert replica.known_hash(dns)


def test_pax_dns_sqlite_source_reads_a_private_account(env):
    from pax_dns.sources import SqliteSource
    aid, h = private(env)
    env.client.get("/v1/dns", headers=h)
    env.client.post("/v1/blocklist", headers=h, json={"domain": "example.net"})
    src = SqliteSource(env.settings.db_path, clock=lambda: env.clock.now())
    feed = src.fetch_sync(0)
    mine = [a for a in feed["accounts"] if a["account_id"] == aid]
    assert len(mine) == 1 and mine[0]["block"] == ["example.net"]


def test_mac_sync_link_on_a_private_account(env):
    aid, h = private(env)
    link = env.client.post("/v1/sync/links", headers=h, json={"device_name": "Mac"}).json()
    assert link["account_email"] is None
    r = env.client.post("/v1/sync", headers={"X-Pax-Sync-Token": link["sync_token"]},
                        json={"add": ["example.org"], "partner_email": FRIEND, "wait_seconds": DAY})
    assert r.status_code == 200 and r.json()["account_email"] is None
    r = env.client.post("/v1/sync/unblock", headers={"X-Pax-Sync-Token": link["sync_token"]},
                        json={"domain": "example.org"})
    assert r.status_code == 202
    assert [m.to for m in env.mail.outbox] == [FRIEND]
    assert env.mail.outbox[0].body.startswith("Someone using Pax asked to unblock")
    assert_no_none(env)


def test_notify_relay_on_a_private_account(env):
    aid, h = private(env)
    r = env.client.post("/v1/notify", headers=h, json={"kind": "pax_off", "subject": "s", "body": "b",
                                                        "partner_email": FRIEND, "partner_body": "pb"})
    assert r.status_code == 202
    assert [m.to for m in env.mail.outbox] == [FRIEND]


# ------------------------------------------------------------------ migration
# The accounts table exactly as v0.1 created it; later columns were added by ALTER
# TABLE, as on the live server.
V01_ACCOUNTS = """
CREATE TABLE accounts (
    id                     TEXT PRIMARY KEY,
    email                  TEXT NOT NULL UNIQUE,
    token_hash             TEXT NOT NULL,
    created_at             INTEGER NOT NULL,
    wait_seconds           INTEGER NOT NULL,
    pending_wait_seconds   INTEGER,
    pending_wait_effective INTEGER,
    partner_email          TEXT,
    pending_partner_email  TEXT,      -- '' means "remove partner"
    pending_partner_effective INTEGER,
    last_emergency_at      INTEGER
);
"""
# And as v0.8.30's db.py has it (a database first created on 0.8.18 or later).
V0830_ACCOUNTS = """
CREATE TABLE IF NOT EXISTS accounts (
    id                     TEXT PRIMARY KEY,
    email                  TEXT NOT NULL UNIQUE,
    token_hash             TEXT NOT NULL,
    created_at             INTEGER NOT NULL,
    wait_seconds           INTEGER NOT NULL,
    pending_wait_seconds   INTEGER,
    pending_wait_effective INTEGER,
    partner_email          TEXT,
    pending_partner_email  TEXT,      -- '' means "remove partner"
    pending_partner_effective INTEGER,
    last_emergency_at      INTEGER,
    adblock                INTEGER NOT NULL DEFAULT 1,  -- v0.4: Mac ad/tracker blocking
    block_remote_desktop   INTEGER NOT NULL DEFAULT 1,  -- v0.5: remote-desktop category
    trial_started_at       INTEGER                      -- v0.8.18: when this account's trial day began
);
"""


def _rest_of_schema():
    """Every other table of today's schema (without accounts)."""
    start = SCHEMA.index("CREATE TABLE IF NOT EXISTS accounts")
    end = SCHEMA.index(");", start) + 2
    return SCHEMA[:start] + SCHEMA[end:]


def _old_db(path, accounts_sql, live_columns=True):
    """An old database with data in it, made the way an old server would have."""
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(accounts_sql + _rest_of_schema().replace("PRAGMA foreign_keys = ON;", ""))
    if live_columns:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(accounts)")}
        for col, typ in (("adblock", "INTEGER NOT NULL DEFAULT 1"), ("block_remote_desktop", "INTEGER NOT NULL DEFAULT 1"),
                         ("dns_family_layer", "INTEGER NOT NULL DEFAULT 0"), ("dns_x_media", "INTEGER NOT NULL DEFAULT 1"),
                         ("dns_bluesky_media", "INTEGER NOT NULL DEFAULT 1"),
                         ("dns_youtube_restricted", "INTEGER NOT NULL DEFAULT 1"), ("trial_started_at", "INTEGER")):
            if col not in cols:
                conn.execute(f"ALTER TABLE accounts ADD COLUMN {col} {typ}")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _seed(path, key):
    """Accounts, devices with real ciphertexts, requests, lists and tokens through the
    real server on the old-shaped database."""
    clock_env = Settings(db_path=path, server_key_b64=key)
    from test_v0826_device_state import FakeClock
    clock, mail = FakeClock(), FlakySender()
    client = TestClient(create_app(clock_env, clock=clock, sender=mail))
    out = []
    for i in range(3):
        r = client.post("/v1/accounts", json={"email": f"user{i}@example.com"})
        assert r.status_code == 201, r.text
        h = {"Authorization": f"Bearer {r.json()['token']}"}
        client.put("/v1/accounts/me/partner", headers=h, json={"email": f"friend{i}@example.org"})
        did = device(type("E", (), {"client": client})(), h)
        client.post("/v1/blocklist", headers=h, json={"domain": f"site{i}.example"})
        client.get("/v1/dns", headers=h)
        client.post("/v1/sync/links", headers=h, json={"device_name": "Mac"})
        out.append((r.json()["account_id"], h, did))
    clock.advance(2 * HOUR)
    client.post(f"/v1/devices/{out[0][2]}/removal-request", headers=out[0][1])
    return out


def _snapshot(conn):
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                         "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    snap = {}
    for t in tables:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({t})") if r[1] != "display_name"]
        snap[t] = sorted((tuple(r) for r in conn.execute(f"SELECT {', '.join(cols)} FROM {t}")), key=repr)
    return snap


@pytest.mark.parametrize("accounts_sql", [V01_ACCOUNTS, V0830_ACCOUNTS], ids=["v0.1-shape", "v0.8.30-shape"])
def test_migration_on_a_copy_with_data(tmp_path, accounts_sql, monkeypatch):
    path = str(tmp_path / "live.sqlite3")
    old = _old_db(path, accounts_sql)
    old.close()
    # Seed with the pre-0.8.31 rebuild switched off, so the data is written on the old shape.
    monkeypatch.setattr(Database, "_email_nullable", lambda self: None)
    key = generate_key_b64()
    seeded = _seed(path, key)
    monkeypatch.undo()
    raw = sqlite3.connect(path)
    assert [r for r in raw.execute("PRAGMA table_info(accounts)") if r[1] == "email"][0][3] == 1
    before = _snapshot(raw)
    reader = sqlite3.connect(f"file:{path}?mode=ro", uri=True)   # pax-dns's read-only view stays open
    reader.execute("SELECT COUNT(*) FROM accounts").fetchone()
    raw.close()

    db = Database(path)                                  # the migration
    conn = db._conn
    info = {r[1]: r for r in conn.execute("PRAGMA table_info(accounts)")}
    assert info["email"][3] == 0 and "display_name" in info
    assert _snapshot(conn) == before                     # every row of every table kept
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert {r[2] for r in conn.execute("PRAGMA foreign_key_list(devices)")} == {"accounts"}
    assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'accounts_v0831%'").fetchone()
    # UNIQUE still holds for real addresses; NULLs are allowed (many of them).
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) "
                   "VALUES ('x', 'user1@example.com', 'h', 0, 1)")
    db.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) VALUES ('p1', NULL, 'h1', 0, 1)")
    db.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) VALUES ('p2', NULL, 'h2', 0, 1)")
    # Foreign keys are still enforced.
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO devices(id, account_id, name, platform, profile_identifier, password_ct, "
                   "installed_at) VALUES ('d', 'no-such-account', 'n', 'ios', 'p', x'00', 0)")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM accounts WHERE id=?", (seeded[0][0],))
    db.execute("DELETE FROM accounts WHERE id IN ('p1','p2')")
    sql_after = conn.execute("SELECT sql FROM sqlite_master WHERE name='accounts'").fetchone()[0]
    db.close()
    # The open reader sees the new table.
    assert reader.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 3
    reader.close()

    # Idempotent: a second start changes nothing.
    db2 = Database(path)
    assert db2._conn.execute("SELECT sql FROM sqlite_master WHERE name='accounts'").fetchone()[0] == sql_after
    db2.close()

    # The server works on the migrated database: old tokens, old ciphertexts, new private accounts.
    client = TestClient(create_app(Settings(db_path=path, server_key_b64=key), sender=FlakySender()))
    aid, h, did = seeded[1]
    me = client.get("/v1/accounts/me", headers=h).json()
    assert me["email"] == "user1@example.com" and me["private"] is False and me["partner_email"] == "friend1@example.org"
    assert client.get(f"/v1/devices/{did}", headers=h).status_code == 200
    esc = client.app.state.escrow
    ct = esc.db.one("SELECT password_ct FROM devices WHERE id=?", (did,))[0]
    assert esc.box.decrypt(ct, aad=did) == PW
    r = client.post("/v1/accounts/device", json={"label": "iPhone app"})
    assert r.status_code == 201
    assert client.get(f"/v1/devices/{seeded[0][2]}", headers=seeded[0][1]).json()["removal_request"]["kind"] == "standard"


def test_migration_refuses_an_unexpected_shape_and_changes_nothing(tmp_path):
    path = str(tmp_path / "odd.sqlite3")
    odd = V01_ACCOUNTS.replace("email                  TEXT NOT NULL UNIQUE",
                               "email                  TEXT NOT NULL CHECK (email != '')")
    conn = _old_db(path, odd)
    conn.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) VALUES ('a', 'a@x.io', 'h', 0, 1)")
    sql_before = conn.execute("SELECT sql FROM sqlite_master WHERE name='accounts'").fetchone()[0]
    conn.close()
    with pytest.raises(RuntimeError, match="unexpected shape"):
        Database(path)
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT sql FROM sqlite_master WHERE name='accounts'").fetchone()[0].startswith(sql_before[:40])
    assert conn.execute("SELECT email FROM accounts").fetchall() == [("a@x.io",)]
    assert [r for r in conn.execute("PRAGMA table_info(accounts)") if r[1] == "email"][0][3] == 1


def test_migration_rolls_back_when_a_step_fails(tmp_path):
    """Anything failing inside the rebuild rolls it all back: the old table stays and
    the server doesn't start on a half-migrated database."""
    path = str(tmp_path / "fail.sqlite3")
    conn = _old_db(path, V01_ACCOUNTS)
    conn.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) VALUES ('a', 'a@x.io', 'h', 0, 1)")
    # A view with the rebuild's scratch name makes the rebuild's first step fail.
    conn.execute("CREATE VIEW accounts_v0831_rebuild AS SELECT 1")
    conn.close()
    with pytest.raises(sqlite3.OperationalError):
        Database(path)
    conn = sqlite3.connect(path)
    assert [r for r in conn.execute("PRAGMA table_info(accounts)") if r[1] == "email"][0][3] == 1
    assert conn.execute("SELECT id, email FROM accounts").fetchall() == [("a", "a@x.io")]
    assert conn.execute("SELECT type FROM sqlite_master WHERE name='accounts_v0831_rebuild'").fetchone() == ("view",)


def test_migration_tolerates_an_old_orphan_row(tmp_path):
    """A row that already broke a foreign key before 0.8.31 doesn't stop the server
    starting; it is left exactly as it was."""
    path = str(tmp_path / "fk.sqlite3")
    conn = _old_db(path, V01_ACCOUNTS)
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("INSERT INTO devices(id, account_id, name, platform, profile_identifier, password_ct, installed_at) "
                 "VALUES ('orphan', 'gone', 'n', 'ios', 'p', x'00', 0)")
    conn.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) VALUES ('a', 'a@x.io', 'h', 0, 1)")
    conn.close()
    db = Database(path)
    assert [r for r in db._conn.execute("PRAGMA table_info(accounts)") if r[1] == "email"][0][3] == 0
    assert db.one("SELECT account_id FROM devices WHERE id='orphan'")[0] == "gone"
    assert [tuple(r) for r in db.all("SELECT id, email FROM accounts")] == [("a", "a@x.io")]
    # Defaults survive the rebuild.
    db.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) VALUES ('p', NULL, 'h2', 0, 1)")
    row = db.one("SELECT adblock, block_remote_desktop, dns_family_layer, dns_x_media FROM accounts WHERE id='p'")
    assert tuple(row) == (1, 1, 0, 1)


def test_new_database_needs_no_rebuild(tmp_path):
    db = Database(str(tmp_path / "new.sqlite3"))
    info = {r[1]: r for r in db._conn.execute("PRAGMA table_info(accounts)")}
    assert info["email"][3] == 0 and "display_name" in info
    sql = db._conn.execute("SELECT sql FROM sqlite_master WHERE name='accounts'").fetchone()[0]
    assert "accounts_v0831" not in sql and "UNIQUE" in sql


def test_token_hash_lookup_unchanged_after_migration(tmp_path, monkeypatch):
    path = str(tmp_path / "t.sqlite3")
    _old_db(path, V0830_ACCOUNTS).close()
    monkeypatch.setattr(Database, "_email_nullable", lambda self: None)
    db = Database(path)
    db.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) VALUES (?,?,?,?,?)",
               ("a1", "a@example.com", hash_account_token("pax_tok"), 0, 1))
    db.close()
    monkeypatch.undo()
    db = Database(path)
    assert db.one("SELECT id FROM accounts WHERE token_hash=?", (hash_account_token("pax_tok"),))[0] == "a1"
