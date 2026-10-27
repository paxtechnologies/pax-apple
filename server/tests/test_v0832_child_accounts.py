# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.32: child accounts verified by a parent (docs/CHILD_ACCOUNTS.md; Ruben's option a).

* POST /v1/accounts/child/start {email} -> 202: a code to the PARENT's address.
* POST /v1/accounts/child/verify {email, code, child_name?, device_name?} -> 201: always a
  NEW, separate child account (kind 'child', 30-day wait set at creation); 401 bad code;
  429 child_limit (5 per parent address).
* POST /v1/accounts/child/signin {email, code, account_id} -> 200: back in to that child.
* Every email about a child account goes to the parent; the parent's own account and
  sign-in are untouched. The child wait never drops below 30 days; no trial day.
"""
import re
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pax_server.config import DAY, HOUR  # noqa: E402
from pax_server.db import Database  # noqa: E402
from pax_server.escrow import CHILD_EMAIL_DOMAIN, Escrow  # noqa: E402

from test_v085_limits import build  # noqa: E402
from test_v0826_device_state import PW  # noqa: E402
from verified_signup import verified_signup  # noqa: E402

PARENT = "parent@example.com"
FRIEND = "friend@example.org"


@pytest.fixture
def env(tmp_path):
    return build(tmp_path)


def code_to(env, to, kind="child_code"):
    m = [m for m in env.mail.outbox if m.to == to and m.kind == kind][-1]
    return re.search(r"\b(\d{6})\b", m.body).group(1)


def child_start(env, email=PARENT, xff=None):
    headers = {"X-Forwarded-For": xff} if xff else {}
    return env.client.post("/v1/accounts/child/start", json={"email": email}, headers=headers)


def child_verify(env, email=PARENT, code=None, **extra):
    code = code or code_to(env, email.strip().lower())
    return env.client.post("/v1/accounts/child/verify", json={"email": email, "code": code, **extra})


def make_child(env, email=PARENT, **extra):
    assert child_start(env, email).status_code == 202
    r = child_verify(env, email, **extra)
    assert r.status_code == 201, r.text
    b = r.json()
    return b, {"Authorization": f"Bearer {b['token']}"}


def device(env, h, trial=None, hw=None):
    body = {"name": "Sam's iPhone", "platform": "ios", "profile_identifier": "org.paxpeace.pax.appstore.t",
            "removal_password": PW}
    if trial is not None:
        body.update({"trial": trial, "hardware_id": hw})
    r = env.client.post("/v1/devices", headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def no_placeholder_leaks(env, *bodies):
    for m in env.mail.outbox:
        assert CHILD_EMAIL_DOMAIN not in m.to and CHILD_EMAIL_DOMAIN not in m.body, (m.to, m.body)
        assert "None" not in m.subject and "None" not in m.body
    for b in bodies:
        assert CHILD_EMAIL_DOMAIN not in str(b)


# ------------------------------------------------------------------ making one
def test_child_account_is_made_with_the_parents_code(env):
    r = child_start(env, "  Parent@Example.COM ")
    assert r.status_code == 202 and r.json() == {"sent": True}
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 0         # nothing before the code
    m = env.mail.outbox[-1]
    assert (m.to, m.kind) == (PARENT, "child_code")
    assert "child's iPhone or iPad" in m.subject + m.body and "separate Pax account" in m.body
    row = env.escrow.db.one("SELECT * FROM signup_codes")
    assert row["purpose"] == "child" and PARENT not in repr(tuple(row))       # hashes only
    r = child_verify(env, "PARENT@example.com", child_name="Sam", device_name="iPhone", label="iPhone app")
    assert r.status_code == 201, r.text
    b = r.json()
    assert set(b) == {"account_id", "token", "created", "kind", "label", "wait_seconds"}
    assert b["created"] is True and b["kind"] == "child" and b["label"] == "Sam's iPhone (child)"
    assert b["wait_seconds"] == 30 * DAY
    h = {"Authorization": f"Bearer {b['token']}"}
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["email"] == PARENT and me["parent_email"] == PARENT and me["kind"] == "child"
    assert me["email_verified"] is True and me["wait_seconds"] == 30 * DAY and me["display_name"] == "Sam"
    db_row = env.escrow.db.one("SELECT * FROM accounts WHERE id=?", (b["account_id"],))
    assert db_row["email"] == f"child.{b['account_id']}@{CHILD_EMAIL_DOMAIN}"
    assert db_row["email_verified_at"] == env.clock.now()
    assert [(m.to, m.kind) for m in env.mail.outbox] == [(PARENT, "child_code"), (PARENT, "child_set_up")]
    assert "30d" in env.mail.outbox[-1].body
    no_placeholder_leaks(env, b, me)


@pytest.mark.parametrize("name,dev,label", [
    (None, None, "Child's device (child)"),
    (None, "iPad", "iPad (child)"),
    ("Sam", None, "Sam's device (child)"),
    ("bad\nname", "iPhone", "iPhone (child)"),
])
def test_labels(env, name, dev, label):
    b, _ = make_child(env, child_name=name, device_name=dev)
    assert b["label"] == label


def test_parents_own_account_is_untouched(env):
    r = verified_signup(env.client, PARENT, label="Mac")
    parent = r.json()
    ph = {"Authorization": f"Bearer {parent['token']}"}
    assert env.client.put("/v1/accounts/me/wait", headers=ph, json={"wait_days": 3}).status_code == 200
    kid, kh = make_child(env, child_name="Sam")
    assert kid["account_id"] != parent["account_id"]
    me = env.client.get("/v1/accounts/me", headers=ph).json()
    assert me["kind"] == "adult" and me["email"] == PARENT and me["wait_seconds"] == 3 * DAY
    # The parent still signs in to their own account with the same email.
    r = verified_signup(env.client, PARENT, label="iPhone")
    assert r.status_code == 200 and r.json()["account_id"] == parent["account_id"]
    assert env.client.post("/v1/accounts", json={"email": PARENT}).json()["sign_in"] is True
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 2
    # The child's account doesn't see the parent's blocked sites, and the reverse.
    assert env.client.post("/v1/blocklist", headers=ph, json={"domain": "parent-only.example"}).status_code == 201
    assert "parent-only.example" not in str(env.client.get("/v1/blocklist", headers=kh).json())


def test_one_parent_can_look_after_several_then_the_limit(env):
    ids = {make_child(env, child_name=f"Kid{i}")[0]["account_id"] for i in range(5)}
    assert len(ids) == 5
    env.clock.advance(HOUR + 1)                          # 5 child codes an hour per address
    assert child_start(env).status_code == 202
    r = child_verify(env)
    assert r.status_code == 429 and r.json()["error"] == "child_limit" and r.json()["pax_code"] == "PAX-ESCROW-022"
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts WHERE kind='child'")[0] == 5
    # Another parent is counted separately.
    assert make_child(env, "other@example.com")[0]["kind"] == "child"


def test_limit_setting(tmp_path):
    env = build(tmp_path, child_accounts_per_parent=1)
    make_child(env)
    assert child_start(env).status_code == 202
    assert child_verify(env).status_code == 429


# ------------------------------------------------------------- codes are separate
def test_child_and_signup_codes_never_stand_in_for_each_other(env):
    assert child_start(env).status_code == 202
    child_code = code_to(env, PARENT)
    r = env.client.post("/v1/accounts/email/verify", json={"email": PARENT, "code": child_code})
    assert r.status_code == 401                                               # no adult account from it
    assert env.client.post("/v1/accounts/email/start", json={"email": PARENT}).status_code == 202
    signup_code = code_to(env, PARENT, "signup_code")
    assert child_verify(env, code=signup_code).status_code == 401 or signup_code == child_code
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 0
    # Each still works for its own purpose.
    assert child_verify(env, code=child_code).status_code == 201
    r = env.client.post("/v1/accounts/email/verify", json={"email": PARENT, "code": signup_code})
    assert r.status_code == 201 and r.json()["created"] is True


def test_wrong_used_expired_codes_and_limits(env):
    child_start(env)
    good = code_to(env, PARENT)
    bad = "000000" if good != "000000" else "111111"
    assert child_verify(env, code=bad).status_code == 401
    assert child_verify(env, code=good).status_code == 201
    assert child_verify(env, code=good).status_code == 401                   # used
    child_start(env)
    good = code_to(env, PARENT)
    env.clock.advance(15 * 60 + 1)
    assert child_verify(env, code=good).status_code == 401                   # expired
    for _ in range(3):
        assert child_start(env).status_code == 202
    r = child_start(env)                                                      # 6th code in the hour
    assert r.status_code == 429 and r.json()["pax_code"] == "PAX-ESCROW-006"
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 1


def test_five_wrong_tries_lock_the_code(env):
    child_start(env)
    good = code_to(env, PARENT)
    bad = "000000" if good != "000000" else "111111"
    for _ in range(5):
        assert child_verify(env, code=bad).status_code == 401
    assert child_verify(env, code=good).status_code == 401


def test_child_start_shares_the_per_ip_sign_up_bucket(tmp_path):
    env = build(tmp_path, peer=("127.0.0.1", 50000))
    for i in range(5):
        assert child_start(env, f"p{i}@example.com", xff="198.51.100.9").status_code == 202
    assert env.client.post("/v1/accounts/email/start", json={"email": "x@example.com"},
                           headers={"X-Forwarded-For": "198.51.100.9"}).status_code == 429


def test_validation_and_the_placeholder_is_unreachable(env):
    assert env.client.post("/v1/accounts/child/start", json={"email": "nope"}).status_code == 422
    assert env.client.post("/v1/accounts/child/verify",
                           json={"email": PARENT, "code": "123456", "child_name": "x" * 41}).status_code == 422
    b, _ = make_child(env)
    placeholder = f"child.{b['account_id']}@{CHILD_EMAIL_DOMAIN}"
    for path in ("/v1/accounts/email/start", "/v1/accounts/signin/start", "/v1/accounts", "/v1/accounts/child/start"):
        assert env.client.post(path, json={"email": placeholder}).status_code == 422, path
    # Even past the validator, nothing mails or finds it.
    n = len(env.mail.outbox)
    env.app.state.list_sync.email_start(placeholder)
    env.app.state.list_sync.child_start(placeholder)
    assert len(env.mail.outbox) == n


# --------------------------------------------------------------- 30-day wait
def test_child_wait_never_below_30_days(env):
    _, h = make_child(env)
    for days in (1, 3, 7, 29):
        r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": days})
        assert r.status_code == 403, days
        assert r.json()["error"] == "child_wait_fixed" and r.json()["pax_code"] == "PAX-ESCROW-021"
    assert env.client.get("/v1/accounts/me", headers=h).json()["wait_seconds"] == 30 * DAY
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 60})       # longer: at once
    assert r.status_code == 200 and r.json()["wait_seconds"] == 60 * DAY
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 30})       # back to 30: waits
    assert r.status_code == 200
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["wait_seconds"] == 60 * DAY and me["pending_wait_seconds"] == 30 * DAY
    assert env.mail.outbox[-1].to == PARENT                                  # the parent is told


def test_child_wait_setting(tmp_path):
    env = build(tmp_path, child_wait_seconds=45 * DAY)
    b, h = make_child(env)
    assert b["wait_seconds"] == 45 * DAY
    assert env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 30}).status_code == 403


def test_no_trial_day_on_a_child_account(env):
    _, h = make_child(env)
    d = device(env, h, trial=True, hw="a" * 64)
    assert d["trial"] is None
    row = env.escrow.db.one("SELECT trial_until FROM devices WHERE id=?", (d["device_id"],))
    assert row["trial_until"] is None


# ----------------------------------------------------- all mail goes to the parent
def test_turn_off_tells_the_parent_first_and_fails_closed(env):
    _, h = make_child(env, child_name="Sam")
    dev = device(env, h)["device_id"]
    env.clock.advance(env.settings.grace_seconds + 1)
    env.mail.down.add(PARENT)
    r = env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    assert r.status_code == 503 and r.json()["pax_code"] == "PAX-ESCROW-010"
    assert env.client.get(f"/v1/devices/{dev}", headers=h).json()["removal_request"] is None
    r = env.client.post(f"/v1/devices/{dev}/emergency", headers=h, json={"reason": "a real emergency here"})
    assert r.status_code == 503
    assert env.escrow.db.one("SELECT last_emergency_at FROM accounts WHERE kind='child'")[0] is None
    env.mail.down.clear()
    r = env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["removal_request"]["seconds_remaining"] == 30 * DAY
    m = env.mail.outbox[-1]
    assert m.to == PARENT and m.kind == "removal_requested" and "Sam's device (child)" in m.subject
    assert "Sam" in m.body and "You asked" not in m.body                    # the parent is told about Sam
    no_placeholder_leaks(env)


def test_emergency_release_emails_the_parent(env):
    _, h = make_child(env, child_name="Sam")
    dev = device(env, h)["device_id"]
    env.clock.advance(env.settings.grace_seconds + 1)
    n = len(env.mail.outbox)
    r = env.client.post(f"/v1/devices/{dev}/emergency", headers=h, json={"reason": "a real emergency here"})
    assert r.status_code == 201, r.text
    sent = [(m.to, m.kind) for m in env.mail.outbox[n:]]
    assert sent == [(PARENT, "emergency_requested")]
    no_placeholder_leaks(env)


def test_trusted_person_on_a_child_account(env):
    _, h = make_child(env, child_name="Sam")
    r = env.client.put("/v1/accounts/me/partner", headers=h, json={"email": PARENT})
    assert r.status_code == 400 and "parent already gets every email" in r.json()["message"]
    assert env.client.put("/v1/accounts/me/partner", headers=h, json={"email": FRIEND}).status_code == 200
    dev = device(env, h)["device_id"]
    env.clock.advance(env.settings.grace_seconds + 1)
    n = len(env.mail.outbox)
    assert env.client.post(f"/v1/devices/{dev}/removal-request", headers=h).status_code == 201
    got = [m for m in env.mail.outbox[n:]]
    assert [m.to for m in got] == [PARENT, FRIEND]                         # parent first
    assert "Sam" in got[1].body                                             # who(): the child's name
    no_placeholder_leaks(env)


def test_who_for_a_child():
    child = {"kind": "child", "display_name": None, "label": "iPad (child)", "email": "child.x@" + CHILD_EMAIL_DOMAIN,
             "parent_email": PARENT}
    assert Escrow.who(child) == "iPad (child)"
    assert Escrow.who({**child, "display_name": "Sam"}) == "Sam"
    assert Escrow.who({**child, "label": None}) == "Your child"
    assert Escrow.who({**child, "label": None}, mid=True) == "your child"


# ---------------------------------------------------------------- sign in again
def test_child_signin_gets_back_into_that_child_only(env):
    kid, kh = make_child(env, child_name="Sam")
    other, _ = make_child(env, "other@example.com")
    parent = verified_signup(env.client, PARENT).json()
    assert child_start(env).status_code == 202
    code = code_to(env, PARENT)
    for wrong in (parent["account_id"], other["account_id"]):
        r = env.client.post("/v1/accounts/child/signin",
                            json={"email": PARENT, "code": code, "account_id": wrong, "label": "iPhone app"})
        assert r.status_code == 401
    r = env.client.post("/v1/accounts/child/signin",
                        json={"email": PARENT, "code": code, "account_id": kid["account_id"], "label": "iPhone app"})
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["account_id"] == kid["account_id"] and b["created"] is False and b["kind"] == "child"
    assert b["token"] != kid["token"]
    h2 = {"Authorization": f"Bearer {b['token']}"}
    assert env.client.get("/v1/accounts/me", headers=h2).json()["account_id"] == kid["account_id"]
    assert env.client.get("/v1/accounts/me", headers=kh).status_code == 200            # old token still works
    assert (env.mail.outbox[-1].to, env.mail.outbox[-1].kind) == (PARENT, "child_signed_in")
    r = env.client.post("/v1/accounts/child/signin",
                        json={"email": PARENT, "code": code, "account_id": kid["account_id"]})
    assert r.status_code == 401                                                         # code used
    assert env.client.post("/v1/accounts/child/signin",
                           json={"email": PARENT, "code": "123456", "account_id": "nope"}).status_code == 422


# --------------------------------------------------------------------- delete
def test_deleting_a_child_account(env):
    parent = verified_signup(env.client, PARENT).json()
    kid, kh = make_child(env, child_name="Sam")
    dev = device(env, kh)["device_id"]
    r = env.client.delete("/v1/accounts/me", headers=kh)
    assert r.status_code == 409 and r.json()["error"] == "devices_still_protected"
    env.escrow.db.execute("UPDATE devices SET released_at=? WHERE id=?", (env.clock.now(), dev))
    assert env.client.delete("/v1/accounts/me", headers=kh).status_code == 204
    m = env.mail.outbox[-1]
    assert (m.to, m.kind) == (PARENT, "account_deleted")
    assert env.client.get("/v1/accounts/me", headers=kh).status_code == 401
    ph = {"Authorization": f"Bearer {parent['token']}"}
    assert env.client.get("/v1/accounts/me", headers=ph).json()["account_id"] == parent["account_id"]
    no_placeholder_leaks(env)


def test_deleting_the_parent_leaves_children(env):
    parent = verified_signup(env.client, PARENT).json()
    kid, kh = make_child(env)
    ph = {"Authorization": f"Bearer {parent['token']}"}
    assert env.client.delete("/v1/accounts/me", headers=ph).status_code == 204
    assert env.client.get("/v1/accounts/me", headers=kh).json()["email"] == PARENT


# -------------------------------------------------------------------- storage
def test_upgrade_from_0831_adds_columns_only(tmp_path):
    """A live 0.8.31 database: a plain column add on signup_codes (existing codes stay
    sign-up codes) next to the three on accounts; idempotent."""
    path = tmp_path / "old.sqlite3"
    db = Database(str(path))
    db.close()
    conn = sqlite3.connect(path)
    # Make signup_codes 0.8.31-shaped (the accounts side is test_upgrade_from_0830_only_adds_two_columns).
    conn.executescript("""
        DROP TABLE signup_codes;
        CREATE TABLE signup_codes (id TEXT PRIMARY KEY, email_hash TEXT NOT NULL, code_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            used_at INTEGER);
        INSERT INTO signup_codes(id, email_hash, code_hash, created_at, expires_at) VALUES ('c', 'e', 'h', 1, 2);
    """)
    conn.commit()
    conn.close()
    db = Database(str(path))
    scols = [r[1] for r in db.all("PRAGMA table_info(signup_codes)")]
    assert scols[-1] == "purpose"
    assert db.one("SELECT purpose FROM signup_codes WHERE id='c'")[0] == "signup"
    cols = [r[1] for r in db.all("PRAGMA table_info(accounts)")]
    assert {"kind", "parent_email", "label"} <= set(cols)
    assert db.one("SELECT name FROM sqlite_master WHERE name='idx_accounts_parent'")
    db.close()
    Database(str(path)).close()


def test_old_adult_rows_are_adults(env):
    r = verified_signup(env.client, "a@example.com")
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["kind"] == "adult" and me["label"] is None and me["parent_email"] is None
