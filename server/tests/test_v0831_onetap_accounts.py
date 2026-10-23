# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.31: accounts for the iPhone app's one-tap set-up. Every account has a
verified email (project decision, 22 Oct 2026: a lost device token must never mean
a lost account).

* POST /v1/accounts/email/start {email} -> 202 {"sent": true}: a 6-digit code to the
  address, new or existing (the answer never says which).
* POST /v1/accounts/email/verify {email, code, label} -> 201 {account_id, token,
  created: true} (new account, email verified) or 200 {..., created: false} (a
  sign-in to the existing account). 401 for a wrong/used/expired code; nothing made.
* There is no email-less account: no POST /v1/accounts/device, accounts.email stays
  NOT NULL UNIQUE (no table rebuild; two plain ADD COLUMNs).
* who(acct) = display_name -> email in every email that names the holder;
  PUT /v1/accounts/me/partner {from_name} sets display_name.
* PUT /v1/devices/{id}/escrow replaces a device's escrowed secret (409 while released,
  retired, or a removal request / emergency release is open).
"""
import re
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "guard"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pax_server.config import DAY, HOUR  # noqa: E402
from pax_server.db import SCHEMA, Database  # noqa: E402
from pax_server.escrow import Escrow  # noqa: E402

from test_v085_limits import build  # noqa: E402
from test_v0826_device_state import PW  # noqa: E402

import ed25519  # noqa: E402
import support_code as sc  # noqa: E402

PW2 = "paxios1.second-secret-0123456789abcdef"
FRIEND = "friend@example.org"
ME = "me@example.com"


def last_code(env, to):
    m = [m for m in env.mail.outbox if m.to == to and m.kind in ("signup_code", "signin_code")][-1]
    return re.search(r"\b(\d{6})\b", m.body).group(1)


def start(env, email, xff=None):
    headers = {"X-Forwarded-For": xff} if xff else {}
    return env.client.post("/v1/accounts/email/start", json={"email": email}, headers=headers)


def verify(env, email, code, label="iPhone app"):
    return env.client.post("/v1/accounts/email/verify", json={"email": email, "code": code, "label": label})


def account(env, email=ME):
    """An account made the iPhone 1.2 way (email -> code -> verified)."""
    assert start(env, email).status_code == 202
    r = verify(env, email, last_code(env, email.strip().lower()))
    assert r.status_code in (200, 201), r.text
    b = r.json()
    return b["account_id"], {"Authorization": f"Bearer {b['token']}"}


def legacy_account(env, email):
    """v0.8.32: an account as POST /v1/accounts made it up to 0.8.31 (email never
    proved). That route no longer makes accounts, so tests seed one directly; these
    accounts are grandfathered and keep working."""
    from pax_server.crypto import hash_token, new_token
    import uuid
    aid, tok = uuid.uuid4().hex, new_token()
    env.escrow.db.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) VALUES (?,?,?,?,?)",
                          (aid, email, hash_token(tok), env.clock.now(), env.settings.default_wait_seconds))
    return {"account_id": aid, "token": tok}


def device(env, h, name="iPhone", platform="ios", support=False):
    r = env.client.post("/v1/devices", headers=h, json={
        "name": name, "platform": platform, "profile_identifier": "org.paxpeace.pax.appstore.t",
        "removal_password": PW, "support_release": support})
    assert r.status_code == 201, r.text
    return r.json()["device_id"]


def assert_no_none(env):
    for m in env.mail.outbox:
        assert m.to and "None" not in m.to
        assert "None" not in m.subject and "None" not in m.body, (m.subject, m.body)


def events(env, kind):
    return env.escrow.db.all("SELECT * FROM events WHERE kind=? ORDER BY id", (kind,))


@pytest.fixture
def env(tmp_path):
    return build(tmp_path)


# ------------------------------------------------------- verified email accounts
def test_new_account_by_email_code(env):
    r = start(env, "  Me@Example.COM ")
    assert r.status_code == 202 and r.json() == {"sent": True}
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 0      # nothing until the code is back
    assert [(m.to, m.kind) for m in env.mail.outbox] == [(ME, "signup_code")]
    code = last_code(env, ME)
    row = env.escrow.db.one("SELECT * FROM signup_codes")
    assert ME not in repr(tuple(row)) and code not in repr(tuple(row))     # hashes only
    assert row["expires_at"] - row["created_at"] == 15 * 60
    r = verify(env, "ME@example.com", code)
    assert r.status_code == 201, r.text
    b = r.json()
    assert set(b) == {"account_id", "token", "created"} and b["created"] is True
    assert b["token"].startswith("pax_") and len(b["account_id"]) == 32
    h = {"Authorization": f"Bearer {b['token']}"}
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["email"] == ME and me["email_verified"] is True and me["display_name"] is None
    assert "private" not in me
    assert me["wait_seconds"] == env.settings.default_wait_seconds
    assert [e["detail"] for e in events(env, "account_registered")] == ["email verified"]
    assert [m.kind for m in env.mail.outbox] == ["signup_code"]            # no welcome on top of the code
    assert env.escrow.db.one("SELECT used_at FROM signup_codes")[0] is not None
    # The app raises the wait at once, as before.
    r = env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 7})
    assert r.status_code == 200 and r.json()["wait_seconds"] == 7 * DAY


def test_existing_account_signs_in_with_the_same_two_calls(env):
    made = legacy_account(env, ME)                                          # made by a Mac before 0.8.32
    old = {"Authorization": f"Bearer {made['token']}"}
    assert env.client.get("/v1/accounts/me", headers=old).json()["email_verified"] is False
    assert start(env, ME).status_code == 202
    assert env.mail.outbox[-1].kind == "signin_code"
    assert env.escrow.db.one("SELECT COUNT(*) FROM signup_codes")[0] == 0
    r = verify(env, ME, last_code(env, ME))
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["created"] is False
    new = {"Authorization": f"Bearer {b['token']}"}
    me = env.client.get("/v1/accounts/me", headers=new).json()
    assert me["account_id"] == env.client.get("/v1/accounts/me", headers=old).json()["account_id"]
    assert me["email_verified"] is True
    assert env.mail.outbox[-1].kind == "signed_in"
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 1


def test_start_answers_the_same_for_new_and_existing(env):
    legacy_account(env, "known@example.com")
    a, b = start(env, "known@example.com"), start(env, "unknown@example.com")
    assert (a.status_code, a.json()) == (b.status_code, b.json()) == (202, {"sent": True})


def test_wrong_used_or_expired_code_fails_closed(env):
    start(env, ME)
    code = last_code(env, ME)
    wrong = "000000" if code != "000000" else "111111"
    r = verify(env, ME, wrong)
    assert r.status_code == 401 and r.json()["error"] == "unauthorized"
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 0
    assert verify(env, ME, code).status_code == 201
    assert verify(env, ME, code).status_code == 401                         # used up
    # Expired after 15 minutes.
    start(env, "late@example.com")
    env.clock.advance(15 * 60 + 1)
    assert verify(env, "late@example.com", last_code(env, "late@example.com")).status_code == 401
    # A code for one address doesn't work for another.
    start(env, "a@example.com")
    assert verify(env, "b@example.com", last_code(env, "a@example.com")).status_code == 401
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 1


def test_five_tries_per_code(env):
    start(env, ME)
    code = last_code(env, ME)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        assert verify(env, ME, wrong).status_code == 401
    assert verify(env, ME, code).status_code == 401                         # locked
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 0


def test_only_the_newest_code_works(env):
    start(env, ME)
    first = last_code(env, ME)
    start(env, ME)
    second = last_code(env, ME)
    if first != second:
        assert verify(env, ME, first).status_code == 401
    assert verify(env, ME, second).status_code == 201


def test_five_codes_an_hour_per_address(tmp_path):
    env = build(tmp_path, signup_per_ip_hour=0, signup_per_ip_day=0)
    for _ in range(5):
        assert start(env, ME).status_code == 202
    r = start(env, ME)
    assert r.status_code == 429 and r.json()["error"] == "rate_limited"
    assert start(env, "other@example.com").status_code == 202
    env.clock.advance(HOUR + 1)
    assert start(env, ME).status_code == 202


def test_shares_the_per_ip_sign_up_limit(env):
    assert env.client.post("/v1/accounts", json={"email": "a@example.com"}).status_code == 410   # still counts
    assert env.client.post("/v1/accounts/signin/start", json={"email": "a@example.com"}).status_code == 202
    for e in ("b@example.com", "c@example.com", "d@example.com"):
        assert start(env, e).status_code == 202
    r = start(env, "e@example.com")                                          # 6th in the hour
    assert r.status_code == 429
    assert r.json()["error"] == "rate_limited" and r.json()["pax_code"] == "PAX-ESCROW-006"
    assert env.client.post("/v1/accounts", json={"email": "f@example.com"}).status_code == 429


def test_limit_counts_per_client_behind_the_proxy(tmp_path):
    env = build(tmp_path, peer=("127.0.0.1", 50000))
    for i in range(5):
        assert start(env, f"u{i}@example.com", xff="198.51.100.7").status_code == 202
    assert start(env, "u9@example.com", xff="198.51.100.7").status_code == 429
    assert start(env, "u9@example.com", xff="198.51.100.8").status_code == 202


def test_signup_code_then_someone_made_the_account_signs_in(env):
    """A code sent while the address had no account still proves the address."""
    start(env, ME)
    code = last_code(env, ME)
    made = legacy_account(env, ME)
    r = verify(env, ME, code)
    assert r.status_code == 200 and r.json()["created"] is False
    assert r.json()["account_id"] == made["account_id"]
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 1


def test_unique_email_race_signs_in_instead(env):
    ls = env.app.state.list_sync
    start(env, ME)
    code = last_code(env, ME)
    real = ls._signup_code

    def racing(email, c):
        row = real(email, c)
        legacy_account(env, email)                                         # lands in between
        return row
    ls._signup_code = racing
    r = verify(env, ME, code)
    assert r.status_code == 200 and r.json()["created"] is False
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 1
    assert env.client.get("/v1/accounts/me",
                          headers={"Authorization": f"Bearer {r.json()['token']}"}).json()["email"] == ME


def test_mail_budget_spent_means_no_account(tmp_path):
    env = build(tmp_path, account_mail_daily_cap=0)
    assert start(env, ME).status_code == 202                                # same answer
    assert env.mail.outbox == []
    for guess in ("000000", "123456"):
        assert verify(env, ME, guess).status_code == 401
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 0


def test_expired_signup_codes_are_pruned(env):
    start(env, "old@example.com")
    env.clock.advance(15 * 60 + DAY + 1)
    start(env, ME)
    assert env.escrow.db.one("SELECT COUNT(*) FROM signup_codes")[0] == 1


def test_validation(env):
    assert env.client.post("/v1/accounts/email/start", json={"email": "not-an-email"}).status_code == 422
    assert env.client.post("/v1/accounts/email/start", json={}).status_code == 422
    assert env.client.post("/v1/accounts/email/verify", json={"email": ME, "code": "12"}).status_code == 422
    assert env.client.post("/v1/accounts/email/verify",
                           json={"email": ME, "code": "123456", "label": "x" * 101}).status_code == 422


def test_old_mac_route_no_longer_makes_accounts(env):
    """v0.8.32: POST /v1/accounts refuses new accounts (410 app_update_required,
    PAX-ESCROW-020); an existing address still gets 409 sign_in, and the old code
    sign-in keeps working for grandfathered (unverified) accounts."""
    r = env.client.post("/v1/accounts", json={"email": ME})
    assert r.status_code == 410
    b = r.json()
    assert b["error"] == "app_update_required" and b["pax_code"] == "PAX-ESCROW-020"
    assert "Download the latest Pax" in b["message"] and "token" not in b
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 0
    assert env.mail.outbox == []                                            # no welcome, nothing
    legacy_account(env, ME)
    r = env.client.post("/v1/accounts", json={"email": ME.upper()})
    assert r.status_code == 409 and r.json()["sign_in"] is True and "token" not in r.json()
    assert env.client.post("/v1/accounts/signin/start", json={"email": ME}).status_code == 202
    r = env.client.post("/v1/accounts/signin", json={"email": ME, "code": last_code(env, ME), "label": "Mac"})
    assert r.status_code == 200 and set(r.json()) == {"account_id", "token"}
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    assert env.client.get("/v1/accounts/me", headers=h).json()["email_verified"] is True
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 1


def test_no_email_less_accounts(env):
    r = env.client.post("/v1/accounts/device", json={"label": "iPhone app"})
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}
    info = {r[1]: r for r in env.escrow.db.all("PRAGMA table_info(accounts)")}
    assert info["email"][3] == 1                                            # NOT NULL
    with pytest.raises(sqlite3.IntegrityError):
        env.escrow.db.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) "
                              "VALUES ('x', NULL, 'h', 0, 1)")


def test_unknown_routes_keep_fastapi_404_and_pax_404s_carry_error(env):
    aid, h = account(env)
    r = env.client.put("/v1/devices/nope/escrow", headers=h, json={"removal_password": PW2})
    assert r.status_code == 404 and r.json()["error"] == "not_found"
    r = env.client.post("/v1/accounts/nothing-here")
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}


# The accounts table as v0.8.30's db.py has it.
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


def test_upgrade_from_0830_only_adds_two_columns(tmp_path):
    path = tmp_path / "old.sqlite3"
    start_ = SCHEMA.index("CREATE TABLE IF NOT EXISTS accounts")
    end = SCHEMA.index(");", start_) + 2
    old_schema = SCHEMA[:start_] + V0830_ACCOUNTS + SCHEMA[end:]
    old_schema = old_schema[:old_schema.index("-- v0.8.31: a one-time code")] + \
        old_schema[old_schema.index("CREATE INDEX IF NOT EXISTS idx_signup_email ON signup_codes(email_hash, created_at);")
                   + len("CREATE INDEX IF NOT EXISTS idx_signup_email ON signup_codes(email_hash, created_at);"):]
    conn = sqlite3.connect(path)
    conn.executescript(old_schema)
    conn.execute("INSERT INTO accounts(id, email, token_hash, created_at, wait_seconds) "
                 "VALUES ('a1', 'old@example.com', 'h', 1, 259200)")
    conn.commit()
    conn.close()
    db = Database(str(path))
    cols = [r[1] for r in db.all("PRAGMA table_info(accounts)")]
    assert cols[-2:] == ["display_name", "email_verified_at"]
    info = {r[1]: r for r in db.all("PRAGMA table_info(accounts)")}
    assert info["email"][3] == 1
    sql = db.one("SELECT sql FROM sqlite_master WHERE name='accounts'")[0]
    assert "email                  TEXT NOT NULL UNIQUE" in sql             # no rebuild
    row = db.one("SELECT * FROM accounts WHERE id='a1'")
    assert row["email"] == "old@example.com" and row["display_name"] is None and row["email_verified_at"] is None
    assert db.one("SELECT name FROM sqlite_master WHERE name='signup_codes'")
    assert not db.one("SELECT name FROM sqlite_master WHERE name LIKE 'accounts_v0831%'")
    db.close()
    Database(str(path)).close()                                             # idempotent


# --------------------------------------------------------------------- who()
def test_who_order():
    assert Escrow.who({"display_name": "Sam", "email": "s@example.com"}) == "Sam"
    assert Escrow.who({"display_name": None, "email": "s@example.com"}) == "s@example.com"
    assert Escrow.who({"display_name": "bad\nname", "email": "s@example.com"}) == "s@example.com"
    # Defensive only: every real account has an email.
    assert Escrow.who({"display_name": "", "email": None}) == "Someone using Pax"
    assert Escrow.who({"email": None}, mid=True) == "someone using Pax"


def test_partner_with_from_name_and_every_email_uses_it(env):
    aid, h = account(env)
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
    assert all(ME not in m.body for m in to_friend)        # the first name, not the address
    assert_no_none(env)


def test_without_a_name_emails_use_the_address(env):
    aid, h = account(env)
    did = device(env, h)
    assert env.client.put("/v1/accounts/me/partner", headers=h, json={"email": FRIEND}).status_code == 200
    env.clock.advance(2 * HOUR)
    assert env.client.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 201
    bodies = [m.body for m in env.mail.outbox if m.to == FRIEND]
    assert bodies[0].startswith(f"{ME} has made you their Pax accountability partner")
    assert bodies[1].startswith(f"{ME} asked to turn Pax off on iPhone")
    assert all("Someone using Pax" not in b for b in bodies)
    assert_no_none(env)


def test_applied_blocklist_change_and_partner_change_after_wait(env):
    aid, h = account(env)
    c = env.client
    assert c.put("/v1/accounts/me/partner", headers=h, json={"email": FRIEND, "from_name": "Sam"}).status_code == 200
    assert c.post("/v1/blocklist", headers=h, json={"domain": "example.net"}).status_code == 201
    assert c.post("/v1/blocklist/remove", headers=h, json={"domain": "example.net"}).status_code == 202
    assert c.put("/v1/accounts/me/partner", headers=h, json={"email": "new@example.org"}).status_code == 200
    env.clock.advance(env.settings.max_wait_seconds)
    env.app.state.blocklist.apply_due()
    assert c.get("/v1/accounts/me", headers=h).json()["partner_email"] == "new@example.org"
    applied = [m for m in env.mail.outbox if m.kind == "blocklist_unblock_applied" and m.to != ME]
    assert applied and applied[0].body.startswith("For Sam: ")
    added = [m for m in env.mail.outbox if m.to == "new@example.org" and m.kind == "partner_added"]
    assert added and added[0].body.startswith("Sam has made you")
    assert_no_none(env)


def test_support_release_email_names_the_holder(env, monkeypatch):
    seed = b"\x09" * 32
    monkeypatch.setattr(sc, "SUPPORT_PUBLIC_KEYS_HEX", [ed25519.public_key(seed).hex()])
    aid, h = account(env)
    assert env.client.put("/v1/accounts/me/partner", headers=h,
                          json={"email": FRIEND, "from_name": "Sam"}).status_code == 200
    did = device(env, h, support=True)
    sid = env.client.get(f"/v1/devices/{did}", headers=h).json()["support_id"]
    code = sc.issue(seed, sid, env.clock.now(), lifetime=24 * 3600)
    r = env.client.post(f"/v1/devices/{did}/support-release/redeem", headers=h, json={"code": code})
    assert r.status_code == 200, r.text
    used = [m for m in env.mail.outbox if m.kind == "support_release_used" and m.to == FRIEND]
    assert len(used) == 1
    assert "Pax support checked an emergency with Sam and" in used[0].body
    assert_no_none(env)


def test_from_name_validation(env):
    aid, h = account(env)
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


def test_cannot_be_your_own_partner(env):
    aid, h = account(env)
    r = env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "ME@example.com"})
    assert r.status_code == 400 and "own" in r.json()["message"]


# ------------------------------------------------------------- escrow replace
def _reveal(env, h, did):
    r = env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    assert r.status_code == 201, r.text
    env.clock.advance(r.json()["removal_request"]["seconds_remaining"] + 60)
    r = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 200, r.text
    return r.json()["removal_password"]


def test_escrow_replace_ok_and_revealed_later(env):
    aid, h = account(env)
    did = device(env, h)
    sent = len(env.mail.outbox)
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
    assert len(env.mail.outbox) == sent                                     # sends no email
    env.clock.advance(2 * HOUR)
    assert _reveal(env, h, did) == PW2


def test_escrow_replace_is_bound_to_the_device(env):
    aid, h = account(env)
    a, b = device(env, h, "A"), device(env, h, "B")
    assert env.client.put(f"/v1/devices/{a}/escrow", headers=h, json={"removal_password": PW2}).status_code == 200
    ct = env.escrow.db.one("SELECT password_ct FROM devices WHERE id=?", (a,))[0]
    with pytest.raises(Exception):
        env.escrow.box.decrypt(ct, aad=b)
    assert env.escrow.box.decrypt(ct, aad=a) == PW2


def test_escrow_replace_validation_and_auth(env):
    aid, h = account(env)
    did = device(env, h)
    url = f"/v1/devices/{did}/escrow"
    assert env.client.put(url, headers=h, json={"removal_password": "x" * 19}).status_code == 422
    assert env.client.put(url, headers=h, json={"removal_password": "x" * 257}).status_code == 422
    assert env.client.put(url, headers=h, json={}).status_code == 422
    r = env.client.put(url, json={"removal_password": PW2})
    assert r.status_code == 401 and r.json()["error"] == "unauthorized"
    other_aid, other = account(env, "other@example.com")
    r = env.client.put(url, headers=other, json={"removal_password": PW2})
    assert r.status_code == 404 and r.json()["error"] == "not_found"
    assert env.escrow.box.decrypt(env.escrow.db.one("SELECT password_ct FROM devices WHERE id=?", (did,))[0],
                                  aad=did) == PW


def test_escrow_replace_refused_while_a_request_is_open(env):
    aid, h = account(env)
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
    env.clock.advance(DAY + 60)
    r = env.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.json()["removal_password"] == PW


def test_escrow_replace_after_cancel_works(env):
    aid, h = account(env)
    did = device(env, h)
    env.clock.advance(2 * HOUR)
    env.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    env.client.post(f"/v1/devices/{did}/removal-request/cancel", headers=h)
    assert env.client.put(f"/v1/devices/{did}/escrow", headers=h,
                          json={"removal_password": PW2}).status_code == 200


def test_escrow_replace_refused_once_released_or_retired(env):
    aid, h = account(env)
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
    aid, h = account(env)
    did = device(env, h)
    assert env.client.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 201
    r = env.client.put(f"/v1/devices/{did}/escrow", headers=h, json={"removal_password": PW2})
    assert r.status_code == 409 and r.json()["reason"] == "removal_request_open"


def test_delete_account_made_by_code_confirms_by_email(env):
    aid, h = account(env)
    r = env.client.delete("/v1/accounts/me", headers=h)
    assert r.status_code == 204
    assert env.mail.outbox[-1].to == ME and env.mail.outbox[-1].kind == "account_deleted"
    assert env.client.get("/v1/accounts/me", headers=h).status_code == 401
