# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.32: no client can make an account without a verified email.

* POST /v1/accounts (Pax for Mac <= 0.8.31) refuses new accounts: 410
  app_update_required (PAX-ESCROW-020), nothing written, no email. An address that
  already has an account still answers 409 sign_in (the old code sign-in works).
* The only code that writes an accounts row is ListSync.email_verify (a 6-digit
  code to the email), which sets email_verified_at.
* Accounts made before 0.8.32 without a proved email are grandfathered.
"""
import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_v085_limits import build  # noqa: E402
from test_v0831_onetap_accounts import device, last_code, legacy_account  # noqa: E402
from verified_signup import verified_signup  # noqa: E402

PKG = ROOT / "pax_server"
# Functions allowed to INSERT into accounts (each proves the email with a code first).
CREATORS = {("sync.py", "email_verify")}


@pytest.fixture
def env(tmp_path):
    return build(tmp_path)


def _account_writers():
    found = set()
    for f in sorted(PKG.glob("*.py")):
        tree = ast.parse(f.read_text())
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    sql = " ".join(node.value.upper().split())
                    if any(k in sql for k in ("INTO ACCOUNTS(", "INTO ACCOUNTS (", "REPLACE INTO ACCOUNTS")):
                        found.add((f.name, fn.name))
    return found


def test_only_the_code_check_writes_account_rows():
    assert _account_writers() == CREATORS


def test_escrow_has_no_unverified_creator(env):
    assert not hasattr(env.escrow, "register_account")


@pytest.mark.parametrize("email", ["new@example.com", "  New@Example.COM "])
def test_old_route_refuses_and_writes_nothing(env, email):
    r = env.client.post("/v1/accounts", json={"email": email})
    assert r.status_code == 410, r.text
    b = r.json()
    assert b == {"error": "app_update_required", "pax_code": "PAX-ESCROW-020", "message": b["message"]}
    assert b["message"].startswith("This version of Pax can't make new accounts any more.")
    assert "paxpeace.com" in b["message"]
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 0
    assert env.escrow.db.one("SELECT COUNT(*) FROM signup_codes")[0] == 0
    assert env.mail.outbox == []


def test_old_route_still_rate_limited_and_still_hints_sign_in(env):
    legacy_account(env, "old@example.com")
    assert env.client.post("/v1/accounts", json={"email": "old@example.com"}).json()["sign_in"] is True
    for i in range(4):
        assert env.client.post("/v1/accounts", json={"email": f"n{i}@example.com"}).status_code == 410
    r = env.client.post("/v1/accounts", json={"email": "n9@example.com"})
    assert r.status_code == 429 and r.json()["pax_code"] == "PAX-ESCROW-006"


def test_old_route_validation_unchanged(env):
    assert env.client.post("/v1/accounts", json={"email": "not-an-email"}).status_code == 422
    assert env.client.post("/v1/accounts", json={}).status_code == 422


def test_verify_is_the_way_and_marks_the_email_verified(env):
    r = verified_signup(env.client, "mac@example.com", label="Mac")
    assert r.status_code == 201 and r.json()["created"] is True
    row = env.escrow.db.one("SELECT * FROM accounts WHERE email='mac@example.com'")
    assert row["email_verified_at"] == env.clock.now()
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    assert env.client.get("/v1/accounts/me", headers=h).json()["email_verified"] is True
    # The same address again signs in to that account (what a second Mac does).
    r2 = verified_signup(env.client, "mac@example.com", label="Mac 2")
    assert r2.status_code == 200 and r2.json()["account_id"] == r.json()["account_id"]
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 1


def test_grandfathered_unverified_accounts_keep_working(env):
    made = legacy_account(env, "before@example.com")
    h = {"Authorization": f"Bearer {made['token']}"}
    me = env.client.get("/v1/accounts/me", headers=h).json()
    assert me["email_verified"] is False and me["email"] == "before@example.com"
    assert env.client.put("/v1/accounts/me/wait", headers=h, json={"wait_days": 7}).status_code == 200
    device(env, h, name="Mac", platform="mac")
    # A code sign-in proves the address from then on.
    assert env.client.post("/v1/accounts/email/start", json={"email": "before@example.com"}).status_code == 202
    r = env.client.post("/v1/accounts/email/verify",
                        json={"email": "before@example.com", "code": last_code(env, "before@example.com")})
    assert r.status_code == 200 and r.json()["account_id"] == made["account_id"]
    assert env.client.get("/v1/accounts/me", headers=h).json()["email_verified"] is True


def test_wrong_code_makes_nothing(env):
    assert env.client.post("/v1/accounts/email/start", json={"email": "x@example.com"}).status_code == 202
    good = last_code(env, "x@example.com")
    bad = "000000" if good != "000000" else "111111"
    r = env.client.post("/v1/accounts/email/verify", json={"email": "x@example.com", "code": bad})
    assert r.status_code == 401 and r.json()["pax_code"] == "PAX-ESCROW-001"
    assert env.escrow.db.one("SELECT COUNT(*) FROM accounts")[0] == 0
