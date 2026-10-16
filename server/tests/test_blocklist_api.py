# SPDX-License-Identifier: GPL-3.0-only
"""Custom blocklist: instant adds, 72 h removals/exceptions with an injectable
clock, cancellation, partner notification, limits, DNS tokens and the pax-dns feed."""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pax_server.config import HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64, hash_token  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402

T0 = 1_800_000_000
KEY = "internal-test-key"


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
    settings = Settings(db_path=str(tmp_path / "pax.sqlite3"), server_key_b64=generate_key_b64(),
                        internal_api_key=KEY, blocklist_max_entries=5, allowlist_max_entries=2,
                        dns_base_url="https://dns.example.test/")
    app = create_app(settings, clock=clock, sender=mail)

    class Env:
        pass

    e = Env()
    e.client, e.clock, e.mail, e.settings, e.app = TestClient(app), clock, mail, settings, app
    r = e.client.post("/v1/accounts", json={"email": "user@example.com"})
    e.h = {"Authorization": f"Bearer {r.json()['token']}"}
    return e


def blocked(env):
    return [b["domain"] for b in env.client.get("/v1/blocklist", headers=env.h).json()["blocked"]]


def effective(env):
    acct = env.app.state.escrow.authenticate(env.h["Authorization"][7:])
    return env.app.state.blocklist.effective(acct["id"])


def test_requires_auth(env):
    assert env.client.get("/v1/blocklist").status_code == 401
    assert env.client.post("/v1/blocklist", json={"domain": "a.com"}).status_code == 401


def test_add_is_immediate_and_normalised(env):
    r = env.client.post("/v1/blocklist", headers=env.h, json={"domain": "https://Bad.Example/x"})
    assert r.status_code == 201, r.text
    assert r.json()["domain"] == "bad.example" and r.json()["created"] is True
    assert blocked(env) == ["bad.example"]
    assert effective(env) == (["bad.example"], [])
    # idempotent
    r = env.client.post("/v1/blocklist", headers=env.h, json={"domain": "bad.example"})
    assert r.status_code == 201 and r.json()["created"] is False
    assert blocked(env) == ["bad.example"]


@pytest.mark.parametrize("bad", ["com", "1.2.3.4", "*.co.uk", "a.*.b.com", "localhost", ""])
def test_add_rejects_bad_domains(env, bad):
    r = env.client.post("/v1/blocklist", headers=env.h, json={"domain": bad})
    assert r.status_code in (400, 422)


def test_size_cap(env):
    for i in range(5):
        assert env.client.post("/v1/blocklist", headers=env.h,
                               json={"domain": f"site{i}.com"}).status_code == 201
    r = env.client.post("/v1/blocklist", headers=env.h, json={"domain": "one-more.com"})
    assert r.status_code == 422 and r.json()["error"] == "limit_reached"


def test_removal_waits_72h_then_applies(env):
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "bad.example"})
    r = env.client.post("/v1/blocklist/remove", headers=env.h, json={"domain": "BAD.example"})
    assert r.status_code == 202, r.text
    req = r.json()["request"]
    assert req["action"] == "unblock" and req["seconds_remaining"] == 72 * HOUR
    listed = r.json()["list"]["blocked"][0]
    assert listed["pending_removal"]["request_id"] == req["request_id"]
    # Still blocked during the wait.
    env.clock.advance(72 * HOUR - 1)
    assert effective(env)[0] == ["bad.example"]
    assert blocked(env) == ["bad.example"]
    # A second request for the same site is refused while one waits.
    assert env.client.post("/v1/blocklist/remove", headers=env.h,
                           json={"domain": "bad.example"}).status_code == 409
    env.clock.advance(1)
    # Effective view changes at once, even before anything sweeps.
    assert effective(env)[0] == []
    assert blocked(env) == []
    assert "blocklist_unblock_applied" in env.mail.kinds_to("user@example.com")


def test_remove_unknown_is_404(env):
    assert env.client.post("/v1/blocklist/remove", headers=env.h,
                           json={"domain": "never.example"}).status_code == 404


def test_cancel_removal_keeps_block_and_notifies_partner(env):
    env.client.put("/v1/accounts/me/partner", headers=env.h, json={"email": "friend@example.com"})
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "bad.example"})
    rid = env.client.post("/v1/blocklist/remove", headers=env.h,
                          json={"domain": "bad.example"}).json()["request"]["request_id"]
    assert "blocklist_unblock_requested" in env.mail.kinds_to("friend@example.com")
    env.clock.advance(10 * HOUR)
    r = env.client.post(f"/v1/blocklist/requests/{rid}/cancel", headers=env.h)
    assert r.status_code == 200, r.text
    assert r.json()["pending"] == []
    assert "blocklist_unblock_cancelled" in env.mail.kinds_to("friend@example.com")
    env.clock.advance(100 * HOUR)
    assert blocked(env) == ["bad.example"]
    # Cancelling twice: conflict.
    assert env.client.post(f"/v1/blocklist/requests/{rid}/cancel", headers=env.h).status_code == 409


def test_cancel_after_effective_is_too_late(env):
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "bad.example"})
    rid = env.client.post("/v1/blocklist/remove", headers=env.h,
                          json={"domain": "bad.example"}).json()["request"]["request_id"]
    env.clock.advance(72 * HOUR)
    assert env.client.post(f"/v1/blocklist/requests/{rid}/cancel", headers=env.h).status_code == 409
    assert blocked(env) == []


def test_readding_cancels_pending_removal(env):
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "bad.example"})
    env.client.post("/v1/blocklist/remove", headers=env.h, json={"domain": "bad.example"})
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "bad.example"})
    env.clock.advance(80 * HOUR)
    assert blocked(env) == ["bad.example"]


def test_other_users_cannot_cancel(env):
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "bad.example"})
    rid = env.client.post("/v1/blocklist/remove", headers=env.h,
                          json={"domain": "bad.example"}).json()["request"]["request_id"]
    other = env.client.post("/v1/accounts", json={"email": "other@example.com"}).json()["token"]
    r = env.client.post(f"/v1/blocklist/requests/{rid}/cancel",
                        headers={"Authorization": f"Bearer {other}"})
    assert r.status_code == 404


def test_allow_exception_waits_and_remove_is_immediate(env):
    env.client.put("/v1/accounts/me/partner", headers=env.h, json={"email": "friend@example.com"})
    r = env.client.post("/v1/allowlist", headers=env.h, json={"domain": "news-site.com"})
    assert r.status_code == 202, r.text
    assert "blocklist_allow_requested" in env.mail.kinds_to("friend@example.com")
    assert effective(env)[1] == []
    env.clock.advance(72 * HOUR)
    assert effective(env)[1] == ["news-site.com"]
    view = env.client.get("/v1/blocklist", headers=env.h).json()
    assert [a["domain"] for a in view["allowed"]] == ["news-site.com"]
    # Dropping the exception is immediate.
    r = env.client.post("/v1/allowlist/remove", headers=env.h, json={"domain": "news-site.com"})
    assert r.status_code == 200 and r.json()["allowed"] == []
    assert effective(env)[1] == []


def test_allow_rules(env):
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "bad.example"})
    # Can't sneak a custom block out through the allow-list.
    assert env.client.post("/v1/allowlist", headers=env.h,
                           json={"domain": "bad.example"}).status_code == 409
    # Public suffixes / TLDs refused (would switch the filter off).
    assert env.client.post("/v1/allowlist", headers=env.h, json={"domain": "com"}).status_code == 400
    assert env.client.post("/v1/allowlist", headers=env.h, json={"domain": "co.uk"}).status_code == 400
    # Cap counts pending requests too.
    assert env.client.post("/v1/allowlist", headers=env.h, json={"domain": "a.com"}).status_code == 202
    assert env.client.post("/v1/allowlist", headers=env.h, json={"domain": "b.com"}).status_code == 202
    assert env.client.post("/v1/allowlist", headers=env.h, json={"domain": "c.com"}).status_code == 422


def test_blocking_beats_pending_or_existing_exception(env):
    env.client.post("/v1/allowlist", headers=env.h, json={"domain": "x.com"})
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "x.com"})
    env.clock.advance(73 * HOUR)
    assert effective(env) == (["x.com"], [])
    env.client.post("/v1/blocklist/remove", headers=env.h, json={"domain": "x.com"})
    env.clock.advance(73 * HOUR)
    env.client.post("/v1/allowlist", headers=env.h, json={"domain": "x.com"})
    env.clock.advance(73 * HOUR)
    assert effective(env) == ([], ["x.com"])
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "x.com"})
    assert effective(env) == (["x.com"], [])


def test_delay_is_configurable(tmp_path):
    clock = FakeClock()
    settings = Settings(db_path=str(tmp_path / "p.sqlite3"), server_key_b64=generate_key_b64(),
                        blocklist_delay="fixed", blocklist_delay_seconds=24 * HOUR)
    c = TestClient(create_app(settings, clock=clock, sender=MemoryEmailSender()))
    h = {"Authorization": "Bearer " + c.post("/v1/accounts", json={"email": "a@b.co"}).json()["token"]}
    c.post("/v1/blocklist", headers=h, json={"domain": "bad.example"})
    r = c.post("/v1/blocklist/remove", headers=h, json={"domain": "bad.example"})
    assert r.json()["request"]["seconds_remaining"] == 24 * HOUR
    assert r.json()["list"]["limits"]["delay_seconds"] == 24 * HOUR


# ------------------------------------------------------------------ DNS tokens
def test_dns_info_stable_and_url(env):
    a = env.client.get("/v1/dns", headers=env.h).json()
    b = env.client.get("/v1/dns", headers=env.h).json()
    assert a["token"] == b["token"] and len(a["token"]) >= 22
    assert a["doh_url"] == f"https://dns.example.test/u/{a['token']}/dns-query"


def test_token_stored_hashed_and_encrypted(env):
    tok = env.client.get("/v1/dns", headers=env.h).json()["token"]
    db = env.app.state.escrow.db
    row = db.one("SELECT * FROM dns_tokens")
    assert row["token_hash"] == hash_token(tok)
    assert tok.encode() not in bytes(row["token_ct"])


def test_rotation_keeps_old_token_for_the_wait(env):
    old = env.client.get("/v1/dns", headers=env.h).json()["token"]
    r = env.client.post("/v1/dns/rotate", headers=env.h)
    assert r.status_code == 202
    new = r.json()["token"]
    assert new != old and r.json()["retiring"][0]["retire_at"] == T0 + 72 * HOUR
    feed = env.client.get("/internal/v1/dns/changes", headers={"X-Pax-Internal-Key": KEY}).json()
    hashes = {t["hash"] for t in feed["accounts"][0]["tokens"]}
    assert hashes == {hash_token(old), hash_token(new)}
    assert env.client.post("/v1/dns/rotate", headers=env.h).status_code == 409
    env.clock.advance(72 * HOUR)
    feed = env.client.get("/internal/v1/dns/changes", headers={"X-Pax-Internal-Key": KEY}).json()
    assert {t["hash"] for t in feed["accounts"][0]["tokens"]} == {hash_token(new)}


def test_rotation_cancel_keeps_both(env):
    old = env.client.get("/v1/dns", headers=env.h).json()["token"]
    env.client.post("/v1/dns/rotate", headers=env.h)
    rid = env.client.get("/v1/blocklist", headers=env.h).json()["pending"][0]["request_id"]
    env.client.post(f"/v1/blocklist/requests/{rid}/cancel", headers=env.h)
    env.clock.advance(100 * HOUR)
    feed = env.client.get("/internal/v1/dns/changes", headers={"X-Pax-Internal-Key": KEY}).json()
    assert hash_token(old) in {t["hash"] for t in feed["accounts"][0]["tokens"]}


# --------------------------------------------------------------- pax-dns feed
def test_internal_feed_auth_and_incremental(env):
    assert env.client.get("/internal/v1/dns/changes").status_code == 404
    assert env.client.get("/internal/v1/dns/changes",
                          headers={"X-Pax-Internal-Key": "wrong"}).status_code == 404
    hk = {"X-Pax-Internal-Key": KEY}
    tok = env.client.get("/v1/dns", headers=env.h).json()["token"]
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "bad.example"})
    full = env.client.get("/internal/v1/dns/changes", headers=hk).json()
    assert full["full"] is True
    (acct,) = full["accounts"]
    assert acct["block"] == ["bad.example"] and acct["tokens"][0]["hash"] == hash_token(tok)
    seq = full["seq"]
    assert env.client.get(f"/internal/v1/dns/changes?since={seq}", headers=hk).json()["accounts"] == []
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "worse.example"})
    inc = env.client.get(f"/internal/v1/dns/changes?since={seq}", headers=hk).json()
    assert inc["accounts"][0]["block"] == ["bad.example", "worse.example"]
    # A removal reaching its time shows up in the feed without any user action.
    seq = inc["seq"]
    env.client.post("/v1/blocklist/remove", headers=env.h, json={"domain": "bad.example"})
    seq = env.client.get(f"/internal/v1/dns/changes?since={seq}", headers=hk).json()["seq"]
    env.clock.advance(72 * HOUR)
    inc = env.client.get(f"/internal/v1/dns/changes?since={seq}", headers=hk).json()
    assert inc["accounts"][0]["block"] == ["worse.example"]


def test_internal_feed_disabled_without_key(tmp_path):
    settings = Settings(db_path=str(tmp_path / "p.sqlite3"), server_key_b64=generate_key_b64())
    c = TestClient(create_app(settings, clock=FakeClock(), sender=MemoryEmailSender()))
    assert c.get("/internal/v1/dns/changes", headers={"X-Pax-Internal-Key": ""}).status_code == 404


def test_sweeper_runs_in_lifespan(tmp_path):
    clock = FakeClock()
    settings = Settings(db_path=str(tmp_path / "p.sqlite3"), server_key_b64=generate_key_b64(),
                        blocklist_sweep_seconds=1)
    app = create_app(settings, clock=clock, sender=MemoryEmailSender())
    with TestClient(app) as c:
        h = {"Authorization": "Bearer " + c.post("/v1/accounts",
                                                  json={"email": "a@b.co"}).json()["token"]}
        c.post("/v1/blocklist", headers=h, json={"domain": "bad.example"})
        c.post("/v1/blocklist/remove", headers=h, json={"domain": "bad.example"})
        clock.advance(72 * HOUR)
        import time
        deadline = time.time() + 5
        db = app.state.escrow.db
        while time.time() < deadline:
            if db.one("SELECT status FROM blocklist_requests")["status"] == "applied":
                break
            time.sleep(0.1)
        assert db.one("SELECT status FROM blocklist_requests")["status"] == "applied"
