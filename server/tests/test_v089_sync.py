# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.9: one blocked-sites list per account, synced to a Mac on local escrow;
one removal rule (partner first, the user's wait, cancellable); one wait minimum
(24 h); sign in to an existing account with an emailed code."""
import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "guard"))

from pax_server.config import DAY, HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402
from verified_signup import verified_signup  # noqa: E402  (v0.8.32)

T0 = 1_800_000_000


class FakeClock:
    def __init__(self, t=T0):
        self.t = t

    def now(self):
        return self.t

    def advance(self, s):
        self.t += s


class Env:
    pass


def _env(tmp_path, **kw):
    e = Env()
    e.clock, e.mail = FakeClock(), MemoryEmailSender()
    e.settings = Settings(db_path=str(tmp_path / "p.sqlite3"), server_key_b64=generate_key_b64(), **kw)
    e.client = TestClient(create_app(e.settings, clock=e.clock, sender=e.mail))
    tok = verified_signup(e.client, "me@example.com").json()["token"]
    e.h = {"Authorization": f"Bearer {tok}"}
    return e


def _link(e, name="Alex's MacBook"):
    r = e.client.post("/v1/sync/links", headers=e.h, json={"device_name": name})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["sync_token"].startswith("pxs_") and body["account_email"] == "me@example.com"
    return {"X-Pax-Sync-Token": body["sync_token"]}


def _sync(e, s, **body):
    r = e.client.post("/v1/sync", headers=s, json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_mac_adds_are_instant_on_the_account_list(tmp_path):
    e = _env(tmp_path)
    s = _link(e)
    out = _sync(e, s, add=["Example.com", "https://www.bad.example/x", "not a site"])
    assert out["added"] == ["example.com", "www.bad.example"]
    assert out["blocked"] == ["example.com", "www.bad.example"]
    assert [r["domain"] for r in out["rejected"]] == ["not a site"]
    # The iPhone path (account list, DoH feed) sees it at once.
    blocked = [b["domain"] for b in e.client.get("/v1/blocklist", headers=e.h).json()["blocked"]]
    assert blocked == ["example.com", "www.bad.example"]
    feed = e.client.app.state.blocklist.changes(0)
    # Pulling an iPhone addition back to the Mac.
    e.client.post("/v1/blocklist", headers=e.h, json={"domain": "phone.example"})
    assert "phone.example" in _sync(e, s)["blocked"]
    assert feed["seq"] >= 1


def test_sync_token_is_narrow(tmp_path):
    e = _env(tmp_path)
    s = _link(e)
    # Not an account token: can't read the account, reveal, or change the wait.
    assert e.client.get("/v1/accounts/me", headers={"Authorization": "Bearer " + s["X-Pax-Sync-Token"]}).status_code == 401
    assert e.client.post("/v1/sync", headers={"X-Pax-Sync-Token": "pxs_wrong"}, json={}).status_code == 401
    assert e.client.post("/v1/sync", json={}).status_code == 401
    assert e.client.get("/v1/sync/links", headers=e.h).json()["links"][0]["device_name"] == "Alex's MacBook"


def test_one_removal_rule_default_is_the_users_wait(tmp_path):
    e = _env(tmp_path)
    e.client.put("/v1/accounts/me/partner", headers=e.h, json={"email": "pal@example.com"})
    s = _link(e)
    _sync(e, s, add=["bad.example"], wait_seconds=5 * DAY)
    n = len(e.mail.outbox)
    r = e.client.post("/v1/sync/unblock", headers=s, json={"domain": "bad.example"})
    assert r.status_code == 202, r.text
    req = r.json()["request"]
    # Strictest wins: the Mac's 5-day wait beats the account's 72 h.
    assert req["seconds_remaining"] == 5 * DAY
    assert "pal@example.com" in [m.to for m in e.mail.outbox[n:]]
    # Still blocked everywhere during the wait (a waiting removal counts as blocked for the Mac).
    st = _sync(e, s)
    assert st["blocked"] == ["bad.example"] and st["pending"][0]["domain"] == "bad.example"
    # The same rule from the iPhone side (account token).
    e.client.post("/v1/blocklist", headers=e.h, json={"domain": "two.example"})
    r2 = e.client.post("/v1/blocklist/remove", headers=e.h, json={"domain": "two.example"})
    assert r2.json()["request"]["seconds_remaining"] == 5 * DAY
    e.clock.advance(5 * DAY)
    st = _sync(e, s, since=T0)
    assert st["blocked"] == []
    assert sorted(x["domain"] for x in st["removed"]) == ["bad.example", "two.example"]


def test_removal_can_be_cancelled_from_the_mac(tmp_path):
    e = _env(tmp_path)
    s = _link(e)
    _sync(e, s, add=["bad.example"])
    rid = e.client.post("/v1/sync/unblock", headers=s, json={"domain": "bad.example"}).json()["request"]["request_id"]
    r = e.client.post(f"/v1/sync/requests/{rid}/cancel", headers=s)
    assert r.status_code == 200 and r.json()["state"]["pending"] == []
    e.clock.advance(30 * DAY)
    assert _sync(e, s)["blocked"] == ["bad.example"]


def test_partner_unreachable_starts_nothing(tmp_path):
    e = _env(tmp_path)
    s = _link(e)
    _sync(e, s, add=["bad.example"], partner_email="pal@example.com")

    def boom(_email):
        raise OSError("smtp down")
    e.mail.send = boom
    r = e.client.post("/v1/sync/unblock", headers=s, json={"domain": "bad.example"})
    assert r.status_code == 503
    assert _sync(e, s)["pending"] == []


def test_linked_macs_partner_is_told_first(tmp_path):
    e = _env(tmp_path)
    s = _link(e)
    _sync(e, s, add=["bad.example"], partner_email="macpal@example.com")
    e.client.post("/v1/sync/unblock", headers=s, json={"domain": "bad.example"})
    kinds = e.mail.kinds_to("macpal@example.com")
    assert "blocklist_unblock_requested" in kinds


def test_fixed_delay_setting(tmp_path):
    e = _env(tmp_path, blocklist_delay="fixed", blocklist_delay_seconds=72 * HOUR)
    s = _link(e)
    _sync(e, s, add=["bad.example"], wait_seconds=10 * DAY)
    r = e.client.post("/v1/sync/unblock", headers=s, json={"domain": "bad.example"})
    assert r.json()["request"]["seconds_remaining"] == 72 * HOUR


def test_delay_env_setting(monkeypatch):
    monkeypatch.setenv("PAX_BLOCKLIST_DELAY", "fixed")
    assert Settings.from_env().blocklist_delay == "fixed"
    monkeypatch.setenv("PAX_BLOCKLIST_DELAY", "")
    assert Settings.from_env().blocklist_delay == "wait"
    monkeypatch.setenv("PAX_BLOCKLIST_DELAY", "sometimes")
    try:
        Settings.from_env()
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_removed_only_after_link_and_since(tmp_path):
    e = _env(tmp_path)
    e.client.post("/v1/blocklist", headers=e.h, json={"domain": "old.example"})
    e.client.post("/v1/blocklist/remove", headers=e.h, json={"domain": "old.example"})
    e.clock.advance(3 * DAY)
    e.client.get("/v1/blocklist", headers=e.h)      # applied before the Mac linked
    s = _link(e)
    assert _sync(e, s)["removed"] == []
    # Union on link: the Mac's copy of old.example comes back to the account list.
    assert _sync(e, s, add=["old.example"])["blocked"] == ["old.example"]


def test_readding_cancels_a_waiting_removal(tmp_path):
    e = _env(tmp_path)
    s = _link(e)
    _sync(e, s, add=["bad.example"])
    e.client.post("/v1/blocklist/remove", headers=e.h, json={"domain": "bad.example"})
    assert _sync(e, s, add=["bad.example"])["pending"] == []


def test_wait_minimum_is_24_hours_and_health_says_so(tmp_path):
    e = _env(tmp_path)
    assert e.client.put("/v1/accounts/me/wait", headers=e.h, json={"wait_hours": 24}).status_code == 200
    h = e.client.get("/v1/health").json()["wait_limits"]
    assert h == {"min_wait_seconds": DAY, "max_wait_seconds": 365 * DAY, "default_wait_seconds": 3 * DAY}
    import local_escrow as le
    assert (le.MIN_WAIT, le.MAX_WAIT) == (Settings().min_wait_seconds, Settings().max_wait_seconds)
    me = e.client.get("/v1/accounts/me", headers=e.h).json()
    assert me["limits"] == {"min_wait_seconds": DAY, "max_wait_seconds": 365 * DAY}


def test_wait_decrease_still_waits_and_tells_partner(tmp_path):
    e = _env(tmp_path)
    e.client.put("/v1/accounts/me/partner", headers=e.h, json={"email": "pal@example.com"})
    r = e.client.put("/v1/accounts/me/wait", headers=e.h, json={"wait_hours": 24}).json()
    assert r["wait_seconds"] == 3 * DAY and r["pending_wait_seconds"] == DAY
    assert "wait_decrease_requested" in e.mail.kinds_to("pal@example.com")


def test_register_conflict_hints_sign_in_and_code_signin(tmp_path):
    e = _env(tmp_path)
    r = e.client.post("/v1/accounts", json={"email": "me@example.com"})
    assert r.status_code == 409 and r.json()["sign_in"] is True
    # Unknown address: same answer, no email.
    n = len(e.mail.outbox)
    assert e.client.post("/v1/accounts/signin/start", json={"email": "nobody@example.com"}).status_code == 202
    assert len(e.mail.outbox) == n
    assert e.client.post("/v1/accounts/signin/start", json={"email": "Me@Example.com"}).status_code == 202
    mail = [m for m in e.mail.outbox if m.kind == "signin_code"][-1]
    code = re.search(r"\b(\d{6})\b", mail.body).group(1)
    wrong = "000000" if code != "000000" else "111111"
    assert e.client.post("/v1/accounts/signin", json={"email": "me@example.com", "code": wrong}).status_code == 401
    r = e.client.post("/v1/accounts/signin", json={"email": "me@example.com", "code": code, "label": "Mac 2"})
    assert r.status_code == 200
    h2 = {"Authorization": f"Bearer {r.json()['token']}"}
    assert e.client.get("/v1/accounts/me", headers=h2).json()["email"] == "me@example.com"
    # The first sign-in still works; the code can't be reused.
    assert e.client.get("/v1/accounts/me", headers=e.h).status_code == 200
    assert e.client.post("/v1/accounts/signin", json={"email": "me@example.com", "code": code}).status_code == 401


def test_code_attempts_are_limited(tmp_path):
    e = _env(tmp_path)
    e.client.post("/v1/accounts/signin/start", json={"email": "me@example.com"})
    code = re.search(r"\b(\d{6})\b", [m for m in e.mail.outbox if m.kind == "signin_code"][-1].body).group(1)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        e.client.post("/v1/accounts/signin", json={"email": "me@example.com", "code": wrong})
    assert e.client.post("/v1/accounts/signin", json={"email": "me@example.com", "code": code}).status_code == 401


def test_replica_feed_carries_synced_sites(tmp_path):
    """The second server (PAX_ROLE=dns) replicates from the same change feed."""
    e = _env(tmp_path)
    tok = e.client.get("/v1/dns", headers=e.h).json()["token"]
    assert tok
    s = _link(e)
    before = e.client.app.state.blocklist.changes(0)["seq"]
    _sync(e, s, add=["fromthemac.example"])
    ch = e.client.app.state.blocklist.changes(before)
    assert any("fromthemac.example" in a["block"] for a in ch["accounts"])
