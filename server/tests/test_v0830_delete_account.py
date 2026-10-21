# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.30: DELETE /v1/accounts/me (App Store guideline 5.1.1(v)). Fail closed: refused
(409 devices_still_protected) while Pax still holds any device's key or a turn-off wait,
emergency release or other removal request is open. Otherwise every row of the account
goes in one transaction, the holder is emailed (best-effort), 204."""
import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "guard"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pax_server.config import DAY, HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.doh import Policies, hash_token  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402

from test_v0826_device_state import PW, FakeClock  # noqa: E402

TABLES = ("accounts", "devices", "removal_requests", "guard_tokens", "blocklist_entries",
          "blocklist_requests", "dns_tokens", "dns_changes", "sync_links", "account_tokens",
          "signin_codes", "events", "activity")


class FlakySender(MemoryEmailSender):
    def __init__(self):
        super().__init__()
        self.down: set = set()

    def send(self, email):
        if email.to in self.down:
            raise OSError("smtp down")
        super().send(email)


class Env:
    pass


def _env(tmp_path):
    e = Env()
    e.clock, e.mail = FakeClock(), FlakySender()
    e.settings = Settings(db_path=str(tmp_path / "p.sqlite3"), server_key_b64=generate_key_b64())
    e.client = TestClient(create_app(e.settings, clock=e.clock, sender=e.mail))
    e.db = e.client.app.state.escrow.db
    return e


def _account(e, email):
    r = e.client.post("/v1/accounts", json={"email": email})
    assert r.status_code == 201, r.text
    return r.json()["account_id"], {"Authorization": f"Bearer {r.json()['token']}"}


def _device(e, h, name="iPhone", platform="ios"):
    r = e.client.post("/v1/devices", headers=h, json={"name": name, "platform": platform,
                                                       "profile_identifier": "org.paxpeace.t",
                                                       "removal_password": PW})
    assert r.status_code == 201, r.text
    return r.json()["device_id"]


def _release(e, h, did):
    r = e.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    assert r.status_code == 201, r.text
    e.clock.advance(r.json()["removal_request"]["seconds_remaining"] + 60)
    r = e.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 200, r.text


def _full(e, email, release=True):
    """An account with a row in every one of the 13 tables."""
    aid, h = _account(e, email)
    c = e.client
    assert c.put("/v1/accounts/me/partner", headers=h, json={"email": "friend-" + email}).status_code == 200
    did = _device(e, h)
    mac = _device(e, h, name="Mac", platform="mac")
    assert c.post(f"/v1/devices/{mac}/guard-token", headers=h).status_code == 201
    assert c.post("/v1/blocklist", headers=h, json={"domain": "example.org"}).status_code == 201
    assert c.post("/v1/blocklist/remove", headers=h, json={"domain": "example.org"}).status_code == 202
    dns = c.get("/v1/dns", headers=h).json()["token"]
    link = c.post("/v1/sync/links", headers=h, json={"device_name": "Mac"}).json()
    assert c.post("/v1/sync", headers={"X-Pax-Sync-Token": link["sync_token"]},
                  json={"add": ["example.net"]}).status_code == 200
    second = _second_signin(e, email)
    st = c.app.state.stats
    st.saw_dns(hash_token(dns))
    st.tick(force=True)
    e.clock.advance(2 * HOUR)
    if release:
        _release(e, h, did)
        _release(e, h, mac)
    return aid, h, {"device": did, "mac": mac, "dns": dns, "sync": link["sync_token"], "second": second}


def _second_signin(e, email):
    """Another sign-in to the account (email + one-time code): an account_tokens row."""
    import pax_server.sync as sync_mod
    orig = sync_mod.secrets.randbelow
    sync_mod.secrets.randbelow = lambda n: 123456
    try:
        e.client.app.state.list_sync.signin_start(email)
    finally:
        sync_mod.secrets.randbelow = orig
    r = e.client.post("/v1/accounts/signin", json={"email": email, "code": "123456"})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def _rows(e, aid):
    """Rows of each of the 13 tables that belong to account `aid`."""
    db = e.db
    dev = [r[0] for r in db.all("SELECT id FROM devices WHERE account_id=?", (aid,))]
    links = [r[0] for r in db.all("SELECT id FROM sync_links WHERE account_id=?", (aid,))]
    q = ",".join("?" * len(dev)) or "''"
    subj = [f"device:{d}" for d in dev] + [f"link:{x}" for x in links] + [f"dns-account:{aid}"]
    qs = ",".join("?" * len(subj))
    return {
        "accounts": db.one("SELECT COUNT(*) FROM accounts WHERE id=?", (aid,))[0],
        "devices": len(dev),
        "removal_requests": db.one(f"SELECT COUNT(*) FROM removal_requests WHERE device_id IN ({q})", dev)[0],
        "guard_tokens": db.one(f"SELECT COUNT(*) FROM guard_tokens WHERE device_id IN ({q})", dev)[0],
        "activity": db.one(f"SELECT COUNT(*) FROM activity WHERE subject IN ({qs})", subj)[0],
        **{t: db.one(f"SELECT COUNT(*) FROM {t} WHERE account_id=?", (aid,))[0]
           for t in ("blocklist_entries", "blocklist_requests", "dns_tokens", "dns_changes",
                     "sync_links", "account_tokens", "signin_codes", "events")},
    }


def test_needs_a_token(tmp_path):
    e = _env(tmp_path)
    r = e.client.delete("/v1/accounts/me")
    assert r.status_code == 401 and r.json()["error"] == "unauthorized"
    r = e.client.delete("/v1/accounts/me", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_schema_has_exactly_the_tables_we_delete(tmp_path):
    """If a new table is added, this test makes someone decide about deletion."""
    e = _env(tmp_path)
    names = {r[0] for r in e.db.all("SELECT name FROM sqlite_master WHERE type='table' "
                                    "AND name NOT LIKE 'sqlite_%'")}
    kept = {"support_nonces", "trial_hardware", "signup_attempts", "mail_log", "stats_daily"}
    assert names == set(TABLES) | kept
    from pax_server.escrow import Escrow
    assert {t for t, _ in Escrow._DELETE_SQL} == set(TABLES)


def _refused(e, h, reason):
    r = e.client.delete("/v1/accounts/me", headers=h)
    assert r.status_code == 409, r.text
    b = r.json()
    assert b["error"] == "devices_still_protected" and b["count"] == len(b["devices"]) >= 1
    assert "Turn Pax off on every device first" in b["message"]
    assert reason in {d["reason"] for d in b["devices"]}
    return b


def test_refused_while_pax_is_on(tmp_path):
    e = _env(tmp_path)
    aid, h, ids = _full(e, "a@example.com", release=False)
    before = _rows(e, aid)
    b = _refused(e, h, "pax_on")
    assert b["count"] == 2 and {d["device_id"] for d in b["devices"]} == {ids["device"], ids["mac"]}
    assert b["pax_code"] == "PAX-ESCROW-005"
    after = _rows(e, aid)
    assert after["events"] == before["events"] + 1        # the refusal is logged
    after["events"] = before["events"]
    assert after == before                                 # nothing deleted
    assert e.client.get("/v1/accounts/me", headers=h).status_code == 200
    assert "account_deleted" not in e.mail.kinds_to("a@example.com")


def test_refused_in_a_turn_off_wait_and_emergency(tmp_path):
    e = _env(tmp_path)
    aid, h = _account(e, "a@example.com")
    did = _device(e, h)
    e.clock.advance(2 * HOUR)
    assert e.client.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 201
    b = _refused(e, h, "turn_off_wait")
    assert b["devices"][0]["removal_request"] == "standard"
    r = e.client.post(f"/v1/devices/{did}/emergency", headers=h, json={"reason": "a real emergency here"})
    assert r.status_code == 201
    _refused(e, h, "emergency_release")


def test_refused_with_any_pending_request_even_on_a_released_device(tmp_path):
    e = _env(tmp_path)
    aid, h = _account(e, "a@example.com")
    did = _device(e, h)
    e.clock.advance(2 * HOUR)
    _release(e, h, did)
    # A pending row on a released device can't be made through the API; fail closed anyway.
    e.db.execute("INSERT INTO removal_requests(id, device_id, kind, status, created_at, unlock_at, expires_at) "
                 "VALUES ('x', ?, 'standard', 'pending', ?, ?, ?)",
                 (did, e.clock.now(), e.clock.now() + DAY, e.clock.now() + 8 * DAY))
    _refused(e, h, "pending_request")


def test_not_checking_in_still_counts_as_protected(tmp_path):
    e = _env(tmp_path)
    aid, h = _account(e, "a@example.com")
    did = _device(e, h)
    tok = e.client.get("/v1/dns", headers=h).json()["token"]
    st = e.client.app.state.stats
    st.saw_dns(hash_token(tok))
    st.tick(force=True)
    e.clock.advance(10 * DAY)                       # a phone reset or wiped long ago
    assert e.client.get(f"/v1/devices/{did}", headers=h).json()["checking_in"] is False
    b = _refused(e, h, "pax_on")
    assert b["devices"][0]["checking_in"] is False


def test_a_lapsed_request_doesnt_block(tmp_path):
    e = _env(tmp_path)
    aid, h = _account(e, "a@example.com")
    did = _device(e, h)
    e.clock.advance(2 * HOUR)
    _release(e, h, did)
    e.db.execute("INSERT INTO removal_requests(id, device_id, kind, status, created_at, unlock_at, expires_at) "
                 "VALUES ('old', ?, 'standard', 'pending', ?, ?, ?)",
                 (did, e.clock.now() - 9 * DAY, e.clock.now() - 8 * DAY, e.clock.now() - DAY))
    assert e.client.delete("/v1/accounts/me", headers=h).status_code == 204


def test_deletes_every_row_and_only_this_account(tmp_path):
    e = _env(tmp_path)
    aid, h, ids = _full(e, "a@example.com")
    bid, hb, _ = _full(e, "b@example.com")
    before_a, before_b = _rows(e, aid), _rows(e, bid)
    assert all(before_a[t] > 0 for t in TABLES), [t for t in TABLES if not before_a[t]]
    hw = e.db.one("SELECT COUNT(*) FROM trial_hardware")[0]
    nonces = e.db.one("SELECT COUNT(*) FROM support_nonces")[0]
    r = e.client.delete("/v1/accounts/me", headers=h)
    assert r.status_code == 204 and r.content == b""
    after = _rows(e, aid)
    # Only the DNS-feed tombstone (random account ID, a seq and a time) is left...
    assert after.pop("dns_changes") == 1
    assert all(n == 0 for n in after.values()), after
    tomb = e.db.one("SELECT * FROM dns_changes WHERE account_id=?", (aid,))
    assert set(tomb.keys()) == {"seq", "account_id", "at"}
    # ...nothing anywhere names the email or the trusted person
    for t in [r[0] for r in e.db.all("SELECT name FROM sqlite_master WHERE type='table'")]:
        for col in [c[1] for c in e.db.all(f"PRAGMA table_info({t})")]:
            n = e.db.one(f"SELECT COUNT(*) FROM {t} WHERE CAST({col} AS TEXT) LIKE '%a@example.com%'")[0]
            assert n == 0, (t, col)
    assert e.db.all("PRAGMA foreign_key_check") == []
    assert _rows(e, bid) == before_b                       # the other account is untouched
    assert e.client.get("/v1/accounts/me", headers=hb).status_code == 200
    # Kept by design: hardware hashes (no second trial day) and used support codes.
    assert e.db.one("SELECT COUNT(*) FROM trial_hardware")[0] == hw
    assert e.db.one("SELECT COUNT(*) FROM support_nonces")[0] == nonces
    # The tombstone goes after an hour (by then every DNS server has had a full sync).
    e.clock.advance(HOUR + 1)
    assert e.client.app.state.escrow.prune_deleted(force=True) == 1
    assert _rows(e, aid)["dns_changes"] == 0
    assert _rows(e, bid)["dns_changes"] == before_b["dns_changes"]


def test_every_token_stops_working(tmp_path):
    e = _env(tmp_path)
    aid, h, ids = _full(e, "a@example.com")
    second = ids["second"]
    assert e.client.delete("/v1/accounts/me", headers=second).status_code == 204   # any sign-in works
    for hdr in (h, second):
        assert e.client.get("/v1/accounts/me", headers=hdr).status_code == 401
        assert e.client.delete("/v1/accounts/me", headers=hdr).status_code == 401
    assert e.client.post("/v1/sync", headers={"X-Pax-Sync-Token": ids["sync"]}, json={}).status_code == 401
    # The address can make a new account afterwards.
    assert e.client.post("/v1/accounts", json={"email": "a@example.com"}).status_code == 201


def test_confirmation_email_and_no_partner_email(tmp_path):
    e = _env(tmp_path)
    aid, h, ids = _full(e, "a@example.com")
    partner_before = list(e.mail.kinds_to("friend-a@example.com"))
    assert e.client.delete("/v1/accounts/me", headers=h).status_code == 204
    msgs = [m for m in e.mail.outbox if m.kind == "account_deleted"]
    assert len(msgs) == 1 and msgs[0].to == "a@example.com"
    assert msgs[0].subject == "Your Pax account has been deleted"
    assert msgs[0].body.startswith("Your Pax account has been deleted") and msgs[0].body.endswith("\n\nPax")
    assert e.mail.kinds_to("friend-a@example.com") == partner_before    # trusted person not emailed


def test_mail_failure_still_deletes(tmp_path, caplog):
    e = _env(tmp_path)
    aid, h, ids = _full(e, "a@example.com")
    e.mail.down.add("a@example.com")
    with caplog.at_level("INFO"):
        r = e.client.delete("/v1/accounts/me", headers=h)
    assert r.status_code == 204
    assert _rows(e, aid)["accounts"] == 0
    assert not [m for m in e.mail.outbox if m.kind == "account_deleted"]
    text = "\n".join(rec.getMessage() for rec in caplog.records if rec.name.startswith("pax."))
    assert "account_deleted" in text and "a@example.com" not in text


def test_refusals_are_rate_limited(tmp_path):
    e = _env(tmp_path)
    aid, h = _account(e, "a@example.com")
    _device(e, h)
    for _ in range(10):
        assert e.client.delete("/v1/accounts/me", headers=h).status_code == 409
    r = e.client.delete("/v1/accounts/me", headers=h)
    assert r.status_code == 429 and r.json()["pax_code"] == "PAX-ESCROW-006"
    e.clock.advance(HOUR + 1)
    assert e.client.delete("/v1/accounts/me", headers=h).status_code == 409


def test_dns_servers_drop_the_account_at_the_next_poll(tmp_path):
    e = _env(tmp_path)
    aid, h, ids = _full(e, "a@example.com")
    bid, hb, idb = _full(e, "b@example.com")
    bl = e.client.app.state.blocklist
    replica = Policies()
    full = bl.changes(0)
    replica.apply(dict(full, full=True))
    seq = full["seq"]
    assert replica.known_hash(ids["dns"]) and replica.known_hash(idb["dns"])
    assert e.client.delete("/v1/accounts/me", headers=h).status_code == 204
    inc = bl.changes(seq)                               # the next 3-second poll
    assert not inc["full"] and [a["account_id"] for a in inc["accounts"]] == [aid]
    assert inc["accounts"][0]["deleted"] is True and inc["accounts"][0]["tokens"] == []
    replica.apply(inc)
    assert replica.known_hash(ids["dns"]) is None       # default (still filtered) policy now
    assert replica.known_hash(idb["dns"])
    assert aid not in replica.snapshot()["accounts"] and len(replica) == 1
    # A full sync never lists it.
    assert aid not in [a["account_id"] for a in bl.changes(0)["accounts"]]


def test_fk_safe_order_on_a_raw_connection(tmp_path):
    """The same DELETEs pass with foreign keys enforced on a fresh connection."""
    e = _env(tmp_path)
    aid, h, ids = _full(e, "a@example.com")
    assert e.client.delete("/v1/accounts/me", headers=h).status_code == 204
    conn = sqlite3.connect(e.settings.db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    conn.close()
