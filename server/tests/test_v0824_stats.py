# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.24: /v1/stats answers aggregate counts only, to the operator's key only
(404 otherwise), and keeps one row of counts per UTC day."""
import hashlib
import json
import logging
import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "guard"))

from pax_server import stats as stats_mod  # noqa: E402
from pax_server.config import DAY, HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.doh import DropDnsQueryLogs, hash_token  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402
from verified_signup import verified_signup  # noqa: E402  (v0.8.32)

KEY = "k" * 20 + "test-stats-key-not-real-0123456789abcdef"
KEY_HASH = hashlib.sha256(KEY.encode()).hexdigest()
REPLICA_KEY = "r" * 48
PW = "abcde-fghjk-mnpqr-stuvw-xyz23-45678"
T0 = 1_800_000_000 - (1_800_000_000 % DAY) + 10 * HOUR    # 10:00 UTC


class FakeClock:
    def __init__(self, t=T0):
        self.t = t

    def now(self):
        return self.t

    def advance(self, s):
        self.t += s


class Env:
    pass


def _env(tmp_path):
    e = Env()
    e.clock, e.mail = FakeClock(), MemoryEmailSender()
    e.settings = Settings(db_path=str(tmp_path / "p.sqlite3"), server_key_b64=generate_key_b64(),
                          stats_key_sha256=(KEY_HASH,),
                          replica_key_sha256=(hashlib.sha256(REPLICA_KEY.encode()).hexdigest(),))
    e.client = TestClient(create_app(e.settings, clock=e.clock, sender=e.mail))
    return e


def _account(e, email):
    tok = verified_signup(e.client, email).json()["token"]
    return {"Authorization": f"Bearer {tok}"}


def _device(e, h, name, platform):
    r = e.client.post("/v1/devices", headers=h, json={"name": name, "platform": platform,
                                                       "profile_identifier": "org.paxpeace.t", "removal_password": PW})
    assert r.status_code == 201, r.text
    return r.json()["device_id"]


def _link(e, h, name):
    r = e.client.post("/v1/sync/links", headers=h, json={"device_name": name})
    assert r.status_code == 201, r.text
    return {"X-Pax-Sync-Token": r.json()["sync_token"]}


def _stats(e, **params):
    r = e.client.get("/v1/stats", params={"key": KEY, "format": "json", **params})
    assert r.status_code == 200, r.text
    return r.json()


def test_404_without_a_valid_key(tmp_path):
    e = _env(tmp_path)
    assert e.client.get("/v1/stats").status_code == 404
    assert e.client.get("/v1/stats", params={"key": "wrong" * 10}).status_code == 404
    assert e.client.get("/v1/stats", params={"key": "short"}).status_code == 404
    assert e.client.get("/v1/stats", headers={"X-Pax-Stats-Key": KEY + "x"}).status_code == 404
    assert e.client.get("/v1/stats", headers={"Authorization": "Bearer nope" * 5}).status_code == 404
    # 404 looks like any unknown path: nothing advertises the endpoint.
    assert e.client.get("/v1/stats").json() == e.client.get("/v1/nothing-here").json()
    assert e.client.get("/v1/stats", params={"key": KEY}).status_code == 200
    assert e.client.get("/v1/stats", headers={"X-Pax-Stats-Key": KEY}).status_code == 200
    assert e.client.get("/v1/stats", headers={"Authorization": f"Bearer {KEY}"}).status_code == 200


def test_shipped_key_hash_is_well_formed_and_not_a_placeholder():
    for h in stats_mod.STATS_KEY_SHA256:
        assert re.fullmatch(r"[0-9a-f]{64}", h)
    assert not stats_mod.key_allowed("")
    assert not stats_mod.key_allowed(None)


def test_counts_are_correct(tmp_path):
    e = _env(tmp_path)
    h1 = _account(e, "alex@example.com")
    h2 = _account(e, "sam@example.com")
    _device(e, h1, "Alex's iPhone", "ios")
    _device(e, h1, "Alex's iPad", "ipados")
    s = _link(e, h2, "Sam's MacBook")
    r = e.client.post("/v1/sync", headers={**s, "X-Pax-Version": "0.8.24"}, json={})
    assert r.status_code == 200, r.text
    v = _stats(e)
    assert v["authoritative"] is True and v["role"] == "all"
    assert v["accounts"] == {"total": 2, "new_today": 2, "new_last_7_days": 2}
    assert v["devices"]["total"] == 3
    assert v["devices"]["by_platform"] == {"mac": 1, "iphone": 1, "ipad": 1}
    assert v["active_devices"]["today"] == {"mac": 1, "iphone": 1, "ipad": 1, "total": 3}
    assert v["mac_app_versions"]["counts"] == {"0.8.24": 1}
    assert v["generated_at"].endswith("Z") and "UTC" in v["timezone"]

    # Three days later: nobody active; 7-day window still counts them.
    e.clock.advance(3 * DAY)
    v = _stats(e)
    assert v["active_devices"]["today"]["total"] == 0
    assert v["active_devices"]["today_or_yesterday"]["total"] == 0
    assert v["active_devices"]["last_7_days"]["total"] == 3
    assert v["accounts"]["new_today"] == 0 and v["accounts"]["new_last_7_days"] == 2

    # The iPhone account's DNS address is used: its iPhone and iPad count, once a day.
    tok = e.client.get("/v1/dns", headers=h1).json()["token"]
    st = e.client.app.state.stats
    for _ in range(5):
        st.saw_dns(hash_token(tok))
    st.tick(force=True)
    v = _stats(e)
    assert v["active_devices"]["today"] == {"mac": 0, "iphone": 1, "ipad": 1, "total": 2}
    assert v["accounts_using_pax_dns"] == {"today": 1, "last_7_days": 1}
    # A Mac syncing many times a day is one active Mac; an older guard sends no version.
    for _ in range(3):
        e.client.post("/v1/sync", headers=s, json={})
    v = _stats(e)
    assert v["active_devices"]["today"]["mac"] == 1
    assert v["mac_app_versions"]["counts"] == {"0.8.24": 1}     # last reported version kept

    # History: one row per UTC day; activity counted once per device per day.
    hist = {r["day"]: r for r in _stats(e, days=30)["history"]}
    d0, d3 = stats_mod.utc_day(T0), stats_mod.utc_day(T0 + 3 * DAY)
    assert hist[d0]["active_devices"]["total"] == 3 and hist[d0]["accounts_new"] == 2
    assert hist[d0]["complete"] is True
    assert hist[d3]["active_devices"] == {"total": 3, "mac": 1, "iphone": 1, "ipad": 1}
    assert hist[d3]["complete"] is False and hist[d3]["accounts_total"] == 2
    assert hist[d3]["devices_total"] == 3
    assert len(_stats(e, days=1)["history"]) == 1
    assert _stats(e, days=0)["history"] == []


def test_guard_token_mac_counts_with_version(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "mac@example.com")
    did = _device(e, h, "Mac", "mac")
    gt = e.client.post(f"/v1/devices/{did}/guard-token", headers=h).json()["guard_token"]
    e.clock.advance(2 * DAY)
    r = e.client.get("/v1/guard/config", headers={"X-Pax-Guard-Token": gt, "X-Pax-Version": "0.8.24"})
    assert r.status_code == 200
    v = _stats(e)
    assert v["active_devices"]["today"]["mac"] == 1 and v["devices"]["by_platform"]["mac"] == 1
    assert v["mac_app_versions"]["counts"] == {"0.8.24": 1}
    # Junk in the version header is ignored, not stored.
    e.clock.advance(DAY)
    e.client.get("/v1/guard/config", headers={"X-Pax-Guard-Token": gt, "X-Pax-Version": "<b>alex</b>"})
    assert _stats(e)["mac_app_versions"]["counts"] == {"0.8.24": 1}


def test_released_devices_leave_the_total(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "r@example.com")
    did = _device(e, h, "Phone", "ios")
    e.client.app.state.escrow.db.execute("UPDATE devices SET released_at=? WHERE id=?", (e.clock.now(), did))
    e.clock.advance(1)
    assert _stats(e)["devices"]["total"] == 0


def test_no_personal_fields_in_output(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "private.person@example.com")
    did = _device(e, h, "Private Person's iPhone", "ios")
    s = _link(e, h, "Private Person's MacBook")
    e.client.post("/v1/sync", headers={**s, "X-Pax-Version": "0.8.24"}, json={"add": ["secret-site.example"]})
    e.client.put("/v1/accounts/me/partner", headers=h, json={"partner_email": "partner.person@example.com"})
    tok = e.client.get("/v1/dns", headers=h).json()["token"]
    e.client.app.state.stats.saw_dns(hash_token(tok))
    db = e.client.app.state.escrow.db
    secrets = {"private.person", "partner.person", "example.com", "Private Person", "secret-site",
               did, tok, hash_token(tok), "testclient", "127.0.0.1"}
    secrets |= {r["id"] for r in db.all("SELECT id FROM accounts")}
    secrets |= {r["id"] for r in db.all("SELECT id FROM sync_links")}
    secrets |= {r["token_hash"] for r in db.all("SELECT token_hash FROM sync_links")}
    out_json = json.dumps(_stats(e, days=30))
    out_html = e.client.get("/v1/stats", params={"key": KEY}, headers={"Accept": "text/html"}).text
    assert "<table>" in out_html
    for text in (out_json, out_html):
        for sec in secrets:
            assert sec not in text, sec
        assert "@" not in text
    # The keys of the JSON are counts and labels only.
    allowed = {"generated_at", "timezone", "server", "role", "version", "authoritative", "accounts",
               "devices", "active_devices", "accounts_using_pax_dns", "mac_app_versions", "doh_queries",
               "history"}
    assert set(json.loads(out_json)) == allowed
    # What is stored per device: platform, last day, version. Nothing else.
    cols = [r[1] for r in db.all("PRAGMA table_info(activity)")]
    assert cols == ["subject", "platform", "last_day", "app_version"]
    for r in db.all("SELECT last_day FROM activity"):
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", r["last_day"])


def test_stats_lines_never_reach_the_access_log(tmp_path):
    _env(tmp_path)      # creating the app installs the filter, DoH on or off
    assert any(isinstance(x, DropDnsQueryLogs) for x in logging.getLogger("uvicorn.access").filters)
    f = DropDnsQueryLogs()
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0,
                            '%s - "%s %s HTTP/%s" %d', ("1.2.3.4", "GET", f"/v1/stats?key={KEY}", "1.1", 200), None)
    assert f.filter(rec) is False
    ok = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "GET /v1/health", (), None)
    assert f.filter(ok) is True


def test_replica_activity_needs_the_replica_key_and_counts(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "dns@example.com")
    _device(e, h, "Phone", "ios")
    tok = e.client.get("/v1/dns", headers=h).json()["token"]
    e.clock.advance(2 * DAY)
    body = {"server": "pax-dns2", "token_hashes": [hash_token(tok), "zz" * 32], "queries": 40,
            "since_restart": 100, "started_at": T0}
    assert e.client.post("/v1/replica/activity", json=body).status_code == 404
    assert e.client.post("/v1/replica/activity", json=body,
                         headers={"X-Pax-Replica-Key": "x" * 48}).status_code == 404
    r = e.client.post("/v1/replica/activity", json=body, headers={"X-Pax-Replica-Key": REPLICA_KEY})
    assert r.status_code == 200 and r.json()["resolved"] == 1
    v = _stats(e)
    assert v["active_devices"]["today"]["iphone"] == 1
    assert v["doh_queries"]["today_all_servers"] == 40
    assert v["doh_queries"]["other_servers"]["pax-dns2"]["since_restart"] == 100


def test_backfill_rebuilds_totals_without_inventing_activity(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "old@example.com")
    _device(e, h, "Phone", "ios")
    db = e.client.app.state.escrow.db
    db.execute("DELETE FROM stats_daily")
    db.execute("DELETE FROM activity")
    e.clock.advance(3 * DAY)
    st = stats_mod.Stats(db, e.clock, role="all")
    rows = {r["day"]: r for r in st.history(30)}
    d0 = stats_mod.utc_day(T0)
    assert rows[d0]["rebuilt_from_dates"] is True
    assert rows[d0]["accounts_total"] == 1 and rows[d0]["devices_total"] == 1
    assert rows[d0]["active_devices"] is None and rows[d0]["doh_queries"] is None


def test_dns_role_server_is_not_authoritative_and_needs_the_key(tmp_path):
    class FakeDoh:
        stats = {"queries": 7}

        def start(self):
            pass

        def stop(self):
            pass

        def status(self):
            return {}

    s = Settings(role="dns", doh_enabled=False, stats_key_sha256=(KEY_HASH,))
    c = TestClient(create_app(s, doh=FakeDoh()))
    assert c.get("/v1/stats").status_code == 404
    v = c.get("/v1/stats", params={"key": KEY, "format": "json"}).json()
    assert v["authoritative"] is False and v["role"] == "dns"
    assert v["doh_queries"]["this_server_since_restart"] == 7
    assert "pax. usage" in c.get("/v1/stats", params={"key": KEY, "format": "html"}).text


def test_replica_reporter_sends_hashes_and_query_deltas():
    class FakeDoh:
        stats = {"queries": 0}

    sent = []

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"{}"

    def opener(req):
        sent.append((dict(req.header_items()), json.loads(req.data)))
        return Resp()

    doh = FakeDoh()
    st = stats_mod.Stats(None, FakeClock(), doh, role="dns")
    rep = stats_mod.ReplicaReporter("https://primary.example", REPLICA_KEY, st, server="pax-dns2", opener=opener)
    st.saw_dns("a" * 64)
    st.saw_dns("a" * 64)
    doh.stats["queries"] = 12
    assert rep.report_once()
    hdrs, body = sent[-1]
    assert hdrs.get("X-pax-replica-key") == REPLICA_KEY
    assert body["token_hashes"] == ["a" * 64] and body["queries"] == 12 and body["since_restart"] == 12
    doh.stats["queries"] = 15
    rep.report_once()
    assert sent[-1][1]["queries"] == 3 and sent[-1][1]["token_hashes"] == []
    assert set(sent[-1][1]) == {"server", "token_hashes", "queries", "since_restart", "started_at"}
