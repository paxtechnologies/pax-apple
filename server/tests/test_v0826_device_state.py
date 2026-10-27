# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.26: the Mac shows an iPhone's real state. Device status says plainly whether
the password was released, and (owner only) the last UTC day the account's Pax DNS
address was used and whether the phone is still checking in. POST
/v1/devices/{id}/retire forgets a device on the owner's list, only once it is released."""
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "guard"))

from pax_server import stats as stats_mod  # noqa: E402
from pax_server.config import DAY, HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.doh import hash_token  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402
from verified_signup import verified_signup  # noqa: E402  (v0.8.32)

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
    e.settings = Settings(db_path=str(tmp_path / "p.sqlite3"), server_key_b64=generate_key_b64())
    e.client = TestClient(create_app(e.settings, clock=e.clock, sender=e.mail))
    return e


def _account(e, email):
    tok = verified_signup(e.client, email).json()["token"]
    return {"Authorization": f"Bearer {tok}"}


def _device(e, h, name="Ruben's iPhone", platform="ios"):
    r = e.client.post("/v1/devices", headers=h, json={"name": name, "platform": platform,
                                                       "profile_identifier": "org.paxpeace.t", "removal_password": PW})
    assert r.status_code == 201, r.text
    return r.json()["device_id"]


def _status(e, h, did):
    r = e.client.get(f"/v1/devices/{did}", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def _dns_used(e, h):
    tok = e.client.get("/v1/dns", headers=h).json()["token"]
    st = e.client.app.state.stats
    st.saw_dns(hash_token(tok))
    st.tick(force=True)


def _release(e, h, did):
    """A finished turn-off wait with the password revealed."""
    e.clock.advance(2 * HOUR)                    # past the first hour after set-up
    r = e.client.post(f"/v1/devices/{did}/removal-request", headers=h)
    assert r.status_code == 201, r.text
    e.clock.advance(r.json()["removal_request"]["seconds_remaining"] + 60)
    r = e.client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert r.status_code == 200, r.text


# ------------------------------------------------------------------ released

def test_released_is_plain_and_outlives_the_reveal_window(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    did = _device(e, h)
    assert _status(e, h, did)["released"] is False
    _release(e, h, did)
    s = _status(e, h, did)
    assert s["released"] is True and s["released_at"]
    # Days later the "revealed" request is past its window and no longer returned,
    # but the device still says released (the bug: the Mac fell back to "Protected").
    e.clock.advance(30 * DAY)
    s = _status(e, h, did)
    assert s["removal_request"] is None and s["released"] is True
    listed = e.client.get("/v1/devices", headers=h).json()["devices"]
    assert [d["released"] for d in listed] == [True]


# ------------------------------------------------------------------ retire

def test_retire_refuses_a_device_still_protected(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    did = _device(e, h)
    r = e.client.post(f"/v1/devices/{did}/retire", headers=h)
    assert r.status_code == 409, r.text
    s = _status(e, h, did)
    assert s["released"] is False and s["removal_request"] is None      # nothing turned off
    assert len(e.client.get("/v1/devices", headers=h).json()["devices"]) == 1
    db = e.client.app.state.escrow.db
    assert db.one("SELECT 1 FROM events WHERE kind='device_retire_refused' AND device_id=?", (did,))
    # A running turn-off wait doesn't count as released either.
    assert e.client.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 201
    e.clock.advance(3600)
    assert e.client.post(f"/v1/devices/{did}/retire", headers=h).status_code == 409
    assert db.one("SELECT released_at, retired_at FROM devices WHERE id=?", (did,))[:] == (None, None)


def test_retire_refuses_another_account(tmp_path):
    e = _env(tmp_path)
    owner = _account(e, "owner@example.com")
    other = _account(e, "other@example.com")
    did = _device(e, owner)
    _release(e, owner, did)
    assert e.client.post(f"/v1/devices/{did}/retire", headers=other).status_code == 404
    assert e.client.post(f"/v1/devices/{did}/retire").status_code == 401
    assert e.client.post(f"/v1/devices/{did}/retire",
                         headers={"Authorization": "Bearer nope"}).status_code == 401
    assert _status(e, owner, did)["released"] is True          # still on the owner's list


def test_retire_forgets_a_released_device(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    keep = _device(e, h, "Ruben's iPad", "ipados")
    did = _device(e, h)
    _release(e, h, did)
    r = e.client.post(f"/v1/devices/{did}/retire", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["retired"] is True
    ids = [d["device_id"] for d in e.client.get("/v1/devices", headers=h).json()["devices"]]
    assert ids == [keep]
    assert e.client.get(f"/v1/devices/{did}", headers=h).status_code == 404
    # Idempotent, and logged once.
    assert e.client.post(f"/v1/devices/{did}/retire", headers=h).status_code == 200
    db = e.client.app.state.escrow.db
    assert db.one("SELECT COUNT(*) FROM events WHERE kind='device_retired' AND device_id=?", (did,))[0] == 1
    assert db.one("SELECT 1 FROM activity WHERE subject=?", (f"device:{did}",)) is None
    # The other phone is untouched and still protected.
    assert _status(e, h, keep)["released"] is False


# ------------------------------------------------------------------ last seen

def test_last_seen_and_checking_in(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    did = _device(e, h)
    d0 = stats_mod.utc_day(T0)
    s = _status(e, h, did)
    # Set-up counts as seen, but until the account's Pax DNS address is used Pax can't tell.
    assert s["last_seen"] == d0 and s["checking_in"] is None
    _dns_used(e, h)
    s = _status(e, h, did)
    assert s["last_seen"] == d0 and s["checking_in"] is True
    e.clock.advance(2 * DAY)                    # at most 2 UTC days quiet: still fine
    assert _status(e, h, did)["checking_in"] is True
    e.clock.advance(DAY)                        # 3 UTC days (48 h or more) with no traffic
    s = _status(e, h, did)
    assert s["checking_in"] is False and s["last_seen"] == d0
    _dns_used(e, h)                              # it comes back
    s = _status(e, h, did)
    assert s["checking_in"] is True and s["last_seen"] == stats_mod.utc_day(e.clock.now())


def test_last_seen_is_day_only_and_kept_for_quiet_phones(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    did = _device(e, h)
    _dns_used(e, h)
    s = _status(e, h, did)
    assert isinstance(s["last_seen"], str) and len(s["last_seen"]) == 10      # YYYY-MM-DD, no time
    # Weeks later the normal 35-day pruning keeps an unreleased phone's row, so it
    # still shows "not checking in" with its last day.
    e.clock.advance(60 * DAY)
    e.client.app.state.stats.snapshot()
    s = _status(e, h, did)
    assert s["checking_in"] is False and s["last_seen"] == stats_mod.utc_day(T0)


def test_no_last_seen_for_macs_or_released_phones(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    mac = _device(e, h, "Mac", "mac")
    _dns_used(e, h)
    s = _status(e, h, mac)
    assert s["last_seen"] is None and s["checking_in"] is None
    did = _device(e, h)
    _release(e, h, did)
    s = _status(e, h, did)
    assert s["released"] is True and s["checking_in"] is None


def test_last_seen_is_owner_only(tmp_path):
    e = _env(tmp_path)
    owner = _account(e, "owner@example.com")
    other = _account(e, "other@example.com")
    did = _device(e, owner)
    assert e.client.get(f"/v1/devices/{did}", headers=other).status_code == 404
    assert e.client.get(f"/v1/devices/{did}").status_code == 401
    assert e.client.get("/v1/devices", headers=other).json()["devices"] == []
