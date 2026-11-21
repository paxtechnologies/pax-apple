# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.37 (no server change): after Pax for Mac is reinstalled the app rebuilds its iPhone/iPad
list from GET /v1/devices and matches a plugged-in phone by its protection profile's identifier.
This pins the contract the app relies on: every device status carries `profile_identifier`
exactly as registered, the list is the account's own, released devices say so, and retired
ones are gone."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from test_v0826_device_state import _account, _env, _release, PW  # noqa: E402

PID = "org.paxpeace.pax.ios.1f2e3d4c-0000-4000-8000-00000000abcd"


def _register(e, h, name, pid, platform="ios"):
    r = e.client.post("/v1/devices", headers=h, json={"name": name, "platform": platform,
                                                       "profile_identifier": pid, "removal_password": PW})
    assert r.status_code == 201, r.text
    return r.json()["device_id"]


def test_every_status_carries_the_profile_identifier(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    did = _register(e, h, "Ruben's iPhone", PID)
    assert e.client.post("/v1/devices", headers=h, json={}).status_code == 422
    one = e.client.get(f"/v1/devices/{did}", headers=h).json()
    assert one["profile_identifier"] == PID and one["platform"] == "ios" and one["name"] == "Ruben's iPhone"
    listed = e.client.get("/v1/devices", headers=h).json()["devices"]
    assert [(d["device_id"], d["profile_identifier"]) for d in listed] == [(did, PID)]


def test_list_is_the_accounts_own_and_keeps_same_named_set_ups_apart(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    other = _account(e, "b@example.com")
    real = _register(e, h, "Ruben's iPhone", PID)
    # The failed reinstall attempt: a second password stored for the same phone name.
    orphan = _register(e, h, "Ruben's iPhone", "org.paxpeace.pax.ios.99999999-0000-4000-8000-000000000001")
    mac = _register(e, h, "Ruben's Mac", "org.paxpeace.pax.macos.x", platform="mac")
    _register(e, other, "Ruben's iPhone", "org.paxpeace.pax.ios.someone-else")
    listed = {d["device_id"]: d for d in e.client.get("/v1/devices", headers=h).json()["devices"]}
    assert set(listed) == {real, orphan, mac}
    assert listed[real]["profile_identifier"] == PID
    assert listed[orphan]["profile_identifier"] != PID
    assert listed[mac]["platform"] == "mac"
    assert e.client.get(f"/v1/devices/{real}", headers=other).status_code == 404


def test_released_says_so_and_retired_is_gone(tmp_path):
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    did = _register(e, h, "Ruben's iPhone", PID)
    _release(e, h, did)
    listed = e.client.get("/v1/devices", headers=h).json()["devices"]
    assert listed[0]["released"] is True and listed[0]["profile_identifier"] == PID
    assert e.client.post(f"/v1/devices/{did}/retire", headers=h).status_code == 200
    assert e.client.get("/v1/devices", headers=h).json()["devices"] == []


def test_a_protected_device_cannot_be_retired(tmp_path):
    """Hiding a set-up on the Mac is local only: the server keeps every protected device."""
    e = _env(tmp_path)
    h = _account(e, "a@example.com")
    did = _register(e, h, "Ruben's iPhone", PID)
    assert e.client.post(f"/v1/devices/{did}/retire", headers=h).status_code == 409
    assert [d["device_id"] for d in e.client.get("/v1/devices", headers=h).json()["devices"]] == [did]
