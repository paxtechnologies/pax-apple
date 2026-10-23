# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0 iPhone/iPad end to end, mocked (no phone, no cfgutil, no network):

  profile  make_profile builds the iOS profile: CleanBrowsing Family as direct
           DoH (the iPhone has no pax-guard forwarder), the removal password,
           the built-in media deny hosts, and it validates;
  pairing  the supervision plan (device/seed.py) turns supervision on with the
           Pax host certificate registered, so the profile installs silently;
  server   the account gets a witness partner, the device is escrowed with the
           profile's password, a blocked-site change waits and emails the
           partner, a removal request emails the partner, waits, can be
           cancelled and asked again, and after the wait the server hands back
           exactly the password inside the profile (with a partner email). The
           partner never approves or vetoes anything: no endpoint takes their
           answer.
"""
import plistlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "profile"))
sys.path.insert(0, str(ROOT / "device"))

from pax_server.config import DAY, HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402
import make_profile as mp  # noqa: E402
import seed  # noqa: E402
from verified_signup import verified_signup  # noqa: E402  (v0.8.32)

PARTNER = "friend@example.org"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000

    def now(self):
        return self.t


@pytest.fixture
def server(tmp_path):
    clock, mail = Clock(), MemoryEmailSender()
    settings = Settings(db_path=str(tmp_path / "pax.sqlite3"), server_key_b64=generate_key_b64())
    return TestClient(create_app(settings, clock=clock, sender=mail)), clock, mail, settings


def test_iphone_profile_pairing_change_and_unlock(server):
    client, clock, mail, settings = server

    # ---- 1. profile ---------------------------------------------------------
    gen = mp.build_profile(mp.ProfileOptions(platform="ios", custom_url_blocks=["https://my-trigger.example"]))
    prof = plistlib.loads(gen.to_bytes())
    payloads = {p["PayloadType"]: p for p in prof["PayloadContent"]}
    dns = payloads["com.apple.dnsSettings.managed"]["DNSSettings"]
    assert dns["DNSProtocol"] == "HTTPS" and dns["ServerURL"] == mp.CLEANBROWSING_FAMILY_DOH
    assert "127.0.0.1" not in gen.to_bytes().decode()           # no local forwarder on iOS
    assert payloads["com.apple.profileRemovalPassword"]["RemovalPassword"] == gen.removal_password
    deny = " ".join(payloads["com.apple.webcontent-filter"]["DenyListURLs"])
    assert "my-trigger.example" in deny and all(h in deny for h in mp.IOS_BUILTIN_DENY_HOSTS)
    mp.validate_profile(gen.profile, platform="ios")

    # ---- 2. pairing / supervision --------------------------------------------
    cert = b"0\x82pax-supervision-cert-der"
    phone_now = {"OrganizationName": "", "AllowPairing": True}
    cfg = seed.plan_cloud_configuration(phone_now, supervisor_cert_der=cert)
    assert seed.reads_supervised(cfg) and seed.host_cert_registered(cfg, cert)
    assert cfg["AllowPairing"] is True                                # Finder backups keep working
    strict = seed.plan_cloud_configuration(phone_now, supervisor_cert_der=cert, allow_pairing=False)
    assert strict["AllowPairing"] is False

    # ---- 3. the server: account, witness partner, device ----------------------
    r = verified_signup(client, "alex@example.org")
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    assert client.put("/v1/accounts/me/partner", headers=h, json={"email": PARTNER}).status_code == 200
    r = client.post("/v1/devices", headers=h, json={
        "name": "Alex's iPhone", "platform": "ios", "profile_identifier": gen.profile_identifier,
        "removal_password": gen.removal_password})
    assert r.status_code == 201, r.text
    did = r.json()["device_id"]
    clock.t += settings.grace_seconds + 1

    # a change: blocking is instant, unblocking waits and tells the partner
    assert client.post("/v1/blocklist", headers=h, json={"domain": "another-trigger.example"}).status_code == 201
    rq = client.post("/v1/blocklist/remove", headers=h, json={"domain": "another-trigger.example"})
    assert rq.status_code == 202 and rq.json()["request"]["seconds_remaining"] == 72 * HOUR
    assert "blocklist_unblock_requested" in mail.kinds_to(PARTNER)

    # removal: request, cancel (partner told), request again
    rr = client.post(f"/v1/devices/{did}/removal-request", headers=h).json()["removal_request"]
    assert rr["kind"] == "standard" and rr["can_reveal"] is False
    assert client.post(f"/v1/devices/{did}/removal-request/cancel", headers=h).status_code == 200
    assert "removal_cancelled" in mail.kinds_to(PARTNER)
    rr = client.post(f"/v1/devices/{did}/removal-request", headers=h).json()["removal_request"]
    assert mail.kinds_to(PARTNER).count("removal_requested") == 2
    early = client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert early.status_code != 200 and gen.removal_password not in early.text
    for e in mail.outbox:                                   # never a password in an email
        assert gen.removal_password not in e.body

    # ---- 4. unlock via the server after the wait ------------------------------
    clock.t += 72 * HOUR + 1
    ok = client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert ok.status_code == 200, ok.text
    assert ok.json()["removal_password"] == gen.removal_password
    assert "password_revealed" in mail.kinds_to(PARTNER)
    # the blocked-site change has also taken effect after its wait
    assert "another-trigger.example" not in [b["domain"] for b in
                                             client.get("/v1/blocklist", headers=h).json()["blocked"]]
    # witness only: there is no partner approve/veto route
    paths = {r.path for r in client.app.routes}
    assert not any("approve" in p or "veto" in p for p in paths)
