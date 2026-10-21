# SPDX-License-Identifier: GPL-3.0-only
"""The Windows set-up against the real Pax server code (server/, in-process, no network):
account, turn-off wait, trusted person, the existing-account code, DNS token, device with
trial day, and after the wait the server hands back exactly the password inside the profile
that went to the phone."""
import plistlib
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "server"))
pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("email_validator")

from fastapi.testclient import TestClient  # noqa: E402
from pax_server.config import HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402

from pax_windows import choices as ch  # noqa: E402
from pax_windows.account import EmailAccount  # noqa: E402
from pax_windows.escrow import EscrowClient  # noqa: E402
from pax_windows.flow import SetupSession  # noqa: E402
from pax_windows.helper import DemoHelperRunner  # noqa: E402


class Clock:
    t = 1_800_000_000

    def now(self):
        return self.t


@pytest.fixture
def server(tmp_path):
    clock, mail = Clock(), MemoryEmailSender()
    settings = Settings(db_path=str(tmp_path / "pax.sqlite3"), server_key_b64=generate_key_b64())
    client = TestClient(create_app(settings, clock=clock, sender=mail))

    def transport(method, url, headers, body, timeout):
        path = url.split("://", 1)[1].split("/", 1)[1]
        r = client.request(method, "/" + path, headers=headers, content=body)
        return r.status_code, r.content
    return client, transport, clock, mail, settings


def test_windows_setup_end_to_end(server, tmp_path):
    client, transport, clock, mail, settings = server
    escrow = EscrowClient("https://api.test/", transport=transport)
    assert escrow.wait_limits().presets() == [1, 3, 7]
    s = SetupSession(DemoHelperRunner(ios="26.4"), escrow, tmp_path, dns_health=lambda b: True)
    c = ch.SetupChoices(wait_days=3, partner_email="friend@example.org", find_my_confirmed_off=True,
                        backup_confirmed=True, agreed=True, blocked_sites=["example.org"])
    assert s.ensure_account(EmailAccount("alex@example.org"), c).state == "ready"
    me = escrow.account_summary()
    assert me.get("wait_seconds", 3 * 24 * HOUR) == 3 * 24 * HOUR

    d = s.find_devices()[0]
    s.start(d, s.preflight(d, c), c)
    while s.connect_once(d) != "paired":
        pass
    s.confirm(d, c)
    assert s.lock_and_escrow(d, c) == "installed"

    prof = plistlib.loads(s.runner.installed_profiles[0])
    pw = next(p for p in prof["PayloadContent"] if p["PayloadType"] == "com.apple.profileRemovalPassword")
    dns = next(p for p in prof["PayloadContent"] if p["PayloadType"] == "com.apple.dnsSettings.managed")
    token = escrow.dns_info()["token"]
    assert dns["DNSSettings"]["ServerURL"] == f"https://dns.paxpeace.com/u/{token}/dns-query"

    h = {"Authorization": f"Bearer {escrow.token}"}
    did = s.escrowed_device_id
    dev = client.get(f"/v1/devices/{did}", headers=h).json()
    assert dev["name"] == "Demo iPhone" and dev["platform"] == "ios"
    assert (dev.get("trial") or {}).get("active") is True
    assert dev.get("support_release") in (True, None) or dev.get("support_release", {})

    # End the trial so the normal turn-off wait applies, then wait it out.
    assert client.post(f"/v1/devices/{did}/trial/end", headers=h).status_code == 200
    clock.t += settings.grace_seconds + 1
    assert client.post(f"/v1/devices/{did}/removal-request", headers=h).status_code == 201
    early = client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert early.status_code != 200 and pw["RemovalPassword"] not in early.text
    clock.t += 72 * HOUR + 1
    ok = client.post(f"/v1/devices/{did}/removal-request/confirm", headers=h, json={"confirm": True})
    assert ok.status_code == 200, ok.text
    assert ok.json()["removal_password"] == pw["RemovalPassword"]
    assert "removal_requested" in mail.kinds_to("friend@example.org")
    for e in mail.outbox:
        assert pw["RemovalPassword"] not in e.body


def test_existing_account_signs_in_with_the_emailed_code(server, tmp_path):
    client, transport, clock, mail, settings = server
    EscrowClient("https://api.test/", transport=transport).register_account("alex@example.org")
    escrow = EscrowClient("https://api.test/", transport=transport)
    acct = EmailAccount("alex@example.org")
    assert acct.ensure(escrow).state == "code_sent"
    body = [e for e in mail.outbox if e.kind == "signin_code"][-1].body
    acct.code = re.search(r"\b(\d{6})\b", body).group(1)
    assert acct.ensure(escrow).state == "ready" and escrow.token
    assert escrow.account_summary()
