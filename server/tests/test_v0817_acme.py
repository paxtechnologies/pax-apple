# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.17: the primary never got a dns.paxpeace.com certificate because the
second server redirected the primary's ACME challenges (Caddy's automatic
redirect sat in front of its catch-all port-80 forwarder). No network."""
import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pax_server import caddy_sync as cs  # noqa: E402
from pax_server.config import Settings  # noqa: E402

PRIMARY, DNS2 = "167.233.42.17", "89.167.17.42"

# What Caddy adapts the second server's Caddyfile (http:// catch-all + sites) to.
DNS2_JSON = {"apps": {"http": {"servers": {
    "srv0": {"listen": [":443"], "routes": [
        {"match": [{"host": ["dns.paxpeace.com"]}], "handle": [{"handler": "subroute"}], "terminal": True},
        {"match": [{"host": [DNS2]}], "handle": [{"handler": "subroute"}], "terminal": True}]},
    "srv1": {"listen": [":80"], "routes": [
        {"handle": [{"handler": "subroute", "routes": [
            {"group": "g0", "match": [{"path": ["/.well-known/acme-challenge/*"]}], "handle": []},
            {"group": "g0", "handle": [{"handler": "static_response", "status_code": 308}]}]}]}]}}}}}


class FakeAdmin:
    def __init__(self, cfg, health=True):
        self.cfg, self.loads, self.forced, self._health = json.loads(json.dumps(cfg)), [], [], health

    def opener(self, req):
        class R(io.BytesIO):
            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False
        if req.get_method() == "GET":
            return R(json.dumps(self.cfg).encode())
        body = json.loads(req.data)
        self.loads.append(body)
        self.forced.append(req.get_header("Cache-control") == "must-revalidate")
        self.cfg = body
        return R(b"")

    def health(self):
        return self._health


def dns2_sync(a, addrs=(PRIMARY, DNS2)):
    return cs.CaddySync("dns.paxpeace.com", "api.paxpeace.com", own_ip=DNS2, mode="dns",
                        resolver=lambda h: list(addrs), opener=a.opener, health=a.health)


def test_second_server_puts_host_matched_forwarder_first_on_port_80():
    a = FakeAdmin(DNS2_JSON)
    c = dns2_sync(a)
    assert c.check_once() == "applied"
    srv80 = a.cfg["apps"]["http"]["servers"]["srv1"]
    first = srv80["routes"][0]
    assert first["@id"] == cs.FWD_ROUTE_ID
    # A host matcher: Caddy inserts its automatic redirects after the last route
    # that has one, so this forwarder now comes before them.
    assert first["match"][0]["host"] == ["dns.paxpeace.com"]
    assert first["match"][0]["not"] == [{"header": {cs.FWD_HEADER: ["*"]}}]
    assert first["handle"][0]["upstreams"] == [{"dial": f"{PRIMARY}:80"}]
    assert first["handle"][0]["headers"]["request"]["set"] == {cs.FWD_HEADER: ["1"]}
    assert srv80["routes"][1:] == DNS2_JSON["apps"]["http"]["servers"]["srv1"]["routes"]
    # Nothing else touched: no extra server, no TLS policy, :443 unchanged.
    assert set(a.cfg["apps"]["http"]["servers"]) == {"srv0", "srv1"}
    assert "tls" not in a.cfg["apps"]
    assert a.cfg["apps"]["http"]["servers"]["srv0"] == DNS2_JSON["apps"]["http"]["servers"]["srv0"]
    assert c.check_once() == "in_place" and len(a.loads) == 1


def test_second_server_rolls_back_and_skips_when_unhealthy():
    a = FakeAdmin(DNS2_JSON, health=False)
    assert dns2_sync(a).check_once() == "api_unhealthy_skip" and not a.loads


def test_second_server_waits_for_its_dns_record():
    a = FakeAdmin(DNS2_JSON)
    assert dns2_sync(a, addrs=(PRIMARY,)).check_once() == "waiting_for_dns_record" and not a.loads


def test_peer_forward_config_without_port80_server_adds_one():
    cfg = {"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": []}}}}}
    out = cs.peer_forward_config(cfg, "dns.paxpeace.com", [PRIMARY])
    assert out["apps"]["http"]["servers"][cs.ACME_SERVER]["listen"] == [":80"]


PRIMARY_JSON = {"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [
    {"match": [{"host": ["api.paxpeace.com"]}], "handle": [{"handler": "subroute"}], "terminal": True}]}}}}}


def test_primary_retries_certificate_when_none_is_served():
    a = FakeAdmin(PRIMARY_JSON)
    t = {"v": 1000.0}
    cert = {"ok": False}
    c = cs.CaddySync("dns.paxpeace.com", "api.paxpeace.com", own_ip=PRIMARY,
                     resolver=lambda h: [PRIMARY, DNS2], opener=a.opener, health=a.health,
                     cert_probe=lambda h: cert["ok"], now=lambda: t["v"], kick_every=1200)
    assert c.check_once() == "applied"
    applied = json.loads(json.dumps(a.cfg))
    assert c.check_once() == "certificate_retry"
    assert a.forced[-1] is True and a.loads[-1] == applied      # same config, forced
    t["v"] += 600
    assert c.check_once() == "waiting_for_certificate" and len(a.loads) == 2
    t["v"] += 700
    assert c.check_once() == "certificate_retry" and len(a.loads) == 3
    cert["ok"] = True
    assert c.check_once() == "in_place" and len(a.loads) == 3


def test_primary_does_not_retry_when_api_unhealthy():
    a = FakeAdmin(PRIMARY_JSON)
    c = cs.CaddySync("dns.paxpeace.com", "api.paxpeace.com", own_ip=PRIMARY,
                     resolver=lambda h: [PRIMARY, DNS2], opener=a.opener, health=a.health,
                     cert_probe=lambda h: False)
    c.check_once()
    a._health = False
    assert c.check_once() == "api_unhealthy_skip" and len(a.loads) == 1


def test_settings_acme_forward_only_for_dns_role(monkeypatch):
    monkeypatch.setenv("PAX_ROLE", "dns")
    monkeypatch.setenv("PAX_CADDY_SYNC", "0")
    s = Settings.from_env()
    assert s.caddy_acme_forward is True and s.caddy_sync is False
    monkeypatch.setenv("PAX_CADDY_ACME_FORWARD", "0")
    assert Settings.from_env().caddy_acme_forward is False
    monkeypatch.setenv("PAX_ROLE", "all")
    monkeypatch.delenv("PAX_CADDY_ACME_FORWARD")
    assert Settings.from_env().caddy_acme_forward is False
    assert Settings().caddy_acme_forward is False
