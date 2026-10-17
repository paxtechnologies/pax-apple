# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.8: Pax's own DoH filter for iPhones/iPads (pax_server/doh.py), the DNS
settings API, the replica feed for a DoH-only second server, and the Caddy
admin-API sync (caddy_sync.py). No network: upstreams are fakes."""
import base64
import hashlib
import io
import json
import logging
import struct
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pax_server import caddy_sync as cs  # noqa: E402
from pax_server import doh as doh_mod  # noqa: E402
from pax_server import replica  # noqa: E402
from pax_server.config import HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.main import create_app  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402

import dns_forwarder as dnsf  # noqa: E402  (guard/, on sys.path via doh)
import filter_lists as fl  # noqa: E402

T0 = 1_800_000_000
REPLICA_KEY = "test-replica-key-" + "x" * 40


class FakeClock:
    def __init__(self, t=T0):
        self.t = t

    def now(self):
        return self.t

    def advance(self, s):
        self.t += s


class FakeUpstream:
    """Answers every A query with 203.0.113.7 (AAAA: NODATA); records names."""

    def __init__(self, name="Fake Family", fail=False):
        self.name, self.url, self.host = name, f"https://{name}.test/dns-query", f"{name}.test"
        self.ips, self.healthy, self.last_error, self.trusted_time = ["192.0.2.1"], True, "", None
        self.fail = fail
        self.asked = []

    def query(self, wire):
        if self.fail:
            raise dnsf.DNSError("down")
        q = dnsf.Query(wire)
        self.asked.append(q.name)
        if q.qtype == dnsf.QTYPE_A:
            rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 120, 4) + bytes([203, 0, 113, 7])
            return dnsf._header(q, 0, 1) + q.question + rr
        return dnsf._header(q, 0, 0) + q.question


def query(name, qtype=dnsf.QTYPE_A):
    return dnsf.build_query(name, qtype, 4242)


def answer_kind(resp: bytes) -> str:
    rcode, answers = dnsf.parse_answers(resp)
    if rcode == dnsf.RCODE_SERVFAIL:
        return "servfail"
    for _o, rtype, _c, _t, rdata in answers:
        if rtype == dnsf.QTYPE_CNAME:
            return "rewrite"
        if rtype in (dnsf.QTYPE_A, dnsf.QTYPE_AAAA):
            return "blocked" if not any(rdata) else "forwarded"
    return "nodata"


@pytest.fixture(scope="session")
def filterset(tmp_path_factory):
    """The real bundled v2 lists (same as the Mac), compiled once."""
    store = fl.FilterStore(tmp_path_factory.mktemp("lists"), plugin_dirs=[], compile_in_subprocess=False)
    return store.load()


@pytest.fixture
def env(tmp_path, filterset):
    clock, mail = FakeClock(), MemoryEmailSender()
    settings = Settings(db_path=str(tmp_path / "pax.sqlite3"), server_key_b64=generate_key_b64(),
                        dns_base_url="https://dns.paxpeace.test", blocklist_sweep_seconds=0,
                        replica_key_sha256=(hashlib.sha256(REPLICA_KEY.encode()).hexdigest(),))
    up, yt = FakeUpstream(), FakeUpstream("Fake Adult")
    fwd = dnsf.Forwarder([up], filters=filterset, youtube_upstreams=[yt], log=lambda m: None)
    app0 = create_app(settings, clock=clock, sender=mail)          # doh off: build the DB side
    bl = app0.state.blocklist
    doh = doh_mod.DohService(doh_mod.LocalFeed(bl), str(tmp_path / "dns"), forwarder=fwd,
                             rate=1000, burst=1000, clock=clock.now)
    app = create_app(settings, clock=clock, sender=mail, doh=doh)

    class E:
        pass

    e = E()
    e.client, e.clock, e.mail, e.settings, e.doh, e.up, e.yt = TestClient(app), clock, mail, settings, doh, up, yt
    e.app = app
    r = e.client.post("/v1/accounts", json={"email": "user@example.com"})
    e.h = {"Authorization": f"Bearer {r.json()['token']}"}
    e.token = e.client.get("/v1/dns", headers=e.h).json()["token"]
    return e


def ask(e, name, token=None, qtype=dnsf.QTYPE_A):
    e.doh.sync_once()
    status, body, _h = e.doh.answer(query(name, qtype), e.token if token is None else token, "198.51.100.1")
    assert status == 200
    return answer_kind(body)


def add_device(e):
    r = e.client.post("/v1/devices", headers=e.h, json={
        "name": "iPhone", "platform": "ios", "profile_identifier": "org.paxpeace.pax.ios.x",
        "removal_password": "abcde-fghjk-mnpqr-stuvw-xyz23"})
    assert r.status_code == 201, r.text


# ------------------------------------------------------------------ resolver
def test_default_dns_base_is_paxpeace():
    assert Settings().dns_base_url == "https://dns.paxpeace.com"


def test_users_own_sites_block_instantly_with_subdomains(env):
    assert ask(env, "example.org") == "forwarded"
    assert env.client.post("/v1/blocklist", headers=env.h, json={"domain": "example.org"}).status_code == 201
    assert ask(env, "example.org") == "blocked"
    assert ask(env, "www.example.org") == "blocked"
    assert ask(env, "m.example.org", qtype=dnsf.QTYPE_AAAA) == "blocked"
    # Another user's token (or none) isn't affected by this user's list.
    assert ask(env, "example.org", token="z" * 32) == "forwarded"


def test_removal_waits_and_partner_is_told_first(env):
    env.client.put("/v1/accounts/me/partner", headers=env.h, json={"email": "friend@example.com"})
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "example.org"})
    r = env.client.post("/v1/blocklist/remove", headers=env.h, json={"domain": "example.org"})
    assert r.status_code == 202
    assert "blocklist_unblock_requested" in env.mail.kinds_to("friend@example.com")
    assert ask(env, "example.org") == "blocked"            # still waiting
    env.clock.advance(env.settings.blocklist_delay_seconds + 1)
    assert ask(env, "example.org") == "forwarded"


def test_pax_lists_media_and_rules_match_the_mac(env):
    for name in ("pbs.twimg.com", "video.twimg.com", "cdn.bsky.app"):
        assert ask(env, name) == "blocked", name
    for name in ("redd.it", "i.redd.it", "i.imgur.com"):          # Reddit/Imgur media (v2 lists)
        assert ask(env, name) == "blocked", name
    assert ask(env, "ssstik.io") == "blocked"                      # media converter
    assert ask(env, "x.com") == "forwarded"                        # X text stays readable
    assert ask(env, "www.google.com") == "rewrite"                 # SafeSearch
    assert ask(env, "www.youtube.com") == "rewrite"                # Restricted Mode on by default


def test_restricted_site_never_freed_by_exception(env):
    r = env.client.post("/v1/allowlist", headers=env.h, json={"domain": "ssstik.io"})
    assert r.status_code == 422 and r.json()["error"] == "restricted_site"
    assert ask(env, "ssstik.io") == "blocked"


def test_unknown_or_malformed_token_is_still_filtered(env):
    assert ask(env, "pbs.twimg.com", token="A" * 40) == "blocked"
    assert ask(env, "pbs.twimg.com", token="bad") == "blocked"


def test_all_upstreams_down_is_servfail_never_open(env):
    env.up.fail = True
    assert ask(env, "example.net") == "servfail"


def test_lists_not_loaded_is_servfail(env):
    env.doh.forwarder.set_filters(None)
    assert ask(env, "example.net") == "servfail"


def test_rate_limit_per_client(env):
    env.doh.limiter = doh_mod.RateLimiter(rate=0.001, burst=3)
    codes = [env.doh.answer(query("example.net"), env.token, "198.51.100.9")[0] for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
    assert env.doh.answer(query("example.net"), env.token, "198.51.100.10")[0] == 200


# ---------------------------------------------------------------- settings
def test_youtube_choice_applies_instantly_before_a_device(env):
    # v0.8.13: X / Bluesky media can't be turned off any more (test_v0813_media.py).
    r = env.client.put("/v1/dns/settings", headers=env.h, json={"youtube_restricted": False})
    assert r.status_code == 200 and r.json()["settings"]["youtube_restricted"] is False
    assert ask(env, "pbs.twimg.com") == "blocked"
    assert ask(env, "cdn.bsky.app") == "blocked"
    assert ask(env, "www.youtube.com") == "forwarded"
    assert env.yt.asked and env.yt.asked[-1] == "www.youtube.com"   # Adult filter for YouTube names
    assert ask(env, "www.google.com") == "rewrite"                   # Google SafeSearch stays


def test_youtube_switch_is_instant_both_ways_after_setup(env):
    add_device(env)
    assert env.client.put("/v1/dns/settings", headers=env.h,
                          json={"youtube_restricted": False}).status_code == 200
    assert ask(env, "www.youtube.com") == "forwarded"
    env.client.put("/v1/dns/settings", headers=env.h, json={"youtube_restricted": True})
    assert ask(env, "www.youtube.com") == "rewrite"


# --------------------------------------------------------------- HTTP layer
def test_doh_http_get_post_and_paths(env):
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "example.org"})
    env.doh.sync_once()
    wire = query("example.org")
    b64 = base64.urlsafe_b64encode(wire).decode().rstrip("=")
    for path in (f"/u/{env.token}/dns-query", f"/v1/doh/u/{env.token}/dns-query"):
        r = env.client.get(path, params={"dns": b64})
        assert r.status_code == 200 and r.headers["content-type"] == "application/dns-message"
        assert answer_kind(r.content) == "blocked"
        r = env.client.post(path, content=wire, headers={"Content-Type": "application/dns-message"})
        assert r.status_code == 200 and answer_kind(r.content) == "blocked"
    assert env.client.post(f"/u/{env.token}/dns-query", content=wire,
                           headers={"Content-Type": "text/plain"}).status_code == 415
    assert env.client.get("/u/bad/dns-query", params={"dns": b64}).status_code == 404
    assert env.client.get(f"/u/{env.token}/dns-query", params={"dns": "!!"}).status_code == 400


def test_no_query_logging_filter():
    f = doh_mod.DropDnsQueryLogs()
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s"', ("1.2.3.4", "GET",
                            "/u/secret/dns-query?dns=AAAB"), None)
    assert f.filter(rec) is False
    ok = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s"', ("1.2.3.4", "GET",
                           "/v1/health"), None)
    assert f.filter(ok) is True


def test_health_reports_dns(env):
    h = env.client.get("/v1/health").json()
    assert h["ok"] is True and h["dns"]["role"] == "all" and h["dns"]["ready"] is True


# ------------------------------------------------------------------ replica
def test_replica_feed_needs_the_key(env):
    assert env.client.get("/v1/replica/dns/changes").status_code == 404
    assert env.client.get("/v1/replica/dns/changes",
                          headers={"X-Pax-Replica-Key": "wrong" * 10}).status_code == 404
    r = env.client.get("/v1/replica/dns/changes", headers={"X-Pax-Replica-Key": REPLICA_KEY})
    assert r.status_code == 200 and r.json()["full"] is True
    body = json.dumps(r.json())
    assert env.token not in body and "user@example.com" not in body      # hashes only


def test_shipped_replica_hash_is_well_formed():
    assert all(len(h) == 64 for h in replica.REPLICA_KEY_SHA256)
    assert not replica.key_allowed("short")


def test_dns_role_server_uses_feed_then_cache_when_primary_down(env, tmp_path, filterset):
    env.client.post("/v1/blocklist", headers=env.h, json={"domain": "example.org"})
    primary = env.client
    state = {"down": False}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req):
        if state["down"]:
            raise OSError("primary down")
        path = req.full_url.split("api.paxpeace.test", 1)[1]
        r = primary.get(path, headers={"X-Pax-Replica-Key": req.get_header("X-pax-replica-key")})
        assert r.status_code == 200
        return Resp(r.content)

    cache = str(tmp_path / "replica-cache.json")

    def make():
        feed = doh_mod.ReplicaFeed("https://api.paxpeace.test", REPLICA_KEY, cache_path=cache, opener=opener)
        fwd = dnsf.Forwarder([FakeUpstream()], filters=filterset, log=lambda m: None)
        return doh_mod.DohService(feed, str(tmp_path / "dns2"), role="dns", forwarder=fwd,
                                  rate=1000, burst=1000, clock=env.clock.now)

    d = make()
    d.sync_once()
    wire = query("www.example.org")
    assert answer_kind(d.answer(wire, env.token, "x")[1]) == "blocked"
    # Primary down, the second server restarts: its disk copy keeps the lists.
    state["down"] = True
    d2 = make()
    d2.restore_cache()
    with pytest.raises(OSError):
        d2.sync_once()
    assert answer_kind(d2.answer(wire, env.token, "x")[1]) == "blocked"
    assert answer_kind(d2.answer(query("pbs.twimg.com"), env.token, "x")[1]) == "blocked"
    # The dns-role app answers DoH and health, and has no account API.
    s = Settings(role="dns", replica_key=REPLICA_KEY, doh_enabled=True)
    app = create_app(s, doh=d2)
    c = TestClient(app)
    assert c.get("/v1/health").json()["role"] == "dns"
    assert c.post("/v1/accounts", json={"email": "a@b.co"}).status_code == 404
    b64 = base64.urlsafe_b64encode(wire).decode().rstrip("=")
    assert answer_kind(c.get(f"/u/{env.token}/dns-query", params={"dns": b64}).content) == "blocked"


# -------------------------------------------------------------- caddy sync
CADDYFILE_JSON = {"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [
    {"match": [{"host": ["api.paxpeace.com"]}], "handle": [{"handler": "subroute"}], "terminal": True}]}}}}}


class FakeAdmin:
    def __init__(self, cfg, health_after=True):
        self.cfg, self.loads, self.health_after = json.loads(json.dumps(cfg)), [], health_after
        self.applied = False

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
        self.cfg = body
        self.applied = True
        return R(b"")

    def health(self):
        return True if not self.applied else self.health_after


def test_caddy_sync_waits_for_dns_then_adds_site_once():
    a = FakeAdmin(CADDYFILE_JSON)
    addrs = {"v": []}
    c = cs.CaddySync("dns.paxpeace.com", "api.paxpeace.com", own_ip="167.233.42.17",
                     resolver=lambda h: addrs["v"], opener=a.opener, health=a.health,
                     cert_probe=lambda h: True)
    assert c.check_once() == "waiting_for_dns_record" and not a.loads
    addrs["v"] = ["167.233.42.17", "198.51.100.20"]
    assert c.check_once() == "applied"
    cfg = a.cfg
    srv = cfg["apps"]["http"]["servers"]["srv0"]
    assert srv["routes"][0]["@id"] == cs.DNS_ROUTE_ID
    assert srv["routes"][1]["match"][0]["host"] == ["api.paxpeace.com"]      # API untouched
    fwd = cfg["apps"]["http"]["servers"][cs.ACME_SERVER]["routes"][0]
    assert fwd["handle"][0]["upstreams"] == [{"dial": "198.51.100.20:80"}]
    pol = cfg["apps"]["tls"]["automation"]["policies"][0]
    assert pol["subjects"] == ["dns.paxpeace.com"] and pol["issuers"][0]["challenges"]["tls-alpn"]["disabled"]
    assert c.check_once() == "in_place" and len(a.loads) == 1


def test_caddy_sync_rolls_back_when_api_breaks():
    a = FakeAdmin(CADDYFILE_JSON, health_after=False)
    c = cs.CaddySync("dns.paxpeace.com", "api.paxpeace.com", own_ip="167.233.42.17",
                     resolver=lambda h: ["167.233.42.17"], opener=a.opener, health=a.health,
                     cert_probe=lambda h: True)
    assert c.check_once() == "rolled_back"
    assert a.loads[-1] == CADDYFILE_JSON


def test_caddy_sync_disabled_in_plain_settings():
    assert Settings().caddy_sync is False and Settings().doh_enabled is False
