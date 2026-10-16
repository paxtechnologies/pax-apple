# SPDX-License-Identifier: GPL-3.0-only
"""pax-dns reading the escrow server's effective lists: shared SQLite and the
internal HTTP feed, end to end against the real server code."""
import asyncio
import re
import sys
from pathlib import Path

import httpx
import pytest
from dnslib import DNSRecord
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "server"))

from pax_server import blocklist as server_blocklist  # noqa: E402
from pax_server.config import HOUR, Settings  # noqa: E402
from pax_server.crypto import generate_key_b64  # noqa: E402
from pax_server.main import create_app as create_server  # noqa: E402
from pax_server.notify import MemoryEmailSender  # noqa: E402

from pax_dns import sources  # noqa: E402
from pax_dns.lists import CategoryList  # noqa: E402
from pax_dns.policy import Store  # noqa: E402
from pax_dns.sources import HttpSource, SqliteSource, Syncer, make_source  # noqa: E402

KEY = "k" * 32
T0 = 1_800_000_000


class Clock:
    def __init__(self):
        self.t = T0

    def now(self):
        return self.t

    def __call__(self):
        return self.t


@pytest.fixture
def server(tmp_path):
    clock = Clock()
    db = tmp_path / "pax.sqlite3"
    settings = Settings(db_path=str(db), server_key_b64=generate_key_b64(), internal_api_key=KEY,
                        blocklist_sweep_seconds=0)
    app = create_server(settings, clock=clock, sender=MemoryEmailSender())
    c = TestClient(app)
    h = {"Authorization": "Bearer " + c.post("/v1/accounts", json={"email": "u@e.co"}).json()["token"]}
    token = c.get("/v1/dns", headers=h).json()["token"]
    return app, c, h, token, clock, db


def norm(sql):
    return re.sub(r"\s+", " ", sql).strip()


def test_sql_and_domain_logic_match_server():
    for name in ("EFFECTIVE_BLOCK_SQL", "EFFECTIVE_ALLOW_SQL", "VALID_TOKENS_SQL"):
        assert norm(getattr(sources, name)) == norm(getattr(server_blocklist, name))
    a = (REPO / "server/pax_server/domains.py").read_text()
    b = (REPO / "pax-dns/pax_dns/domains.py").read_text()
    assert a == b, "pax-dns/pax_dns/domains.py must be a copy of server/pax_server/domains.py"


def test_sqlite_source_end_to_end(server):
    app, c, h, token, clock, db = server
    src = SqliteSource(str(db), clock=clock)
    store = Store(clock=clock)
    syncer = Syncer(store, src)
    asyncio.run(syncer.sync_once())
    assert store.lookup(token).block == frozenset()
    # Add: visible on the next poll.
    c.post("/v1/blocklist", headers=h, json={"domain": "bad.example"})
    asyncio.run(syncer.sync_once())
    assert store.lookup(token).block == {"bad.example"}
    # Removal: still blocked during the wait, gone after, with no server sweep.
    c.post("/v1/blocklist/remove", headers=h, json={"domain": "bad.example"})
    asyncio.run(syncer.sync_once())
    clock.t += 72 * HOUR - 1
    asyncio.run(syncer.sync_once())
    assert store.lookup(token).block == {"bad.example"}
    clock.t += 1
    asyncio.run(syncer.sync_once())
    assert store.lookup(token).block == frozenset()
    # Allow exception after its wait.
    c.post("/v1/allowlist", headers=h, json={"domain": "news.example"})
    clock.t += 72 * HOUR
    asyncio.run(syncer.sync_once())
    assert store.lookup(token).allow == {"news.example"}
    # v0.8.1: a restricted site is refused at request time (no wait, nothing to sync).
    r = c.post("/v1/allowlist", headers=h, json={"domain": "reddit.com"})
    assert r.status_code == 422 and r.json()["pax_code"] == "PAX-DNS-010"


def test_sqlite_source_is_read_only(server):
    *_, db = server
    conn = SqliteSource(str(db))._connect()
    with pytest.raises(Exception):
        conn.execute("DELETE FROM blocklist_entries")
    conn.close()


def test_http_source_end_to_end(server):
    app, c, h, token, clock, db = server

    async def run():
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://srv")
        src = HttpSource("http://srv", KEY, client=client)
        store = Store(clock=clock)
        syncer = Syncer(store, src)
        await syncer.sync_once()
        assert store.lookup(token) is not None
        c.post("/v1/blocklist", headers=h, json={"domain": "worse.example"})
        await syncer.sync_once()
        assert store.lookup(token).block == {"worse.example"}
        # rotation: old token keeps working for the wait, then drops
        new = c.post("/v1/dns/rotate", headers=h).json()["token"]
        await syncer.sync_once()
        assert store.lookup(token) is not None and store.lookup(new).block == {"worse.example"}
        clock.t += 72 * HOUR
        await syncer.sync_once()
        assert store.lookup(token) is None and store.lookup(new) is not None
        bad = HttpSource("http://srv", "wrong", client=client)
        with pytest.raises(httpx.HTTPStatusError):
            await bad.fetch(0)
        await client.aclose()

    asyncio.run(run())


def test_dns_answer_changes_after_add_without_restart(server, tmp_path):
    """Full path: server API -> SQLite -> pax-dns syncer -> DoH answer."""
    from conftest import FakeUpstream
    from pax_dns.config import DNSSettings
    from pax_dns.doh import b64url_encode, create_app as create_dns
    from pax_dns.resolver import Resolver

    app, c, h, token, clock, db = server
    store = Store(clock=clock)
    syncer = Syncer(store, SqliteSource(str(db), clock=clock), CategoryList())
    resolver = Resolver(DNSSettings(), store, syncer, upstream=FakeUpstream(),
                        allow_upstream=FakeUpstream())
    dns = TestClient(create_dns(DNSSettings(), resolver=resolver, start_sync=False))

    def ask(name):
        wire = bytes(DNSRecord.question(name).pack())
        r = dns.get(f"/u/{token}/dns-query", params={"dns": b64url_encode(wire)})
        return str(DNSRecord.parse(r.content).rr[0].rdata)

    asyncio.run(syncer.sync_once())
    assert ask("www.bad.example") == "93.184.216.34"
    c.post("/v1/blocklist", headers=h, json={"domain": "bad.example"})
    asyncio.run(syncer.sync_once())
    assert ask("www.bad.example") == "0.0.0.0"


def test_make_source():
    assert make_source("") is None
    assert isinstance(make_source("sqlite:////tmp/x.db"), SqliteSource)
    assert make_source("sqlite:////tmp/x.db").path == "/tmp/x.db"
    assert isinstance(make_source("https://srv", "key"), HttpSource)
    with pytest.raises(ValueError):
        make_source("https://srv", "")
    with pytest.raises(ValueError):
        make_source("ftp://x")


def test_sqlite_source_remote_desktop_switch_v05(server):
    """v0.5: turning the remote-desktop category off reaches pax-dns only after
    the wait, with no server sweep; turning it on again is immediate."""
    app, c, h, token, clock, db = server
    src = SqliteSource(str(db), clock=clock)
    store = Store(clock=clock)
    syncer = Syncer(store, src)
    asyncio.run(syncer.sync_once())
    assert store.lookup(token).categories_off == frozenset()
    assert c.put("/v1/categories/remote_desktop", headers=h, json={"enabled": False}).status_code == 202
    clock.t += 72 * HOUR - 1
    asyncio.run(syncer.sync_once())
    assert store.lookup(token).categories_off == frozenset()
    clock.t += 1
    asyncio.run(syncer.sync_once())
    assert store.lookup(token).categories_off == {"remote_desktop"}
    c.put("/v1/categories/remote_desktop", headers=h, json={"enabled": True})
    asyncio.run(syncer.sync_once())
    assert store.lookup(token).categories_off == frozenset()
