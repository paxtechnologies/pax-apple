# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.13 (project decision): pictures and video on X and Bluesky are always
blocked, with no switch anywhere. The server refuses any request to turn them off
(422 media_always_blocked, PAX-DNS-016) before any request, wait or email, and an
account or a waiting request from before 0.8.13 is forced back on at start-up.
Text (x.com, bsky.app) stays reachable."""
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v088_doh import add_device, ask, env, filterset  # noqa: E402,F401  (fixtures)
from pax_server import restricted  # noqa: E402
from pax_server.main import create_app  # noqa: E402

import guard_config as gc  # noqa: E402  (guard/, on sys.path via doh)


MEDIA = gc.X_MEDIA_NAMES + gc.BLUESKY_MEDIA_NAMES


@pytest.mark.parametrize("body", [{"x_media": False}, {"bluesky_media": False},
                                  {"x_media": False, "bluesky_media": False, "youtube_restricted": False}])
@pytest.mark.parametrize("with_device", [False, True])
def test_turning_media_off_is_refused_before_anything_changes(env, body, with_device):
    if with_device:
        add_device(env)
    sent = len(env.mail.outbox)
    r = env.client.put("/v1/dns/settings", headers=env.h, json=body)
    assert r.status_code == 422
    j = r.json()
    assert j["error"] == "media_always_blocked" and j["pax_code"] == "PAX-DNS-016"
    assert len(env.mail.outbox) == sent                       # nobody emailed
    s = env.client.get("/v1/dns/settings", headers=env.h).json()
    assert s["settings"]["x_media"] is True and s["settings"]["bluesky_media"] is True
    assert s["settings"]["youtube_restricted"] is True      # refused as a whole: nothing changed
    assert s["pending"] == {"x_media": None, "bluesky_media": None}
    assert sorted(s["always_blocked"]) == ["bluesky_media", "x_media"]
    for name in MEDIA:
        assert ask(env, name) == "blocked"
    assert ask(env, "x.com") == "forwarded" and ask(env, "bsky.app") == "forwarded"


def test_keeping_media_on_is_accepted_and_changes_nothing(env):
    add_device(env)
    r = env.client.put("/v1/dns/settings", headers=env.h, json={"x_media": True, "bluesky_media": True})
    assert r.status_code == 200 and r.json()["settings"]["x_media"] is True
    assert ask(env, "pbs.twimg.com") == "blocked"


def test_no_exception_frees_x_or_bluesky_media(env):
    for d in ("pbs.twimg.com", "cdn.bsky.app", "video.cdn.bsky.app"):
        r = env.client.post("/v1/allowlist", headers=env.h, json={"domain": d})
        assert r.status_code == 422 and r.json()["error"] == "restricted_site", (d, r.text)


def test_server_list_matches_guard_list():
    assert tuple(restricted.ALWAYS_BLOCKED_MEDIA_NAMES) == tuple(gc.ALWAYS_BLOCKED_MEDIA_NAMES)
    assert restricted.is_restricted("pbs.twimg.com") and restricted.is_restricted("gifs.bsky.app")
    assert not restricted.is_restricted("bsky.app") and not restricted.is_restricted("x.com")


def test_migration_forces_old_accounts_back_on(env):
    """An account set up before 0.8.13 with media off, and a waiting request to
    turn it off, are both forced back on when the server starts."""
    db = env.app.state.blocklist.db
    aid = db.one("SELECT id FROM accounts")["id"]
    db.execute("UPDATE accounts SET dns_x_media=0, dns_bluesky_media=0 WHERE id=?", (aid,))
    db.execute("INSERT INTO blocklist_requests(id, account_id, action, domain, status, created_at, effective_at) "
               "VALUES ('r1', ?, 'x_media_off', NULL, 'pending', 1, 2)", (aid,))
    # Restart: a new app on the same database runs the migration.
    app2 = create_app(env.settings, clock=env.clock, sender=env.mail)
    db2 = app2.state.blocklist.db
    row = db2.one("SELECT dns_x_media, dns_bluesky_media FROM accounts WHERE id=?", (aid,))
    assert tuple(row) == (1, 1)
    assert db2.one("SELECT status FROM blocklist_requests WHERE id='r1'")["status"] == "refused"
    c = TestClient(app2)
    s = c.get("/v1/dns/settings", headers=env.h).json()["settings"]
    assert s["x_media"] is True and s["bluesky_media"] is True


def test_a_waiting_request_never_applies(env):
    """Belt and braces: a legacy request that slipped past the migration is refused, not applied."""
    db = env.app.state.blocklist.db
    aid = db.one("SELECT id FROM accounts")["id"]
    db.execute("INSERT INTO blocklist_requests(id, account_id, action, domain, status, created_at, effective_at) "
               "VALUES ('r2', ?, 'bluesky_media_off', NULL, 'pending', 1, 2)", (aid,))
    env.app.state.blocklist.apply_due(aid)
    assert db.one("SELECT status FROM blocklist_requests WHERE id='r2'")["status"] == "refused"
    assert db.one("SELECT dns_bluesky_media FROM accounts WHERE id=?", (aid,))[0] == 1
    assert ask(env, "cdn.bsky.app") == "blocked"


def test_feed_saying_off_is_ignored_by_the_resolver(env):
    """A replica fed an old primary's 'off' still blocks."""
    from pax_server import doh as doh_mod
    pol = doh_mod.Policies(list_dirs=None)
    p = pol._build({"settings": {"x_media": False, "bluesky_media": False}})
    for name in MEDIA:
        assert name in p.restricted
