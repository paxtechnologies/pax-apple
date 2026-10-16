# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.9: blocked sites sync between this Mac (local escrow) and the account.

A fake account server stands in for server/pax_server/sync.py (the server side
has its own tests in server/tests/test_v089_sync.py)."""
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
sys.path.append(str(HERE.parents[1] / "common"))
import list_sync as ls  # noqa: E402
import local_blocklist as lb  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402

TOKEN = "pxs_" + "a" * 40
URL = "https://api.example.test/"


class Clock:
    def __init__(self, t=1_800_000_000):
        self.t = t

    def __call__(self):
        return self.t


class FakeAccount:
    """The account list: adds instant, removals wait `delay` and become `removed`."""

    def __init__(self, clock, delay=72 * 3600):
        self.clock, self.delay = clock, delay
        self.blocked: dict = {}
        self.pending: list = []
        self.removed: list = []
        self.down = False
        self.partner_ok = True
        self.calls: list = []
        self.n = 0

    def apply(self):
        now = int(self.clock())
        for r in list(self.pending):
            if r["effective_at"] <= now:
                self.blocked.pop(r["domain"], None)
                self.removed.append({"domain": r["domain"], "applied_at": now})
                self.pending.remove(r)

    def state(self, since=0):
        self.apply()
        return {"blocked": sorted(self.blocked), "pending": list(self.pending), "delay_seconds": self.delay,
                "removed": [r for r in self.removed if r["applied_at"] >= since and r["domain"] not in self.blocked],
                "account_email": "me@example.com", "rejected": []}

    def __call__(self, url, headers, body):
        self.calls.append((url, dict(body)))
        if self.down:
            raise OSError("unreachable")
        if headers.get("X-Pax-Sync-Token") != TOKEN:
            raise ls.HTTPFailure(401, {})
        path = url[len(URL):]
        if path == "v1/sync":
            for d in body.get("add", []):
                self.blocked.setdefault(d, int(self.clock()))
                self.pending = [p for p in self.pending if p["domain"] != d]
            return self.state(body.get("since", 0))
        if path == "v1/sync/unblock":
            if not self.partner_ok:
                raise ls.HTTPFailure(503, {"error": "partner_unreachable"})
            d = body["domain"]
            if d not in self.blocked:
                raise ls.HTTPFailure(404, {"message": "not on the list", "pax_code": "PAX-ESCROW-005"})
            self.n += 1
            r = {"request_id": f"r{self.n}", "action": "unblock", "domain": d, "status": "pending",
                 "created_at": int(self.clock()), "effective_at": int(self.clock()) + self.delay,
                 "seconds_remaining": self.delay}
            self.pending.append(r)
            return {"request": r, "state": self.state()}
        if path.startswith("v1/sync/requests/") and path.endswith("/cancel"):
            rid = path.split("/")[3]
            self.pending = [p for p in self.pending if p["request_id"] != rid]
            return {"state": self.state()}
        raise ls.HTTPFailure(404, {})


def make(tmp_path, delay=72 * 3600):
    clock = Clock()
    bl = lb.LocalBlocklist(tmp_path / "blocklist.json", clock=clock)
    acct = FakeAccount(clock, delay)
    events = []
    sync = ls.ListSync(tmp_path / "sync.json", bl, clock=clock, wait_seconds=lambda: 24 * 3600,
                       partner_email=lambda: "pal@example.com",
                       tamper=lambda k, d: events.append((k, d)), log=lambda *_: None, http=acct)
    return sync, bl, acct, clock, events


def test_default_on_and_link_merges_as_union(tmp_path):
    sync, bl, acct, clock, events = make(tmp_path)
    assert sync.enabled() and not sync.linked() and not sync.active()
    bl.add("mac-only.example")
    acct.blocked["phone-only.example"] = 1
    st = sync.link(URL, TOKEN, "me@example.com", uid=501)
    assert st["linked"] and "token" not in st and TOKEN not in str(st)
    sync.sync_once()
    assert sorted(acct.blocked) == ["mac-only.example", "phone-only.example"]
    assert bl.blocked() == ["mac-only.example", "phone-only.example"]
    assert ("sync:linked", {"account": "me@example.com", "uid": 501}) in events
    # The Mac reports its wait and partner so the one removal rule covers them.
    body = acct.calls[-1][1]
    assert body["wait_seconds"] == 24 * 3600 and body["partner_email"] == "pal@example.com"


def test_add_here_is_queued_and_pushed(tmp_path):
    sync, bl, acct, clock, _ = make(tmp_path)
    sync.link(URL, TOKEN)
    sync.sync_once()
    bl.add("new.example")
    sync.note_added("new.example")
    assert sync.status()["queued"] == 1
    sync.sync_once()
    assert "new.example" in acct.blocked and sync.status()["queued"] == 0


def test_offline_keeps_list_and_queue_never_fails_open(tmp_path):
    sync, bl, acct, clock, _ = make(tmp_path)
    sync.link(URL, TOKEN)
    acct.blocked["a.example"] = 1
    sync.sync_once()
    acct.down = True
    bl.add("b.example")
    sync.note_added("b.example")
    sync.sync_once()
    assert bl.blocked() == ["a.example", "b.example"]
    assert sync.status()["last_error"]["error"] == "OSError"
    # Removal can't start while offline: nothing changes, the site stays blocked.
    with pytest.raises(lb.BlocklistError) as e:
        sync.request_unblock("a.example")
    assert e.value.code == "PAX-DNS-013"
    acct.down = False
    sync.sync_once()
    assert sorted(acct.blocked) == ["a.example", "b.example"]


def test_missing_from_server_is_pushed_back_not_removed(tmp_path):
    """A wiped or new account never unblocks anything here."""
    sync, bl, acct, clock, _ = make(tmp_path)
    sync.link(URL, TOKEN)
    bl.add("keep.example")
    sync.sync_once()
    acct.blocked.clear()                 # server lost it
    clock.t += 60
    sync.sync_once()
    assert bl.blocked() == ["keep.example"] and "keep.example" in acct.blocked


def test_removal_goes_through_the_one_rule_and_applies_after_wait(tmp_path):
    sync, bl, acct, clock, events = make(tmp_path, delay=24 * 3600)
    sync.link(URL, TOKEN)
    bl.add("bad.example")
    sync.note_added("bad.example")
    sync.sync_once()
    clock.t += 10
    out = sync.request_unblock("bad.example")
    assert out["request"]["domain"] == "bad.example"
    v = sync.decorate(bl.view())
    assert v["blocked"][0]["pending_removal"]["request_id"] == "r1"
    assert v["limits"]["delay_seconds"] == 24 * 3600
    # Still blocked during the wait.
    clock.t += 3600
    sync.sync_once()
    assert bl.blocked() == ["bad.example"]
    clock.t += 24 * 3600
    sync.sync_once()
    assert bl.blocked() == []
    assert events[-1][0] == "sync:removed"


def test_removal_from_another_device_applies_here_after_its_wait(tmp_path):
    sync, bl, acct, clock, _ = make(tmp_path)
    sync.link(URL, TOKEN)
    acct.blocked["x.example"] = 1
    sync.sync_once()
    acct.pending.append({"request_id": "p1", "action": "unblock", "domain": "x.example", "status": "pending",
                         "created_at": int(clock()), "effective_at": int(clock()) + 100})
    sync.sync_once()
    assert bl.blocked() == ["x.example"]
    clock.t += 101
    sync.sync_once()
    assert bl.blocked() == []


def test_cancel_from_the_mac(tmp_path):
    sync, bl, acct, clock, _ = make(tmp_path)
    sync.link(URL, TOKEN)
    bl.add("bad.example")
    sync.note_added("bad.example")
    sync.sync_once()
    sync.request_unblock("bad.example")
    assert sync.owns_request("r1")
    sync.cancel("r1")
    assert acct.pending == [] and not sync.owns_request("r1")
    clock.t += 30 * 24 * 3600
    sync.sync_once()
    assert bl.blocked() == ["bad.example"]


def test_partner_unreachable_refuses(tmp_path):
    sync, bl, acct, clock, _ = make(tmp_path)
    sync.link(URL, TOKEN)
    bl.add("bad.example")
    sync.note_added("bad.example")
    sync.sync_once()
    acct.partner_ok = False
    with pytest.raises(lb.BlocklistError) as e:
        sync.request_unblock("bad.example")
    assert e.value.code == "PAX-ESCROW-010"
    assert acct.pending == []


def test_turning_off_keeps_copy_and_diverges_on_merges_union(tmp_path):
    sync, bl, acct, clock, events = make(tmp_path)
    sync.link(URL, TOKEN)
    acct.blocked["shared.example"] = 1
    sync.sync_once()
    st = sync.set_enabled(False, uid=501)
    assert st["enabled"] is False and not sync.active()
    assert events[-1] == ("setting:sync_blocked_sites", {"from": True, "to": False, "uid": 501})
    # While off: the account removes shared.example; this Mac keeps it.
    acct.pending.append({"request_id": "p1", "action": "unblock", "domain": "shared.example",
                         "status": "pending", "created_at": int(clock()), "effective_at": int(clock()) + 5})
    clock.t += 10
    acct.apply()
    bl.add("mac-later.example")
    sync.note_added("mac-later.example")           # not queued while off
    sync.sync_once()
    assert bl.blocked() == ["mac-later.example", "shared.example"]
    # On again: union, no removals (the removal happened before sync came back on).
    clock.t += 10
    sync.set_enabled(True, uid=501)
    sync.sync_once()
    assert bl.blocked() == ["mac-later.example", "shared.example"]
    assert sorted(acct.blocked) == ["mac-later.example", "shared.example"]


def test_readded_here_after_a_removal_is_kept_and_pushed(tmp_path):
    sync, bl, acct, clock, _ = make(tmp_path)
    sync.link(URL, TOKEN)
    acct.blocked["x.example"] = 1
    sync.sync_once()
    acct.pending.append({"request_id": "p1", "action": "unblock", "domain": "x.example", "status": "pending",
                         "created_at": int(clock()), "effective_at": int(clock()) + 5})
    clock.t += 10
    acct.apply()
    bl.add("x.example")                    # already here; user adds it again
    sync.note_added("x.example")
    sync.sync_once()
    assert bl.blocked() == ["x.example"] and "x.example" in acct.blocked


def test_link_validation_and_401_keeps_list(tmp_path):
    sync, bl, acct, clock, _ = make(tmp_path)
    with pytest.raises(lb.BlocklistError):
        sync.link("http://evil.example/", TOKEN)
    with pytest.raises(lb.BlocklistError):
        sync.link(URL, "not-a-token")
    sync.link(URL, "pxs_" + "b" * 40)       # a token the account doesn't know
    bl.add("a.example")
    sync.sync_once()
    assert bl.blocked() == ["a.example"] and sync.status()["last_error"]["error"] == "HTTP 401"


def test_state_file_is_private_and_token_not_in_status(tmp_path):
    sync, bl, acct, clock, _ = make(tmp_path)
    sync.link(URL, TOKEN)
    assert oct((tmp_path / "sync.json").stat().st_mode & 0o777) == "0o600"
    assert TOKEN not in str(sync.status()) and TOKEN not in str(sync.decorate(bl.view()))


# ------------------------------------------------------------ through pax-guard
def test_guard_ipc_sync_commands_and_unblock_routing(tmp_path):
    g, s = local_guard(tmp_path)
    clock = Clock()
    acct = FakeAccount(clock)
    g.list_sync.http = acct
    r = g.handle_request({"cmd": "sync.get"}, 501)
    assert r["ok"] and r["sync"]["enabled"] is True and r["sync"]["linked"] is False
    r = g.handle_request({"cmd": "sync.link", "server_url": URL, "token": TOKEN,
                          "account_email": "me@example.com"}, 501)
    assert r["ok"] and r["sync"]["linked"]
    r = g.handle_request({"cmd": "blocklist.add", "domain": "bad.example"}, 501)
    assert r["ok"] and r["list"]["sync"]["queued"] == 1
    g.list_sync.sync_once()
    assert "bad.example" in acct.blocked
    r = g.handle_request({"cmd": "blocklist.unblock", "domain": "bad.example"}, 501)
    assert r["ok"] and acct.pending and r["request"]["request_id"] == "r1"
    r = g.handle_request({"cmd": "blocklist.cancel", "request_id": "r1"}, 501)
    assert r["ok"] and acct.pending == []
    r = g.handle_request({"cmd": "sync.set", "enabled": False}, 501)
    assert r["ok"] and r["sync"]["enabled"] is False
    # Off: removals use this Mac's own wait again (local rule).
    r = g.handle_request({"cmd": "blocklist.unblock", "domain": "bad.example"}, 501)
    assert r["ok"] and acct.pending == []
    assert g.status_summary()["sync"]["enabled"] is False
    kinds = [e["kind"] for e in g.tamper_log.entries()]
    assert "sync:linked" in kinds and "setting:sync_blocked_sites" in kinds
