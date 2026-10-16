# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0 local escrow: the wait timer (24 h / 72 h / 7 days), grace, cancel,
emergency, permissions and tamper checks, clock moved forward or backwards,
network time, the local blocklist, and the app socket."""
import json
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import guard_ipc  # noqa: E402
import local_blocklist as lb  # noqa: E402
import local_escrow as le  # noqa: E402

H, D = 3600, 86400


class Clock:
    def __init__(self):
        self.wall = 1_800_000_000.0
        self.mono = 1000.0
        self.boot = 1_799_000_000
        self.trusted = None

    def advance(self, s, wall=True, mono=True):
        if wall:
            self.wall += s
        if mono:
            self.mono += s


def make(tmp_path, wait=72 * H, installed_ago=30 * D, events=None):
    c = Clock()
    ev = events if events is not None else []
    esc = le.LocalEscrow(tmp_path / "escrow", clock=lambda: c.wall, mono=lambda: c.mono,
                         boot_time=lambda: c.boot, trusted_time=lambda: c.trusted,
                         tamper_log=lambda k, d: ev.append((k, d)), require_root=False)
    c.wall -= installed_ago
    esc.deposit("paxadmin", "S3cret-paxadmin", wait_seconds=wait)
    c.wall += installed_ago
    esc.heartbeat()
    return esc, c, ev


def run_for(esc, c, seconds, step=30 * 60):
    left = seconds
    while left > 0:
        s = min(step, left)
        c.advance(s)
        esc.heartbeat()
        left -= s


def test_files_are_root_only_modes(tmp_path):
    esc, c, _ = make(tmp_path)
    base = tmp_path / "escrow"
    assert stat.S_IMODE(base.stat().st_mode) == 0o700
    for f in ("secrets.json", "state.json", "hmac.key"):
        assert stat.S_IMODE((base / f).stat().st_mode) == 0o600, f
    assert "S3cret" not in json.dumps(esc.status())


@pytest.mark.parametrize("wait", [24 * H, 72 * H, 7 * D])
def test_wait_choices_release_only_after_the_wait(tmp_path, wait):
    esc, c, _ = make(tmp_path, wait=wait)
    st = esc.request_removal()
    assert st["removal_request"]["seconds_remaining"] == wait and not st["removal_request"]["can_reveal"]
    with pytest.raises(le.EscrowError) as e:
        esc.reveal()
    assert e.value.code == "PAX-ESCROW-007"
    run_for(esc, c, wait - H)
    with pytest.raises(le.EscrowError):
        esc.reveal()
    run_for(esc, c, H)
    out = esc.reveal()
    assert out["removal_password"] == "S3cret-paxadmin"
    assert esc.released() and esc.status()["removal_request"]["status"] == "revealed"


def test_default_wait_is_72_hours_and_bounds(tmp_path):
    assert le.DEFAULT_WAIT == 72 * H and le.WAIT_CHOICES == (24 * H, 72 * H, 7 * D)
    for bad in (H, 23 * H, 400 * D, "x"):
        with pytest.raises(le.EscrowError):
            le.validate_wait(bad)


def test_grace_period_needs_no_wait(tmp_path):
    esc, c, _ = make(tmp_path, installed_ago=10 * 60)
    st = esc.request_removal()
    assert st["in_grace_period"] and st["removal_request"]["kind"] == "grace"
    assert esc.reveal()["removal_password"]


def test_cancel_and_single_open_request(tmp_path):
    esc, c, _ = make(tmp_path)
    esc.request_removal()
    with pytest.raises(le.EscrowError):
        esc.request_removal()
    assert esc.cancel()["removal_request"] is None
    with pytest.raises(le.EscrowError):
        esc.reveal()


def test_clock_forward_while_running_gains_nothing(tmp_path):
    esc, c, ev = make(tmp_path, wait=24 * H)
    esc.request_removal()
    c.advance(30 * D, mono=False)           # someone sets the date a month ahead
    esc.heartbeat()
    assert ("clock_forward" in [k for k, _ in ev])
    with pytest.raises(le.EscrowError):
        esc.reveal()                         # wall says yes, credited time says no
    run_for(esc, c, 24 * H)
    assert esc.reveal()["removal_password"]


def test_clock_backwards_logs_and_holds_until_network_time(tmp_path):
    esc, c, ev = make(tmp_path, wait=24 * H)
    esc.request_removal()
    run_for(esc, c, 12 * H)
    c.advance(-6 * H, mono=False)            # clock moved back
    esc.heartbeat()
    assert any(k == "clock_backwards" for k, _ in ev)
    run_for(esc, c, 20 * H)
    st = esc.status()["removal_request"]
    assert st["clock_hold"] and not st["can_reveal"]
    with pytest.raises(le.EscrowError) as e:
        esc.reveal()
    assert "network time" in e.value.message
    c.trusted = c.wall + 6 * H               # TLS-dated network time confirms
    assert esc.reveal()["removal_password"]


def test_network_time_vetoes_a_faked_clock_across_restart(tmp_path):
    esc, c, _ = make(tmp_path, wait=7 * D)
    esc.request_removal()
    # "restart" with the clock set 8 days ahead (as Recovery's Terminal could)
    c.boot += 100
    c.mono = 5.0
    c.advance(8 * D, mono=False)
    esc.heartbeat()
    c.trusted = c.wall - 8 * D               # the upstream's Date header disagrees
    with pytest.raises(le.EscrowError):
        esc.reveal()
    c.trusted = None
    assert esc.reveal()["removal_password"]  # offline: local time is all there is


def test_emergency_release_cooloff_and_rate_limit(tmp_path):
    esc, c, _ = make(tmp_path, wait=7 * D)
    with pytest.raises(le.EscrowError):
        esc.emergency("short")
    st = esc.emergency("my family needs this laptop for a medical form")
    assert st["removal_request"]["kind"] == "emergency"
    run_for(esc, c, 24 * H)
    assert esc.reveal()["removal_password"]
    with pytest.raises(le.EscrowError) as e:
        esc.emergency("another emergency right after the first one")
    assert e.value.code == "PAX-ESCROW-006"


def test_shorter_wait_takes_the_current_wait(tmp_path):
    esc, c, _ = make(tmp_path, wait=7 * D)
    st = esc.set_wait(24 * H)
    assert st["wait_seconds"] == 7 * D and st["pending_wait"]["seconds"] == 24 * H
    run_for(esc, c, 7 * D)
    assert esc.status()["wait_seconds"] == 24 * H
    assert esc.set_wait(72 * H)["wait_seconds"] == 72 * H   # longer: straight away


def test_locked_out_releases_recovery_key_and_firmware_only(tmp_path):
    esc, c, _ = make(tmp_path, wait=24 * H)
    esc.deposit("recovery_key", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF", replace=True)
    esc.deposit("firmware", "FwPass123456", replace=True)
    esc.request_removal("locked_out")
    run_for(esc, c, 24 * H)
    out = esc.reveal()
    assert out["recovery_key"].startswith("AAAA") and out["firmware_password"] == "FwPass123456"
    assert "removal_password" not in out and not esc.released()


def test_paxadmin_deposited_once(tmp_path):
    esc, c, _ = make(tmp_path)
    with pytest.raises(le.EscrowError):
        esc.deposit("paxadmin", "another")
    with pytest.raises(le.EscrowError):
        esc.deposit("paxadmin", "another", replace=True)


@pytest.mark.parametrize("damage", ["edit", "mode", "key", "symlink", "dirmode"])
def test_tamper_blocks_release(tmp_path, damage):
    esc, c, _ = make(tmp_path, installed_ago=10 * 60)
    esc.request_removal()
    base = tmp_path / "escrow"
    if damage == "edit":
        doc = json.loads((base / "secrets.json").read_text())
        doc["data"]["paxadmin"] = "attacker"
        (base / "secrets.json").write_text(json.dumps(doc))
    elif damage == "mode":
        os.chmod(base / "secrets.json", 0o644)
    elif damage == "key":
        (base / "hmac.key").write_bytes(os.urandom(32))
    elif damage == "symlink":
        (base / "state.json").unlink()
        (base / "state.json").symlink_to(base / "secrets.json")
    elif damage == "dirmode":
        os.chmod(base, 0o755)
    with pytest.raises(le.TamperError) as e:
        esc.reveal()
    assert e.value.code == "PAX-GUARD-010"


def test_require_root_rejects_non_root_owner(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root")
    esc, c, _ = make(tmp_path)
    strict = le.LocalEscrow(tmp_path / "escrow", require_root=True)
    with pytest.raises(le.TamperError):
        strict.status()


# ------------------------------------------------------------- blocklist
def test_local_blocklist_add_now_remove_after_wait(tmp_path):
    c = Clock()
    bl = lb.LocalBlocklist(tmp_path / "bl.json", wait_seconds=lambda: 72 * H, clock=lambda: c.wall)
    r = bl.add("https://Example.COM/path")
    assert r["created"] and r["domain"] == "example.com" and bl.blocked() == ["example.com"]
    req = bl.request_unblock("example.com")["request"]
    assert req["seconds_remaining"] == 72 * H
    c.advance(71 * H)
    assert bl.apply_due() == [] and bl.blocked() == ["example.com"]
    c.advance(H)
    assert bl.apply_due() == ["unblock example.com"] and bl.blocked() == []
    view = bl.view()
    assert set(view) == {"now", "blocked", "allowed", "pending", "limits"}
    assert view["limits"]["delay_seconds"] == 72 * H


def test_local_blocklist_exception_waits_and_cancel(tmp_path):
    c = Clock()
    bl = lb.LocalBlocklist(tmp_path / "bl.json", wait_seconds=lambda: 24 * H, clock=lambda: c.wall)
    rid = bl.request_allow("reddit.com")["request"]["request_id"]
    bl.cancel(rid)
    c.advance(25 * H)
    assert bl.allowed() == []
    bl.request_allow("reddit.com")
    c.advance(24 * H)
    bl.apply_due()
    assert bl.allowed() == ["reddit.com"]
    assert bl.remove_allow("reddit.com")["allowed"] == []      # stricter: instant
    with pytest.raises(lb.BlocklistError):
        bl.add("not a domain")
    with pytest.raises(lb.BlocklistError):
        bl.add("192.168.1.1")


# --------------------------------------------------------------- socket
def test_socket_round_trip_and_errors(tmp_path):
    path = str(tmp_path / "g.sock")

    def handler(req, uid):
        if req.get("cmd") == "boom":
            raise RuntimeError("x")
        return {"ok": True, "echo": req, "uid": uid}
    srv = guard_ipc.IPCServer(handler, path=path, log=lambda m: None)
    srv.start()
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o666
        r = guard_ipc.request({"cmd": "status"}, path=path)
        assert r["ok"] and r["echo"] == {"cmd": "status"} and r["uid"] == os.getuid()
        r = guard_ipc.request({"cmd": "boom"}, path=path)
        assert not r["ok"] and r["code"] == "PAX-GUARD-012"
        results = []
        ts = [threading.Thread(target=lambda: results.append(guard_ipc.request({"cmd": "x"}, path=path)))
              for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert len(results) == 8 and all(r["ok"] for r in results)
    finally:
        srv.stop()


def test_rate_limit():
    rl = guard_ipc.RateLimit(2)
    assert rl.allow() and rl.allow() and not rl.allow()
