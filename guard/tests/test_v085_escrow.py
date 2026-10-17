# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.5 local escrow: stale requests lapse on their own. A request made in the
1-hour grace period can only be used until the grace period ends (wall clock,
credited time or network time, whichever says so first); any request lapses once
its 7-day reveal window has passed. Also: pax-guard's default server is the
production one."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import local_escrow as le  # noqa: E402
import pax_guard as pg  # noqa: E402
from test_v08_escrow import make, run_for  # noqa: E402
from test_v08_partner import World  # noqa: E402

H, D = 3600, 86400


def raw_request(esc):
    return esc._read("state.json")["request"]


def test_grace_is_one_hour():
    assert le.GRACE == H


def test_grace_request_lapses_when_the_hour_ends(tmp_path):
    esc, c, _ = make(tmp_path, wait=72 * H, installed_ago=10 * 60)
    st = esc.request_removal()
    assert st["in_grace_period"]
    rr = st["removal_request"]
    assert rr["kind"] == "grace" and rr["can_reveal"]
    run_for(esc, c, 50 * 60 + 1, step=5 * 60)           # past the end of the first hour
    assert raw_request(esc)["status"] == "lapsed"        # by the heartbeat, nobody looked
    assert esc.status()["removal_request"] is None
    with pytest.raises(le.EscrowError) as e:
        esc.reveal()
    assert e.value.code == "PAX-ESCROW-005"
    # A new request now takes the full wait.
    rr = esc.request_removal()["removal_request"]
    assert rr["kind"] == "standard" and not rr["can_reveal"] and rr["seconds_remaining"] >= 72 * H - 1


def test_grace_request_works_within_the_hour(tmp_path):
    esc, c, _ = make(tmp_path, installed_ago=10 * 60)
    esc.request_removal()
    run_for(esc, c, 40 * 60, step=5 * 60)
    assert esc.reveal()["removal_password"] == "S3cret-paxadmin"


def test_moving_the_clock_back_does_not_keep_a_grace_request_alive(tmp_path):
    esc, c, _ = make(tmp_path, installed_ago=50 * 60)
    esc.request_removal()
    c.advance(-2 * H, mono=False)                        # wall clock set two hours back
    esc.heartbeat()
    assert raw_request(esc)["status"] == "pending"
    run_for(esc, c, 15 * 60, step=5 * 60)                # wall still "inside" the grace hour
    assert c.wall < 1_800_000_000 + 10 * 60              # (sanity: the wall clock says so)
    assert raw_request(esc)["status"] == "lapsed"        # credited time says the hour is over
    with pytest.raises(le.EscrowError):
        esc.reveal()


def test_network_time_ends_the_grace_window(tmp_path):
    esc, c, _ = make(tmp_path, installed_ago=30 * 60)
    esc.request_removal()
    c.advance(-D, mono=False)
    c.trusted = c.wall + D + 2 * H                       # TLS-dated time: well past the hour
    assert esc.status()["removal_request"] is None
    assert raw_request(esc)["status"] == "lapsed"


def test_grace_emergency_closes_with_the_grace_period(tmp_path):
    esc, c, _ = make(tmp_path, installed_ago=30 * 60)
    rr = esc.emergency("I need to get into this Mac today")["removal_request"]
    assert rr["kind"] == "emergency" and rr["can_reveal"]
    run_for(esc, c, 31 * 60, step=5 * 60)
    assert esc.status()["removal_request"] is None


def test_standard_request_lapses_after_the_reveal_window(tmp_path):
    esc, c, _ = make(tmp_path, wait=24 * H)
    esc.request_removal()
    run_for(esc, c, 24 * H + 7 * D - H, step=6 * H)
    assert raw_request(esc)["status"] == "pending" and esc.status()["removal_request"]["can_reveal"]
    run_for(esc, c, 2 * H, step=H)
    assert raw_request(esc)["status"] == "lapsed"        # by the heartbeat
    assert esc.status()["removal_request"] is None
    with pytest.raises(le.EscrowError):
        esc.reveal()


def test_clock_forward_does_not_lapse_a_standard_request_early(tmp_path):
    esc, c, _ = make(tmp_path, wait=24 * H)
    esc.request_removal()
    run_for(esc, c, 24 * H)
    c.advance(30 * D, mono=False)
    esc.heartbeat()
    assert raw_request(esc)["status"] == "pending"
    assert esc.reveal()["removal_password"]


def test_waiting_on_partner_grace_request_lapses_and_its_email_is_dropped(tmp_path):
    w = World(tmp_path, installed_ago=20 * 60)
    w.mail.up = False
    with pytest.raises(le.EscrowError) as e:
        w.esc.request_removal()
    assert e.value.code == "PAX-ESCROW-010"
    assert raw_request(w.esc)["status"] == "notifying"
    assert any(m.get("gate", {}).get("type") == "removal" for m in w.esc.partner.config()["outbox"])
    w.run(45 * 60, step=5 * 60)                          # grace over before the email went out
    assert raw_request(w.esc)["status"] == "lapsed"
    assert not any(m.get("gate", {}).get("type") == "removal" for m in w.esc.partner.config()["outbox"])
    w.mail.up = True
    w.flush()
    assert raw_request(w.esc)["status"] == "lapsed"
    assert w.esc.status()["removal_request"] is None


def test_partner_told_after_grace_does_not_start_a_no_wait_unlock(tmp_path):
    w = World(tmp_path, installed_ago=50 * 60)
    w.mail.up = False
    with pytest.raises(le.EscrowError):
        w.esc.request_removal()
    rid = raw_request(w.esc)["id"]
    w.wall += 20 * 60                                    # no heartbeat in between
    assert w.esc.activate({"type": "removal", "id": rid}) is True
    assert raw_request(w.esc)["status"] == "lapsed"


# ------------------------------------------------------- production server
def test_guard_defaults_to_the_production_server():
    assert pg.GuardConfig().server_url == "https://api.paxpeace.com/"
    assert pg.VERSION == "0.8.24"


def test_guard_still_takes_a_self_hosted_server(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"server_url": "https://pax.example.org/", "guard_token": "t"}))
    assert pg.GuardConfig.load(p).server_url == "https://pax.example.org/"
