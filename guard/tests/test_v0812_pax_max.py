# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.12 Pax Max after set-up (project decision).

On: instant, any time after set-up. Off: a loosening, so the partner is told
first (fail closed), then a fixed hour (not the user's own wait), cancellable,
written to the tamper log, refused offline. Pax Image Blur goes quiet only when
pax-guard writes the off signal into /etc/hosts after the hour; with no signal
(older set-up, unknown choice, anything broken) it keeps blurring."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import guard_config as gc  # noqa: E402
import local_blocklist as lb  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402

SIGNAL = f"{gc.PAX_MAX_OFF_ADDR} {gc.PAX_MAX_OFF_NAME}"


class FakeForwarder:
    """Only trusted_now, for Guard.online() itself."""
    def __init__(self, online):
        self.is_online = online

    def trusted_now(self, max_age=24 * 3600):
        return 1.0 if self.is_online else None


class Partner:
    def __init__(self, ok=True):
        self.ok, self.sent, self.dropped = ok, [], []

    def partner(self):
        return "partner@example.com"

    def notify(self, kind, subject, own, theirs, gate=None):
        self.sent.append((kind, own, theirs, gate))
        return self.ok

    def drop_gate(self, gate):
        self.dropped.append(gate)


def guard(tmp_path, on=True, online=True, partner=None, **cfg):
    g, s = local_guard(tmp_path, pax_max_switchable=True, pax_max_default=on, **cfg)
    g.online = lambda: online          # the forwarder's network time (see test_online_needs_network_time)
    if partner is not None:
        g.blocklist.partner = partner
    return g, s


def ask(g, cmd, **kw):
    return g.handle_request({"cmd": cmd, **kw}, 501)


def hosts(s):
    return s.files[gc.HOSTS_PATH]


def tamper_kinds(g):
    return [e.get("kind") or e.get("event") or e.get("type") for e in g.tamper_log.entries(50)]


def test_off_waits_one_hour_then_the_signal_goes_in(tmp_path):
    g, s = guard(tmp_path)
    g.enforce_hosts()
    assert SIGNAL not in hosts(s)
    r = ask(g, "paxmax.off")
    assert r["ok"] and r["request"]["action"] == "pax_max_off"
    assert r["request"]["seconds_remaining"] == 3600 == lb.PAX_MAX_OFF_SECONDS
    assert r["request"]["seconds_remaining"] != g._wait_seconds()          # not the user's own wait
    assert r["pax_max"]["on"] is True and r["pax_max"]["pending"]["request_id"] == r["request"]["request_id"]
    s.t += 3599
    g.cycle()
    assert g.pax_max_on() is True and SIGNAL not in hosts(s)               # still on during the hour
    s.t += 2
    g.cycle()
    assert g.pax_max_on() is False and SIGNAL in hosts(s)
    assert g.settings_view()["pax_max"]["pending"] is None
    assert "setting:pax_max_off_requested" in str(g.tamper_log.entries(50))
    assert "setting:pax_max" in str(g.tamper_log.entries(50))


def test_on_is_instant_any_time_and_cancels_a_waiting_off(tmp_path):
    g, s = guard(tmp_path, on=False)
    g.enforce_hosts()
    assert SIGNAL in hosts(s)                                              # chosen off at set-up
    r = ask(g, "paxmax.on")
    assert r["ok"] and r["pax_max"]["on"] is True and SIGNAL not in hosts(s)
    ask(g, "paxmax.off")
    r = ask(g, "paxmax.on")
    assert r["pax_max"]["pending"] is None
    s.t += 10 * 3600
    g.cycle()
    assert g.pax_max_on() is True and SIGNAL not in hosts(s)


def test_cancel_keeps_it_on(tmp_path):
    g, s = guard(tmp_path)
    rid = ask(g, "paxmax.off")["request"]["request_id"]
    r = ask(g, "paxmax.cancel", request_id=rid)
    assert r["ok"] and r["pax_max"]["pending"] is None
    s.t += 2 * 3600
    g.cycle()
    assert g.pax_max_on() is True
    assert "setting:pax_max_off_cancelled" in str(g.tamper_log.entries(50))
    assert ask(g, "paxmax.cancel", request_id=rid)["code"] == "PAX-ESCROW-005"


def test_partner_is_told_first_and_the_hour_starts_then(tmp_path):
    p = Partner()
    g, s = guard(tmp_path, partner=p)
    r = ask(g, "paxmax.off")
    assert r["ok"] and p.sent and p.sent[0][0] == "blocklist_pax_max_off_requested"
    assert "Pax Max" in p.sent[0][2] and "1 hour" in p.sent[0][2]
    assert r["request"]["status"] == "pending" and r["request"]["seconds_remaining"] == 3600


def test_fails_closed_when_the_partner_cant_be_told(tmp_path):
    p = Partner(ok=False)
    g, s = guard(tmp_path, partner=p)
    r = ask(g, "paxmax.off")
    assert r["ok"] is False and r["code"] == "PAX-ESCROW-010"
    s.t += 30 * 24 * 3600
    g.cycle()
    assert g.pax_max_on() is True and SIGNAL not in hosts(s)               # never started
    assert g.blocklist.pax_max_pending()["status"] == "notifying"
    # Told later: the hour starts then, not before.
    assert g.blocklist.activate(g.blocklist.pax_max_pending()["request_id"])
    assert g.blocklist.pax_max_pending()["seconds_remaining"] == 3600


def test_offline_cannot_start(tmp_path):
    g, s = guard(tmp_path, online=False)
    r = ask(g, "paxmax.off")
    assert r["ok"] is False and r["code"] == "PAX-GUARD-014"
    assert g.blocklist.pax_max_pending() is None
    s.t += 2 * 3600
    g.cycle()
    assert g.pax_max_on() is True


def test_off_on_an_untrusted_clock_waits_for_network_time(tmp_path):
    g, s = guard(tmp_path)
    ask(g, "paxmax.off")
    s.t += 2 * 3600                                    # the wall clock moved, network time didn't
    g.blocklist.trusted_time = lambda: s.t - 2 * 3600
    g.cycle()
    assert g.pax_max_on() is True


def test_online_needs_network_time(tmp_path):
    g, _ = local_guard(tmp_path, pax_max_switchable=True)
    assert g.online() is False                         # no forwarder: no proof
    g.forwarder = FakeForwarder(False)
    assert g.online() is False
    g.forwarder = FakeForwarder(True)
    assert g.online() is True
    g.forwarder = None


@pytest.mark.parametrize("cfg", [dict(), dict(pax_max_switchable=True, escrow_mode="server", guard_token="t" * 30)])
def test_not_switchable_before_0812_or_on_server_escrow(tmp_path, cfg):
    import pax_guard as pg
    from test_v08_guard import NetSystem
    s = NetSystem(tmp_path)
    c = pg.GuardConfig(profile_identifier="org.paxpeace.pax.macos-selflock.abc", user="alex", **cfg)
    g = pg.Guard(c, s, state_dir=tmp_path / "PaxGuard" / "state", quarantine_dir=tmp_path / "q")
    v = ask(g, "paxmax.get")["pax_max"]
    assert v["switchable"] is False and v["on"] is None
    for cmd in ("paxmax.on", "paxmax.off", "paxmax.cancel"):
        assert ask(g, cmd)["code"] == "PAX-GUARD-015"
    assert g.hosts_extra() == []                                           # never writes the off signal


def test_unknown_set_up_choice_counts_as_on(tmp_path):
    g, s = local_guard(tmp_path, pax_max_switchable=True)
    assert g.pax_max_on() is True and g.hosts_extra() == []


def test_settings_view_and_ipc_doc():
    import guard_ipc
    for cmd in ("paxmax.get", "paxmax.on", "paxmax.off", "paxmax.cancel"):
        assert cmd in guard_ipc.__doc__


def test_hosts_signal_line_is_kept_inside_the_pax_block():
    out = gc.render_hosts("127.0.0.1 localhost\n", ["a.example"], [(gc.PAX_MAX_OFF_ADDR, gc.PAX_MAX_OFF_NAME)])
    block = out.split(gc.BEGIN, 1)[1]
    assert SIGNAL in block and gc.strip_pax_block(out) == "127.0.0.1 localhost\n"
    assert gc.render_hosts(out, ["a.example"], [(gc.PAX_MAX_OFF_ADDR, gc.PAX_MAX_OFF_NAME)]) == out


def test_the_extension_uses_the_same_name_and_address():
    core = (Path(__file__).resolve().parents[2] / "extension" / "src" / "core.js").read_text()
    assert gc.PAX_MAX_OFF_NAME in core and gc.PAX_MAX_OFF_ADDR in core
