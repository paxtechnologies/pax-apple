# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.18 trial day on a Mac's own escrow (pax-guard).

On a genuinely new set-up the first 24 hours are a trial day: turning Pax off
needs no wait (the partner is still told first, fail closed), turning on
verified support release is instant, and "Start my wait now" ends it early.
The day is anchored in a marker outside the escrow folder that removing Pax
leaves behind, so setting up again never starts a new one."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(GUARD))
import local_escrow as le  # noqa: E402
import pax_guard as pg  # noqa: E402
from test_v08_partner import Mail  # noqa: E402

H, D = 3600, 86400
T0 = 1_800_000_000.0


class Mac:
    """One Mac: its escrow folder can be wiped (Pax removed) while the marker stays."""

    def __init__(self, tmp_path, partner=None, wait=72 * H, trial=True, support=True, start=T0):
        self.tmp = tmp_path
        self.wall, self.mono = start, 100.0
        self.mail = Mail()
        self.events = []
        self.partner_email = partner
        self.setup(wait=wait, trial=trial, support=support)

    def setup(self, wait=72 * H, trial=True, support=True):
        import shutil
        if (self.tmp / "escrow").exists():
            shutil.rmtree(self.tmp / "escrow")          # what removing Pax / --reset does
        self.esc = le.LocalEscrow(self.tmp / "escrow", clock=lambda: self.wall, mono=lambda: self.mono,
                                  boot_time=lambda: 1, require_root=False, log=lambda m: None,
                                  tamper_log=lambda k, d: self.events.append((k, d)),
                                  senders={"relay": self.mail.relay, "smtp": self.mail.smtp})
        self.esc.deposit("paxadmin", "pw", wait_seconds=wait, support_release=support, trial=trial)
        self.esc.heartbeat()
        if self.partner_email:
            self.esc.partner.set_transport({"kind": "relay", "url": "https://pax.example.org", "token": "tok"})
            self.esc.set_partner(self.partner_email)
        return self.esc.status()

    def run(self, seconds, step=1800):
        while seconds > 0:
            s = min(step, seconds)
            self.wall += s
            self.mono += s
            self.esc.heartbeat()
            seconds -= s


def test_new_setup_gets_a_trial_day_and_turns_off_with_no_wait(tmp_path):
    m = Mac(tmp_path)
    st = m.esc.status()
    assert st["trial"] == {"active": True, "until": int(T0) + D, "ended_at": None, "started_at": int(T0)}
    assert st["in_grace_period"] and st["grace_until"] == int(T0) + D
    m.run(20 * H)                                       # well past the old first hour
    st = m.esc.request_removal()
    rr = st["removal_request"]
    assert rr["kind"] == "trial" and rr["seconds_remaining"] == 0 and rr["can_reveal"]
    assert m.esc.reveal()["removal_password"] == "pw"


def test_after_24_hours_the_chosen_wait_applies_by_itself(tmp_path):
    m = Mac(tmp_path, wait=72 * H)
    m.run(D + 60)
    st = m.esc.status()
    assert st["trial"]["active"] is False and not st["in_grace_period"]
    rr = m.esc.request_removal()["removal_request"]
    assert rr["kind"] == "standard" and rr["seconds_remaining"] == 72 * H
    with pytest.raises(le.EscrowError):
        m.esc.reveal()


def test_trial_request_lapses_when_the_day_ends(tmp_path):
    m = Mac(tmp_path)
    m.run(23 * H)
    m.esc.request_removal()
    m.run(2 * H)                                        # the trial day ends: no standing unlock
    assert m.esc.status()["removal_request"] is None
    with pytest.raises(le.EscrowError):
        m.esc.reveal()


def test_partner_still_told_first_and_fail_closed_in_trial(tmp_path):
    m = Mac(tmp_path, partner="friend@example.org")
    m.mail.up = False
    with pytest.raises(le.EscrowError) as e:
        m.esc.request_removal()
    assert e.value.code == "PAX-ESCROW-010"
    assert m.esc.status()["removal_request"]["status"] == "notifying"
    with pytest.raises(le.EscrowError):
        m.esc.reveal()
    m.mail.up = True
    m.run(15 * 60, step=300)                            # the queued email's retry comes round
    for g in m.esc.partner.flush():
        m.esc.activate(g)
    assert m.esc.status()["removal_request"]["can_reveal"]
    assert m.esc.reveal()["removal_password"] == "pw"
    kinds = [k for k, _ in m.mail.sent]
    assert "removal_requested" in kinds and "password_revealed" in kinds


def test_start_my_wait_now_ends_the_trial_and_closes_a_no_wait_request(tmp_path):
    m = Mac(tmp_path, wait=72 * H)
    m.run(2 * H)
    m.esc.request_removal()
    st = m.esc.end_trial()
    assert st["trial"]["active"] is False and st["trial"]["ended_at"] == int(m.wall)
    assert st["removal_request"] is None and not st["in_grace_period"]
    assert ("trial_ended_early", {"left_seconds": 22 * H}) in m.events
    rr = m.esc.request_removal()["removal_request"]
    assert rr["kind"] == "standard" and rr["seconds_remaining"] == 72 * H
    # Ending it again is harmless.
    assert m.esc.end_trial()["trial"]["ended_at"] == st["trial"]["ended_at"]


def test_reinstalling_never_resets_the_trial(tmp_path):
    m = Mac(tmp_path)
    marker = tmp_path / "trial-marker.json"
    assert json.loads(marker.read_text())["first_at"] == int(T0)
    m.run(10 * H)
    st = m.setup()                                      # unfinished set-up redone, or removed and set up again
    assert st["trial"]["active"] and st["trial"]["until"] == int(T0) + D   # only the rest of the first day
    m.run(2 * D)
    st = m.setup()
    assert st["trial"] is None and st["in_grace_period"] is True   # no trial; the normal first hour only
    assert st["grace_until"] == int(m.wall) + H
    rr = m.esc.request_removal()["removal_request"]
    assert rr["kind"] == "grace"                        # the first-hour grace still applies, as before


def test_setup_without_trial_still_marks_the_mac(tmp_path):
    m = Mac(tmp_path, trial=False)
    assert m.esc.status()["trial"] is None
    assert (tmp_path / "trial-marker.json").exists()
    st = m.setup(trial=True)                            # set up again within the same minute
    assert st["trial"]["active"] and st["trial"]["until"] == int(T0) + D


def test_older_setups_are_marked_at_their_first_heartbeat(tmp_path):
    """A Mac set up before 0.8.18 (no marker, no trial key) gets a marker dated
    to its install time, so removing and setting up again gives no trial."""
    m = Mac(tmp_path, trial=False, start=T0 - 40 * D)
    marker = tmp_path / "trial-marker.json"
    marker.unlink()
    st = json.loads((tmp_path / "escrow" / "state.json").read_text())
    st["data"].pop("trial")
    body = json.dumps(st["data"], sort_keys=True).encode()
    st["mac"] = m.esc._mac(body)
    (tmp_path / "escrow" / "state.json").write_text(json.dumps(st, sort_keys=True))
    m.wall = T0
    m.esc.heartbeat()
    assert m.esc.status()["trial"] is None
    assert json.loads(marker.read_text())["first_at"] == int(T0 - 40 * D)
    assert m.setup(trial=True)["trial"] is None


def test_an_unreadable_marker_means_no_trial(tmp_path):
    (tmp_path / "trial-marker.json").write_text("not json")
    m = Mac(tmp_path)
    assert m.esc.status()["trial"] is None


def test_support_release_on_is_instant_in_trial_with_partner_told(tmp_path):
    m = Mac(tmp_path, partner="friend@example.org", support=False)
    st = m.esc.set_support_release(True)
    assert st["support_release"]["allowed"] is True and st["support_release"]["pending_on_at"] is None
    assert ("support_release_on", "friend@example.org") in m.mail.sent
    assert ("support_release_setting", {"allowed": True, "trial_day": True}) in m.events


def test_support_release_on_in_trial_fails_closed_without_partner_email(tmp_path):
    m = Mac(tmp_path, partner="friend@example.org", support=False)
    m.mail.up = False
    with pytest.raises(le.EscrowError) as e:
        m.esc.set_support_release(True)
    assert e.value.code == "PAX-ESCROW-010"
    assert m.esc.status()["support_release"]["allowed"] is False
    assert m.esc.partner.config()["outbox"] == []       # nothing queued to turn it on later


def test_support_release_on_after_trial_takes_the_full_wait(tmp_path):
    m = Mac(tmp_path, support=False, wait=72 * H)
    m.esc.end_trial()
    st = m.esc.set_support_release(True)
    assert st["support_release"]["allowed"] is False
    assert st["support_release"]["pending_on_at"] == int(m.wall) + 72 * H
    m.run(72 * H + 60)
    assert m.esc.status()["support_release"]["allowed"] is True


def test_support_release_off_is_instant_any_time(tmp_path):
    m = Mac(tmp_path, support=True)
    m.esc.end_trial()
    assert m.esc.set_support_release(False)["support_release"]["allowed"] is False


def test_emergency_in_trial_has_no_cooling_off(tmp_path):
    m = Mac(tmp_path)
    m.run(5 * H)
    rr = m.esc.emergency("I need my Mac for an urgent work thing")["removal_request"]
    assert rr["can_reveal"] and rr["seconds_remaining"] == 0


def test_cli_deposit_trial_flag(tmp_path, monkeypatch):
    """The set-up step sends --trial on; the receipt says until when."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    secret = tmp_path / "s"
    secret.write_text("pw-cli")
    import io
    import contextlib
    out = io.StringIO()
    monkeypatch.setattr(le.LocalEscrow, "__init__", _no_root_init(le.LocalEscrow.__init__))
    with contextlib.redirect_stdout(out):
        rc = le.main(["deposit", "--secret-file", str(secret), "--wait-seconds", str(72 * H),
                      "--dir", str(tmp_path / "esc"), "--trial", "on", "--support-release", "on"])
    assert rc == 0
    receipt = json.loads(out.getvalue().strip().splitlines()[-1])
    assert receipt["stored"] == "paxadmin" and receipt["trial_until"] is not None
    # Default is off: an older app never asks for one.
    secret.write_text("pw-cli")
    out = io.StringIO()
    (tmp_path / "trial-marker.json").unlink()
    with contextlib.redirect_stdout(out):
        rc = le.main(["deposit", "--secret-file", str(secret), "--dir", str(tmp_path / "esc"), "--reset"])
    assert rc == 0 and "trial_until" not in json.loads(out.getvalue().strip().splitlines()[-1])
    assert le.LocalEscrow(tmp_path / "esc", require_root=False).status()["trial"] is None


def _no_root_init(orig):
    def init(self, *a, **kw):
        kw["require_root"] = False
        orig(self, *a, **kw)
    return init


def test_guard_ipc_end_trial(tmp_path):
    """escrow.end_trial over the app socket."""
    m = Mac(tmp_path)
    g = pg.Guard.__new__(pg.Guard)
    g.cfg = pg.GuardConfig(escrow_mode="local")
    g.escrow = m.esc
    g.tamper_log = type("T", (), {"append": staticmethod(lambda k, d: m.events.append((k, d)))})()
    assert g.handle_request({"cmd": "escrow.status"}, 501)["device"]["trial"]["active"]
    out = g.handle_request({"cmd": "escrow.end_trial"}, 501)
    assert out["ok"] and out["device"]["trial"]["active"] is False
