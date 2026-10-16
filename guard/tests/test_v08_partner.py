# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0 accountability partner on local escrow: no partner = fully local;
with a partner every notifying action delivers (or queues and retries) BEFORE
its wait starts (fail closed, PAX-ESCROW-010); changing/removing a partner waits
the current wait; relay and SMTP transports; the SMTP password stays root-only."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import local_blocklist as lb  # noqa: E402
import local_escrow as le  # noqa: E402
import partner as pt  # noqa: E402

H, D = 3600, 86400


class Mail:
    def __init__(self):
        self.up = True
        self.sent = []

    def relay(self, t, msg, partner):
        if not self.up:
            raise OSError("mail server unreachable")
        self.sent.append((msg["kind"], partner))

    def smtp(self, t, msg, partner, owner):
        self.relay(t, msg, partner)


class World:
    def __init__(self, tmp_path, partner="friend@example.org", installed_ago=30 * D, wait=24 * H):
        self.wall, self.mono = 1_800_000_000.0, 100.0
        self.mail = Mail()
        self.esc = le.LocalEscrow(tmp_path / "escrow", clock=lambda: self.wall, mono=lambda: self.mono,
                                  boot_time=lambda: 1, require_root=False, log=lambda m: None,
                                  senders={"relay": self.mail.relay, "smtp": self.mail.smtp})
        self.wall -= installed_ago
        self.esc.deposit("paxadmin", "pw", wait_seconds=wait)
        self.wall += installed_ago
        self.esc.heartbeat()
        if partner:
            self.esc.partner.set_transport({"kind": "relay", "url": "https://pax.example.org", "token": "tok"})
            self.esc.set_partner(partner)

    def run(self, seconds, step=1800):
        while seconds > 0:
            s = min(step, seconds)
            self.wall += s
            self.mono += s
            self.esc.heartbeat()
            seconds -= s

    def flush(self):
        for g in self.esc.partner.flush():
            self.esc.activate(g)


def test_no_partner_means_nothing_sent_and_fully_local(tmp_path):
    w = World(tmp_path, partner=None)
    st = w.esc.request_removal()
    assert st["removal_request"]["status"] == "pending" and w.mail.sent == []
    w.run(24 * H)
    assert w.esc.reveal()["removal_password"] == "pw" and w.mail.sent == []


def test_partner_told_before_wait_starts(tmp_path):
    w = World(tmp_path)
    assert w.mail.sent == [("partner_added", "friend@example.org")]
    st = w.esc.request_removal()
    assert st["removal_request"]["status"] == "pending"
    assert ("removal_requested", "friend@example.org") in w.mail.sent
    w.run(24 * H)
    w.esc.reveal()
    assert ("password_revealed", "friend@example.org") in w.mail.sent


def test_fail_closed_no_email_no_countdown_then_retry_starts_it(tmp_path):
    w = World(tmp_path)
    w.mail.up = False
    with pytest.raises(le.EscrowError) as e:
        w.esc.request_removal()
    assert e.value.code == "PAX-ESCROW-010"
    rr = w.esc.status()["removal_request"]
    assert rr["status"] == "notifying" and not rr["can_reveal"]
    w.run(3 * D)                                  # time passes: no countdown ran
    with pytest.raises(le.EscrowError) as e:
        w.esc.reveal()
    assert e.value.code == "PAX-ESCROW-010"
    w.mail.up = True
    w.flush()                                     # the queued email goes out: wait starts NOW
    rr = w.esc.status()["removal_request"]
    assert rr["status"] == "pending" and rr["seconds_remaining"] == 24 * H
    with pytest.raises(le.EscrowError):
        w.esc.reveal()
    w.run(24 * H)
    assert w.esc.reveal()["removal_password"] == "pw"


def test_retry_backs_off(tmp_path):
    w = World(tmp_path)
    w.mail.up = False
    with pytest.raises(le.EscrowError):
        w.esc.request_removal()
    assert w.esc.partner.flush() == []            # not due yet (60 s)
    w.wall += 61
    assert w.esc.partner.flush() == []            # still down: next try in 5 min
    q = w.esc.partner.public_view()["queued"][0]
    assert q["attempts"] == 2 and q["gate"]["type"] == "removal"


def test_reveal_needs_its_email_delivered(tmp_path):
    w = World(tmp_path)
    w.esc.request_removal()
    w.run(24 * H)
    w.mail.up = False
    with pytest.raises(le.EscrowError) as e:
        w.esc.reveal()
    assert e.value.code == "PAX-ESCROW-010"
    assert not w.esc.released()
    w.mail.up = True
    w.wall += 61
    w.flush()
    assert w.esc.reveal()["removal_password"] == "pw"


def test_cancel_is_never_held_up_by_email(tmp_path):
    w = World(tmp_path)
    w.esc.request_removal()
    w.mail.up = False
    assert w.esc.cancel()["removal_request"] is None
    assert w.esc.partner.public_view()["queued"][0]["kind"] == "removal_cancelled"
    # a request the partner never heard about is dropped with its email
    w2 = World(tmp_path / "b")
    w2.mail.up = False
    with pytest.raises(le.EscrowError):
        w2.esc.request_removal()
    w2.esc.cancel()
    assert w2.esc.partner.public_view()["queued"] == []


def test_emergency_and_wait_decrease_are_gated(tmp_path):
    w = World(tmp_path, wait=7 * D)
    w.mail.up = False
    with pytest.raises(le.EscrowError) as e:
        w.esc.emergency("a real emergency with my family")
    assert e.value.code == "PAX-ESCROW-010" and w.esc.status()["removal_request"] is None
    w.mail.up = True
    w.wall += 61
    w.flush()
    assert w.esc.status()["removal_request"]["kind"] == "emergency"
    w3 = World(tmp_path / "w", wait=7 * D)
    w3.mail.up = False
    with pytest.raises(le.EscrowError):
        w3.esc.set_wait(24 * H)
    assert w3.esc.status()["pending_wait"] is None
    w3.mail.up = True
    w3.wall += 61
    w3.flush()
    assert w3.esc.status()["pending_wait"]["seconds"] == 24 * H


def test_partner_change_and_removal_wait_the_current_wait(tmp_path):
    w = World(tmp_path, wait=72 * H)
    st = w.esc.set_partner("new@example.org")
    assert st["partner"]["partner"] == "friend@example.org"
    assert st["partner"]["pending_partner"]["email"] == "new@example.org"
    assert ("partner_change_requested", "friend@example.org") in w.mail.sent
    w.run(71 * H)
    assert w.esc.partner.partner() == "friend@example.org"
    w.run(2 * H)
    assert w.esc.partner.partner() == "new@example.org"
    assert ("partner_added", "new@example.org") in w.mail.sent
    w.esc.set_partner(None)                       # removal waits too
    assert w.esc.partner.partner() == "new@example.org"
    w.run(73 * H)
    assert w.esc.partner.partner() is None
    # re-asserting the current partner cancels a pending change
    w2 = World(tmp_path / "c")
    w2.esc.set_partner("other@example.org")
    w2.esc.set_partner("friend@example.org")
    assert w2.esc.partner.config()["pending_partner"] is None


def test_partner_needs_a_transport_and_a_real_address(tmp_path):
    w = World(tmp_path, partner=None)
    with pytest.raises(le.EscrowError) as e:
        w.esc.set_partner("friend@example.org")
    assert e.value.code == "PAX-ESCROW-011"
    w.esc.partner.set_transport({"kind": "relay", "url": "https://pax.example.org/", "token": "t"})
    with pytest.raises(le.EscrowError):
        w.esc.set_partner("not-an-address")
    with pytest.raises(pt.NotifyError):
        w.esc.partner.set_transport({"kind": "relay", "url": "http://pax.example.org/", "token": "t"})
    with pytest.raises(pt.NotifyError):
        w.esc.partner.set_transport({"kind": "smtp", "host": "", "from": "me@example.org"})


def test_smtp_password_root_only_and_never_shown(tmp_path):
    w = World(tmp_path, partner=None)
    view = w.esc.partner.set_transport({"kind": "smtp", "host": "smtp.example.org", "port": 587,
                                        "username": "me@example.org", "password": "smtp-secret",
                                        "security": "starttls"}, owner_email="me@example.org")
    assert "smtp-secret" not in json.dumps(view) and "smtp-secret" not in json.dumps(w.esc.status())
    f = tmp_path / "escrow" / "notify.json"
    assert oct(f.stat().st_mode & 0o777) == "0o600"
    # saving again without a password keeps the stored one
    w.esc.partner.set_transport({"kind": "smtp", "host": "smtp.example.org", "username": "me@example.org",
                                 "security": "starttls"})
    assert w.esc.partner.config()["transport"]["password"] == "smtp-secret"
    doc = json.loads(f.read_text())
    doc["data"]["partner"] = "attacker@example.org"
    f.write_text(json.dumps(doc))
    with pytest.raises(le.TamperError):
        w.esc.partner.partner()


def test_blocklist_changes_are_gated_too(tmp_path):
    w = World(tmp_path)
    bl = lb.LocalBlocklist(tmp_path / "bl.json", wait_seconds=lambda: 24 * H, clock=lambda: w.wall,
                           partner=w.esc.partner)
    bl.add("example.com")
    w.mail.up = False
    with pytest.raises(lb.BlocklistError) as e:
        bl.request_unblock("example.com")
    assert e.value.code == "PAX-ESCROW-010"
    w.wall += 48 * H
    assert bl.apply_due() == [] and bl.blocked() == ["example.com"]
    w.mail.up = True
    for g in w.esc.partner.flush():
        assert g["type"] == "blocklist"
        bl.activate(g["id"])
    w.wall += 24 * H
    assert bl.apply_due() == ["unblock example.com"]
    assert ("blocklist_change_applied", "friend@example.org") in w.mail.sent


def test_relay_and_smtp_senders_build_the_right_requests():
    seen = {}

    class Resp:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout=20):
        seen["url"], seen["auth"] = req.full_url, req.headers.get("Authorization")
        seen["body"] = json.loads(req.data)
        return Resp()
    msg = {"kind": "removal_requested", "subject": "S", "user_body": "U", "partner_body": "P"}
    pt.send_relay({"url": "https://pax.example.org/", "token": "tok"}, msg, "f@example.org", opener=opener)
    assert seen["url"] == "https://pax.example.org/v1/notify" and seen["auth"] == "Bearer tok"
    assert seen["body"]["partner_email"] == "f@example.org" and seen["body"]["partner_body"] == "P"

    class FakeSMTP:
        def __init__(self, host, port, timeout=20):
            self.calls = [("connect", host, port)]
            FakeSMTP.last = self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            self.calls.append(("starttls",))

        def login(self, u, p):
            self.calls.append(("login", u))

        def send_message(self, m):
            self.calls.append(("send", m["To"], m["Subject"]))
    t = pt.validate_transport({"kind": "smtp", "host": "smtp.example.org", "username": "me@example.org",
                               "password": "x", "security": "starttls"})
    pt.send_smtp(t, msg, "f@example.org", "me@example.org", smtp_factory=FakeSMTP)
    c = FakeSMTP.last.calls
    assert c[0] == ("connect", "smtp.example.org", 587) and ("starttls",) in c
    assert ("send", "f@example.org", "[Pax partner] S") in c and ("send", "me@example.org", "S") in c
