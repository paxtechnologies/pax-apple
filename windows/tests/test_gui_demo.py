# SPDX-License-Identifier: GPL-3.0-only
"""Walks the whole window in demo mode (canned phone, in-memory server): every screen is
built and every step's worker finishes. Skipped where Tk can't open a window."""
import time

import pytest

tk = pytest.importorskip("tkinter")


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


def pump(r, seconds):
    end = time.time() + seconds
    while time.time() < end:
        r.update()
        time.sleep(0.02)


def test_demo_walkthrough(root):
    from pax_windows import gui
    app = gui.App(root, demo=True)
    pump(root, 1.0)
    assert app.device is not None and app.device.paired
    app.show_ready()
    app.v_findmy.set(True)
    app.v_ownbackup.set(True)
    app._ready_changed()
    assert "disabled" not in app.b_ready.state()
    app.show_wait()
    app.v_email.set("alex@example.org")
    app.v_partner.set("not-an-email")
    assert "disabled" in app.b_wait.state()          # a trusted person's address must look right
    app.v_partner.set("friend@example.org")
    app.v_wait.set("custom")
    app.v_custom.set("400")
    app._wait_changed()
    assert "disabled" in app.b_wait.state()          # over 365 days
    app.v_custom.set("14")
    app._wait_changed()
    assert "disabled" not in app.b_wait.state()
    app._save_wait()
    pump(root, 0.5)
    assert app.step == 3 and app.choices.wait_days == 14
    assert "disabled" in app.b_protect.state()       # agreement not ticked
    app.v_agree.set(True)
    app._agree_changed()
    app._protect()
    deadline = time.time() + 20
    while app.phone_state != "trust_requested" and time.time() < deadline:
        pump(root, 0.2)
    assert app.phone_state == "trust_requested"      # Pax stopped polling and waits for the tap
    app._poll_phone()
    deadline = time.time() + 10
    while not app.session.supervised and time.time() < deadline:
        pump(root, 0.2)
    assert app.session.supervised
    app._turn_on()
    deadline = time.time() + 10
    while app.step != 4 and time.time() < deadline:
        pump(root, 0.2)
    assert app.step == 4
    sent = app.session.escrow.devices[0]
    assert sent["trial"] is True and sent["support_release"] is True and "removal_password" not in sent
    assert not app.session.identity.private_key.exists()
