# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.15 verified support release on a Mac's own escrow (pax-guard).

A one-time code from Pax support, signed with the support key, releases ONE Mac
straight away: only with "Allow verified support release" on, only for this Mac's
support ID, only before it expires, only once, and only after the partner email
went out (never queued). Macs set up before 0.8.15 start with the switch off."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent
REPO = GUARD.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(GUARD))
import ed25519  # noqa: E402
import local_escrow as le  # noqa: E402
import pax_guard as pg  # noqa: E402
import support_code as sc  # noqa: E402
from test_v08_partner import World  # noqa: E402

H, D = 3600, 86400
SEED = b"\x07" * 32                       # a test key, never the real support key
PUB = ed25519.public_key(SEED)


@pytest.fixture(autouse=True)
def test_key(monkeypatch):
    monkeypatch.setattr(sc, "SUPPORT_PUBLIC_KEYS_HEX", [PUB.hex()])


def world(tmp_path, partner="friend@example.org", support=True, **kw):
    w = World.__new__(World)
    w.wall, w.mono = 1_800_000_000.0, 100.0
    from test_v08_partner import Mail
    w.mail = Mail()
    w.trusted = None
    w.events = []
    w.esc = le.LocalEscrow(tmp_path / "escrow", clock=lambda: w.wall, mono=lambda: w.mono,
                           boot_time=lambda: 1, require_root=False, log=lambda m: None,
                           trusted_time=lambda: w.trusted,
                           tamper_log=lambda k, d: w.events.append((k, d)),
                           senders={"relay": w.mail.relay, "smtp": w.mail.smtp})
    w.wall -= 30 * D
    w.esc.deposit("paxadmin", "pw", wait_seconds=kw.get("wait", 72 * H), support_release=support)
    w.wall += 30 * D
    w.esc.heartbeat()
    if partner:
        w.esc.partner.set_transport({"kind": "relay", "url": "https://pax.example.org", "token": "tok"})
        w.esc.set_partner(partner)
    return w


def code_for(w, support_id=None, lifetime=24 * H, issued=None, seed=SEED):
    sid = support_id or w.esc.status()["support_id"]
    return sc.issue(seed, sid, int(issued if issued is not None else w.wall), lifetime=lifetime)


def refused(w, code):
    with pytest.raises(le.EscrowError) as e:
        w.esc.redeem_support(code)
    return e.value.code


# ------------------------------------------------------------------ the code
def test_code_round_trip_and_format():
    sid = sc.new_support_id()
    assert len(sid) == 19 and sid.count("-") == 3
    code = sc.issue(SEED, sid, 1_800_000_000)
    assert code.startswith("PAXS-") and all(len(g) <= 5 for g in code.split("-")[1:])
    c = sc.verify(code, sid, 1_800_000_000 + 60)
    assert c["support_id"] == sid and c["expires_at"] - c["issued_at"] == 24 * H
    # Typed by hand: lower case, spaces instead of dashes, 0/1 for O/I still verify.
    typed = code.lower().replace("-", " ").replace("o", "0").replace("i", "1")
    assert sc.verify(typed, sid.lower(), 1_800_000_000 + 60)["nonce"] == c["nonce"]


def test_bad_signature_is_refused():
    sid = sc.new_support_id()
    other = sc.issue(b"\x09" * 32, sid, 1_800_000_000)          # signed with a key Pax doesn't pin
    with pytest.raises(sc.SupportCodeError) as e:
        sc.verify(other, sid, 1_800_000_000 + 1)
    assert e.value.code == sc.BAD_SIGNATURE
    raw = sc.issue(SEED, sid, 1_800_000_000)
    flipped = raw[:-1] + ("A" if raw[-1] != "A" else "B")
    with pytest.raises(sc.SupportCodeError) as e:
        sc.verify(flipped, sid, 1_800_000_000 + 1)
    assert e.value.code in (sc.BAD_SIGNATURE, sc.MALFORMED)
    with pytest.raises(sc.SupportCodeError) as e:
        sc.verify("PAXS-ABCDE-FGHIJ", sid, 1_800_000_000)
    assert e.value.code == sc.MALFORMED


def test_lifetime_is_at_most_a_day():
    with pytest.raises(ValueError):
        sc.issue(SEED, sc.new_support_id(), 1_800_000_000, lifetime=24 * H + 1)


def test_cli_issues_a_code_that_verifies(tmp_path):
    key = tmp_path / "support.key"
    pub = subprocess.run([sys.executable, str(REPO / "tools" / "pax-support-release.py"), "keygen",
                          "--out", str(key)], capture_output=True, text=True, check=True).stdout.strip()
    assert oct(key.stat().st_mode & 0o777) == "0o600" and len(bytes.fromhex(pub)) == 32
    assert key.read_text().strip() not in pub            # the private key is never printed
    sid = sc.new_support_id()
    r = subprocess.run([sys.executable, str(REPO / "tools" / "pax-support-release.py"), "issue", sid,
                        "--key", str(key)], capture_output=True, text=True, check=True)
    code = r.stdout.strip()
    import time
    assert sc.verify(code, sid, time.time(), keys=[bytes.fromhex(pub)])["support_id"] == sid
    v = subprocess.run([sys.executable, str(REPO / "tools" / "pax-support-release.py"), "verify", code, sid,
                        "--key", str(key)], capture_output=True, text=True)
    assert v.returncode == 0 and "valid" in v.stdout


def test_the_real_support_key_is_pinned_and_differs_from_the_update_key():
    import importlib
    import pax_signing
    fresh = importlib.reload(sc)
    try:
        keys = fresh.pinned_keys()
        assert len(keys) == 1
        assert keys[0].hex() not in pax_signing.PUBLIC_KEYS_HEX
    finally:
        importlib.reload(sc)


# ------------------------------------------------------------- local escrow
def test_verified_code_releases_at_once_partner_told_first(tmp_path):
    w = world(tmp_path)
    w.esc.request_removal()                                    # a normal wait already running
    sent_before = len(w.mail.sent)
    out = w.esc.redeem_support(code_for(w))
    assert out["removal_password"] == "pw"                     # released straight away, no wait
    kinds = [k for k, _ in w.mail.sent[sent_before:]]
    assert kinds == ["support_release_used"]                   # the partner, and only that email
    assert w.esc.released()
    assert ("support_release_used" in [k for k, _ in w.events])


def test_wrong_device_is_refused(tmp_path):
    w = world(tmp_path)
    assert refused(w, code_for(w, support_id=sc.new_support_id())) == sc.WRONG_DEVICE
    assert not w.esc.released()
    assert ("support_code_refused", {"code": sc.WRONG_DEVICE}) in w.events


def test_expired_code_is_refused(tmp_path):
    w = world(tmp_path)
    code = code_for(w, lifetime=H)
    w.wall += H + 1
    assert refused(w, code) == sc.EXPIRED
    # Moving this Mac's clock back doesn't help when network time is known.
    w.wall -= 2 * H
    w.trusted = w.wall + 2 * H
    assert refused(w, code) == sc.EXPIRED
    assert not w.esc.released()


def test_code_from_the_future_is_refused(tmp_path):
    w = world(tmp_path)
    assert refused(w, code_for(w, issued=w.wall + 2 * H)) == sc.EXPIRED


def test_reused_nonce_is_refused(tmp_path):
    w = world(tmp_path)
    code = code_for(w)
    w.esc.redeem_support(code)
    # Even after the release, the same code never works again.
    assert refused(w, code) == sc.USED


def test_switch_off_refuses_every_code(tmp_path):
    w = world(tmp_path, support=False)
    assert w.esc.status()["support_release"]["allowed"] is False
    assert refused(w, code_for(w)) == sc.TURNED_OFF
    assert not w.esc.released()


def test_turning_off_is_immediate(tmp_path):
    w = world(tmp_path)
    st = w.esc.set_support_release(False)
    assert st["support_release"]["allowed"] is False
    assert refused(w, code_for(w)) == sc.TURNED_OFF


def test_turning_on_waits_the_full_wait_with_the_partner_told(tmp_path):
    w = world(tmp_path, support=False)
    before = len(w.mail.sent)
    st = w.esc.set_support_release(True)
    assert st["support_release"]["allowed"] is False and st["support_release"]["pending_on_at"]
    assert [k for k, _ in w.mail.sent[before:]] == ["support_release_on_requested"]
    assert refused(w, code_for(w)) == sc.TURNED_OFF
    w.run(72 * H - 1800)
    assert w.esc.status()["support_release"]["allowed"] is False
    w.run(3600)
    assert w.esc.status()["support_release"]["allowed"] is True
    assert w.esc.redeem_support(code_for(w))["removal_password"] == "pw"


def test_turning_on_fails_closed_when_the_partner_cant_be_told(tmp_path):
    w = world(tmp_path, support=False)
    w.mail.up = False
    with pytest.raises(le.EscrowError) as e:
        w.esc.set_support_release(True)
    assert e.value.code == "PAX-ESCROW-010"
    st = w.esc.status()["support_release"]
    assert not st["allowed"] and not st["pending_on_at"] and st["telling_partner"]
    w.run(10 * D)                                    # never on while nobody was told
    assert not w.esc.status()["support_release"]["allowed"]
    w.mail.up = True
    w.wall += 3600
    w.flush()                                        # told now: the wait starts now
    st = w.esc.status()["support_release"]
    assert not st["allowed"] and st["pending_on_at"] >= w.wall + 72 * H - 1


def test_turning_off_cancels_a_pending_on(tmp_path):
    w = world(tmp_path, support=False)
    w.esc.set_support_release(True)
    w.esc.set_support_release(False)
    w.run(10 * D)
    assert not w.esc.status()["support_release"]["allowed"]


def test_partner_email_failure_blocks_the_release(tmp_path):
    w = world(tmp_path)
    w.mail.up = False
    code = code_for(w)
    assert refused(w, code) == sc.PARTNER_UNREACHABLE
    assert not w.esc.released()
    assert w.esc.partner.config()["outbox"] == []            # not queued: nothing releases later
    w.flush()
    assert not w.esc.released()
    # Once mail works, the same (unused) code still works until it expires.
    w.mail.up = True
    assert w.esc.redeem_support(code)["removal_password"] == "pw"


def test_no_partner_releases_without_email(tmp_path):
    w = world(tmp_path, partner=None)
    assert w.esc.redeem_support(code_for(w))["removal_password"] == "pw" and w.mail.sent == []


def test_migration_keeps_older_macs_off(tmp_path):
    """A Mac set up with 0.8.14 has no support state: it gets a support ID and the
    switch OFF, through status, heartbeat and redeem alike, and stays off."""
    w = world(tmp_path)
    st = w.esc._read("state.json")
    st.pop("support")                                         # what a 0.8.14 state.json looks like
    w.esc._write("state.json", st)
    w.esc.heartbeat()
    view = w.esc.status()
    assert view["support_release"]["allowed"] is False and view["support_release"]["since"] == "migrated"
    sid = view["support_id"]
    assert sc.normalise_support_id(sid) == sid
    assert w.esc.status()["support_id"] == sid                # stable once made
    w.run(30 * D)
    assert w.esc.status()["support_release"]["allowed"] is False
    assert refused(w, code_for(w)) == sc.TURNED_OFF


def test_deposit_defaults_to_off_and_the_cli_takes_the_set_up_choice(tmp_path):
    esc = le.LocalEscrow(tmp_path / "a", require_root=False, mono=lambda: 1.0, boot_time=lambda: 1)
    esc.deposit("paxadmin", "pw", wait_seconds=72 * H)
    assert esc.status()["support_release"]["allowed"] is False   # nothing turns it on by accident
    src = (GUARD / "local_escrow.py").read_text()
    assert '"--support-release", choices=["on", "off"], default="off"' in src


def test_guard_socket_commands(tmp_path):
    w = world(tmp_path)

    g = pg.Guard.__new__(pg.Guard)
    g.cfg = pg.GuardConfig(escrow_mode="local")
    g.escrow = w.esc
    g.tamper_log = type("T", (), {"append": staticmethod(lambda k, d: w.events.append((k, d)))})()
    g._support_limit = None
    r = g.handle_request({"cmd": "escrow.redeem_support", "code": "PAXS-NOT-A-CODE"}, 501)
    assert r["ok"] is False and r["code"] == sc.MALFORMED
    r = g.handle_request({"cmd": "escrow.support_release", "allowed": False}, 501)
    assert r["ok"] and r["device"]["support_release"]["allowed"] is False
    for _ in range(3):
        g.handle_request({"cmd": "escrow.redeem_support", "code": "x"}, 501)
    r = g.handle_request({"cmd": "escrow.redeem_support", "code": "x"}, 501)
    assert r["code"] == sc.TOO_MANY_TRIES


def test_support_code_ships_with_pax_guard():
    for f in (REPO / "guard" / "scripts" / "pax-guard-install.sh", REPO / "mac-app" / "scripts" / "build-dmg.sh"):
        assert "recovery_guard support_code; do" in f.read_text(), f
    out = json.loads(subprocess.run([sys.executable, str(GUARD / "pax_guard.py"), "selftest"],
                                    capture_output=True, text=True).stdout or "{}")
    assert not any("support_code" in p for p in out.get("problems", []))
