# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0 Mac end to end, mocked (no root, no network, no real Mac):

  set-up   the app's deposit step (`local_escrow.py deposit`, run as root through
           the admin prompt) stores paxadmin's password; the app's receipt check
           (PaxCore LocalEscrowReceipt) is the SHA-256 it prints;
  guard    pax-guard starts on that escrow: DNS points at 127.0.0.1, pf loads,
           and the app talks to it over a real Unix socket (guard_ipc);
  forwarder the bundled signed lists load; the user's own blocked site, a Pax
           category and a list domain are answered 0.0.0.0, anything else goes
           to the (fake) CleanBrowsing DoH upstream, never plain DNS;
  escrow   with a partner: the request emails the partner before the countdown
           starts, the reveal emails again, and after the wait the app gets the
           very password the set-up stored;
  update   a release signed by scripts/sign-release.py installs, and the new
           pax-guard confirms it.
"""
import base64
import functools
import hashlib
import importlib.util
import io
import json
import os
import contextlib
import sys
from pathlib import Path

GUARD = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GUARD))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dns_forwarder as dnsf  # noqa: E402
import ed25519  # noqa: E402
import filter_lists as fl  # noqa: E402
import guard_config as gc  # noqa: E402
import guard_ipc  # noqa: E402
import local_escrow as le  # noqa: E402
import pax_guard as pg  # noqa: E402
import pax_signing  # noqa: E402
import pax_update as pu  # noqa: E402
from test_v08_dns import FakeUpstream, ask  # noqa: E402
from test_v08_guard import NetSystem  # noqa: E402
from test_v08_update import FakeSys, make_app  # noqa: E402

D = 86400
SEED = b"\x0b" * 32


def a_records(fwd, name):
    rcode, answers = ask(fwd, name)
    assert rcode == 0, (name, rcode)
    return [".".join(str(b) for b in rr[4]) for rr in answers if rr[1] == 1]


class Mail:
    def __init__(self):
        self.sent = []

    def relay(self, t, msg, partner):
        self.sent.append((msg["kind"], partner, t.get("url")))

    def smtp(self, t, msg, partner, owner):
        self.sent.append((msg["kind"], partner, t.get("host")))


def test_mac_setup_guard_forwarder_escrow_update(tmp_path, monkeypatch):
    s = NetSystem(tmp_path)
    escrow_dir = tmp_path / "PaxGuard" / "escrow"
    paxadmin_pw = "Generated-paxadmin-Pw-7f3a"

    # ---- 1. set-up: the root deposit CLI, exactly as MacLockdown calls it -------
    secret = tmp_path / "pax-escrow-secret"
    secret.write_text(paxadmin_pw)
    installed_at = s.t - 30 * D            # past the first-day grace period
    monkeypatch.setattr(le.os, "geteuid", lambda: 0)
    monkeypatch.setattr(le, "LocalEscrow", functools.partial(le.LocalEscrow, require_root=False,
                                                             clock=lambda: installed_at))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = le.main(["deposit", "--secret-file", str(secret), "--wait-seconds", str(D),
                      "--dir", str(escrow_dir), "--reset"])
    monkeypatch.undo()
    assert rc == 0
    receipt = json.loads(out.getvalue().strip().splitlines()[-1])
    assert receipt == {"stored": "paxadmin", "sha256": hashlib.sha256(paxadmin_pw.encode()).hexdigest()}
    assert not secret.exists()                 # the secret file is consumed
    assert paxadmin_pw not in out.getvalue()

    # ---- 2. pax-guard starts on that escrow ------------------------------------
    mail = Mail()
    cfg = pg.GuardConfig(profile_identifier="org.paxpeace.pax.macos-selflock.e2e", user="alex",
                         escrow_mode="local")
    g = pg.Guard(cfg, s, state_dir=tmp_path / "PaxGuard" / "state", quarantine_dir=tmp_path / "q")
    g.escrow.require_root = False
    g.escrow.partner.senders = {"relay": mail.relay, "smtp": mail.smtp}
    mono = {"t": 1000.0}
    g.escrow.mono = lambda: mono["t"]
    g.escrow.heartbeat()
    g._reveal_rate = guard_ipc.RateLimit(10)
    res = g.cycle()
    assert s.dns["Wi-Fi"] == "127.0.0.1" and "port 53" in s.pf_loaded and res["dns_settings"]

    sock = str(tmp_path / "pax-guard.sock")
    server = guard_ipc.IPCServer(g.handle_request, path=sock, log=lambda m: None)
    server.start()
    try:
        def app(cmd, **kw):
            return guard_ipc.request({"cmd": cmd, **kw}, path=sock, timeout=10)

        st = app("status")
        assert st["ok"] and st["escrow_mode"] == "local" and st["version"] == pg.VERSION
        assert app("escrow.status")["device"]["removal_request"] is None

        # ---- 3. the forwarder with the bundled lists + the user's own block -----
        assert app("blocklist.add", domain="my-own-trigger.example")["created"]
        assert "0.0.0.0 my-own-trigger.example" in s.files[gc.HOSTS_PATH]
        store = fl.FilterStore(tmp_path / "PaxGuard" / "state", bundled_dir=GUARD / "filters",
                               plugin_dirs=[], log=lambda m: None)
        filters = store.load()
        assert filters.entries > 1_000_000
        g.remote = {"blocked": [b["domain"] for b in app("blocklist.get")["list"]["blocked"]], "allowed": []}
        cb = FakeUpstream("cleanbrowsing")
        fwd = dnsf.Forwarder([cb, FakeUpstream("adguard")], filters, g.forwarder_policy(), log=lambda m: None)
        assert a_records(fwd, "my-own-trigger.example") == ["0.0.0.0"]
        assert a_records(fwd, "pbs.twimg.com") == ["0.0.0.0"]              # X images category
        sys.path.insert(0, str(GUARD.parent / "common"))
        import pax_restricted as pr
        assert a_records(fwd, pr.samples()[0]) == ["0.0.0.0"]             # bundled pax-block (restricted)
        assert a_records(fwd, "restricted-check.paxpeace.com") == ["0.0.0.0"]
        assert a_records(fwd, "ssstik.io") == ["0.0.0.0"]                  # media converters (v0.8.1)
        assert cb.calls == []
        assert a_records(fwd, "example.org") == ["1.2.3.4"] and len(cb.calls) == 1
        cb.fail = True
        assert a_records(fwd, "wikipedia.org") == ["1.2.3.4"]              # AdGuard Family takes over

        # ---- 4. escrow with a partner, through the socket ----------------------
        assert app("partner.transport", transport={"kind": "relay", "url": "https://relay.paxpeace.com",
                                                    "token": "t" * 32}, owner_email="alex@example.org")["ok"]
        assert app("partner.set", email="friend@example.org")["ok"]
        assert app("partner.get")["partner"]["partner"] == "friend@example.org"
        req = app("escrow.request", reason="remove")
        assert req["ok"]
        assert [k for k, *_ in mail.sent] == ["partner_added", "removal_requested"], mail.sent   # told before the wait runs
        assert app("escrow.status")["device"]["removal_request"]["seconds_remaining"] == D
        early = app("escrow.reveal")
        assert not early["ok"] and early["code"] == "PAX-ESCROW-007" and paxadmin_pw not in json.dumps(early)
        for _ in range(49):                    # 24.5 hours of heartbeats
            s.t += 1800
            mono["t"] += 1800
            g.cycle()
        released = app("escrow.reveal")
        assert released["ok"], released
        assert released["released"]["removal_password"] == paxadmin_pw
        assert [k for k, *_ in mail.sent] == ["partner_added", "removal_requested", "password_revealed"], mail.sent
        assert all(p == "friend@example.org" for _, p, _ in mail.sent)
    finally:
        server.stop()

    # ---- 5. a signed release installs ------------------------------------------
    monkeypatch.setattr(pax_signing, "PUBLIC_KEYS_HEX", [ed25519.public_key(SEED).hex()])
    spec = importlib.util.spec_from_file_location("sign_release", GUARD.parent / "scripts" / "sign-release.py")
    sr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sr)
    zip_path = tmp_path / "Pax-0.8.1.zip"
    zip_path.write_bytes(b"PK fake zip for e2e")
    monkeypatch.setenv("PAX_UPDATE_SIGNING_KEY", base64.b64encode(SEED).decode())
    manifest = tmp_path / "pax-update.json"
    assert sr.main(["sign", "--zip", str(zip_path), "--version", "0.8.1", "--minimum-version", "0.8.0",
                    "--out", str(manifest)]) == 0
    payload = json.loads(manifest.read_text())["payload"]

    appdir = tmp_path / "Applications" / "Pax.app"
    make_app(appdir, "0.8.0", "old")
    gbin = tmp_path / "PaxGuard" / "bin"
    gbin.mkdir(parents=True, exist_ok=True)
    (gbin / "pax_guard.py").write_text('VERSION = "0.8.0"\n')
    fs = FakeSys(tmp_path)
    fs.urls["https://releases.test/pax-update.json"] = manifest.read_bytes()
    fs.urls[payload["url"]] = zip_path.read_bytes()
    notes = []
    up = pu.Updater(fs, tmp_path / "PaxGuard" / "state", "0.8.0", log=lambda m: None, notify=notes.append,
                    app_path=appdir, guard_bin=gbin, updates_dir=tmp_path / "PaxGuard" / "updates",
                    manifest_urls=["https://releases.test/pax-update.json"], clock=lambda: s.t)
    up.start_watchdog = lambda v: None
    assert up.check(force=True)["state"] == "trial"
    assert 'VERSION = "0.8.1"' in (gbin / "pax_guard.py").read_text()
    up2 = pu.Updater(fs, up.state_path.parent, "0.8.1", log=lambda m: None, notify=notes.append,
                     app_path=appdir, guard_bin=gbin, updates_dir=up.updates)
    assert up2.confirm_trial() and up2.status()["state"] == "committed"
