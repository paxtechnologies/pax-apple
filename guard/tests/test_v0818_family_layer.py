# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.18 Advanced: the extra family-filter layer on the Mac (local escrow).
On is immediate; off loosens the filter, so it waits like a removal (partner
first, then the user's own wait). Both go in the tamper log."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from test_v08_guard import local_guard  # noqa: E402
from test_v0812_pax_max import Partner  # noqa: E402


def setting(g, **kw):
    return g.handle_request({"cmd": "settings.set", **kw}, 501)


def test_off_by_default_on_is_instant_off_waits(tmp_path):
    g, s = local_guard(tmp_path)
    assert g.settings_view()["family_layer"] is False
    r = setting(g, family_layer=True)
    assert r["ok"] and r["settings"]["family_layer"] is True
    assert g.forwarder_policy().family_layer is True
    r = setting(g, family_layer=False)
    assert r["ok"] and r["request"]["action"] == "family_layer_off"
    assert r["request"]["seconds_remaining"] == g._wait_seconds()
    assert g.family_layer is True                              # still on during the wait
    s.t += g._wait_seconds() + 1
    g.cycle()
    assert g.family_layer is False and g.forwarder_policy().family_layer is False
    log = str(g.tamper_log.entries(50))
    assert "setting:family_layer_off_requested" in log and "setting:family_layer" in log


def test_turning_on_cancels_a_waiting_off(tmp_path):
    g, s = local_guard(tmp_path)
    setting(g, family_layer=True)
    setting(g, family_layer=False)
    assert g.settings_view()["family_layer_pending"] is not None
    setting(g, family_layer=True)
    assert g.settings_view()["family_layer_pending"] is None
    s.t += g._wait_seconds() + 1
    g.cycle()
    assert g.family_layer is True


def test_partner_told_first_fails_closed(tmp_path):
    g, s = local_guard(tmp_path)
    setting(g, family_layer=True)
    g.blocklist.partner = Partner(ok=False)
    r = setting(g, family_layer=False)
    assert r["ok"] is False and r["code"] == "PAX-ESCROW-010"
    assert g.family_layer is True


def test_server_escrow_refuses_here(tmp_path):
    g, s = local_guard(tmp_path)
    g.cfg.escrow_mode = "server"
    r = setting(g, family_layer=True)
    assert r["ok"] is False and r["code"] == "PAX-ESCROW-009"
