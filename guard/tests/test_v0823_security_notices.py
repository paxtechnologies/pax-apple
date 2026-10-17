# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.23: brief backup-filter episodes stay in the tamper log but aren't sent as notices."""
import pax_guard as pg


def ev(ts, kind):
    return {"ts": ts, "kind": kind, "detail": {}}


def test_brief_fallback_pairs_are_dropped_long_ones_and_real_events_kept():
    events = [ev(100, "dns:fallback_on"), ev(130, "dns:fallback_off"),          # restart, 30 s
              ev(200, "changed:admins"),
              ev(1000, "dns:fallback_on"), ev(1000 + 1500, "dns:fallback_off"),  # 25 min
              ev(5000, "dns:fallback_on"), ev(5005, "dns:fallback_off"),
              ev(6000, "clock_backwards")]
    kinds = [(e["ts"], e["kind"]) for e in pg._shown_tamper_events(events)]
    assert kinds == [(200, "changed:admins"), (1000, "dns:fallback_on"), (2500, "dns:fallback_off"),
                     (6000, "clock_backwards")]


def test_ongoing_fallback_is_passed_on_and_stray_off_dropped():
    out = pg._shown_tamper_events([ev(10, "dns:fallback_off"), ev(50, "dns:fallback_on")])
    assert [e["kind"] for e in out] == ["dns:fallback_on"]
    assert pg.BRIEF_FALLBACK_SECONDS == 600
