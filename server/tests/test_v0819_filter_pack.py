# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.19: the DoH server takes signed filter packs every 6 hours, runs the canary
on the new lists before the swap, rolls back a pack that fails the canary in use,
and reports the pack in /v1/health. No network: the store and forwarder are fakes."""
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pax_server import doh as doh_mod  # noqa: E402

import dns_forwarder as dnsf  # noqa: E402
import filter_lists as fl  # noqa: E402


class FakeStore:
    def __init__(self, report):
        self.report = report
        self.loaded = 0
        self.rolled = []
        self.canary_seen = None

    def update(self, fetch, canary=None):
        self.canary_seen = canary
        return dict(self.report)

    def load(self):
        self.loaded += 1
        return types.SimpleNamespace(info={"version": "x"}, entries=1)

    def rollback_pack(self, why):
        self.rolled.append(why)
        return True

    def pack_status(self):
        return {"version": "2026.1018.300", "origin": "pack"}


class FakeForwarder:
    def __init__(self, results):
        self.results = list(results)
        self.primary_upstreams = [object()]
        self.filters = None
        self.last_canary = {}
        self.set = 0

    def status(self):
        return {"filter_mode": "pax", "canary": self.last_canary}

    ready = True

    def set_filters(self, fs):
        self.set += 1
        self.filters = fs
        self.last_canary = self.results.pop(0) if self.results else {"ok": True, "failures": []}


def service(store, fwd, tmp_path):
    svc = doh_mod.DohService(feed=None, state_dir=str(tmp_path), forwarder=fwd, filter_store=store)
    return svc


def test_pack_applied_and_canary_passed_in(tmp_path):
    store = FakeStore({"changed": ["pax-block"], "version": "2026.1018.300", "ok": True})
    fwd = FakeForwarder([{"ok": True, "failures": []}])
    svc = service(store, fwd, tmp_path)
    svc.update_lists()
    assert store.canary_seen is dnsf.check_filterset
    assert fwd.set == 1 and not store.rolled
    assert svc.status()["filter_pack"] == {"version": "2026.1018.300", "origin": "pack"}


def test_pack_failing_the_canary_after_the_swap_is_rolled_back(tmp_path):
    store = FakeStore({"changed": ["pax-block"], "version": "2026.1019.300", "ok": True})
    fwd = FakeForwarder([{"ok": False, "failures": ["a known restricted name was not blocked"]},
                         {"ok": True, "failures": []}])
    svc = service(store, fwd, tmp_path)
    svc.update_lists()
    assert store.rolled and "restricted name" in store.rolled[0]
    assert fwd.set == 2 and fwd.last_canary["ok"]


def test_nothing_changes_when_the_pack_is_refused(tmp_path):
    store = FakeStore({"changed": [], "version": "2026.1019.300", "ok": False, "error": "canary failed"})
    fwd = FakeForwarder([])
    svc = service(store, fwd, tmp_path)
    svc.update_lists()
    assert fwd.set == 0 and not store.rolled
    assert svc.last_pack_report["error"] == "canary failed"


def test_six_hourly_schedule():
    assert fl.UPDATE_INTERVAL == 6 * 3600
    src = Path(doh_mod.__file__).read_text()
    assert "(self.update_lists, fl.UPDATE_INTERVAL," in src
