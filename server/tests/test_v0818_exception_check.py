# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.18: the exception check uses Pax's own lists first. The outside lookup is
made only with the extra family layer on, or when Pax's lists can't answer."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pax_server import restricted  # noqa: E402

pr = restricted.pr


class Lookup:
    def __init__(self, blocked=()):
        self.calls = 0
        self.fake = pr.fake_lookup(blocked=blocked)

    def __call__(self, wire):
        self.calls += 1
        return self.fake(wire)


def test_pax_lists_decide_without_outside_lookup(monkeypatch):
    lk = Lookup(blocked=["ref-only.example"])
    monkeypatch.setattr(restricted, "LOOKUP_OVERRIDE", lk)
    restricted.check("ref-only.example", "https://x.invalid/", lists_check=lambda d: False)
    assert lk.calls == 0
    with pytest.raises(pr.RestrictedSite):
        restricted.check("listed.example", "https://x.invalid/", lists_check=lambda d: True)
    assert lk.calls == 0


def test_family_layer_or_unhealthy_lists_also_ask_outside(monkeypatch):
    lk = Lookup(blocked=["ref-only.example"])
    monkeypatch.setattr(restricted, "LOOKUP_OVERRIDE", lk)
    with pytest.raises(pr.RestrictedSite):
        restricted.check("ref-only.example", "https://x.invalid/", lists_check=lambda d: False,
                         family_layer=True)
    with pytest.raises(pr.RestrictedSite):
        restricted.check("ref-only.example", "https://x.invalid/", lists_check=lambda d: None)
    with pytest.raises(pr.RestrictedSite):
        restricted.check("ref-only.example", "https://x.invalid/")          # no in-process lists


def test_failed_outside_lookup_still_refuses_when_needed(monkeypatch):
    monkeypatch.setattr(restricted, "LOOKUP_OVERRIDE", pr.fake_lookup(failing=["down.example"]))
    with pytest.raises(pr.RestrictedSite):
        restricted.check("down.example", "https://x.invalid/", lists_check=lambda d: None)
