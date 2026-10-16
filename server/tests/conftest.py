# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1: exception requests are checked against CleanBrowsing Family. Tests
never touch the network: a fake answers NXDOMAIN (CleanBrowsing's block) for
*.blocked-upstream.com and fails for *.down-upstream.com."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "common"))

import pax_restricted  # noqa: E402
from pax_server import restricted  # noqa: E402


@pytest.fixture(autouse=True)
def _fake_upstream(monkeypatch):
    monkeypatch.setattr(restricted, "LOOKUP_OVERRIDE", pax_restricted.fake_lookup(
        blocked=["blocked-upstream.com"], failing=["down-upstream.com"]))
