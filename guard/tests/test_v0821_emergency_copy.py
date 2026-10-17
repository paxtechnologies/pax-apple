# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.21: a Mac's own escrow reports its emergency cooling-off (24 h) in status."""
from test_v0818_trial import Mac
import local_escrow as le


def test_local_status_has_cooloff(tmp_path):
    st = Mac(tmp_path).esc.status()
    assert st["emergency_cooloff_seconds"] == le.EMERGENCY_COOLOFF == 24 * 3600
