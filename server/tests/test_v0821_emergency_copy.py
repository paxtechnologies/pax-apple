# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.21: device status carries the emergency cooling-off, so the app's
"Pax turns off after 24 hours" line follows PAX_EMERGENCY_COOLOFF_SECONDS."""
from test_v085_limits import account, build
from test_v0815_support import device

from pax_server.config import HOUR


def test_status_has_default_cooloff(tmp_path):
    env = build(tmp_path)
    h = account(env)
    d = device(env, h)
    assert d["emergency_cooloff_seconds"] == 24 * HOUR
    st = env.client.get(f"/v1/devices/{d['device_id']}", headers=h).json()
    assert st["emergency_cooloff_seconds"] == 24 * HOUR


def test_status_follows_configured_cooloff(tmp_path):
    env = build(tmp_path, emergency_cooloff_seconds=12 * HOUR)
    h = account(env)
    d = device(env, h)
    st = env.client.get(f"/v1/devices/{d['device_id']}", headers=h).json()
    assert st["emergency_cooloff_seconds"] == 12 * HOUR
