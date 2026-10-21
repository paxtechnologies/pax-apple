# SPDX-License-Identifier: GPL-3.0-only
import sys
from pathlib import Path

import pytest

WINDOWS = Path(__file__).resolve().parents[1]
REPO = WINDOWS.parent
for d in (WINDOWS, REPO / "device", REPO / "profile", REPO / "common"):
    sys.path.insert(0, str(d))


@pytest.fixture(autouse=True)
def _data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PAX_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("PAX_DNS_BASE", raising=False)
