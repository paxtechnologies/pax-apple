# SPDX-License-Identifier: GPL-3.0-only
"""PyInstaller entry for PaxSetup.exe (the window)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
for _d in ("device", "profile", "common"):
    sys.path.insert(0, str(HERE.parent / _d))

from pax_windows.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
