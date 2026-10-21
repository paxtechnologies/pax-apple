# SPDX-License-Identifier: GPL-3.0-only
"""pax-helper.exe: device/pax_device.py, unchanged, as its own console program (started
hidden by the window, like the Mac app starts the bundled Python helper). Prints one JSON
object on its last line."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _d in ("profile", "common", "device"):
    sys.path.insert(0, str(HERE.parent / _d))

import pax_device  # noqa: E402

if __name__ == "__main__":
    sys.exit(pax_device.main())
