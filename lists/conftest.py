# SPDX-License-Identifier: GPL-3.0-only
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for p in (HERE / "loop", HERE, HERE.parent / "guard", HERE.parent / "common"):
    sys.path.insert(0, str(p))
