#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Write windows/requirements-windows.txt: every pin in requirements-windows.in with the
sha256 of each wheel pip may pick on Windows x64 with CPython 3.12. Reuses
device/lock_bundle.py (the Mac helper's lock), with Windows wheel tags instead of macOS.

    python windows/lock_windows.py [--check]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "device"))
import lock_bundle  # noqa: E402

PLAT_OK = re.compile(r"-(any|win_amd64)\.whl$")


def wanted(filename: str) -> bool:
    return (filename.endswith(".whl") and bool(lock_bundle.PY_OK.search(filename))
            and bool(PLAT_OK.search(filename)))


def main() -> int:
    lock_bundle.IN = HERE / "requirements-windows.in"
    lock_bundle.OUT = HERE / "requirements-windows.txt"
    lock_bundle.wanted = wanted
    original = lock_bundle.render

    def render(entries):
        return original(entries).replace("device/lock_bundle.py from requirements-bundle.in",
                                         "windows/lock_windows.py from requirements-windows.in")
    lock_bundle.render = render
    sys.argv = [sys.argv[0]] + sys.argv[1:]
    return lock_bundle.main()


if __name__ == "__main__":
    sys.exit(main())
