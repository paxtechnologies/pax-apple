# SPDX-License-Identifier: GPL-3.0-only
"""python -m pax_windows [--demo] [--selftest-out FILE]"""
from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    from . import paths
    paths.add_shared_paths()
    if "--selftest-out" in argv:
        from . import selftest
        return selftest.main(argv[argv.index("--selftest-out") + 1])
    from . import gui
    return gui.main(demo="--demo" in argv or os.environ.get("PAX_DEMO") == "1")


if __name__ == "__main__":
    sys.exit(main())
