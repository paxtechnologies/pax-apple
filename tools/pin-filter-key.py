#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pin a filter-pack public key (64 hex characters) in guard/pax_signing.py,
replacing the one pinned now. Usage: tools/pin-filter-key.py <public key hex>"""
import re
import sys
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "guard" / "pax_signing.py"


def pin(hex_key: str, path: Path = PATH) -> None:
    key = hex_key.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        raise SystemExit("a filter public key is 64 hex characters (32 bytes)")
    text = path.read_text()
    new, n = re.subn(r'(FILTER_PUBLIC_KEYS_HEX = \[\n    ")[0-9a-f_A-Z]+(",\n\])', rf"\g<1>{key}\g<2>", text)
    if n != 1:
        raise SystemExit("FILTER_PUBLIC_KEYS_HEX not found in the expected shape")
    path.write_text(new)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    pin(sys.argv[1])
    print("pinned", sys.argv[1].strip().lower())
