#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Break-glass for a LOCAL TEST server only: print a device's escrowed password
straight from the SQLite file, ignoring the wait.

Anyone holding both the database and PAX_SERVER_KEY can do this, which is why a
real Pax server keeps the key off the user's machine. On a test where the server
runs on the protected Mac itself, this is your way back in if the app fails.

  PAX_SERVER_KEY=$(cat ~/.pax-test-key) python3 server/scripts/local_reveal.py \
      --db ~/pax-test.sqlite3 [--device DEVICE_ID]

Without --device it lists the devices. It never changes the database.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pax_server.crypto import SecretBox  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", required=True)
    ap.add_argument("--device")
    args = ap.parse_args(argv)
    key = os.environ.get("PAX_SERVER_KEY", "")
    if not key:
        print("set PAX_SERVER_KEY", file=sys.stderr)
        return 2
    con = sqlite3.connect(f"file:{os.path.expanduser(args.db)}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    if not args.device:
        for r in con.execute("SELECT id, name, platform, installed_at FROM devices ORDER BY installed_at"):
            print(f"{r['id']}  {r['platform']:6}  {r['name']}")
        return 0
    row = con.execute("SELECT * FROM devices WHERE id=?", (args.device,)).fetchone()
    if not row:
        print("no such device", file=sys.stderr)
        return 1
    print(SecretBox(key).decrypt(row["password_ct"], aad=row["id"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
