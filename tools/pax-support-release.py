#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Issue a verified support release code for ONE device (v0.8.15).

Only for a genuine emergency that Pax support has checked. The code removes Pax
from the device whose Support ID it names (shown with the turn-off controls),
works once, and expires within 24 hours. The partner is emailed before anything
is released, and a device with "Allow verified support release" off refuses it.

  pax-support-release.py issue  <support-id> --key PATH [--hours H]   prints the code
  pax-support-release.py verify <code> <support-id> [--key PATH]      checks a code offline
  pax-support-release.py keygen --out PATH                            new support key (0600)

PATH holds base64 (or hex) of the 32-byte Ed25519 seed. The private key is never
printed and must never be committed; keygen prints only the public key to pin in
guard/support_code.py. Standard library only (guard/ed25519.py).
"""
from __future__ import annotations

import argparse
import base64
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "guard"))

import ed25519  # noqa: E402
import pax_signing  # noqa: E402  (seed_from_text)
import support_code as sc  # noqa: E402


def _seed(path: str) -> bytes:
    p = Path(path)
    mode = p.stat().st_mode & 0o777
    if mode & 0o077:
        print(f"warning: {p} is readable by others (mode {oct(mode)}); chmod 600 it", file=sys.stderr)
    return pax_signing.seed_from_text(p.read_text())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verified support release codes (one device, single use).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("issue", help="print a code for one device")
    i.add_argument("support_id", help="the device's Support ID, e.g. ABCD-EFGH-IJKL-MNOP")
    i.add_argument("--key", required=True, help="file with the support signing key")
    i.add_argument("--hours", type=float, default=24.0, help="lifetime in hours (max 24, default 24)")
    v = sub.add_parser("verify", help="check a code offline (signature, device, expiry)")
    v.add_argument("code")
    v.add_argument("support_id")
    v.add_argument("--key", help="check against this key's public half instead of the pinned key")
    k = sub.add_parser("keygen", help="make a new support key")
    k.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "issue":
            if not 0 < a.hours <= 24:
                raise ValueError("--hours must be more than 0 and at most 24")
            seed = _seed(a.key)
            pub = ed25519.public_key(seed)
            if pub not in sc.pinned_keys():
                print("warning: this key isn't pinned in this checkout's guard/support_code.py; "
                      "devices will refuse its codes", file=sys.stderr)
            now = int(time.time())
            code = sc.issue(seed, a.support_id, now, lifetime=int(a.hours * 3600))
            c = sc.verify(code, a.support_id, now, keys=[pub])
            print(code)
            print(f"device {c['support_id']} · expires {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(c['expires_at']))}"
                  f" · key {c['key_id']}", file=sys.stderr)
            return 0
        if a.cmd == "verify":
            keys = [ed25519.public_key(_seed(a.key))] if a.key else None
            c = sc.verify(a.code, a.support_id, time.time(), keys=keys)
            print(f"valid: device {c['support_id']}, nonce {c['nonce']}, expires "
                  f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(c['expires_at']))}, key {c['key_id']}")
            return 0
        out = Path(a.out)
        if out.exists():
            raise ValueError(f"{out} already exists; not overwriting a key")
        seed = os.urandom(32)
        out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, base64.b64encode(seed) + b"\n")
        finally:
            os.close(fd)
        os.chmod(out, 0o600)
        print(ed25519.public_key(seed).hex())
        return 0
    except sc.SupportCodeError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
