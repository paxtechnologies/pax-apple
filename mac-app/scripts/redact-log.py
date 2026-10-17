#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hide the signing certificate's name in a CI log (v0.8.15).

The Build DMG workflow publishes build.log to the public ci-logs branch. codesign,
spctl and the build script print the certificate's common name ("Developer ID
Application: <name> (<team ID>)"). The signature itself is unchanged; only the
log shows "[signing identity]" instead of the name. The team ID stays (it is in
every signed binary anyway and pax-guard pins it).

  redact-log.py IN OUT          (or "-" for stdin/stdout)

The name is also read from $PAX_SIGNER_NAME_FILE when set (written by the
workflow's signing step), so any other line that prints it is covered too.
"""
from __future__ import annotations

import os
import re
import sys

MASK = "[signing identity]"
# "Developer ID Application: Some Name (ABCDE12345)" and the Installer/Apple
# Development/Distribution variants; the name runs up to "(", a quote or the line end.
IDENTITY = re.compile(r"((?:Developer ID (?:Application|Installer)|Apple (?:Development|Distribution)|"
                      r"3rd Party Mac Developer (?:Application|Installer)):[ \t]*)"
                      r"[^\"'()\n]*?(?=[ \t]*\(|[\"'\n]|$)", re.M)


def redact(text: str, names: list[str] | None = None) -> str:
    out = IDENTITY.sub(lambda m: m.group(1) + MASK, text)
    for n in names or []:
        n = n.strip()
        if len(n) >= 3:
            out = re.sub(re.escape(n), MASK, out, flags=re.I)
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = argv[1], argv[2]
    text = sys.stdin.read() if src == "-" else open(src, encoding="utf-8", errors="replace").read()
    names = []
    f = os.environ.get("PAX_SIGNER_NAME_FILE")
    if f and os.path.isfile(f):
        names = [open(f, encoding="utf-8").read()]
    out = redact(text, names)
    if dst == "-":
        sys.stdout.write(out)
    else:
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
