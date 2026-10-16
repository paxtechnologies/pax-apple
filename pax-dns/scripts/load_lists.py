#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build pax-dns's category list from HaGeZi / OISD (and local additions).

  python3 scripts/load_lists.py --out /var/lib/pax/category.txt            # default sources
  python3 scripts/load_lists.py --source hagezi-restricted --source hagezi-doh-vpn --out list.txt
  python3 scripts/load_lists.py --from-file my-saved-copy.txt --out list.txt   # offline

Writes atomically (temp file + rename), so a running pax-dns (PAX_DNS_CATEGORY_FILE)
reloads it on its next poll. Refuses to write when a download comes back too small
(--min-entries), so a failed fetch never empties the filter. Run daily (cron /
systemd timer); both projects publish several times a day.

Licences: HaGeZi's lists are GPL-3.0; OISD's are GPL-3.0. Pax downloads them at run
time and does not redistribute them (see THIRD_PARTY_NOTICES.md).
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pax_dns.lists import _restricted_module, compact, parse_lines  # noqa: E402

_pr = _restricted_module()   # common/pax_restricted.py: the restricted sources' addresses, encoded

# Checked 2026-10-12: all three return a "# Title:" header and domain-per-line
# bodies where every entry covers its subdomains.
SOURCES = {
    "hagezi-restricted": _pr.source("list_a_url"),
    "oisd-restricted": _pr.source("list_b_url"),
    # DoH/VPN/Tor/proxy bypass endpoints (roadmap: stop apps routing round the resolver).
    "hagezi-doh-vpn": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
}
# v0.5: the bypass list is on by default (seeds the "bypass" category; Pax's own
# curated cloud-PC/remote-desktop lists are separate built-in categories in
# pax_dns/lists.py). Checked 2026-10-14: 15,548 entries, GPL-3.0.
DEFAULT_SOURCES = ["hagezi-restricted", "oisd-restricted", "hagezi-doh-vpn"]
# Names Pax itself needs. A list entry equal to one of these, or a parent of one
# (HaGeZi's bypass list has "cleanbrowsing.org", which would cover
# doh.cleanbrowsing.org), is dropped: blocking them would cut Pax off.
PROTECTED = ["doh.cleanbrowsing.org", "family-filter-dns.cleanbrowsing.org",
             _pr.source("cb_core_host"), "dns.paxmobile.org", "paxmobile.org",
             "api.paxmobile.org"]
ADDITIONS = Path(__file__).resolve().parents[1] / "lists" / "pax-additions.txt"


def fetch(url: str, timeout: float = 60) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "pax-dns-list-loader/0.3"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URLs)
        return resp.read().decode("utf-8", errors="replace").splitlines()


def drop_protected(domains: set[str], protected: list[str] = PROTECTED) -> set[str]:
    """Remove entries that would block a protected name (same name or a parent)."""
    bad = set()
    for p in protected:
        labels = p.split(".")
        bad |= {".".join(labels[i:]) for i in range(len(labels) - 1)}
    return {d for d in domains if d not in bad}


def build(sources: list[str], files: list[Path], min_entries: int, fetcher=fetch,
          additions: Path | None = ADDITIONS) -> tuple[set[str], dict[str, int]]:
    merged: set[str] = set()
    counts: dict[str, int] = {}
    for name in sources:
        if name not in SOURCES:
            raise SystemExit(f"unknown source {name!r}; choose from {', '.join(SOURCES)}")
        got = parse_lines(fetcher(SOURCES[name]))
        if len(got) < min_entries:
            raise SystemExit(f"{name}: only {len(got)} entries (< {min_entries}); not writing")
        counts[name] = len(got)
        merged |= got
    for f in files:
        got = parse_lines(f.read_text(encoding="utf-8", errors="replace").splitlines())
        counts[str(f)] = len(got)
        merged |= got
    if additions and additions.exists():
        got = parse_lines(additions.read_text(encoding="utf-8").splitlines())
        counts["pax-additions"] = len(got)
        merged |= got
    return compact(drop_protected(merged)), counts


def write_atomic(path: Path, domains: set[str], header: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".category-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(header)
            for d in sorted(domains):
                fh.write(d + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--source", action="append", choices=sorted(SOURCES),
                    help=f"list to download (repeatable; default {' + '.join(DEFAULT_SOURCES)})")
    ap.add_argument("--from-file", action="append", type=Path, default=[],
                    help="also merge a local list file (any supported format)")
    ap.add_argument("--no-download", action="store_true", help="use only --from-file inputs")
    ap.add_argument("--min-entries", type=int, default=10000,
                    help="refuse to write if any downloaded list has fewer entries")
    args = ap.parse_args(argv)
    sources = [] if args.no_download else (args.source or DEFAULT_SOURCES)
    domains, counts = build(sources, args.from_file, args.min_entries)
    if not domains:
        raise SystemExit("no entries; not writing")
    header = "# pax-dns category list\n" + "".join(f"# {k}: {v}\n" for k, v in counts.items())
    write_atomic(args.out, domains, header)
    print(f"wrote {len(domains)} domains to {args.out} ({counts})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
