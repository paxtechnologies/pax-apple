#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build Pax's local filter lists (v0.8.1), reproducibly. Standard library only.

The v2 DNS test's build (passed 2026-10-15) moved into the repo, with the maintainer's
v0.8 changes. Since v0.8.1 the restricted-content sources and the DoH/VPN/proxy
source are separate lists, because an exception may free a VPN/proxy false
positive but never a restricted-content site:

  pax-block    restricted content: HaGeZi and OISD restricted-content lists +
               the UT1 restricted-content category (blogspot.* dropped) + Pax's
               hand list (common/pax_restricted.py) + pax-zones.txt, minus
               pax-exclude.txt (exact names), minus pax-allowlist.txt (suffix),
               parent-collapsed. Single-label entries (whole top-level domains)
               are kept and honoured by the matcher. Never freed by an exception.
  pax-bypass   HaGeZi "Encrypted DNS/VPN/TOR/Proxy Bypass", minus anything
               pax-block already covers. An exception can free an entry.
  pax-nrd      newly registered domains (WhoisDS free daily lists, rolling 14
               days) whose first label matches the name rule at a label edge
               (start, end, or next to "-" or a digit), minus its allow words.
               Restricted. Separate list, updated daily, never required.
  pax-allow    pax-allowlist.txt (wins over every block list, suffix match).
  safesearch   safesearch_rules.csv (385 exact-host rewrites, YouTube Strict).

The source addresses and the name-rule words are kept encoded in
common/pax_restricted.py (the repo is kept free of words that would read badly
for someone in recovery); this script decodes them at run time.

Commands:
  build.py block  --out DIR [--sources DIR]   # pax-block.txt.gz + pax-bypass.txt.gz
  build.py nrd    --out DIR [--days 14] [--raw DIR] [--today YYYY-MM-DD]
  build.py static --out DIR                   # pax-allowlist.txt + safesearch_rules.csv
  build.py manifest --out DIR [--sign-key-env PAX_UPDATE_SIGNING_KEY]
  build.py bundle --from DIR --to ../guard/filters   # split into <85 KB parts for the repo

`--sources` takes a directory with already-downloaded copies (the local file
names are in common/pax_restricted.py, `sources`; the DoH/VPN list is
hagezi_doh_vpn.txt). gzip output has mtime 0, so the same inputs give the same
bytes (and the same SHA-256).
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "guard"))
sys.path.insert(0, str(REPO / "common"))
import pax_restricted as pr  # noqa: E402

SOURCES = {
    # id: (url, license, local file name under --sources). The restricted-content
    # sources' addresses are decoded from common/pax_restricted.py.
    "list_a": (pr.source("list_a_url"), "GPL-3.0", pr.source("list_a_local")),
    "list_b": (pr.source("list_b_url"), "GPL-3.0", pr.source("list_b_local")),
    "hagezi_doh_vpn": ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
                       "doh-vpn-proxy-bypass-onlydomains.txt", "GPL-3.0", "hagezi_doh_vpn.txt"),
    "list_c": (pr.source("list_c_url"), "CC-BY-SA-4.0", pr.source("list_c_local")),
}
RESTRICTED_SOURCES = ("list_a", "list_b")
WHOISDS_URL = "https://www.whoisds.com/whois-database/newly-registered-domains/{b64}/nrd"
BLOGSPOT = re.compile(r"(^|\.)blogspot\.[a-z.]+$")
LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")

# Sanity floors the guard also enforces before swapping a list in.
LIST_RULES = {
    "pax-block": {"file": "pax-block.txt.gz", "kind": "block", "format": "domains", "restricted": True,
                  "min_entries": 1_000_000, "max_drop": 0.10},
    "pax-bypass": {"file": "pax-bypass.txt.gz", "kind": "block", "format": "domains", "restricted": False,
                   "min_entries": 5_000, "max_drop": 0.30},
    "pax-nrd": {"file": "pax-nrd.txt.gz", "kind": "block", "format": "domains", "restricted": True,
                "min_entries": 100, "max_drop": 0.60, "optional": True},
    "pax-allow": {"file": "pax-allowlist.txt", "kind": "allow", "format": "domains",
                  "min_entries": 1, "max_drop": 1.0},
    "safesearch": {"file": "safesearch_rules.csv", "kind": "safesearch", "format": "csv",
                   "min_entries": 300, "max_drop": 0.10},
}
PART_SIZE = 85_000
# jsDelivr (the mirror) serves GitHub files up to 20 MB; pax-guard refuses bigger.
MAX_LIST_BYTES = 20 * 1024 * 1024


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def fetch(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "pax-lists-build/0.8"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed URLs)
        return r.read()


def clean_name(raw: str) -> str | None:
    line = raw.strip()
    if not line or line[0] in "#!;":
        return None
    parts = line.split()
    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
        line = parts[1]
    elif len(parts) != 1:
        return None
    name = line.lstrip("*.").rstrip(".").lower()
    if not name or len(name) > 253:
        return None
    labels = name.split(".")
    if not all(LABEL_RE.match(lab) for lab in labels):
        return None
    if all(lab.isdigit() for lab in labels):   # an IP address, not a name
        return None
    return name


def parse_names(text: str, allow_single_label: bool = True) -> set[str]:
    out = set()
    for raw in text.splitlines():
        n = clean_name(raw)
        if n and (allow_single_label or "." in n):
            out.add(n)
    return out


def read_local_list(name: str) -> list[str]:
    return [n for n in (clean_name(l) for l in (HERE / name).read_text().splitlines()) if n]


def hand_list() -> list[str]:
    """Pax's hand-kept restricted list (encoded in common/pax_restricted.py)."""
    return [n for n in (clean_name(l) for l in pr.hand_list()) if n]


def source_text(sid: str, sources_dir: Path | None) -> str:
    url, _lic, local = SOURCES[sid]
    if sources_dir and (sources_dir / local).is_file():
        log(f"{sid}: using {sources_dir / local}")
        return (sources_dir / local).read_text(errors="ignore")
    log(f"{sid}: downloading {url}")
    data = fetch(url)
    if sid == "list_c":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            member = next(m for m in tf.getmembers() if m.name.endswith("/domains") or m.name == "domains")
            return tf.extractfile(member).read().decode("utf-8", "ignore")
    return data.decode("utf-8", "ignore")


def covered_by_parent(name: str, s: set[str]) -> bool:
    labels = name.split(".")
    return any(".".join(labels[i:]) in s for i in range(1, len(labels)))


def allowed(name: str, allow: set[str]) -> bool:
    labels = name.split(".")
    return any(".".join(labels[i:]) in allow for i in range(len(labels)))


def finalize(block: set[str], exclude: set[str], allow: set[str]) -> list[str]:
    """Exclusions (exact) and allowlist (suffix) out, then parent-collapse."""
    block = {d for d in block if d not in exclude and not allowed(d, allow)}
    return sorted(d for d in block if not covered_by_parent(d, block))


def build_block(sources_dir: Path | None) -> tuple[list[str], list[str], dict]:
    """(pax-block, pax-bypass, stats)."""
    stats: dict = {}
    union: set[str] = set()
    for sid in RESTRICTED_SOURCES:
        names = parse_names(source_text(sid, sources_dir))
        stats[sid] = len(names)
        union |= names
    third = parse_names(source_text("list_c", sources_dir))
    raw_third = len(third)
    third = {d for d in third if not BLOGSPOT.search(d)}
    stats["list_c"] = {"raw": raw_third, "without_blogspot": len(third)}
    union |= third
    hand, zones = hand_list(), read_local_list("pax-zones.txt")
    union |= set(hand) | set(zones)
    exclude, allow = set(read_local_list("pax-exclude.txt")), set(read_local_list("pax-allowlist.txt"))
    final = finalize(union, exclude, allow)
    restricted = set(final)
    bypass_raw = parse_names(source_text("hagezi_doh_vpn", sources_dir))
    stats["hagezi_doh_vpn"] = len(bypass_raw)
    bypass = [d for d in finalize(bypass_raw, exclude, allow)
              if d not in restricted and not covered_by_parent(d, restricted)]
    stats.update({"hand_list": len(hand), "pax_zones": len(zones), "union": len(union),
                  "excluded": sorted(exclude & union), "final": len(final), "bypass": len(bypass),
                  "single_label": len([d for d in final if "." not in d])})
    return final, bypass, stats


# ------------------------------------------------------------------ NRD rule
def nrd_rule():
    """The name rule (common/pax_restricted.py): first label, at a label edge."""
    rule = pr.name_rule()
    return rule.label_hit


def nrd_day(day: dt.date, raw_dir: Path | None) -> list[str] | None:
    name = f"{day.isoformat()}.txt"
    if raw_dir and (raw_dir / name).is_file():
        return (raw_dir / name).read_text().split()
    b64 = base64.b64encode(f"{day.isoformat()}.zip".encode()).decode()
    try:
        data = fetch(WHOISDS_URL.format(b64=b64), timeout=60)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            text = z.read(z.namelist()[0]).decode("utf-8", "ignore")
    except Exception as exc:  # noqa: BLE001 - a missing day is skipped
        log(f"nrd {day}: skipped ({type(exc).__name__})")
        return None
    if raw_dir:
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / name).write_text(text)
    return text.split()


def build_nrd(days: int, raw_dir: Path | None, today: dt.date) -> tuple[list[str], dict]:
    hit = nrd_rule()
    allow = set(read_local_list("pax-allowlist.txt"))
    out: set[str] = set()
    got = 0
    for i in range(1, days + 1):
        names = nrd_day(today - dt.timedelta(days=i), raw_dir)
        if names is None:
            continue
        got += 1
        for d in names:
            d = d.strip().lower().rstrip(".")
            if "." in d and hit(d.split(".")[0]) and not allowed(d, allow):
                out.add(d)
    return sorted(out), {"days_requested": days, "days_found": got, "entries": len(out)}


# ------------------------------------------------------------------- writing
def write_gz(path: Path, lines: list[str], header: str) -> None:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0) as gz:
        gz.write(header.encode())
        gz.write(("\n".join(lines) + "\n").encode())
    path.write_bytes(buf.getvalue())


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def count_entries(lid: str, path: Path) -> int:
    data = path.read_bytes()
    if path.suffix == ".gz":
        data = gzip.decompress(data)
    text = data.decode("utf-8", "ignore")
    if LIST_RULES[lid]["format"] == "csv":
        return max(0, sum(1 for l in text.splitlines() if l.strip()) - 1)
    return len(parse_names(text))


def manifest(out: Path, version: str | None = None) -> dict:
    lists = {}
    for lid, rule in LIST_RULES.items():
        p = out / rule["file"]
        if not p.is_file():
            if rule.get("optional"):
                continue
            raise SystemExit(f"missing {p}")
        if p.stat().st_size >= MAX_LIST_BYTES:
            raise SystemExit(f"{p.name} is {p.stat().st_size} bytes: list files must stay under 20 MB "
                             "for the jsDelivr mirror (split the list or trim it)")
        lists[lid] = dict(rule, sha256=sha256(p), bytes=p.stat().st_size, entries=count_entries(lid, p))
    return {"schema": "pax.lists.v1",
            "version": version or dt.datetime.now(dt.timezone.utc).strftime("%Y.%m%d.%H%M"),
            "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "lists": lists}


def cmd_bundle(src: Path, dst: Path) -> None:
    """Copy a built set into guard/filters: files over PART_SIZE are split into
    name.part-000, -001, ... (the repo is pushed with the contents API, which
    needs every file under ~90 KB); pax-guard reassembles and checks SHA-256."""
    dst.mkdir(parents=True, exist_ok=True)
    for old in dst.iterdir():
        if old.is_file():
            old.unlink()
    man = json.loads((src / "lists-manifest.json").read_text())
    payload = man.get("payload", man)
    for lid, item in payload["lists"].items():
        data = (src / item["file"]).read_bytes()
        if len(data) <= PART_SIZE:
            (dst / item["file"]).write_bytes(data)
        else:
            for i in range(0, len(data), PART_SIZE):
                (dst / f"{item['file']}.part-{i // PART_SIZE:03d}").write_bytes(data[i:i + PART_SIZE])
    (dst / "filters.json").write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n")
    log(f"bundled into {dst}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("block")
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--sources", type=Path)
    n = sub.add_parser("nrd")
    n.add_argument("--out", type=Path, required=True)
    n.add_argument("--days", type=int, default=14)
    n.add_argument("--raw", type=Path)
    n.add_argument("--today", default=None)
    s = sub.add_parser("static")
    s.add_argument("--out", type=Path, required=True)
    m = sub.add_parser("manifest")
    m.add_argument("--out", type=Path, required=True)
    m.add_argument("--sign-key-env", default=None,
                   help="sign with the base64 Ed25519 seed in this environment variable")
    m.add_argument("--version", default=None)
    bu = sub.add_parser("bundle")
    bu.add_argument("--from", dest="src", type=Path, required=True)
    bu.add_argument("--to", dest="dst", type=Path, default=REPO / "guard" / "filters")
    a = ap.parse_args(argv)

    if a.cmd == "block":
        a.out.mkdir(parents=True, exist_ok=True)
        final, bypass, stats = build_block(a.sources)
        header = ("# Pax restricted-content list (suffix match: each entry blocks itself and every subdomain).\n"
                  "# HaGeZi and OISD (GPL-3.0), UT1 (CC BY-SA 4.0, Universite Toulouse Capitole) and\n"
                  "# Pax's own hand list and zones; minus pax-exclude and pax-allowlist. Built by lists/build.py.\n")
        write_gz(a.out / "pax-block.txt.gz", final, header)
        write_gz(a.out / "pax-bypass.txt.gz", bypass,
                 "# Pax DoH/VPN/proxy bypass list: HaGeZi Encrypted DNS/VPN/TOR/Proxy Bypass (GPL-3.0),\n"
                 "# minus anything pax-block covers. Suffix match. Built by lists/build.py.\n")
        (a.out / "block-stats.json").write_text(json.dumps(stats, indent=1) + "\n")
        log(json.dumps({k: v for k, v in stats.items() if k != "excluded"}))
    elif a.cmd == "nrd":
        a.out.mkdir(parents=True, exist_ok=True)
        today = dt.date.fromisoformat(a.today) if a.today else dt.datetime.now(dt.timezone.utc).date()
        names, stats = build_nrd(a.days, a.raw, today)
        header = (f"# Pax new-registration list: domains registered in the {a.days} days before {today}\n"
                  "# (WhoisDS free daily lists) whose name matches the name rule at a label edge.\n")
        write_gz(a.out / "pax-nrd.txt.gz", names, header)
        log(json.dumps(stats))
    elif a.cmd == "static":
        a.out.mkdir(parents=True, exist_ok=True)
        for f in ("pax-allowlist.txt", "safesearch_rules.csv"):
            (a.out / f).write_bytes((HERE / f).read_bytes())
    elif a.cmd == "manifest":
        payload = manifest(a.out, a.version)
        doc: dict = {"payload": payload}
        if a.sign_key_env:
            import pax_signing  # guard/pax_signing.py
            seed = os.environ.get(a.sign_key_env, "")
            if not seed:
                raise SystemExit(f"{a.sign_key_env} is empty: refusing to write an unsigned manifest")
            doc = pax_signing.sign_document(payload, pax_signing.seed_from_text(seed))
        (a.out / "lists-manifest.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        log(f"wrote {a.out / 'lists-manifest.json'}")
    elif a.cmd == "bundle":
        cmd_bundle(a.src, a.dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
