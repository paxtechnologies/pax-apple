#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build Pax Image Blur for Chrome (MV3, unpacked dir + Web Store zip) and
Firefox (MV3, unsigned .xpi). Standard library only, so build-dmg.sh can run it
with the Command Line Tools' /usr/bin/python3 (no Node needed).

  python3 build.py                 # -> dist/chrome/, dist/pax-image-blur-chrome.zip,
                                   #    dist/firefox/, dist/pax-image-blur.xpi
  python3 build.py pack FILE DEST  # gzip + split FILE into src/DEST.gz.part-NNN

Large binaries (the TensorFlow.js bundle and the model weights) are stored in
src/ gzipped and split into parts under 85 KB, so every file in the repo stays
under ~90 KB. `build` re-joins `X.gz.part-NNN` (or `X.gz`) into `X`, and checks
each against src/SHA256SUMS.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
DIST = HERE / "dist"
PART_SIZE = 85_000
PART_RE = re.compile(r"^(?P<base>.+)\.part-(?P<n>\d{3})$")
SUMS = SRC / "SHA256SUMS"
# Chrome-only and Firefox-only files.
CHROME_ONLY = {"offscreen.html", "offscreen.js"}
FIREFOX_ONLY: set[str] = set()
FIXED_TIME = (2026, 10, 14, 0, 0, 0)   # reproducible zips


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_sums() -> dict[str, str]:
    out = {}
    if SUMS.exists():
        for line in SUMS.read_text().splitlines():
            if line.strip():
                digest, name = line.split(None, 1)
                out[name.strip()] = digest
    return out


def assembled_files() -> dict[str, bytes]:
    """{relative path in the extension: bytes}, with parts joined and .gz opened."""
    parts: dict[str, list[tuple[int, Path]]] = {}
    files: dict[str, bytes] = {}
    for p in sorted(SRC.rglob("*")):
        if p.is_dir() or p.name == "SHA256SUMS" or p.name.startswith("manifest."):
            continue
        rel = p.relative_to(SRC).as_posix()
        m = PART_RE.match(rel)
        if m:
            parts.setdefault(m.group("base"), []).append((int(m.group("n")), p))
        else:
            files[rel] = p.read_bytes()
    for base, items in parts.items():
        items.sort()
        if [n for n, _ in items] != list(range(len(items))):
            raise SystemExit(f"missing part of {base}")
        files[base] = b"".join(p.read_bytes() for _, p in items)
    for rel in [r for r in files if r.endswith(".gz")]:
        files[rel[:-3]] = gzip.decompress(files.pop(rel))
    sums = read_sums()
    for name, digest in sums.items():
        if name not in files:
            raise SystemExit(f"{name} listed in SHA256SUMS but not found")
        if sha256(files[name]) != digest:
            raise SystemExit(f"{name}: SHA-256 mismatch")
    return files


def manifest(browser: str) -> dict:
    return json.loads((SRC / f"manifest.{browser}.json").read_text())


def _zip(path: Path, files: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, files[name])


def build(out: Path = DIST) -> dict[str, Path]:
    files = assembled_files()
    results = {}
    for browser, skip, unpacked, archive in (
            ("chrome", FIREFOX_ONLY, out / "chrome", out / "pax-image-blur-chrome.zip"),
            ("firefox", CHROME_ONLY, out / "firefox", out / "pax-image-blur.xpi")):
        mf = manifest(browser)
        chosen = {k: v for k, v in files.items() if k.split("/")[-1] not in skip}
        chosen["manifest.json"] = (json.dumps(mf, indent=2) + "\n").encode()
        if unpacked.exists():
            shutil.rmtree(unpacked)
        for name, data in chosen.items():
            dest = unpacked / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        _zip(archive, chosen)
        results[browser] = archive
    return results


def pack(src_file: Path, dest_rel: str) -> list[Path]:
    """gzip + split a large file into src/<dest_rel>.gz.part-NNN and record its hash."""
    data = src_file.read_bytes()
    gz = gzip.compress(data, compresslevel=9, mtime=0)
    target = SRC / dest_rel
    target.parent.mkdir(parents=True, exist_ok=True)
    for old in target.parent.glob(target.name + ".gz.part-*"):
        old.unlink()
    out = []
    for i in range(0, len(gz), PART_SIZE):
        p = target.parent / f"{target.name}.gz.part-{i // PART_SIZE:03d}"
        p.write_bytes(gz[i:i + PART_SIZE])
        out.append(p)
    sums = read_sums()
    sums[dest_rel] = sha256(data)
    SUMS.write_text("".join(f"{d}  {n}\n" for n, d in sorted(sums.items())))
    return out


def main(argv: list[str]) -> int:
    if argv[:1] == ["pack"] and len(argv) == 3:
        parts = pack(Path(argv[1]), argv[2])
        print(f"packed {argv[1]} into {len(parts)} parts")
        return 0
    if argv:
        print(__doc__)
        return 2
    for browser, path in build().items():
        print(f"{browser}: {path} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
