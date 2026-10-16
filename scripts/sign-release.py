#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Sign Pax releases (v0.8.0). Standard library only (Ed25519 from guard/ed25519.py).

pax-guard installs an update only from a pax-update.json signed by a key pinned
in guard/pax_signing.py (and PaxCore/Updates.swift). This script writes that
file. The private key is the 32-byte Ed25519 seed, base64 (or hex), kept in the
GitHub Actions secret PAX_UPDATE_SIGNING_KEY; it is read from an environment
variable or a file and never printed. See docs/UPDATES.md.

  sign-release.py keygen --out KEYFILE
      new seed into KEYFILE (mode 0600, refuses to overwrite); prints only the
      public key (hex) to pin.
  sign-release.py sign --zip dist/Pax-0.8.0.zip --version 0.8.0 \\
      [--minimum-version 0.8.0] [--url URL] [--mirror URL ...] [--notes TEXT] \\
      [--key-env PAX_UPDATE_SIGNING_KEY | --key-file KEYFILE] --out pax-update.json
      the signed manifest: schema pax.update.v1, version, minimum_version, url,
      mirrors, sha256, size, published_at. --url defaults to this release's
      asset on GitHub.
      v0.8.6: --parts-dir DIR --part-base URL [--part-base URL ...] [--part-size N]
      also splits the zip into DIR/<zip>.part-000, -001 ... (each at most N bytes,
      default 15 MiB, under jsDelivr's 20 MB per-file limit) and adds them to the
      signed payload as "parts": each part's name, size and SHA-256 and the base
      URLs to fetch them from. The zip's own sha256/size stay in the payload, so the
      updater checks the joined parts against the same signed hash. Every field of
      pax.update.v1 is unchanged, so 0.8.4/0.8.5 pax-guard (whole zip from GitHub) and
      the server self-updater (reads "version") read it as before.
  sign-release.py split --zip ZIP --out DIR [--part-size N]
      just the split (prints the parts as JSON).
  sign-release.py verify FILE [--zip ZIP] [--parts-dir DIR]
      checks the signature against the pinned keys (and the zip's hash/size, and
      that the parts in DIR join into exactly that zip).
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "guard"))
import ed25519  # noqa: E402
import pax_signing  # noqa: E402

REPO_SLUG = "paxtechnologies/pax-apple"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
MAX_ZIP = 400 * 1024 * 1024
PART_SIZE = 15 * 1024 * 1024          # jsDelivr refuses GitHub files over 20 MB
MAX_PART = 20 * 1000 * 1000           # same bound as guard/pax_update.py


def read_seed(key_env: str | None, key_file: str | None) -> bytes:
    if key_file:
        text = Path(key_file).read_text()
    else:
        text = os.environ.get(key_env or "PAX_UPDATE_SIGNING_KEY", "")
    if not text.strip():
        raise SystemExit("no signing key: set PAX_UPDATE_SIGNING_KEY (or --key-file); refusing to write "
                         "an unsigned manifest")
    try:
        return pax_signing.seed_from_text(text)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def split_zip(zip_path: Path, out_dir: Path, part_size: int = PART_SIZE) -> list[dict]:
    """Write <zip>.part-NNN files into out_dir; returns [{"name", "size", "sha256"}]."""
    if not 0 < part_size <= MAX_PART:
        raise SystemExit(f"--part-size must be 1..{MAX_PART}")
    out_dir.mkdir(parents=True, exist_ok=True)
    parts = []
    with zip_path.open("rb") as f:
        for i, chunk in enumerate(iter(lambda: f.read(part_size), b"")):
            name = f"{zip_path.name}.part-{i:03d}"
            (out_dir / name).write_bytes(chunk)
            parts.append({"name": name, "size": len(chunk), "sha256": hashlib.sha256(chunk).hexdigest()})
    if not parts:
        raise SystemExit(f"{zip_path} is empty")
    return parts


def build_payload(zip_path: Path, version: str, minimum: str, url: str | None,
                  mirrors: list[str], notes: str | None, parts: list[dict] | None = None,
                  part_bases: list[str] | None = None) -> dict:
    for v in (version, minimum):
        if not VERSION_RE.match(v):
            raise SystemExit(f"bad version {v!r}: use 1.2.3")
    if tuple(map(int, minimum.split("."))) > tuple(map(int, version.split("."))):
        raise SystemExit("--minimum-version is above --version")
    size = zip_path.stat().st_size
    if not 0 < size <= MAX_ZIP:
        raise SystemExit(f"{zip_path} is {size} bytes")
    url = url or f"https://github.com/{REPO_SLUG}/releases/download/v{version}/{zip_path.name}"
    for u in [url, *mirrors]:
        if not u.startswith("https://"):
            raise SystemExit(f"download URLs must be https:// ({u})")
    payload = {
        "schema": "pax.update.v1",
        "version": version,
        "minimum_version": minimum,
        "url": url,
        "mirrors": mirrors,
        "sha256": sha256_file(zip_path),
        "size": size,
        "published_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    if notes:
        payload["notes"] = notes
    if parts:
        bases = list(part_bases or [])
        if not bases or not all(b.startswith("https://") and b.endswith("/") for b in bases):
            raise SystemExit("--part-base URLs must be https:// and end with /")
        if sum(p["size"] for p in parts) != size:
            raise SystemExit("the parts don't add up to the zip")
        payload["parts"] = {"base_urls": bases, "files": parts}
    return payload


def cmd_keygen(out: Path) -> int:
    if out.exists():
        raise SystemExit(f"{out} exists: refusing to overwrite a signing key")
    seed = os.urandom(32)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(seed).decode() + "\n")
    print(ed25519.public_key(seed).hex())
    return 0


def cmd_sign(a) -> int:
    seed = read_seed(a.key_env, a.key_file)
    pub = ed25519.public_key(seed)
    if pub not in pax_signing.pinned_keys():
        raise SystemExit("this signing key's public key isn't pinned in guard/pax_signing.py: pax-guard "
                         "would refuse the release")
    parts = split_zip(Path(a.zip), Path(a.parts_dir), a.part_size) if a.parts_dir else None
    payload = build_payload(Path(a.zip), a.version, a.minimum_version or a.version, a.url, a.mirror or [],
                            a.notes, parts, a.part_base)
    doc = pax_signing.sign_document(payload, seed)
    pax_signing.verify_document(doc)                  # belt and braces
    Path(a.out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {a.out}: {payload['version']} sha256 {payload['sha256']} key {doc['key_id']}")
    return 0


def cmd_verify(path: Path, zip_path: Path | None, parts_dir: Path | None = None) -> int:
    doc = json.loads(path.read_text())
    try:
        payload = pax_signing.verify_document(doc)
    except pax_signing.SignatureError as exc:
        print(f"REJECTED: {exc}")
        return 1
    if zip_path is not None:
        if sha256_file(zip_path) != payload.get("sha256") or zip_path.stat().st_size != payload.get("size"):
            print("REJECTED: the zip doesn't match the manifest")
            return 1
    if parts_dir is not None:
        h, n = hashlib.sha256(), 0
        for p in (payload.get("parts") or {}).get("files") or []:
            data = (parts_dir / p["name"]).read_bytes()
            if len(data) != p["size"] or hashlib.sha256(data).hexdigest() != p["sha256"] or len(data) > MAX_PART:
                print(f"REJECTED: part {p['name']} doesn't match the manifest")
                return 1
            h.update(data)
            n += len(data)
        if not payload.get("parts") or n != payload.get("size") or h.hexdigest() != payload.get("sha256"):
            print("REJECTED: the parts don't join into the signed zip")
            return 1
    print(f"OK: {payload.get('schema')} {payload.get('version')} signed by {doc.get('key_id')}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("sign")
    s.add_argument("--zip", required=True)
    s.add_argument("--version", required=True)
    s.add_argument("--minimum-version")
    s.add_argument("--url")
    s.add_argument("--mirror", action="append")
    s.add_argument("--notes")
    s.add_argument("--parts-dir")
    s.add_argument("--part-base", action="append")
    s.add_argument("--part-size", type=int, default=PART_SIZE)
    sp = sub.add_parser("split")
    sp.add_argument("--zip", required=True)
    sp.add_argument("--out", required=True)
    sp.add_argument("--part-size", type=int, default=PART_SIZE)
    s.add_argument("--key-env", default="PAX_UPDATE_SIGNING_KEY")
    s.add_argument("--key-file")
    s.add_argument("--out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("file", type=Path)
    v.add_argument("--zip", type=Path)
    v.add_argument("--parts-dir", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "keygen":
        return cmd_keygen(a.out)
    if a.cmd == "sign":
        return cmd_sign(a)
    if a.cmd == "split":
        print(json.dumps(split_zip(Path(a.zip), Path(a.out), a.part_size), indent=1))
        return 0
    return cmd_verify(a.file, a.zip, a.parts_dir)


if __name__ == "__main__":
    sys.exit(main())
