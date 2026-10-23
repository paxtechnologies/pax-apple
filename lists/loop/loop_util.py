# SPDX-License-Identifier: GPL-3.0-only
"""Shared helpers for Pax's nightly filter workflow (lists/loop). Standard library only."""
from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import io
import json
import sys
import threading
import time
import urllib.request
from pathlib import Path

LOOP = Path(__file__).resolve().parent
LISTS = LOOP.parent
REPO = LISTS.parent
GUARD = REPO / "guard"
COMMON = REPO / "common"
GATES = LISTS / "gates"
for p in (str(GUARD), str(COMMON), str(LISTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

UA = "pax-filter-loop/1.0 (+https://github.com/paxtechnologies/pax-apple)"


def log(msg: str) -> None:
    print(f"[{dt.datetime.now(dt.timezone.utc):%H:%M:%S}] {msg}", file=sys.stderr, flush=True)


class RateLimiter:
    """At most `qps` starts per second across threads (polite to every server)."""

    def __init__(self, qps: float):
        self.gap = 1.0 / max(0.1, qps)
        self.next = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            at = max(now, self.next)
            self.next = at + self.gap
        if at > now:
            time.sleep(at - now)


class Budget:
    """A hard cap on queries to one server."""

    def __init__(self, limit: int):
        self.limit, self.used = limit, 0
        self.lock = threading.Lock()

    def take(self) -> bool:
        with self.lock:
            if self.used >= self.limit:
                return False
            self.used += 1
            return True


UT1_HTTP = "https://dsi.ut-capitole.fr/blacklists/download/"
UT1_MIRROR = "ftp://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/"


def fetch(url: str, timeout: int = 180, limit: int | None = None) -> bytes:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed URLs)
            return r.read(limit) if limit else r.read()
    except Exception:  # noqa: BLE001 - 2026-10-23: UT1's web site is down; its FTP mirror has the same files
        if not url.startswith(UT1_HTTP):
            raise
        with urllib.request.urlopen(UT1_MIRROR + url[len(UT1_HTTP):], timeout=timeout) as r:  # noqa: S310
            return r.read(limit) if limit else r.read()


def gz_bytes(lines, header: str = "") -> bytes:
    """Reproducible gzip (mtime 0, no file name), like lists/build.py."""
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0) as gz:
        gz.write(header.encode())
        gz.write(("\n".join(lines) + "\n").encode())
    return buf.getvalue()


def gz_names(data: bytes) -> list[str]:
    text = gzip.decompress(data).decode("utf-8", "ignore") if data[:2] == b"\x1f\x8b" else data.decode()
    return [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def name_hash(name: str) -> str:
    return hashlib.sha1(name.encode()).hexdigest()[:12]


def encode_names(names) -> str:
    """Names for the public scoreboard, kept out of plain text (gzip + base64), the
    same way common/pax_restricted.py keeps its data."""
    raw = gzip.compress(json.dumps(sorted(names), separators=(",", ":")).encode(), 9, mtime=0)
    return base64.b64encode(raw).decode()


def decode_names(blob: str) -> list[str]:
    return json.loads(gzip.decompress(base64.b64decode(blob)).decode())


def load_json(path: Path, default):
    try:
        data = path.read_bytes()
        if path.suffix == ".gz":
            data = gzip.decompress(data)
        return json.loads(data)
    except (OSError, ValueError):
        return default


def save_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    if path.suffix == ".gz":
        data = gzip.compress(data, 9, mtime=0)
    path.write_bytes(data)


def today() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")


def days_since(yyyymmdd: str) -> int:
    try:
        d = dt.datetime.strptime(str(yyyymmdd), "%Y%m%d").date()
    except ValueError:
        return 10 ** 6
    return (dt.datetime.now(dt.timezone.utc).date() - d).days


def gate_names(name: str) -> list[str]:
    """A list in lists/gates/ (one name per line, # comments)."""
    return [l.strip().lower() for l in (GATES / name).read_text().splitlines()
            if l.strip() and not l.startswith("#")]
