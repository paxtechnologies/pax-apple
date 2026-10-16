# SPDX-License-Identifier: GPL-3.0-only
"""Memory-conscious suffix matcher for ~1.4 million blocked domains (v0.8.0).

A Python set of 1.4M strings costs ~150 MB. pax-guard instead keeps one sorted,
front-coded byte table (like an SSTable):

  * every domain is stored with its labels reversed ("www.example.com" ->
    b"com.example.www"), so names under the same zone sit next to each other
    and share long prefixes;
  * entries are grouped in blocks of BLOCK entries; the first entry of a block
    is stored whole, the rest as (bytes shared with the previous entry, the
    rest), lengths as varints;
  * an array('I') holds the byte offset of each block.

For the 1.36M-entry Pax list that is ~12 MB in memory (vs ~27 MB of plain text),
and the table is saved to disk so pax-guard starts without re-sorting.

A name matches if it or any parent is in the table ("suffix match"):
`a.b.example.com` checks com, com.example, com.example.b, com.example.b.a.
Single-label entries (a whole top-level domain) work the same way.
Each check is a binary search over block heads plus a scan of one block.
"""
from __future__ import annotations

import bisect
import hashlib
import struct
from array import array
from typing import Iterable

BLOCK = 32
MAGIC = b"PAXM1\n"


def reverse_name(name: str) -> bytes:
    return ".".join(reversed(name.strip(".").lower().split("."))).encode("ascii", "ignore")


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    shift = n = 0
    while True:
        b = buf[pos]
        pos += 1
        n |= (b & 0x7F) << shift
        if b < 0x80:
            return n, pos
        shift += 7


def collapse(domains: Iterable[str]) -> list[str]:
    """Unique, lower-cased names with every name dropped whose parent is also
    listed (it's covered by the suffix match anyway)."""
    s = {d.strip(".").lower() for d in domains if d and d.strip(".")}
    out = []
    for d in s:
        parts = d.split(".")
        if not any(".".join(parts[i:]) in s for i in range(1, len(parts))):
            out.append(d)
    return out


class SuffixMatcher:
    """Immutable; build with `from_domains` or load with `from_bytes`."""

    def __init__(self, blob: bytes, offsets: array, heads: list[bytes] | None, count: int):
        self._blob = blob
        self._offsets = offsets
        self.count = count
        # Block heads are decoded lazily into a small list for bisect (one
        # bytes object per block: ~43k for 1.4M entries, ~2.5 MB).
        self._heads = heads if heads is not None else [self._head(i) for i in range(len(offsets))]

    # ------------------------------------------------------------- build
    @classmethod
    def from_domains(cls, domains: Iterable[str], already_collapsed: bool = False) -> "SuffixMatcher":
        names = list(domains) if already_collapsed else collapse(domains)
        keys = sorted({reverse_name(d) for d in names if d})
        blob = bytearray()
        offsets = array("I")
        prev = b""
        for i, k in enumerate(keys):
            if i % BLOCK == 0:
                offsets.append(len(blob))
                blob += _varint(len(k)) + k
            else:
                shared = 0
                limit = min(len(prev), len(k))
                while shared < limit and prev[shared] == k[shared]:
                    shared += 1
                blob += _varint(shared) + _varint(len(k) - shared) + k[shared:]
            prev = k
        heads = [keys[i] for i in range(0, len(keys), BLOCK)]
        return cls(bytes(blob), offsets, heads, len(keys))

    def _head(self, block: int) -> bytes:
        pos = self._offsets[block]
        n, pos = _read_varint(self._blob, pos)
        return self._blob[pos:pos + n]

    # ------------------------------------------------------------ lookup
    def contains_exact(self, key: bytes) -> bool:
        b = bisect.bisect_right(self._heads, key) - 1
        if b < 0:
            return False
        blob = self._blob
        pos = self._offsets[b]
        end = self._offsets[b + 1] if b + 1 < len(self._offsets) else len(blob)
        n, pos = _read_varint(blob, pos)
        cur = blob[pos:pos + n]
        pos += n
        while True:
            if cur == key:
                return True
            if cur > key or pos >= end:
                return False
            shared, pos = _read_varint(blob, pos)
            rest, pos = _read_varint(blob, pos)
            cur = cur[:shared] + blob[pos:pos + rest]
            pos += rest

    def match(self, name: str) -> str | None:
        """The listed suffix that covers `name` (shortest first), or None."""
        labels = name.strip(".").lower().split(".")
        if not labels or not labels[0]:
            return None
        key = b""
        for i in range(len(labels) - 1, -1, -1):
            lab = labels[i].encode("ascii", "ignore")
            key = lab if not key else key + b"." + lab
            if self.contains_exact(key):
                return ".".join(labels[i:])
        return None

    def __contains__(self, name: str) -> bool:
        return self.match(name) is not None

    def __len__(self) -> int:
        return self.count

    @property
    def nbytes(self) -> int:
        return len(self._blob) + self._offsets.itemsize * len(self._offsets) + sum(len(h) for h in self._heads)

    # --------------------------------------------------------- serialise
    def to_bytes(self) -> bytes:
        offs = self._offsets.tobytes()
        body = struct.pack("<III", self.count, len(self._offsets), len(self._blob)) + offs + self._blob
        return MAGIC + hashlib.sha256(body).digest() + body

    @classmethod
    def from_bytes(cls, data: bytes) -> "SuffixMatcher":
        if not data.startswith(MAGIC):
            raise ValueError("not a Pax matcher file")
        digest, body = data[len(MAGIC):len(MAGIC) + 32], data[len(MAGIC) + 32:]
        if hashlib.sha256(body).digest() != digest:
            raise ValueError("matcher file is damaged")
        count, nblocks, nblob = struct.unpack("<III", body[:12])
        offsets = array("I")
        offsets.frombytes(body[12:12 + 4 * nblocks])
        if offsets.itemsize != 4:
            raise ValueError("unsupported platform array size")
        blob = body[12 + 4 * nblocks:12 + 4 * nblocks + nblob]
        if len(blob) != nblob:
            raise ValueError("matcher file is truncated")
        return cls(blob, offsets, None, count)


class SmallSuffixSet:
    """Suffix match for short lists (allowlist, user blocks): a plain set."""

    def __init__(self, domains: Iterable[str]):
        self._s = {d.strip(".").lower() for d in domains if d and d.strip(".")}

    def match(self, name: str) -> str | None:
        labels = name.strip(".").lower().split(".")
        for i in range(len(labels) - 1, -1, -1):
            cand = ".".join(labels[i:])
            if cand in self._s:
                return cand
        return None

    def __contains__(self, name: str) -> bool:
        return self.match(name) is not None

    def __len__(self) -> int:
        return len(self._s)
