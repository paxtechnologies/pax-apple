# SPDX-License-Identifier: GPL-3.0-only
"""Score names with Pax's real decision code (dns_forwarder.Forwarder.decide) on a
given set of lists, offline: no upstream is asked anything."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import loop_util as lu

import dns_forwarder as dnsf
import filter_lists as fl
import guard_config as gc
import pax_restricted as pr

BUNDLED = lu.GUARD / "filters"


def bundled_bytes(lid: str) -> bytes:
    man = json.loads((BUNDLED / "filters.json").read_text())
    return fl.read_bytes_maybe_parts(BUNDLED / man["lists"][lid]["file"])


def make_filters_dir(dst: Path, lists: dict, version: str) -> Path:
    """A filters directory like guard/filters: the bundled set with `lists`
    ({lid: bytes}) swapped in and the manifest's hashes and counts updated."""
    dst.mkdir(parents=True, exist_ok=True)
    man = json.loads((BUNDLED / "filters.json").read_text())
    for lid, item in man["lists"].items():
        data = lists.get(lid)
        if data is None:
            data = fl.read_bytes_maybe_parts(BUNDLED / item["file"])
        else:
            item["sha256"] = lu.sha256(data)
            item["bytes"] = len(data)
            item["entries"] = fl.count_entries(item, data)
        (dst / item["file"]).write_bytes(data)
    man["version"] = version
    (dst / "filters.json").write_text(json.dumps(man, indent=1, sort_keys=True))
    return dst


class Decider:
    """Pax's decision for a name with the default policy (every category on)."""

    def __init__(self, filters_dir: Path):
        self.work = Path(tempfile.mkdtemp(prefix="pax-decider-"))
        store = fl.FilterStore(self.work, bundled_dir=filters_dir, plugin_dirs=[],
                               compile_in_subprocess=False, log=lambda m: None)
        self.fs = store.load()
        dirs = [lu.REPO / "pax-dns" / "lists", lu.LISTS]
        cats = gc.load_curated("bypass", dirs) + gc.load_curated("remote_desktop", dirs)
        restricted = []
        for c in gc.RESTRICTED_CATEGORIES:
            restricted += gc.load_curated(c, dirs)
        restricted += list(gc.ALWAYS_BLOCKED_MEDIA_NAMES)
        rule = pr.parse_rule_file(gc.find_list("media_converter_rule", dirs).read_text())
        pol = dnsf.Policy(categories=cats, restricted=restricted, restricted_rules=[rule],
                          never_except=pr.RestrictedCheck())
        self.fw = dnsf.Forwarder([], filters=self.fs, policy=pol, log=lambda m: None)
        self._cache: dict = {}

    def blocked(self, name: str) -> bool:
        name = name.lower().strip(".")
        hit = self._cache.get(name)
        if hit is None:
            action, _why = self.fw.decide(name)
            hit = self._cache[name] = action == "block"
        return hit

    def list_entry(self, name: str) -> str | None:
        """The list entry that blocks `name` ("name-rule" etc. for code rules)."""
        name = name.lower().strip(".")
        if self.fs.allowed(name):
            return None
        return self.fs.blocked_by(name)

    def close(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)
