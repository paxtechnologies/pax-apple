# SPDX-License-Identifier: GPL-3.0-only
"""Pax's local filter lists inside pax-guard (v0.8.1): load, match, update.

Lists (built by lists/build.py, bundled in guard/filters, described by
filters.json):
  pax-block   ~1.34M domains of restricted content (HaGeZi, OISD, UT1, Pax's
              hand list and zones, minus exclusions). Restricted.
  pax-bypass  ~15.6k DoH/VPN/Tor/proxy names (HaGeZi). An exception can free one.
  pax-nrd     newly registered domains matching the name rule (daily). Restricted.
  pax-allow   tailscale.com, character.ai: never blocked by a local list
  safesearch  385 exact-host rewrites (Google, YouTube Strict, Bing, DuckDuckGo)

"Restricted" lists (v0.8.1) are never freed by a user's exception: the
forwarder blocks their hits even when the name is on the exception list, and
pax-guard refuses an exception request for them (PAX-DNS-010). The flag comes
from the bundled manifest; an update can't change it.

Plus pluggable lists: a JSON descriptor per list in /Library/PaxGuard/lists.d/
(root-owned, not group/world writable) or guard/filters/plugins/, e.g.
  {"id": "extra-sites", "file": "extra-sites.txt", "kind": "block",
   "format": "domains", "enabled": true, "min_entries": 1000}
kinds: block | allow; formats: domains | hosts | adblock | keywords (keywords
match the first label at a label edge, like the new-registration rule). A
plug-in block list is restricted unless its descriptor says "restricted": false.
See docs/FILTER_LISTS.md.

Updates (v0.8.19, "filter packs"): every ~6 hours a signed filter-pack.json
from the GitHub release tagged `filter-pack`, with a jsDelivr mirror of the
`filter-packs` branch. Packs are built, tested and signed by the nightly
filter workflow in the repo (.github/workflows/filter-loop.yml; see
docs/FILTER_PACKS.md) with a key of their own (pax_signing.FILTER_PUBLIC_KEYS_HEX,
never the app update key). A pack is taken only when:
  * its signature checks out against the filter key;
  * its version is newer than the copy in use (and the bundled copy), and it is
    not a version this Mac/server already refused;
  * it only changes block lists the bundled manifest knows (the allowlist and
    SafeSearch rules change only with an app update), and the bundled manifest's
    floors, max_drop and "restricted" flags apply whatever the pack says;
  * every changed file matches its signed SHA-256, parses, has at least
    min_entries, and shrinks by no more than max_drop against both the copy in
    use and the bundled copy;
  * the canary self-test passes on the new lists before they are swapped in.
The copy it replaces is kept as "previous". If a swapped-in pack later fails
the canary, the caller rolls back to the previous good copy (rollback_pack) and
the version is never taken again; the bundled copy is the last fallback, and
the family-filter chain covers a total failure. A failed update changes nothing
(never fail open).
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import random
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# pax_restricted.py ships next to this file; in the repo it lives in common/.
sys.path.append(str(Path(__file__).resolve().parent.parent / "common"))
import pax_signing  # noqa: E402
import pax_restricted as pr  # noqa: E402
from domain_matcher import SmallSuffixSet, SuffixMatcher  # noqa: E402

HERE = Path(__file__).resolve().parent
BUNDLED_DIR = HERE / "filters"
REPO_SLUG = "paxtechnologies/pax-apple"
# v0.8.19 filter packs. Primary: the rolling "filter-pack" release. Mirror: jsDelivr
# serving the orphan `filter-packs` branch the same workflow pushes. List files in a
# pack are content-addressed ("object" names carry their SHA-256), so a mirror that
# lags behind still serves files that match the manifest it serves.
PACK_BASES = [
    f"https://github.com/{REPO_SLUG}/releases/download/filter-pack/",
    f"https://cdn.jsdelivr.net/gh/{REPO_SLUG}@filter-packs/",
]
LISTS_BASES = PACK_BASES          # (name kept for callers written before 0.8.19)
PACK_MANIFEST = "filter-pack.json"
MANIFEST_NAME = PACK_MANIFEST
PACK_SCHEMA = "pax.filterpack.v1"
UPDATE_INTERVAL = 6 * 3600
UPDATE_JITTER = 3600
REFUSED_KEEP = 20                 # refused pack versions remembered
_OBJECT = re.compile(r"^[a-z0-9-]{1,40}-[0-9a-f]{16}\.(txt\.gz|txt|csv)$")
_VERSION = re.compile(r"^\d{4}\.\d{1,4}\.\d{1,6}$")
# jsDelivr serves files up to 20 MB from GitHub; lists/build.py keeps every list
# file under this, and a bigger download is refused.
MAX_DOWNLOAD = 20 * 1024 * 1024
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


class ListError(Exception):
    pass


def version_key(v) -> tuple:
    """"2026.1018.300" -> (2026, 1018, 300). Unparseable versions sort first."""
    try:
        return tuple(int(x) for x in str(v).split("."))
    except (TypeError, ValueError):
        return ()


# ------------------------------------------------------------------ parsing
def clean_name(raw: str, fmt: str = "domains") -> str | None:
    line = raw.strip()
    if not line or line[0] in "#!;[":
        return None
    if fmt == "adblock":
        if not (line.startswith("||") and line.endswith("^")):
            return None
        line = line[2:-1]
    parts = line.split()
    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
        line = parts[1]
    elif len(parts) != 1:
        return None
    name = line.lstrip("*.").rstrip(".").lower()
    if not name or len(name) > 253 or name in ("localhost", "local", "broadcasthost"):
        return None
    labels = name.split(".")
    if not all(_LABEL.match(lab) for lab in labels) or all(lab.isdigit() for lab in labels):
        return None
    return name


def read_bytes_maybe_parts(path: Path) -> bytes:
    """A file, or its name.part-NNN pieces joined (the repo stores big files split)."""
    if path.is_file():
        return path.read_bytes()
    parts = sorted(path.parent.glob(path.name + ".part-*"))
    if not parts:
        raise FileNotFoundError(str(path))
    return b"".join(p.read_bytes() for p in parts)


def decode_text(data: bytes, filename: str) -> str:
    if filename.endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8", "ignore")


def parse_domains(text: str, fmt: str = "domains") -> list[str]:
    out = []
    for raw in text.splitlines():
        n = clean_name(raw, fmt)
        if n:
            out.append(n)
    return out


def parse_safesearch(text: str) -> dict[str, str]:
    rules: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        host = (row.get("host_exact") or "").strip().lower().rstrip(".")
        target = (row.get("rewrite_to") or "").strip().lower().rstrip(".")
        if clean_name(host) and clean_name(target):
            rules[host] = target
    return rules


def count_entries(item: dict, data: bytes) -> int:
    text = decode_text(data, item["file"])
    if item.get("kind") == "safesearch":
        return len(parse_safesearch(text))
    if item.get("format") == "keywords":
        return len(parse_keywords(text))
    return len(parse_domains(text, item.get("format", "domains")))


def parse_keywords(text: str) -> list[str]:
    return [l.strip().lower() for l in text.splitlines()
            if l.strip() and not l.startswith("#") and re.fullmatch(r"[a-z0-9-]{2,30}", l.strip().lower())]


class KeywordRule:
    """Block a name whose first label holds a keyword at a label edge (start,
    end, or next to "-" or a digit). The new-registration list uses the same rule."""

    def __init__(self, keywords: list[str], allow_words: list[str] | None = None):
        kw = "|".join(map(re.escape, keywords)) or "(?!)"
        self._re = re.compile(rf"(?:^|[-0-9])(?:{kw})|(?:{kw})(?:$|[-0-9])")
        words = sorted(allow_words or [], key=len, reverse=True)
        self._allow = re.compile("|".join(map(re.escape, words))) if words else None

    def match(self, name: str) -> bool:
        label = name.strip(".").lower().split(".")[0]
        if label.startswith("xn--"):
            return False
        if self._allow:
            label = self._allow.sub("~", label)
        return bool(self._re.search(label))


# ------------------------------------------------------------ validation
def validate_candidate(item: dict, data: bytes, previous_entries: int | None) -> int:
    """Raise ListError unless `data` is a sane replacement. Returns its entry count."""
    if hashlib.sha256(data).hexdigest() != item.get("sha256"):
        raise ListError(f"{item['file']}: SHA-256 does not match the signed manifest")
    try:
        n = count_entries(item, data)
    except (OSError, ValueError, EOFError, gzip.BadGzipFile) as exc:
        raise ListError(f"{item['file']}: unreadable ({type(exc).__name__})") from exc
    if n < int(item.get("min_entries", 1)):
        raise ListError(f"{item['file']}: only {n} entries (minimum {item.get('min_entries')})")
    if previous_entries:
        floor = previous_entries * (1 - float(item.get("max_drop", 0.10)))
        if n < floor:
            raise ListError(f"{item['file']}: {n} entries, down from {previous_entries} "
                            f"(more than {item.get('max_drop')} would be removed)")
    return n


def _is_root_owned_safe(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    if os.geteuid() != 0:          # tests / development: ownership can't be root
        return not (st.st_mode & stat.S_IWOTH)
    return st.st_uid == 0 and not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


# ---------------------------------------------------------------- the set
class FilterSet:
    """Everything the forwarder asks: rewrite? block? (allow wins over lists).

    `block` holds the lists an exception may free (pax-bypass, plug-ins marked
    "restricted": false); `restricted` the ones it never frees (pax-block,
    pax-nrd, other plug-ins), with `keyword_rules` (restricted too).

    v0.8.18: `name_rules` (restricted) and `bypass_rules` (an exception may
    free them) are name rules applied to every lookup, after the lists:
    FilterStore.load() adds pax_restricted.lookup_rule() and
    bypass_name_rule()."""

    def __init__(self, block: list, allow: SmallSuffixSet, safesearch: dict[str, str],
                 keyword_rules: list[KeywordRule] | None = None, info: dict | None = None,
                 restricted: list | None = None, name_rules: list | None = None,
                 bypass_rules: list | None = None):
        self.block = block                  # SuffixMatcher / SmallSuffixSet objects
        self.restricted = restricted or []
        self.allow = allow
        self.safesearch = safesearch
        self.keyword_rules = keyword_rules or []
        self.name_rules = name_rules or []
        self.bypass_rules = bypass_rules or []
        self.info = info or {}

    def safesearch_target(self, name: str) -> str | None:
        return self.safesearch.get(name.strip(".").lower())

    def allowed(self, name: str) -> bool:
        return name in self.allow

    def restricted_by(self, name: str) -> str | None:
        """The restricted-list entry (or "keyword") that blocks `name`."""
        for m in self.restricted:
            hit = m.match(name)
            if hit:
                return hit
        for r in self.keyword_rules:
            if r.match(name):
                return "keyword"
        for r in self.name_rules:
            if r.match(name):
                return "name-rule"
        return None

    def overridable_by(self, name: str) -> str | None:
        """The hit from a list an exception may free."""
        for m in self.block:
            hit = m.match(name)
            if hit:
                return hit
        for r in self.bypass_rules:
            if r.match(name):
                return "bypass-name-rule"
        return None

    def blocked_by(self, name: str) -> str | None:
        """Any list hit (restricted first)."""
        return self.restricted_by(name) or self.overridable_by(name)

    @property
    def entries(self) -> int:
        return sum(len(m) for m in self.block) + sum(len(m) for m in self.restricted)


def empty_filterset() -> FilterSet:
    return FilterSet([], SmallSuffixSet([]), {}, info={"state": "empty"})


class FilterStore:
    """Where the lists live and which copy is in use."""

    def __init__(self, state_dir: Path, bundled_dir: Path = BUNDLED_DIR,
                 plugin_dirs: list[Path] | None = None, compile_in_subprocess: bool = True,
                 log=print):
        self.root = state_dir / "lists"
        self.bundled_dir = bundled_dir
        self.plugin_dirs = plugin_dirs if plugin_dirs is not None else [
            Path("/Library/PaxGuard/lists.d"), bundled_dir / "plugins"]
        self.compile_in_subprocess = compile_in_subprocess
        self.log = log

    # ------------------------------------------------------------ manifests
    def bundled_manifest(self) -> dict:
        return json.loads((self.bundled_dir / "filters.json").read_text())

    def current_manifest(self) -> dict | None:
        try:
            return json.loads((self.root / "current" / "manifest.json").read_text())
        except (OSError, ValueError):
            return None

    def _current_usable(self, cur: dict | None, bundled: dict) -> bool:
        """v0.8.19: an updated copy older than the bundled one (e.g. after an app
        update that bundles newer lists) is ignored."""
        return bool(cur) and version_key(cur.get("version")) >= version_key(bundled.get("version"))

    def _list_bytes(self, lid: str, item: dict, current_dir: Path | None = None,
                    current: dict | None = None) -> tuple[bytes, str]:
        """The copy to use: the updated one if it still checks out, else bundled."""
        cdir = current_dir or (self.root / "current")
        cur = current if current_dir is not None else self.current_manifest()
        if cur and lid in cur.get("lists", {}) and (current_dir is not None
                                                    or self._current_usable(cur, self.bundled_manifest())):
            citem = cur["lists"][lid]
            p = cdir / citem["file"]
            try:
                data = p.read_bytes()
                if hashlib.sha256(data).hexdigest() == citem["sha256"]:
                    return data, "updated"
                self.log(f"PAX-DNS-006 updated list {lid} is damaged; using the bundled copy")
            except OSError:
                pass
        data = read_bytes_maybe_parts(self.bundled_dir / item["file"])
        if item.get("sha256") and hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ListError(f"bundled {item['file']} is damaged")
        return data, "bundled"

    # -------------------------------------------------------------- compile
    def _matcher(self, lid: str, data: bytes, item: dict) -> SuffixMatcher:
        digest = hashlib.sha256(data).hexdigest()
        cache = self.root / "compiled" / f"{lid}-{digest[:16]}.paxm"
        try:
            return SuffixMatcher.from_bytes(cache.read_bytes())
        except (OSError, ValueError):
            pass
        cache.parent.mkdir(parents=True, exist_ok=True)
        # v0.8.19: keep the two newest compiled copies (the one in use and the one a
        # pack being checked needs), so a refused pack doesn't cost a recompile.
        olds = sorted(cache.parent.glob(f"{lid}-*.paxm"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in olds[1:]:
            old.unlink(missing_ok=True)
        src = cache.with_suffix(".src")
        src.write_bytes(data)
        try:
            if self.compile_in_subprocess:
                # A child process, so the ~300 MB peak of sorting 1.4M names is
                # handed back to macOS when it exits.
                r = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "compile",
                                    str(src), str(cache), item.get("format", "domains"), item["file"]],
                                   capture_output=True, text=True, timeout=600)
                if r.returncode != 0:
                    raise ListError(f"compiling {lid} failed: {r.stderr.strip()[-200:]}")
                return SuffixMatcher.from_bytes(cache.read_bytes())
            m = compile_bytes(data, item.get("format", "domains"), item["file"])
            cache.write_bytes(m.to_bytes())
            return m
        finally:
            src.unlink(missing_ok=True)

    # ----------------------------------------------------------------- load
    def load(self, current_dir: Path | None = None) -> FilterSet:
        """The lists in use. `current_dir` (v0.8.19): load a staged pack from
        there instead of current/ (to check it before it is swapped in)."""
        man = self.bundled_manifest()
        staged = None
        if current_dir is not None:
            staged = json.loads((current_dir / "manifest.json").read_text())
        block, restricted, allow_names, safesearch, kw_rules, info = [], [], [], {}, [], {"lists": {}}
        for lid, item in man.get("lists", {}).items():
            try:
                data, origin = self._list_bytes(lid, item, current_dir, staged)
                kind = item.get("kind")
                if kind == "block":
                    m = self._matcher(lid, data, item)
                    # Restricted unless the bundled manifest says otherwise.
                    (restricted if item.get("restricted", True) else block).append(m)
                    info["lists"][lid] = {"entries": len(m), "origin": origin,
                                          "restricted": bool(item.get("restricted", True))}
                elif kind == "allow":
                    names = parse_domains(decode_text(data, item["file"]))
                    allow_names += names
                    info["lists"][lid] = {"entries": len(names), "origin": origin}
                elif kind == "safesearch":
                    safesearch = parse_safesearch(decode_text(data, item["file"]))
                    info["lists"][lid] = {"entries": len(safesearch), "origin": origin}
            except (OSError, ValueError, ListError) as exc:
                if item.get("optional"):
                    self.log(f"PAX-DNS-006 optional list {lid} unavailable ({exc}); carrying on")
                    continue
                raise
        for desc_path, desc in self.plugins():
            lid = desc["id"]
            try:
                data = (desc_path.parent / desc["file"]).read_bytes()
                if desc.get("sha256") and hashlib.sha256(data).hexdigest() != desc["sha256"]:
                    raise ListError("SHA-256 mismatch")
                n = count_entries(desc, data)
                if n < int(desc.get("min_entries", 1)):
                    raise ListError(f"only {n} entries")
                fmt = desc.get("format", "domains")
                if desc["kind"] == "allow":
                    allow_names += parse_domains(decode_text(data, desc["file"]), fmt)
                elif fmt == "keywords":
                    kw_rules.append(KeywordRule(parse_keywords(decode_text(data, desc["file"]))))
                elif desc.get("restricted", True) is False:
                    block.append(self._matcher(f"plugin-{lid}", data, desc))
                else:
                    restricted.append(self._matcher(f"plugin-{lid}", data, desc))
                info["lists"][f"plugin:{lid}"] = {"entries": n, "origin": "plugin"}
            except (OSError, ValueError, ListError, KeyError) as exc:
                self.log(f"PAX-DNS-007 plugin list {lid} skipped: {exc}")
        cur = staged if current_dir is not None else self.current_manifest()
        if current_dir is None and not self._current_usable(cur, man):
            cur = None
        info["version"] = (cur or man).get("version")
        info["bundled_version"] = man.get("version")
        info["origin"] = "pack" if cur and cur.get("schema") == PACK_SCHEMA else (
            "updated" if cur else "bundled")
        # v0.8.18: the built-in name rules ship with the code (a signed app
        # update), not with the list manifest.
        info["name_rules"] = True
        return FilterSet(block, SmallSuffixSet(allow_names), safesearch, kw_rules, info, restricted=restricted,
                         name_rules=[pr.lookup_rule()], bypass_rules=[pr.bypass_name_rule()])

    def plugins(self) -> list[tuple[Path, dict]]:
        out = []
        for d in self.plugin_dirs:
            if not d.is_dir() or not _is_root_owned_safe(d):
                continue
            for p in sorted(d.glob("*.json")):
                if not _is_root_owned_safe(p):
                    self.log(f"PAX-DNS-007 plugin {p.name} ignored: not root-owned")
                    continue
                try:
                    desc = json.loads(p.read_text())
                except (OSError, ValueError):
                    continue
                if (isinstance(desc, dict) and desc.get("enabled") and desc.get("kind") in ("block", "allow")
                        and re.fullmatch(r"[a-z0-9-]{1,40}", str(desc.get("id", "")))
                        and isinstance(desc.get("file"), str) and "/" not in desc["file"]):
                    out.append((p, desc))
        return out

    # --------------------------------------------------------------- update
    def due(self, now: float) -> bool:
        try:
            meta = json.loads((self.root / "update.json").read_text())
        except (OSError, ValueError):
            return True
        if now < float(meta.get("backoff_until", 0)):
            return False
        return now >= float(meta.get("next_at", float(meta.get("checked_at", 0)) + UPDATE_INTERVAL))

    def update(self, fetch, now: float | None = None, bases: list[str] | None = None,
               canary=None) -> dict:
        """Fetch the signed filter pack and any changed lists; swap in only what
        passes every check. `fetch(url) -> bytes`. `canary(FilterSet) -> list of
        failures` runs on the new lists before the swap (v0.8.19). Returns a report."""
        now = time.time() if now is None else now
        report: dict = {"checked_at": now, "changed": [], "rejected": [], "ok": False}
        bases = bases or PACK_BASES
        payload = None
        base_used = None
        errors = []
        limited = None
        for base in bases:
            try:
                doc = json.loads(fetch(base + PACK_MANIFEST))
                payload = pax_signing.verify_document(doc, pax_signing.filter_keys(),
                                                       context=pax_signing.FILTER_CONTEXT)
                base_used = base
                break
            except pax_signing.SignatureError as exc:
                errors.append(f"{base}: {exc}")
                self.log(f"PAX-UPDATE-002 filter pack from {base} rejected: {exc}")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{base}: {type(exc).__name__}")
                status = getattr(exc, "status", None) or getattr(exc, "code", None)
                if isinstance(status, int) and (status == 429 or status >= 500):
                    limited = exc
        if payload is None:
            report["error"] = "; ".join(errors) or "no source"
            if limited is not None:
                prev = self._meta().get("backoff_seconds", 0)
                wait = min(24 * 3600, max(3600, int(prev) * 2 if prev else 3600))
                ra = getattr(limited, "retry_after", None)
                if ra:
                    wait = min(24 * 3600, max(wait, int(ra)))
                report["backoff_seconds"] = wait
                report["backoff_until"] = now + wait + random.randint(0, 300)
                self.log(f"PAX-UPDATE-008 filter pack source rate-limited; next try in {wait // 60} min")
            self._save_meta(report)
            return report
        version = str(payload.get("version", ""))
        report["version"] = version
        if (payload.get("schema") != PACK_SCHEMA or not isinstance(payload.get("lists"), dict)
                or not _VERSION.match(version)):
            report["error"] = "unknown filter pack schema"
            self._save_meta(report)
            return report
        bundled = self.bundled_manifest()
        cur_raw = self.current_manifest()
        cur = cur_raw if self._current_usable(cur_raw, bundled) else bundled
        if version in self.refused_versions():
            report.update(ok=True, up_to_date=True, note=f"pack {version} was refused before")
            self._save_meta(report)
            return report
        if version_key(version) <= version_key(cur.get("version")):
            if version_key(version) < version_key(cur.get("version")):
                report["error"] = f"older lists ({version} < {cur.get('version')}) refused"
                self.log(f"PAX-DNS-005 {report['error']}")
            else:
                report.update(ok=True, up_to_date=True)
            self._save_meta(report)
            return report
        staging = self.root / "staging"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        new_lists: dict = {}
        # Every list the bundled manifest knows starts as the copy in use.
        for lid, rule in bundled.get("lists", {}).items():
            old = cur.get("lists", {}).get(lid) or rule
            try:
                src = self.root / "current" / old["file"]
                if cur is not bundled and src.is_file():
                    data = src.read_bytes()
                else:
                    data, old = read_bytes_maybe_parts(self.bundled_dir / rule["file"]), rule
            except OSError:
                continue
            (staging / old["file"]).write_bytes(data)
            new_lists[lid] = old
        for lid, item in payload["lists"].items():
            rule = bundled.get("lists", {}).get(lid)
            if rule is None or not isinstance(item, dict):
                continue                      # unknown list: ignore (newer manifest)
            if rule.get("kind") != "block":
                # v0.8.19: a pack can't touch the allowlist or SafeSearch rules.
                if item.get("sha256") != (new_lists.get(lid) or {}).get("sha256"):
                    report["rejected"].append({"list": lid, "why": "packs may only change block lists"})
                continue
            item = dict(item)
            # The bundled floors are the minimum; a manifest can only tighten them.
            item["min_entries"] = max(int(item.get("min_entries", 1)), int(rule.get("min_entries", 1)))
            item["max_drop"] = min(float(item.get("max_drop", 1.0)), float(rule.get("max_drop", 1.0)))
            item["kind"], item["file"] = rule["kind"], rule["file"]
            item["format"] = rule.get("format", "domains")
            if "restricted" in rule:
                item["restricted"] = rule["restricted"]   # a pack can't free a restricted list
            else:
                item.pop("restricted", None)
            old = new_lists.get(lid) or rule
            if old.get("sha256") == item.get("sha256"):
                continue
            obj = item.get("object") or item["file"]
            if not (_OBJECT.match(str(obj)) or obj == item["file"]):
                report["rejected"].append({"list": lid, "why": "bad object name", "check": True})
                continue
            try:
                data = fetch(base_used + obj)
            except Exception as exc:  # noqa: BLE001 - a download problem, not a bad pack
                report["download_failed"] = True
                report["rejected"].append({"list": lid, "why": f"download failed ({type(exc).__name__})"})
                continue
            try:
                if len(data) > MAX_DOWNLOAD:
                    raise ListError("too large")
                n = validate_candidate(item, data, old.get("entries"))
                if rule.get("entries"):
                    # ...and never more than max_drop below the bundled copy either.
                    validate_candidate(item, data, int(rule["entries"]))
                (staging / item["file"]).write_bytes(data)
                item["entries"] = n
                new_lists[lid] = item
                report["changed"].append(lid)
            except Exception as exc:  # noqa: BLE001 - keep the copy in use
                report["rejected"].append({"list": lid, "why": str(exc)[:200], "check": True})
                self.log(f"PAX-DNS-005 list {lid} update rejected: {exc}")
        if report.get("download_failed"):
            # Take a pack whole or not at all; try again at the next check.
            report["changed"] = []
            report["error"] = "a list file could not be downloaded; trying again later"
        elif any(r.get("check") and r["list"] in bundled.get("lists", {}) and
                 bundled["lists"][r["list"]].get("restricted", True) and
                 not bundled["lists"][r["list"]].get("optional")
                 for r in report["rejected"]):
            # A required restricted list failed its checks: the pack as a whole is
            # suspect, so none of it is taken.
            report["changed"] = []
            report["error"] = "a required list failed its checks; pack refused"
            self.refuse(version, report["error"])
        if report["changed"]:
            manifest = {"schema": PACK_SCHEMA, "version": version, "lists": new_lists,
                        "taken_at": int(now)}
            (staging / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
            if canary is not None:
                try:
                    failures = list(canary(self.load(current_dir=staging)) or [])
                except Exception as exc:  # noqa: BLE001 - a pack that won't load fails
                    failures = [f"the pack would not load ({type(exc).__name__}: {str(exc)[:120]})"]
                if failures:
                    report["changed"] = []
                    report["error"] = "canary failed on the new lists: " + "; ".join(failures)[:300]
                    report["canary"] = failures
                    self.refuse(version, report["error"])
                    self.log(f"PAX-DNS-005 filter pack {version} refused: {report['error']}")
        if report["changed"]:
            self._promote(staging)
            report["ok"] = report["taken"] = True
        elif "error" not in report and not report["rejected"]:
            # A newer pack whose lists match the ones in use: take its version (so
            # status shows the pack in use), no list changes, nothing to re-check.
            manifest = {"schema": PACK_SCHEMA, "version": version, "lists": new_lists, "taken_at": int(now)}
            (staging / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
            self._promote(staging)
            report["ok"] = report["taken"] = True
        else:
            shutil.rmtree(staging, ignore_errors=True)
            report["ok"] = "error" not in report
        self._save_meta(report)
        return report

    # ------------------------------------------------------- v0.8.19 packs
    def refused_versions(self) -> list[str]:
        return [r.get("version") for r in self._meta().get("refused", []) if isinstance(r, dict)]

    def refuse(self, version: str, why: str) -> None:
        meta = self._meta()
        refused = [r for r in meta.get("refused", []) if isinstance(r, dict) and r.get("version") != version]
        refused.append({"version": version, "why": why[:200], "at": int(time.time())})
        meta["refused"] = refused[-REFUSED_KEEP:]
        self._write_meta(meta)

    def rollback_pack(self, why: str) -> bool:
        """A swapped-in pack failed the canary: back to the previous good copy
        and never take that version again. Returns True if a pack was undone."""
        cur = self.current_manifest()
        if not cur:
            return False
        self.refuse(str(cur.get("version")), "after the swap: " + why)
        self.rollback()
        meta = self._meta()
        meta["rolled_back"] = {"version": cur.get("version"), "why": why[:200], "at": int(time.time())}
        self._write_meta(meta)
        return True

    def pack_status(self) -> dict:
        """For health / Settings › Advanced."""
        meta = self._meta()
        bundled = self.bundled_manifest()
        cur = self.current_manifest()
        usable = self._current_usable(cur, bundled)
        return {
            "version": (cur if usable else bundled).get("version"),
            "origin": ("pack" if usable and cur.get("schema") == PACK_SCHEMA else
                       "updated" if usable else "bundled"),
            "bundled_version": bundled.get("version"),
            "last_check_at": meta.get("checked_at"),
            "last_ok": meta.get("ok"),
            "last_error": (meta.get("error") or "")[:200] or None,
            "last_offered": meta.get("version"),
            "next_at": meta.get("next_at"),
            "refused": [r.get("version") for r in meta.get("refused", [])][-5:],
            "rolled_back": meta.get("rolled_back"),
        }

    def _promote(self, staging: Path) -> None:
        """current -> previous, staging -> current (two renames)."""
        cur, prev = self.root / "current", self.root / "previous"
        shutil.rmtree(prev, ignore_errors=True)
        if cur.exists():
            os.replace(cur, prev)
        os.replace(staging, cur)

    def rollback(self) -> bool:
        """Back to the previous good copy (used when a new copy won't load)."""
        cur, prev = self.root / "current", self.root / "previous"
        if not prev.exists():
            shutil.rmtree(cur, ignore_errors=True)
            return False
        shutil.rmtree(cur, ignore_errors=True)
        os.replace(prev, cur)
        return True

    def _meta(self) -> dict:
        try:
            return json.loads((self.root / "update.json").read_text())
        except (OSError, ValueError):
            return {}

    def _save_meta(self, report: dict) -> None:
        report.setdefault("next_at", float(report.get("checked_at", time.time())) + UPDATE_INTERVAL
                          + random.randint(0, UPDATE_JITTER))
        prev = self._meta()
        for k in ("refused", "rolled_back"):          # v0.8.19: kept across checks
            if k in prev and k not in report:
                report[k] = prev[k]
        self._write_meta(report)

    def _write_meta(self, meta: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.root / ".update.json.tmp"
        tmp.write_text(json.dumps(meta))
        os.replace(tmp, self.root / "update.json")


def compile_bytes(data: bytes, fmt: str, filename: str) -> SuffixMatcher:
    return SuffixMatcher.from_domains(parse_domains(decode_text(data, filename), fmt))


def _main(argv: list[str]) -> int:
    if len(argv) == 5 and argv[0] == "compile":
        src, dst, fmt, filename = argv[1:]
        m = compile_bytes(Path(src).read_bytes(), fmt, filename)
        tmp = Path(dst + ".tmp")
        tmp.write_bytes(m.to_bytes())
        os.replace(tmp, dst)
        return 0
    print("usage: filter_lists.py compile <src> <dst> <format> <filename>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
