#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pax's nightly filter workflow (.github/workflows/filter-loop.yml). No person
and no outside service is in the loop: every night it refreshes the sources,
checks new candidates by their homepage, builds the lists reproducibly, runs the
gates, and leaves a pack ready to sign only if every gate passes.

  run.py run --work DIR --state DIR --out DIR      build + gates (exit 0 pass, 3 refused)
  run.py sign --out DIR                            sign with $PAX_FILTER_SIGNING_KEY
  run.py published --state DIR --out DIR           record a pack the workflow published
  run.py check-published [--version V]             fetch + verify the live pack

Gates, in order (any failure: nothing is published, the reason goes to an issue):
  1. unit tests (the workflow runs them before this script)
  2. floors: each block list keeps the bundled minimum size, and shrinks by no more
     than its max_drop against the last published pack and the bundled lists
  3. the 57 everyday UK sites and the known-good set (lists/gates/): none blocked
  4. Tranco top 10k: every name newly blocked against the last published pack must
     be confirmed restricted or a proxy by its homepage. A name the check doesn't
     confirm has its list entry held back from the pack (and from later packs for
     30 days); a known-good name, a code rule, or too many held back fails the run
  5. benchmark on fresh held-out samples vs a reference resolver (bench.py): no
     regression against the last published pack beyond noise

State (the `filter-loop` branch, committed by the workflow so history is visible):
  state/checked/<day>.json.gz  homepage verdicts {name: [verdict, yyyymmdd]}, one file a night
  state/verified-block.txt.gz  names this workflow confirmed restricted (added to pax-block)
  state/verified-bypass.txt.gz names it confirmed as web proxies (added to pax-bypass)
  state/held-back.json.gz      list entries held back {entry: yyyymmdd}
  state/sampled/<day>.json.gz  hashes of names already used as held-out samples
  state/packs.json             the packs published (version + file names)
  scoreboard/history.csv, scoreboard/latest.md, scoreboard/latest.json
Names in the scoreboard are encoded (loop_util.encode_names), never plain text.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import random
import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import loop_util as lu  # noqa: E402
from loop_util import log  # noqa: E402

import bench  # noqa: E402
import build  # noqa: E402
import decider as dec  # noqa: E402
import filter_lists as fl  # noqa: E402
import homepage  # noqa: E402
import pack  # noqa: E402
import pax_restricted as pr  # noqa: E402

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
RECHECK_DAYS = 30           # a confirming verdict (restricted / proxy) is reused this long
RECHECK_OTHER_DAYS = 90     # an "other" / "down" verdict: check the site again after this
HOLD_DAYS = 30
MAX_NEW_TOP10K = 300
MAX_HELD_PER_RUN = 50
CODE_RULES = {"keyword", "name-rule", "bypass-name-rule"}
EXIT_REFUSED = 3


# ------------------------------------------------------------------ state
class State:
    """What the workflow remembers between nights. Verdicts and samples are kept as
    one small file per night (state/checked/<yyyymmdd>.json.gz,
    state/sampled/<yyyymmdd>.json.gz), so the branch grows by kilobytes a night."""

    def __init__(self, root: Path):
        self.root = root
        s = root / "state"
        self.checked: dict = {}
        for p in sorted((s / "checked").glob("*.json.gz")):
            self.checked.update(lu.load_json(p, {}))
        self.new_checked: dict = {}
        self.add_block: set = set(self._names(s / "verified-block.txt.gz"))
        self.add_bypass: set = set(self._names(s / "verified-bypass.txt.gz"))
        self.held: dict = lu.load_json(s / "held-back.json.gz", {})
        self.sampled: list = []
        for p in sorted((s / "sampled").glob("*.json.gz")):
            self.sampled += lu.load_json(p, [])
        self.new_sampled: list = []
        self.packs: list = lu.load_json(s / "packs.json", [])

    @staticmethod
    def _names(p: Path) -> list[str]:
        try:
            return lu.gz_names(p.read_bytes())
        except OSError:
            return []

    def record(self, name: str, verdict: str) -> None:
        self.checked[name] = self.new_checked[name] = [verdict, lu.today()]

    def sample(self, hashes) -> None:
        self.sampled += list(hashes)
        self.new_sampled += list(hashes)

    def recent_verdict(self, name: str) -> str | None:
        v = self.checked.get(name)
        if not v:
            return None
        limit = RECHECK_DAYS if v[0] in ("adult", "proxy") else RECHECK_OTHER_DAYS
        return v[0] if lu.days_since(v[1]) < limit else None

    def held_active(self) -> set:
        return {e for e, d in self.held.items() if lu.days_since(d) < HOLD_DAYS}

    def save(self) -> None:
        s = self.root / "state"
        s.mkdir(parents=True, exist_ok=True)
        day = lu.today()
        for sub, new, keep_days in (("checked", self.new_checked, 180), ("sampled", self.new_sampled, 365)):
            d = s / sub
            d.mkdir(parents=True, exist_ok=True)
            if new:
                p = d / f"{day}.json.gz"
                if sub == "checked":
                    lu.save_json(p, dict(lu.load_json(p, {}), **new))
                else:
                    lu.save_json(p, sorted(set(lu.load_json(p, [])) | set(new)))
            for old in d.glob("*.json.gz"):
                if lu.days_since(old.name.split(".")[0]) > keep_days:
                    old.unlink()
        (s / "verified-block.txt.gz").write_bytes(lu.gz_bytes(sorted(self.add_block),
            "# Names Pax's filter workflow confirmed by their homepage (restricted content).\n"))
        (s / "verified-bypass.txt.gz").write_bytes(lu.gz_bytes(sorted(self.add_bypass),
            "# Names Pax's filter workflow confirmed by their homepage (web proxies).\n"))
        self.held = {k: v for k, v in self.held.items() if lu.days_since(v) < HOLD_DAYS}
        lu.save_json(s / "held-back.json.gz", self.held)
        lu.save_json(s / "packs.json", self.packs[-10:])


# ---------------------------------------------------------------- sources
def fetch_sources(src: Path, fetch=lu.fetch) -> dict:
    """Pax's build sources into `src` (as lists/build.py --sources expects); returns
    {source id: sha256} for the pack manifest."""
    src.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for sid, (_url, _lic, local) in build.SOURCES.items():
        text = build.source_text(sid, None)
        (src / local).parent.mkdir(parents=True, exist_ok=True)
        (src / local).write_text(text)
        hashes[sid] = lu.sha256(text.encode())
        log(f"source {sid}: {len(text)} bytes")
    return hashes


def tranco(fetch=lu.fetch) -> tuple[list[str], str]:
    data = fetch(TRANCO_URL)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        text = z.read(z.namelist()[0]).decode("utf-8", "ignore")
    names = [l.split(",", 1)[1].strip().lower() for l in text.splitlines() if "," in l]
    return names, lu.sha256(data)


def verification_candidates(fetch=lu.fetch) -> tuple[list[str], list[str]]:
    """(restricted candidates, proxy candidates) from the two checked sources."""
    block = build.parse_names(fetch(pr.source("verify_block_url")).decode("utf-8", "ignore"),
                              allow_single_label=False)
    data = fetch(pr.source("verify_bypass_url"))
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        member = next(m for m in tf.getmembers() if m.name.endswith("/domains") or m.name == "domains")
        text = tf.extractfile(member).read().decode("utf-8", "ignore")
    bypass = build.parse_names(text, allow_single_label=False)
    return sorted(block), sorted(bypass)


# ------------------------------------------------------------------ gates
def floor_failures(new_lists: dict, last_payload: dict | None) -> list[str]:
    """The same limits pax-guard and the server apply before taking a pack."""
    out = []
    bundled = pack.bundled_manifest()["lists"]
    for lid, data in new_lists.items():
        rule = bundled[lid]
        n = fl.count_entries(rule, data)
        if n < int(rule.get("min_entries", 1)):
            out.append(f"{lid}: {n} entries, below the minimum {rule['min_entries']}")
        refs = [("the bundled lists", rule.get("entries"))]
        if last_payload and lid in last_payload.get("lists", {}):
            refs.append(("the last published pack", last_payload["lists"][lid].get("entries")))
        for what, prev in refs:
            if prev and n < int(prev) * (1 - float(rule.get("max_drop", 0.1))):
                out.append(f"{lid}: {n} entries, more than {rule['max_drop']:.0%} below {what} ({prev})")
    return out


def gate_known_good(new) -> tuple[list[str], dict]:
    uk = [d for d in lu.gate_names("everyday-uk.txt") if new.blocked(d)]
    kg = [d for d in lu.gate_names("known-good.txt") if new.blocked(d)]
    fails = []
    if uk:
        fails.append(f"{len(uk)} of the 57 everyday UK sites would be blocked")
    if kg:
        fails.append(f"{len(kg)} known-good sites would be blocked")
    return fails, {"uk57_blocked": len(uk), "known_good_blocked": len(kg),
                   "encoded": lu.encode_names(set(uk + kg)) if uk or kg else None}


def gate_top10k(new, last, top10k: list[str], state: State, checker) -> dict:
    """New blocks among the Tranco top 10k: confirmed, or entries to hold back."""
    new_blocks = [d for d in top10k if new.blocked(d) and not last.blocked(d)]
    res = {"new_blocks": len(new_blocks), "confirmed": [], "unconfirmed": [], "hold": set(),
           "code_rule": [], "fail": None}
    if len(new_blocks) > MAX_NEW_TOP10K:
        res["fail"] = f"{len(new_blocks)} new blocks in the Tranco top 10k (more than {MAX_NEW_TOP10K})"
        return res
    todo = [d for d in new_blocks if state.recent_verdict(d) not in ("adult", "proxy")]
    verdicts = checker(todo) if todo else {}
    for d, v in verdicts.items():
        state.record(d, v)
    for d in new_blocks:
        v = verdicts.get(d) or state.recent_verdict(d)
        if v in ("adult", "proxy"):
            res["confirmed"].append(d)
            continue
        res["unconfirmed"].append(d)
        entry = new.list_entry(d)
        if entry is None or entry in CODE_RULES:
            res["code_rule"].append(d)
        else:
            res["hold"].add(entry)
    if res["code_rule"]:
        res["fail"] = f"{len(res['code_rule'])} new top-10k blocks come from a code rule, not a list"
    return res


# -------------------------------------------------------------------- run
def version_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y.%m%d.%H%M")


def build_lists(src: Path, state: State, held: set, last_files: dict, work: Path, nrd_days: int = 14) -> tuple:
    final, bypass, stats = build.build_block(src, sorted(state.add_block), sorted(state.add_bypass),
                                             remove=sorted(held))
    today = dt.datetime.now(dt.timezone.utc).date()
    nrd, nstats = build.build_nrd(nrd_days, work / "nrd_raw", today)
    nrd = [d for d in nrd if not build.allowed(d, held)]
    lists = {"pax-block": lu.gz_bytes(final, build.BLOCK_HEADER),
             "pax-bypass": lu.gz_bytes(bypass, build.BYPASS_HEADER),
             "pax-nrd": lu.gz_bytes(nrd, build.nrd_header(nrd_days, today))}
    rule = pack.bundled_manifest()["lists"]["pax-nrd"]
    prev = last_files.get("pax-nrd")
    prev_n = fl.count_entries(rule, prev) if prev else int(rule.get("entries") or 0)
    if len(nrd) < int(rule["min_entries"]) or (prev_n and len(nrd) < prev_n * (1 - float(rule["max_drop"]))):
        # The new-registration source had a bad night: keep the last list.
        lists["pax-nrd"] = prev if prev else dec.bundled_bytes("pax-nrd")
        nstats["kept_last"] = True
    stats["nrd"] = nstats
    return lists, stats


def run(args) -> int:
    work, out = Path(args.work), Path(args.out)
    work.mkdir(parents=True, exist_ok=True)
    state = State(Path(args.state))
    version = args.version or version_now()
    result: dict = {"version": version, "ok": False, "failures": [], "started_at": version_now(),
                    "code": args.code or None}
    rng = random.Random(version)
    try:
        last_payload, last_files = pack.fetch_published()
        last_version = (last_payload or {}).get("version") or pack.bundled_manifest()["version"]
        result["last_version"] = last_version
        log(f"last published pack: {last_version} ({'pack' if last_payload else 'bundled lists'})")
        last_lists = {lid: last_files.get(lid) or dec.bundled_bytes(lid) for lid in pack.PACK_LISTS}
        last = dec.Decider(dec.make_filters_dir(work / "last-filters", last_lists, last_version))

        src_hashes = fetch_sources(work / "src")
        top, tranco_sha = tranco()
        src_hashes["tranco"] = tranco_sha
        top10k = top[:10_000]

        # Homepage verification of new candidates (rate-limited).
        cblock, cbypass = verification_candidates()
        never = set(build.read_verified("loop-exclude.txt.gz"))        # hand-reviewed: never added
        known_block = set(build.read_verified("pax-block-extra.txt.gz")) | state.add_block | never
        known_bypass = set(build.read_verified("pax-bypass-extra.txt.gz")) | state.add_bypass | never
        fresh = lambda n: state.recent_verdict(n) is None  # noqa: E731
        todo_b = [n for n in cblock if n not in known_block and fresh(n) and not last.blocked(n)]
        todo_p = [n for n in cbypass if n not in known_bypass and fresh(n) and not last.blocked(n)]
        n_todo_b, n_todo_p = len(todo_b), len(todo_p)
        rng.shuffle(todo_b)
        rng.shuffle(todo_p)
        nb = int(args.verify_max * 0.75)
        todo_b, todo_p = todo_b[:nb], todo_p[:args.verify_max - nb]
        verdicts = homepage.check(todo_b + todo_p, qps=args.qps)
        added_b = [n for n in todo_b if verdicts.get(n) == "adult"]
        added_p = [n for n in todo_p if verdicts.get(n) == "proxy"]
        for n, v in verdicts.items():
            state.record(n, v)
        state.add_block |= set(added_b)
        state.add_bypass |= set(added_p)
        result["verification"] = {"checked": len(verdicts), "added_restricted": len(added_b),
                                  "added_proxy": len(added_p),
                                  "waiting": {"restricted": max(0, n_todo_b - len(todo_b)),
                                              "proxy": max(0, n_todo_p - len(todo_p))}}

        # Build + gates. A held-back entry means one rebuild; a second round must be clean.
        held = state.held_active()
        held_now: set = set()
        new = None
        for attempt in (1, 2):
            new_lists, stats = build_lists(work / "src", state, held | held_now, last_files, work)
            result["build"] = {k: v for k, v in stats.items() if k != "excluded"}
            result["entries"] = {lid: fl.count_entries(pack.bundled_manifest()["lists"][lid], d)
                                 for lid, d in new_lists.items()}
            fails = floor_failures(new_lists, last_payload)
            if fails:
                result["failures"] += fails
                break
            if new is not None:
                new.close()
            new = dec.Decider(dec.make_filters_dir(work / f"new-filters-{attempt}", new_lists, version))
            fails, kg = gate_known_good(new)
            result["known_good"] = kg
            if fails:
                result["failures"] += fails
                break
            t = gate_top10k(new, last, top10k, state, lambda names: homepage.check(names, qps=args.qps))
            result["top10k"] = {"new_blocks": t["new_blocks"], "confirmed": len(t["confirmed"]),
                                "unconfirmed": len(t["unconfirmed"]),
                                "held_back": len(held_now | t["hold"]),
                                "encoded_held": lu.encode_names(held_now | t["hold"]) if (held_now | t["hold"]) else None}
            if t["fail"]:
                result["failures"].append(t["fail"])
                break
            if not t["hold"]:
                break
            held_now |= t["hold"]
            if len(held_now) > MAX_HELD_PER_RUN:
                result["failures"].append(f"{len(held_now)} list entries would be held back (more than {MAX_HELD_PER_RUN})")
                break
            if attempt == 2:
                result["failures"].append("new top-10k blocks were still unconfirmed after holding entries back")
        for e in held_now:
            state.held[e] = lu.today()

        if not result["failures"] and new is not None:
            seen = set(state.sampled)
            b = bench.run(new.blocked, last.blocked, top, seen, seed=int(rng.random() * 1e9),
                          qps=args.qps, budget=args.ref_budget, adult_n=args.adult_n,
                          benign_n=args.benign_n, proxy_n=args.proxy_n)
            result["bench"] = {"scores": b["scores"], "queries": b["queries"]}
            state.sample(lu.name_hash(d) for d in b["sampled"])
            if b["error"]:
                result["failures"].append(b["error"])
            result["failures"] += b["regressions"]

        if not result["failures"]:
            meta = {"code": args.code or None, "inputs": src_hashes, "built_from": last_version,
                    "gates": {"uk57_blocked": 0, "known_good_blocked": 0,
                              "top10k_new": result["top10k"]["new_blocks"],
                              "top10k_held_back": result["top10k"]["held_back"],
                              "bench": {k: {x: v[x] for x in ("n", "ref", "new", "last")}
                                        for k, v in result["bench"]["scores"].items()}}}
            payload = pack.assemble(out, new_lists, version, meta)
            keep = [i["object"] for i in payload["lists"].values()]
            for p in state.packs[-2:]:
                keep += list(p.get("objects", {}).values())
            (out / "keep.txt").write_text("\n".join(dict.fromkeys(keep)) + "\n")
            mirror = [i["object"] for i in payload["lists"].values()]
            if state.packs:
                mirror += list(state.packs[-1].get("objects", {}).values())
            (out / "mirror.txt").write_text("\n".join(dict.fromkeys(mirror)) + "\n")
            result["ok"] = True
    except Exception as exc:  # noqa: BLE001 - reported, never published
        result["failures"].append(f"the run stopped: {type(exc).__name__}: {str(exc)[:300]}")
        log(f"error: {exc!r}")
    result["finished_at"] = version_now()
    out.mkdir(parents=True, exist_ok=True)
    (out / "result.json").write_text(json.dumps(result, indent=1, sort_keys=True, default=list) + "\n")
    state.save()
    write_scoreboard(Path(args.state), result)
    log("PASSED: pack ready to sign" if result["ok"] else "REFUSED: " + "; ".join(result["failures"]))
    return 0 if result["ok"] else EXIT_REFUSED


# ------------------------------------------------------------- scoreboard
HISTORY_FIELDS = ["version", "result", "last_version", "pax_block", "pax_bypass", "pax_nrd",
                  "added_restricted", "added_proxy", "uk57_blocked", "known_good_blocked",
                  "top10k_new", "top10k_held_back", "adult_n", "adult_ref", "adult_new", "adult_last",
                  "proxy_n", "proxy_ref", "proxy_new", "proxy_last", "benign_n", "benign_new_fp",
                  "benign_last_fp", "ref_queries", "reason"]


def write_scoreboard(root: Path, r: dict) -> None:
    sb = root / "scoreboard"
    sb.mkdir(parents=True, exist_ok=True)
    s = (r.get("bench") or {}).get("scores") or {}
    row = {"version": r["version"], "result": "published" if r["ok"] else "refused",
           "last_version": r.get("last_version"),
           "pax_block": (r.get("entries") or {}).get("pax-block"),
           "pax_bypass": (r.get("entries") or {}).get("pax-bypass"),
           "pax_nrd": (r.get("entries") or {}).get("pax-nrd"),
           "added_restricted": (r.get("verification") or {}).get("added_restricted"),
           "added_proxy": (r.get("verification") or {}).get("added_proxy"),
           "uk57_blocked": (r.get("known_good") or {}).get("uk57_blocked"),
           "known_good_blocked": (r.get("known_good") or {}).get("known_good_blocked"),
           "top10k_new": (r.get("top10k") or {}).get("new_blocks"),
           "top10k_held_back": (r.get("top10k") or {}).get("held_back"),
           "ref_queries": ((r.get("bench") or {}).get("queries") or {}).get("reference"),
           "reason": "; ".join(r.get("failures") or [])[:300]}
    for k in ("adult", "proxy"):
        for f in ("n", "ref", "new", "last"):
            row[f"{k}_{f}"] = (s.get(k) or {}).get(f)
    for f, src in (("benign_n", "n"), ("benign_new_fp", "new_fp"), ("benign_last_fp", "last_fp")):
        row[f] = (s.get("benign") or {}).get(src)
    hist = sb / "history.csv"
    new_file = not hist.exists()
    with hist.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=HISTORY_FIELDS)
        if new_file:
            w.writeheader()
        w.writerow(row)
    (sb / "latest.json").write_text(json.dumps(r, indent=1, sort_keys=True, default=list) + "\n")

    def pct(a, n):
        return f"{100 * a / n:.1f}%" if a is not None and n else "-"
    lines = [f"# Filter workflow: {r['version']} ({row['result']})", "",
             f"Built against the last published lists {r.get('last_version')}.", ""]
    if r.get("failures"):
        lines += ["Not published because:", ""] + [f"- {f}" for f in r["failures"]] + [""]
    lines += ["| set | n | reference blocks | this pack | last pack |", "|---|---|---|---|---|"]
    for k, label in (("adult", "held-out restricted"), ("proxy", "web proxies")):
        x = s.get(k) or {}
        lines.append(f"| {label} | {x.get('n', '-')} | {pct(x.get('ref'), x.get('n'))} | "
                     f"{pct(x.get('new'), x.get('n'))} | {pct(x.get('last'), x.get('n'))} |")
    x = s.get("benign") or {}
    lines.append(f"| ordinary sites (blocked, reference open) | {x.get('n', '-')} | - | "
                 f"{x.get('new_fp', '-')} | {x.get('last_fp', '-')} |")
    lines += ["", f"Everyday UK sites blocked: {row['uk57_blocked']}. Known-good blocked: "
              f"{row['known_good_blocked']}. New blocks in the Tranco top 10k: {row['top10k_new']} "
              f"(held back: {row['top10k_held_back']}).",
              f"Homepage-checked additions tonight: {row['added_restricted']} restricted, "
              f"{row['added_proxy']} proxies.", "",
              "Site names in latest.json are encoded (gzip + base64 JSON), never plain text.", ""]
    (sb / "latest.md").write_text("\n".join(lines))


# ---------------------------------------------------------------- others
def cmd_sign(args) -> int:
    doc = pack.sign(Path(args.out), pack.env_key())
    log(f"signed filter pack {doc['payload']['version']} (key {doc['key_id']})")
    return 0


def cmd_published(args) -> int:
    state = State(Path(args.state))
    payload = json.loads((Path(args.out) / "payload.json").read_text())
    state.packs.append({"version": payload["version"], "published_at": version_now(),
                        "objects": {lid: i["object"] for lid, i in payload["lists"].items()}})
    state.save()
    return 0


def cmd_check_published(args) -> int:
    bases = fl.PACK_BASES[:1] if not args.mirror else fl.PACK_BASES[1:]
    payload, files = pack.fetch_published(base=bases[0])
    if payload is None:
        log("no filter pack is published")
        return 1
    log(f"published pack {payload['version']}: {', '.join(sorted(files))} verified")
    if args.version and payload["version"] != args.version:
        log(f"expected {args.version}")
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--work", required=True)
    r.add_argument("--state", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--version", default=None)
    r.add_argument("--code", default=None, help="the commit the pack was built from")
    r.add_argument("--qps", type=float, default=8.0)
    r.add_argument("--ref-budget", type=int, default=1000)
    r.add_argument("--verify-max", type=int, default=1000)
    r.add_argument("--adult-n", type=int, default=400)
    r.add_argument("--benign-n", type=int, default=250)
    r.add_argument("--proxy-n", type=int, default=0, help="0 = the whole hand-kept proxy set")
    s = sub.add_parser("sign")
    s.add_argument("--out", required=True)
    p = sub.add_parser("published")
    p.add_argument("--state", required=True)
    p.add_argument("--out", required=True)
    c = sub.add_parser("check-published")
    c.add_argument("--version", default=None)
    c.add_argument("--mirror", action="store_true")
    a = ap.parse_args(argv)
    if getattr(a, "qps", 0) > 8:
        raise SystemExit("--qps above 8 is not allowed (be polite)")
    if a.cmd == "run":
        if a.ref_budget > 1000:
            raise SystemExit("--ref-budget above 1,000 is not allowed")
        return run(a)
    return {"sign": cmd_sign, "published": cmd_published, "check-published": cmd_check_published}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
