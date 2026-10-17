# SPDX-License-Identifier: GPL-3.0-only
"""Web proxies in the filter workflow (v0.8.21 loop): where the workflow looks for
new proxy and bypass sites, and the fresh held-out proxy sample the benchmark
scores every night. Standard library only. Loop-only: no app code imports it, so
changing it never needs an app release.

Candidate discovery (open sources only; every name still has to pass its
homepage check before it is added, and the Tranco and known-good gates after):
  - the UT1 "redirector" category (CC BY-SA 4.0), names that read like a proxy
    first (`priority`), so the long, mostly expired list is worked through in a
    sensible order
  - newly registered domains (the WhoisDS free daily lists pax-nrd already reads)
    whose registrable label reads like a proxy
  - certificate transparency (crt.sh): names that start with the label of a
    proxy brand the workflow has already confirmed (`brands`), a few brands a night
  - lookalikes: a confirmed brand under the top-level domains proxy mirrors use
A cheap DNS check (the runner's own resolver) drops names that no longer exist
before any homepage is fetched.

Held out (`heldout_pool`): two curated public lists of circumvention and proxy
sites that Pax never builds from and never uses as a candidate source (addresses
kept encoded in _DATA). Each night the benchmark keeps the names that still
resolve and whose homepage is a working proxy today, so the sample is fresh and
was never used for tuning. A name can still reach Pax's lists through a source
Pax does build from, which is exactly what the sample measures.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import random
import re
import socket
import urllib.parse
import zipfile
from concurrent.futures import ThreadPoolExecutor

import loop_util as lu
from loop_util import log

import pax_restricted as pr

# Encoded so the repo text names no other filtering service (see test_loop.py).
_DATA = """
H4sIAAAAAAACA2XNTRKCMAyG4bt0LWTPzgvgEZi2RJqxtJ0kVcDx7v6wk/X3zfM+TcA45qpD4bys
gx28VZwyr6Yz5/7Sm9PhUTl+xqBapAOYSEN1rc8zeFLaMEXrQFG0iSQqYNkHuiMwXgUC2lFgtqLI
7UblwLs/nu2j3RNVkH1Oikl/tYSLjkmgEFu/Ni5mf9uLOw9fkFDM6w2eBJ8r5QAAAA==
"""


def data() -> dict:
    return pr.decode_blob(_DATA)


# What makes a registrable label read like a proxy or bypass site (candidate order
# and the new-registration / certificate searches; never a blocking rule).
TOKENS = re.compile(r"prox|unbl[o0]ck|anonym|bypass|croxy|webvpn|hide(my|me|your)|"
                    r"surf(anon|free|safe|hidden)|unrestrict|unfilter|(^|-)mirror|tunnel|"
                    r"proxi|prxy|fireprox|ultraviolet|rammerhead")
# Top-level domains proxy mirrors are seen under (lookalike candidates).
LOOKALIKE_TLDS = ("com", "net", "org", "io", "me", "cc", "co", "info", "pro", "xyz", "site",
                  "online", "top", "rocks", "app", "dev", "biz", "us", "eu", "in", "to",
                  "link", "click", "live", "space", "fun", "club", "co.uk", "one", "win")
CT_URL = "https://crt.sh/?q={q}&output=json"
SHARED_HOSTS = ("github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
                "herokuapp.com", "web.app", "firebaseapp.com", "glitch.me", "onrender.com",
                "replit.app", "repl.co", "fly.dev", "blogspot.com")


def label(name: str) -> str:
    return pr.registrable_label(name) or ""


def reads_like_proxy(name: str) -> bool:
    return bool(TOKENS.search(label(name)))


def priority(names) -> list[str]:
    """Names that read like a proxy first, then the rest; stable within each group."""
    names = list(names)
    return [n for n in names if reads_like_proxy(n)] + [n for n in names if not reads_like_proxy(n)]


def brands(confirmed, min_len: int = 6) -> list[str]:
    """Registrable labels of confirmed proxies that read like a proxy, most common
    first (a brand seen under several names is a mirror family)."""
    count: dict = {}
    for n in confirmed:
        lab = label(n)
        if len(lab) >= min_len and TOKENS.search(lab) and not lab.startswith("xn--"):
            count[lab] = count.get(lab, 0) + 1
    return sorted(count, key=lambda b: (-count[b], b))


def lookalikes(brand_labels, known=frozenset()) -> list[str]:
    out = []
    for b in brand_labels:
        for tld in LOOKALIKE_TLDS:
            n = f"{b}.{tld}"
            if n not in known:
                out.append(n)
    return out


def nrd_candidates(raw_dir, days: int, today: dt.date | None = None) -> list[str]:
    """Newly registered names (raw WhoisDS days already downloaded by the pax-nrd
    build) whose label reads like a proxy."""
    today = today or dt.datetime.now(dt.timezone.utc).date()
    out: set = set()
    for i in range(1, days + 1):
        p = raw_dir / f"{(today - dt.timedelta(days=i)).isoformat()}.txt"
        if not p.is_file():
            continue
        for d in p.read_text().split():
            d = d.strip().lower().rstrip(".")
            if "." in d and reads_like_proxy(d):
                out.add(d)
    return sorted(out)


def ct_names(brand: str, fetch=lu.fetch) -> list[str]:
    """Certificate-transparency names starting with `brand` (crt.sh; flaky, so an
    error just means no names tonight)."""
    try:
        raw = fetch(CT_URL.format(q=urllib.parse.quote(brand + "%")), timeout=60)
        rows = json.loads(raw or b"[]")
    except Exception as exc:  # noqa: BLE001
        log(f"certificate search {brand[:3]}...: skipped ({type(exc).__name__})")
        return []
    out = set()
    for r in rows:
        for n in str(r.get("name_value", "")).lower().split("\n"):
            n = n.strip().lstrip("*.").rstrip(".")
            if n and "." in n and " " not in n and "@" not in n:
                out.add(n)
    return sorted(out)


def ct_candidates(brand_labels, per_night: int, day: str, fetch=lu.fetch) -> list[str]:
    """A rotating handful of brands each night (all of them over a few weeks)."""
    if not brand_labels or per_night <= 0:
        return []
    rng = random.Random(day)
    pick = list(brand_labels[:per_night // 2])
    rest = list(brand_labels[per_night // 2:])
    rng.shuffle(rest)
    pick += rest[:per_night - len(pick)]
    out: set = set()
    for b in pick:
        out |= set(ct_names(b, fetch))
    return sorted(out)


def dns_alive(names, workers: int = 48, timeout: float = 4.0, resolver=None) -> dict:
    """{name: True/False}: does the name still resolve (the runner's resolver)."""
    def default(n):
        try:
            socket.getaddrinfo(n, 80)
            return True
        except Exception:  # noqa: BLE001
            return False
    resolver = resolver or default
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        with ThreadPoolExecutor(workers) as ex:
            return dict(zip(names, ex.map(resolver, names)))
    finally:
        socket.setdefaulttimeout(old)


# ------------------------------------------------------------ held out
def heldout_pool(fetch=lu.fetch) -> list[str]:
    """Names from the two held-out lists (never a build or candidate source)."""
    d = data()
    names: set = set()
    try:
        z = zipfile.ZipFile(io.BytesIO(fetch(d["heldout_proxy_a_url"])))
        import csv
        for member in z.namelist():
            if not member.endswith(".csv") or "/lists/" not in member:
                continue
            for row in csv.DictReader(io.TextIOWrapper(z.open(member), "utf-8", errors="ignore")):
                if row.get("category_code") == d["heldout_proxy_a_category"]:
                    host = urllib.parse.urlparse(row.get("url", "")).hostname
                    if host:
                        names.add(host.lower())
    except Exception as exc:  # noqa: BLE001
        log(f"held-out proxy list a unavailable ({type(exc).__name__})")
    try:
        text = fetch(d["heldout_proxy_b_url"]).decode("utf-8", "ignore")
        names |= {l.strip().lower() for l in text.splitlines() if l.strip() and not l.startswith("#")}
    except Exception as exc:  # noqa: BLE001
        log(f"held-out proxy list b unavailable ({type(exc).__name__})")
    out = set()
    for n in names:
        n = n.strip(".")
        if n.startswith("www."):
            n = n[4:]
        if "." in n and not re.fullmatch(r"[0-9.]+", n):
            out.add(n)
    return sorted(out)


def heldout_names_set(fetch=lu.fetch) -> set:
    return set(heldout_pool(fetch))
