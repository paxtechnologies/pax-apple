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
  - (round 2) the Tranco top 1M below the top 10k: names whose registrable label
    reads like a proxy or a VPN (`tranco_candidates`), the list the workflow
    already downloads for its gates
  - (round 4) the UT1 "vpn" category, from the same maintainer as the redirector
    category (`ut1_vpn`)
  - (round 5) the Chrome UX Report top-sites lists (CC BY 4.0), worldwide and per
    country (20 always, 5 more a night in turn): names that read like a proxy or
    VPN (`crux_candidates`)
  - (round 5b) the Majestic Million (CC BY 3.0), ranked by linking sites: names
    that read like a proxy or VPN (`majestic_candidates`)
  - (round 5) curated circumvention lists other maintainers publish under open
    licences (`curated()`, `curated_candidates`): VPN / proxy / bypass categories of
    public DNS blocklists and per-engine mirror lists, read as candidates only
  - (round 2) GitHub: the published sites (repository homepages and
    <user>.github.io sites) of open-source web-proxy and unblocker projects, found
    by repository topic and name (`github_candidates`, the GitHub search API);
    this is how proxies hosted on shared hosts (github.io, pages.dev, vercel.app,
    netlify.app, ...) are found, one host name at a time
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


VPN_TOKEN = re.compile(r"vpn")


def label(name: str) -> str:
    return pr.registrable_label(name) or ""


def reads_like_proxy(name: str) -> bool:
    return bool(TOKENS.search(label(name)))


def reads_like_bypass(name: str) -> bool:
    """A proxy or a VPN by its name (candidate selection only, never a rule)."""
    lab = label(name)
    return bool(TOKENS.search(lab) or VPN_TOKEN.search(lab))


def tranco_candidates(top, start: int = 10_000) -> list[str]:
    """Ranked names below the top `start` whose label reads like a proxy or VPN,
    in rank order."""
    return [n for n in top[start:] if reads_like_bypass(n)]


GITHUB_SEARCH = "https://api.github.com/search/repositories?q={q}&sort=updated&order=desc&per_page=100&page={page}"
GITHUB_QUERIES = ("topic:web-proxy", "topic:unblocker", "topic:proxy-site", "topic:ultraviolet",
                  "topic:interstellar", "topic:holy-unblocker", "topic:rammerhead", "topic:scramjet",
                  "topic:unblocked", "topic:webproxy", "topic:proxy-website", "topic:school-proxy",
                  "unblocker in:name", "github.io in:name proxy", "github.io in:name unblock")
# Hosts a repository homepage often points at that are never the proxy itself.
NOT_SITES = re.compile(r"(^|\.)(github\.com|discord\.(gg|com)|youtube\.com|youtu\.be|npmjs\.com|patreon\.com|"
                       r"ibb\.co|imgur\.com|twitter\.com|x\.com|t\.me|reddit\.com|google\.com|"
                       r"docs\.[a-z0-9.-]+|pypi\.org|crates\.io|wikipedia\.org)$")


GITHUB_README = "https://api.github.com/repos/{full}/readme"
_URL_HOST = re.compile(r"https?://([a-z0-9][a-z0-9.-]*[a-z0-9])", re.I)
README_MAX_HOSTS = 60


def readme_hosts(text: str) -> list[str]:
    """Hosts a README links to (unblocker READMEs list their official mirrors)."""
    out: dict = {}
    for m in _URL_HOST.finditer(text or ""):
        out[m.group(1).lower()] = None
        if len(out) >= README_MAX_HOSTS:
            break
    return list(out)


def github_candidates(token: str | None = None, pages: int = 2, fetch=None, pause: float = 2.5,
                      readmes: int = 80) -> list[str]:
    """Published sites of open-source web-proxy / unblocker repositories (homepage
    field and <user>.github.io repositories), then the sites the READMEs of the
    most recently updated `readmes` of them link to. Flaky or rate-limited
    searches just give fewer names tonight."""
    import time
    import urllib.request

    def default_fetch(url):
        raw = url.endswith("/readme")
        headers = {"Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json",
                   "User-Agent": lu.UA}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:  # noqa: S310
            return r.read()
    fetch = fetch or default_fetch
    out: dict = {}
    repos: dict = {}

    def keep(h):
        h = h.lower().strip(".")
        if h.startswith("www."):
            h = h[4:]
        if "." in h and not re.fullmatch(r"[0-9.:]+", h) and not NOT_SITES.search(h):
            out[h] = None
    for q in GITHUB_QUERIES:
        for page in range(1, pages + 1):
            try:
                items = json.loads(fetch(GITHUB_SEARCH.format(q=urllib.parse.quote(q), page=page)) or b"{}").get("items") or []
            except Exception as exc:  # noqa: BLE001
                log(f"github search {q.split(':')[0]}: skipped ({type(exc).__name__})")
                break
            for it in items:
                if it.get("full_name"):
                    repos.setdefault(it["full_name"], it.get("updated_at") or "")
                hosts = []
                hp = (it.get("homepage") or "").strip()
                if hp:
                    if "://" not in hp:
                        hp = "https://" + hp
                    hosts.append(urllib.parse.urlparse(hp).hostname or "")
                name = (it.get("name") or "").lower()
                if name.endswith(".github.io") and name.count(".") == 2:
                    hosts.append(name)
                for h in hosts:
                    keep(h)
            if len(items) < 100:
                break
            if pause:
                time.sleep(pause)
        if pause:
            time.sleep(pause)
    for full in sorted(repos, key=lambda f: repos[f], reverse=True)[:readmes]:
        try:
            text = fetch(GITHUB_README.format(full=full)).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001 - no README, or rate-limited
            continue
        for h in readme_hosts(text):
            keep(h)
    return list(out)


# Round 5: curated, openly licensed lists of circumvention sites (VPN services,
# web proxies, unblocker mirrors) kept by other maintainers. Candidates only: each
# name still needs a DNS answer, a working proxy homepage and every gate. None of
# them is (or is built from) a held-out list. (id, url, format, licence)
# Addresses kept encoded like the held-out lists (see test_loop.py); `curated()`
# gives (id, url, format, licence). Licences: Unlicense, CC0-1.0, Apache-2.0.
_CURATED = """
H4sIAAAAAAACA62UXWvbMBRA/4ufKysbfepbl8AYtFC2lhZKKTfyja1GH+beqyZe6X+fbIewvGQe
+MmWMOccSVgfhUkEglVx9fxcSAoBHRcXRSPS8pXWBLuyttKkdWIkE4NgkNJEr381UMXdY2O5RULS
31w02xvLwtoDS54ZB/dHZhU92NC/PQRnDQbG4uXiaFU766pZ1Y8Z+Dr6z+gx1Dag8pYo0rS1G8eb
qAk3Do1cqnXvd1mpe8Nx/vVgLGUvJ/7lcqG+lIvBbpocqRg2KJ1ady3wtITFfgW0vQXplwtYWz7J
GHbB5IOtI1lk/d6GA/1szfiJYg/OTcq4RQJOvMJ3jb/jUIBUQtuOW3Gw6JGrM/Ws3tmwZVVBVxGC
308qWNpqCWTXMenv4JHVZbkY5XcU95266Zl6Bd2qZz6VbxxDBvcPNfjy4LoF06D6epoRa5yzIOOm
y23GUz5E54BmjPjxF3Z6DIH3SA1CNWPKzyN0eggPP/6MEeNN8j8BScThrAUDcXqCUNrk+2XOo7g/
IKdHJImthRkTHgbgPwNePv8Al/vYrrEGAAA=
"""


def curated() -> tuple:
    return tuple(tuple(x) for x in pr.decode_blob(_CURATED)["curated"])


# Infrastructure names some of these lists carry for completeness (encrypted DNS
# endpoints) that are never a web proxy site: not worth a homepage check.
_INFRA = re.compile(r"^(dns|doh|dot|ns\d*|resolver\d*|dnscrypt|odoh)[.-]")
_HOSTLINE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+")


def parse_curated(text: str, fmt: str) -> list[str]:
    """Host names from a plain, hosts-format, adblock-style or JSON link list."""
    if fmt == "json-links":
        try:
            obj = json.loads(text)
        except ValueError:
            return []
        items = obj.get("links") if isinstance(obj, dict) else obj
        raw = [urllib.parse.urlparse(u if "://" in u else "https://" + u).hostname or ""
               for u in (items or []) if isinstance(u, str)]
    else:
        raw = []
        for line in text.splitlines():
            line = line.split("#", 1)[0].split("!", 1)[0].strip()
            if not line:
                continue
            line = _HOSTLINE.sub("", line)
            line = line.removeprefix("||").removeprefix("*.").split("^", 1)[0].split()[0]
            if "://" in line:
                line = urllib.parse.urlparse(line).hostname or ""
            raw.append(line)
    out = []
    for n in raw:
        n = n.strip().lower().strip(".")
        if n.startswith("www."):
            n = n[4:]
        if ("." in n and re.fullmatch(r"[a-z0-9.-]+", n) and not re.fullmatch(r"[0-9.]+", n)
                and not _INFRA.search(n)):
            out.append(n)
    return list(dict.fromkeys(out))


def curated_candidates(fetch=lu.fetch, sources=None) -> dict:
    """{source id: names}. A list that is down tonight just gives no names."""
    out: dict = {}
    for sid, url, fmt, _lic in (sources if sources is not None else curated()):
        try:
            out[sid] = parse_curated(fetch(url).decode("utf-8", "ignore"), fmt)
        except Exception as exc:  # noqa: BLE001
            log(f"curated list {sid}: unavailable ({type(exc).__name__})")
            out[sid] = []
    return out


# Round 5: the Chrome UX Report top-sites lists (CrUX, Google, CC BY 4.0; monthly
# snapshots of the public BigQuery data published as CSV files): the origins Chrome
# users actually visit, worldwide and per country. Names whose registrable label
# reads like a proxy or VPN become candidates, like the Tranco names. These lists
# rank sites by real visits, so they reach busy proxies that never make Tranco.
CRUX_URL = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/{path}"
CRUX_COUNTRIES = ("gb", "ie", "us", "ca", "au", "nz", "in", "pk", "id", "ph", "tr", "ru", "ir", "ae", "sa", "eg",
                  "vn", "br", "de", "fr")


# More countries, a few a night in turn (all of them within a fortnight).
CRUX_ROTATING = ("my", "th", "sg", "hk", "tw", "kr", "jp", "cn", "bd", "lk", "np", "kz", "ua", "by", "uz", "az",
                 "ge", "am", "iq", "jo", "lb", "kw", "qa", "om", "bh", "ma", "dz", "tn", "ng", "ke", "za", "gh",
                 "mx", "ar", "co", "cl", "pe", "ve", "es", "it", "nl", "be", "pl", "ro", "gr", "se", "no", "dk",
                 "fi", "pt", "cz", "hu", "at", "ch", "il", "sy", "af", "mm", "kh", "la")
CRUX_ROTATING_PER_NIGHT = 5


def crux_rotation(day: str, n: int = CRUX_ROTATING_PER_NIGHT) -> tuple:
    """The rotating countries for `day` (yyyy-mm-dd): the next `n` in turn."""
    i = dt.date.fromisoformat(day).toordinal() * n % len(CRUX_ROTATING)
    return tuple((CRUX_ROTATING * 2)[i:i + n])


def crux_months(today: dt.date | None = None, back: int = 3) -> list[str]:
    """yyyymm of the last `back` full months, newest first (a snapshot lands a few
    days into the next month)."""
    d = (today or dt.datetime.now(dt.timezone.utc).date()).replace(day=1)
    out = []
    for _ in range(back):
        d = (d - dt.timedelta(days=1)).replace(day=1)
        out.append(d.strftime("%Y%m"))
    return out


def parse_crux(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        origin = line.split(",", 1)[0].strip()
        if "://" not in origin:
            continue
        h = (urllib.parse.urlparse(origin).hostname or "").lower()
        if h.startswith("www."):
            h = h[4:]
        if "." in h and not re.fullmatch(r"[0-9.]+", h):
            out.append(h)
    return out


def crux_candidates(fetch=lu.fetch, countries=None, today: dt.date | None = None) -> list[str]:
    """Names in the CrUX top-sites lists (global first, then each country, rank
    order) that read like a proxy or VPN. A missing month or country is skipped."""
    import gzip
    out: dict = {}
    if countries is None:
        day = (today or dt.datetime.now(dt.timezone.utc).date()).isoformat()
        countries = CRUX_COUNTRIES + crux_rotation(day)
    months = crux_months(today)
    for where in ("global",) + tuple(f"country/{c}" for c in countries):
        for m in months:
            try:
                text = gzip.decompress(fetch(CRUX_URL.format(path=f"{where}/{m}.csv.gz"), timeout=120)).decode(
                    "utf-8", "ignore")
            except Exception:  # noqa: BLE001 - not published yet, or the host is down
                continue
            for n in parse_crux(text):
                if reads_like_bypass(n):
                    out[n] = None
            break
        else:
            log(f"chrome top sites {where}: unavailable")
    return list(out)


# Round 5b: the Majestic Million (Majestic-12, CC BY 3.0), ranked by the number of
# sites linking to a name. Long-lived proxies collect links for years, so it reaches
# established ones that Tranco and the Chrome lists miss.
MAJESTIC_URL = "https://downloads.majestic.com/majestic_million.csv"


def majestic_candidates(fetch=lu.fetch, start: int = 10_000) -> list[str]:
    """Names below rank `start` whose label reads like a proxy or VPN, in rank order."""
    try:
        text = fetch(MAJESTIC_URL, timeout=180).decode("utf-8", "ignore")
    except Exception as exc:  # noqa: BLE001
        log(f"majestic million unavailable ({type(exc).__name__})")
        return []
    out = []
    for i, line in enumerate(text.splitlines()):
        parts = line.split(",")
        if i == 0 or len(parts) < 3 or i <= start:
            continue
        n = parts[2].strip().lower()
        if "." in n and reads_like_bypass(n):
            out.append(n)
    return list(dict.fromkeys(out))


def ut1_vpn(fetch=lu.fetch) -> list[str]:
    """The UT1 "vpn" category (same maintainer and licence, CC BY-SA 4.0, as the
    redirector category the workflow already reads): VPN services and their sites.
    A candidate source only; every name still needs its homepage verdict."""
    import tarfile
    url = pr.source("verify_bypass_url").replace("redirector", "vpn")
    try:
        data = fetch(url)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            member = next(m for m in tf.getmembers() if m.name.endswith("/domains") or m.name == "domains")
            text = tf.extractfile(member).read().decode("utf-8", "ignore")
    except Exception as exc:  # noqa: BLE001
        log(f"vpn category unavailable ({type(exc).__name__})")
        return []
    out = []
    for line in text.splitlines():
        n = line.strip().lower().strip(".")
        if n.startswith("www."):
            n = n[4:]
        if "." in n and not n.startswith("#") and not re.fullmatch(r"[0-9.]+", n):
            out.append(n)
    return list(dict.fromkeys(out))


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
            if "." in d and reads_like_bypass(d):
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


def dns_alive(names, workers: int = 128, timeout: float = 4.0, resolver=None) -> dict:
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
