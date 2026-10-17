# SPDX-License-Identifier: GPL-3.0-only
"""The benchmark gate: fresh held-out samples, scored by the candidate pack, the
last published pack and a reference resolver.

Held out means drawn from sources Pax's lists are not built from (addresses kept
encoded in common/pax_restricted.py, sources.heldout_*), plus a hand-kept set of
web proxies (lists/gates/proxy-heldout.txt) and a random slice of ordinary sites
(Tranco ranks 10,001-200,000). Each night's adult sample avoids names sampled on
earlier nights, so the test set is always fresh.

The reference resolver is only a yardstick: its answers are never copied into
Pax's lists. It is asked politely (at most `qps` queries a second, at most
`budget` queries a run). A neutral, non-filtering resolver is used to keep only
adult names that still exist.

The gate is paired: both packs are scored on the same names, so the difference
is the list change itself. A pack regresses when, against the last published
pack, it loses more held-out restricted or proxy names than it gains by more
than the noise allowance, or blocks more ordinary sites the reference leaves
open.

v0.8.21 loop, web proxies:
  - the hand-kept proxy set is scored on names that still resolve (a neutral
    resolver), because a name that no longer exists is "blocked" by the reference
    (NXDOMAIN) and unreachable through Pax alike; counting it skewed the score
  - a fresh held-out proxy sample (proxy.heldout_pool: lists Pax never builds
    from): names that resolve tonight and whose homepage is a working proxy today
  - proxy gate: Pax's decisions are deterministic, so on the same names the
    candidate pack may not lose a single proxy the last pack blocked unless it
    gains at least as many (no noise allowance)"""
from __future__ import annotations

import math
import random
from concurrent.futures import ThreadPoolExecutor

import loop_util as lu
from loop_util import Budget, RateLimiter, log

import build
import homepage
import pax_restricted as pr
import proxy as px

NEUTRAL_DOH = "https://cloudflare-dns.com/dns-query"
HELDOUT = ("heldout_a_url", "heldout_b_url", "heldout_c_url")


def resolve(name: str, lookup) -> tuple[int, list[str]] | None:
    try:
        return pr.answer_addresses(lookup(pr.build_query(name, pr.QTYPE_A)))
    except Exception:  # noqa: BLE001
        return None


def ref_verdict(name: str, lookup) -> bool | None:
    """True = the reference blocks it, False = open, None = no usable answer."""
    r = resolve(name, lookup)
    if r is None:
        return None
    rcode, addrs = r
    if rcode == pr.RCODE_NXDOMAIN:
        return True
    if rcode != pr.RCODE_NOERROR:
        return None
    return any(a in pr.BLOCK_PAGE_IPS for a in addrs)


def alive(name: str, lookup) -> bool:
    r = resolve(name, lookup)
    return bool(r and r[0] == pr.RCODE_NOERROR and r[1])


def polite_map(fn, names, qps: float, budget: Budget, workers: int = 4) -> dict:
    limiter = RateLimiter(qps)

    def one(n):
        if not budget.take():
            return n, "skipped"
        limiter.wait()
        return n, fn(n)
    with ThreadPoolExecutor(workers) as ex:
        return dict(ex.map(one, names))


# Share of each night's adult sample per held-out source: the curated lists weigh
# more than the big, older one (whose many parked names make a poor yardstick).
SHARES = {"heldout_a_url": 0.5, "heldout_c_url": 0.15, "heldout_b_url": 0.35}


def heldout_adult_pool(fetch=lu.fetch) -> dict:
    """{source key: sorted names}."""
    pools: dict = {}
    for key in HELDOUT:
        try:
            text = fetch(pr.source(key)).decode("utf-8", "ignore")
        except Exception as exc:  # noqa: BLE001 - one source down still leaves a sample
            log(f"held-out source {key} unavailable ({type(exc).__name__})")
            continue
        pools[key] = sorted({n for n in build.parse_names(text, allow_single_label=False)
                             if not n.startswith("www.")})
    return pools


def draw(pools: dict, n: int, seen: set, rng) -> list[str]:
    """Up to `n` names, split across sources by SHARES, never a name sampled before."""
    out: list[str] = []
    for key, share in SHARES.items():
        taken = set(out)
        pool = [d for d in pools.get(key, []) if d not in taken and lu.name_hash(d) not in seen]
        rng.shuffle(pool)
        out += pool[:max(1, round(n * share))]
    return out


def noise(n: int, share: float, floor: int) -> int:
    return max(floor, math.ceil(share * n))


def paired(names, ref: dict, new, last) -> dict:
    """Scores on the names the reference answered for."""
    L = [d for d in names if ref.get(d) in (True, False)]
    nb = {d: new(d) for d in L}
    lb = {d: last(d) for d in L}
    return {"n": len(L), "ref": sum(ref[d] for d in L), "new": sum(nb.values()), "last": sum(lb.values()),
            "losses": sum(1 for d in L if lb[d] and not nb[d]),
            "gains": sum(1 for d in L if nb[d] and not lb[d]),
            "new_open_ref_blocks": sum(1 for d in L if ref[d] and not nb[d]),
            "new_fp": sum(1 for d in L if nb[d] and not ref[d]),
            "last_fp": sum(1 for d in L if lb[d] and not ref[d])}


PROXY_KEYS = ("proxy", "proxy_fresh")


def regressions(scores: dict) -> list[str]:
    out = []
    for key in PROXY_KEYS:
        s = scores.get(key)
        if s and s["n"] and s["losses"] > s["gains"]:
            out.append(f"{key}: {s['losses']} proxies lost vs {s['gains']} gained against the last pack "
                       f"(n={s['n']}; the proxy gate allows no net loss)")
    for key in ("adult",):
        s = scores.get(key)
        if not s or not s["n"]:
            continue
        allow = noise(s["n"], 0.01, 2)
        if s["losses"] - s["gains"] > allow:
            out.append(f"{key}: {s['losses']} held-out names lost vs {s['gains']} gained "
                       f"(n={s['n']}, noise allowance {allow})")
    s = scores.get("benign")
    if s and s["n"]:
        allow = noise(s["n"], 0.005, 1)
        if s["new_fp"] - s["last_fp"] > allow:
            out.append(f"benign: {s['new_fp']} ordinary sites blocked that the reference leaves open, "
                       f"was {s['last_fp']} (n={s['n']}, noise allowance {allow})")
    return out


def fresh_proxies(n: int, exclude: set, rng, qps: float, neutral_lookup, fetch=lu.fetch,
                  labeller=None, max_probe: int = 900, max_pages: int = 600) -> tuple[list[str], dict]:
    """Up to `n` held-out names that resolve tonight and whose homepage is a working
    proxy today. Returns (names, counts)."""
    pool = [d for d in px.heldout_pool(fetch) if d not in exclude]
    rng.shuffle(pool)
    pool = pool[:max_probe]
    live = polite_map(lambda d: alive(d, neutral_lookup), pool, qps, Budget(len(pool)))
    up = [d for d in pool if live.get(d) is True][:max_pages]
    labeller = labeller or (lambda names: homepage.check(names, qps=qps))
    v = labeller(up) if up else {}
    names = [d for d in up if v.get(d) == "proxy"][:n]
    return names, {"pool": len(pool), "resolving": len(up), "working_proxies": len(names)}


def run(new, last, tranco: list[str], seen: set, seed: int, qps: float = 8.0, budget: int = 1000,
        adult_n: int = 400, benign_n: int = 250, proxy_n: int = 0, ref_url: str | None = None,
        neutral_url: str = NEUTRAL_DOH, fetch=lu.fetch, ref_lookup=None, neutral_lookup=None,
        proxy_fresh_n: int = 0, labeller=None) -> dict:
    """Returns {"scores", "regressions", "sampled" (names to remember), "queries", "error"}."""
    rng = random.Random(seed)
    ref_lookup = ref_lookup or pr.doh_lookup(ref_url or pr.source("reference_doh"), timeout=5.0)
    neutral_lookup = neutral_lookup or pr.doh_lookup(neutral_url, timeout=5.0)
    pools = heldout_adult_pool(fetch)
    cand = draw(pools, adult_n * 2, seen, rng)
    neutral_budget = Budget(len(cand))
    live = polite_map(lambda d: alive(d, neutral_lookup), cand, qps, neutral_budget)
    sets = {k: set(v) for k, v in pools.items()}
    alive_pools = {k: [d for d in cand if live.get(d) is True and d in sv] for k, sv in sets.items()}
    adult = draw(alive_pools, adult_n, set(), rng)[:adult_n]
    proxy = lu.gate_names("proxy-heldout.txt")
    if proxy_n:
        proxy = rng.sample(proxy, min(proxy_n, len(proxy)))
    plive = polite_map(lambda d: alive(d, neutral_lookup), proxy, qps, Budget(len(proxy)))
    proxy = [d for d in proxy if plive.get(d) is True]
    fresh, fresh_counts = ([], {})
    if proxy_fresh_n:
        fresh, fresh_counts = fresh_proxies(proxy_fresh_n, set(proxy) | set(adult), rng, qps,
                                            neutral_lookup, fetch, labeller)
    mid = tranco[10_000:200_000]
    benign = rng.sample(mid, min(benign_n, len(mid))) if mid else []
    names = list(dict.fromkeys(adult + proxy + fresh + benign))
    ref_budget = Budget(budget)
    ref = polite_map(lambda d: ref_verdict(d, ref_lookup), names, qps, ref_budget)
    answered = sum(1 for v in ref.values() if v in (True, False))
    out = {"queries": {"reference": ref_budget.used, "neutral": neutral_budget.used},
           "proxy_fresh": fresh_counts,
           "sampled": adult, "error": None, "regressions": [], "scores": {}}
    if not names or answered < 0.8 * len(names):
        out["error"] = (f"the reference resolver answered only {answered} of {len(names)} names; "
                        "the benchmark can't be trusted tonight")
        return out
    out["scores"] = {"adult": paired(adult, ref, new, last), "proxy": paired(proxy, ref, new, last),
                     "benign": paired(benign, ref, new, last)}
    if proxy_fresh_n:
        out["scores"]["proxy_fresh"] = paired(fresh, ref, new, last)
    out["regressions"] = regressions(out["scores"])
    return out
