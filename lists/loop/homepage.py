# SPDX-License-Identifier: GPL-3.0-only
"""Homepage check for the filter workflow: fetch a site's front page (politely,
rate-limited) and read what the site says about itself.

  adult   the page carries the standard adults-only self-label (RTA meta tag or
          rating meta) or its title/body shows restricted content
  proxy   the page is a working web proxy, proxy mirror or public proxy list
          (not a paid proxy network)
  other   answered, but neither
  down    no answer, an error status, or a parked / for-sale page

The patterns are kept encoded in common/pax_restricted.py (homepage_patterns()),
the same patterns Pax's checked lists were built with on 2026-10-17."""
from __future__ import annotations

import re
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from loop_util import UA, RateLimiter, log

import pax_restricted as pr

_P = {k: re.compile(v, re.I) for k, v in pr.homepage_patterns().items()}
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
MAX_BYTES = 200_000


def fetch_home(name: str, timeout: float = 8.0) -> dict:
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_CTX))
    err = "none"
    for scheme in ("http://", "https://"):
        try:
            req = urllib.request.Request(scheme + name + "/", headers={
                "User-Agent": UA, "Accept": "text/html,*/*;q=0.5", "Accept-Language": "en"})
            with opener.open(req, timeout=timeout) as r:
                body = r.read(MAX_BYTES)
                status = getattr(r, "status", 200)
            text = body.decode("utf-8", "ignore")
            t = _TITLE.search(text)
            return {"st": status, "title": (t.group(1)[:150].strip() if t else ""),
                    "rta": bool(_P["rta"].search(text)),
                    "rating": bool(_P["rating"].search(text) or _P["rating2"].search(text)),
                    "pxy": len(_P["pxy"].findall(text)), "adl": len(_P["adl"].findall(text))}
        except urllib.error.HTTPError as exc:
            err = f"http {exc.code}"
        except Exception as exc:  # noqa: BLE001 - try the other scheme, then give up
            err = type(exc).__name__
    return {"st": 0, "err": err}


def verdict(rec: dict) -> str:
    if rec.get("st") != 200:
        return "down"
    title = rec.get("title") or ""
    if _P["park"].search(title):
        return "down"
    if rec.get("rta") or rec.get("rating"):
        return "adult"
    if not _P["neg"].search(title) and (_P["strong"].search(title)
                                        or (_P["atitle"].search(title) and rec.get("adl", 0) >= 2)):
        return "adult"
    if rec.get("adl", 0) >= 8 and not _P["neg"].search(title):
        return "adult"
    if not _P["comm"].search(title) and (_P["ptitle"].search(title) or rec.get("pxy", 0) >= 3):
        return "proxy"
    return "other"


def check(names, qps: float = 8.0, workers: int = 8, timeout: float = 8.0, fetcher=fetch_home) -> dict:
    """{name: verdict}. At most `qps` new requests a second."""
    names = list(dict.fromkeys(names))
    if not names:
        return {}
    limiter = RateLimiter(qps)

    def one(n):
        limiter.wait()
        try:
            return n, verdict(fetcher(n, timeout))
        except Exception:  # noqa: BLE001
            return n, "down"
    out = {}
    with ThreadPoolExecutor(workers) as ex:
        for i, (n, v) in enumerate(ex.map(one, names)):
            out[n] = v
            if (i + 1) % 100 == 0:
                log(f"homepage check: {i + 1}/{len(names)}")
    return out
