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
the same patterns Pax's checked lists were built with on 2026-10-17.

v0.8.21 loop (proxy signals, plain text because they are neutral words): pages
built on the common web-proxy engines (FRAME), "web VPN", unblocker, mirror and
translator-proxy titles (PTITLE2), parked or suspended pages recognised from the
page itself (PARK_BODY: a parking redirect has no title), a gambling page on an
old proxy name is not a proxy (GAMBLE), and the site's own name is taken out of
its title first, so "unblockweb.biz" titled "unblockweb.biz" is not a proxy by
its name alone. Tuned on UT1 redirector pages only, never on the held-out lists
or the hand-kept benchmark set."""
from __future__ import annotations

import re
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from loop_util import UA, RateLimiter, log

import pax_restricted as pr

_P = {k: re.compile(v, re.I) for k, v in pr.homepage_patterns().items()}
FRAME = re.compile(r"uv\.bundle\.js|uv\.config\.js|__uv\$config|rammerhead|scramjet|bare-mux|baremux|"
                   r"epoxy-transport|libcurl-transport|node-unblocker|womginx|holy ?unblocker|"
                   r"miniproxy|phproxy|php-proxy|__cpo=|/browse\.php\?u=|includes/process\.php|"
                   r"proxy\.php\?(?:url|u|q)=", re.I)
PTITLE2 = re.compile(r"web ?vpn|online vpn|vpn (?:online|browser)|unblock(?:ed)? (?:sites|websites|any|youtube|videos?)|"
                     r"bypass (?:filters?|blocks?|restrictions?|censorship)|(?:proxy|unblocked?) mirrors?|"
                     r"mirror (?:sites?|list|links?)|translat(?:e|or) proxy|proxy (?:browser|online|free)", re.I)
GAMBLE = re.compile(r"casino|\bslots?\b|togel|cá cược|nhà cái|tài xỉu|\bbet\d|sunwin|hitclub|\bjudi\b|gacor|baccarat", re.I)
PARK_BODY = re.compile(r"location\.href\s*=\s*[\"']/lander|suspendedpage|defaultwebpage\.cgi|buy\.nameshift\.com|"
                       r"webserver is functioning normally|parkingcrew|sedoparking|bodis\.com|afternic\.com/forsale", re.I)
_LINK = re.compile(r"""href\s*=\s*["']?https?://([a-z0-9][a-z0-9.-]*[a-z0-9])""", re.I)
MAX_LINKS = 300
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
                    "pxy": len(_P["pxy"].findall(text)), "adl": len(_P["adl"].findall(text)),
                    "frame": len(FRAME.findall(text)), "park": bool(PARK_BODY.search(text[:20_000])),
                    "host": name, "links": links(text, name)}
        except urllib.error.HTTPError as exc:
            err = f"http {exc.code}"
        except Exception as exc:  # noqa: BLE001 - try the other scheme, then give up
            err = type(exc).__name__
    return {"st": 0, "err": err}


def links(text: str, own: str) -> list[str]:
    """Other sites a page links to (v0.8.21 loop: proxy pages and proxy directories
    link to more proxies, so their links become candidates)."""
    own_label = pr.registrable_label(own) or own
    out: dict = {}
    for m in _LINK.finditer(text):
        h = m.group(1).lower().rstrip(".")
        if h.startswith("www."):
            h = h[4:]
        if "." not in h or pr.registrable_label(h) == own_label or re.fullmatch(r"[0-9.]+", h):
            continue
        out[h] = None
        if len(out) >= MAX_LINKS:
            break
    return list(out)


def _without_own_name(title: str, host: str) -> str:
    """The title with the site's own name (and its registrable label) taken out."""
    if not host:
        return title
    lab = pr.registrable_label(host) or ""
    for word in sorted({host, host.removeprefix("www."), lab}, key=len, reverse=True):
        if len(word) >= 4:
            title = re.sub(re.escape(word) + r"(\.[a-z.]+)?", " ", title, flags=re.I)
    return title


def verdict(rec: dict) -> str:
    if rec.get("st") != 200:
        return "down"
    title = rec.get("title") or ""
    if _P["park"].search(title) or rec.get("park"):
        return "down"
    if rec.get("rta") or rec.get("rating"):
        return "adult"
    if not _P["neg"].search(title) and (_P["strong"].search(title)
                                        or (_P["atitle"].search(title) and rec.get("adl", 0) >= 2)):
        return "adult"
    if rec.get("adl", 0) >= 8 and not _P["neg"].search(title):
        return "adult"
    if GAMBLE.search(title):
        return "other"
    own = _without_own_name(title, rec.get("host", ""))
    if not _P["comm"].search(title) and (_P["ptitle"].search(own) or PTITLE2.search(own)
                                         or rec.get("pxy", 0) >= 3 or rec.get("frame", 0) >= 1):
        return "proxy"
    return "other"


def check(names, qps: float = 8.0, workers: int = 8, timeout: float = 8.0, fetcher=fetch_home,
          links_out: dict | None = None) -> dict:
    """{name: verdict}. At most `qps` new requests a second. With `links_out`, the
    links of every page judged a proxy go into it ({name: [linked names]})."""
    names = list(dict.fromkeys(names))
    if not names:
        return {}
    limiter = RateLimiter(qps)

    def one(n):
        limiter.wait()
        try:
            rec = fetcher(n, timeout)
            v = verdict(rec)
            if links_out is not None and v == "proxy" and rec.get("links"):
                links_out[n] = rec["links"]
            return n, v
        except Exception:  # noqa: BLE001
            return n, "down"
    out = {}
    with ThreadPoolExecutor(workers) as ex:
        for i, (n, v) in enumerate(ex.map(one, names)):
            out[n] = v
            if (i + 1) % 100 == 0:
                log(f"homepage check: {i + 1}/{len(names)}")
    return out
