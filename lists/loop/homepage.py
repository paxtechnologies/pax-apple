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
its name alone. Paid proxy networks (residential, datacenter, rotating proxies)
count as proxies too: they bypass a DNS filter the same way a VPN does. Tuned on UT1 redirector pages only, never on the held-out lists
or the hand-kept benchmark set.

Round 2 (candidate_verdict, used for new candidates and the top-10k gate only):
consumer VPN services count as bypass sites (VPN_TITLE: the page sells or gives
away a VPN; enterprise gateways, VPN detection services, reviews and news are
not), and pages that only use the word "proxy" for something else are not
proxies (NOT_PROXY: developer and network tools, email security, game test
servers, trading-card "proxies"; "unblock" inside another word). Tuned on Tranco
names that read like a proxy or VPN, never on the held-out lists. The benchmark
keeps labelling its fresh held-out sample with `verdict`, so what counts as a
working proxy there does not move with these changes. Round 4: a handful of proxy
words in the body (fewer than 10) with no proxy word in the title is no longer
enough on its own. Round 5: "unblock" alone in the title (no proxy code, fewer
than 3 proxy words, no proxy or VPN word) is not enough either, and drain and
plumbing services and organisations' own remote-access pages are not proxies.
Round 6 (policy decided 2026-10-17): unblocked-games pages count as bypass sites
(unblocked_games), reversing round 4/5; paid proxy networks and consumer VPN pages
stay bypass sites (VPN review and affiliate pages too, through the bypass list)."""
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
PAID_PROXY = re.compile(r"prox(?:y|ies)", re.I)
VPN_TITLE = re.compile(r"vpns?(?![a-z])|впн", re.I)  # round 6: "VPNs" too
VPN_WORD = re.compile(r"(?<![a-z])vpn|vpn(?![a-z])|впн", re.I)
# Round 6 (decided 2026-10-17): VPN review, ranking and affiliate pages count as bypass
# sites like the VPNs they sell, so "review", "vs" and "compare" no longer rule a page out.
VPN_NOT = re.compile(r"\bsdk\b|detect|log ?in\b|log ?out\b|sign ?in\b|portal|big-ip|globalprotect|anyconnect|"
                     r"fortinet|fortigate|pulse secure|citrix|\bssl ?vpn\b|\bedu|universit|school|news|"
                     r"router|firewall|enterprise|corporate|business vpn|zero trust|"
                     r"\bztna\b|sase|mesh|tailscale|for teams|business|\bauto|\bcars?\b|voiture|capital|"
                     r"invest|\bimages?\b|\bpng\b|guides?\b|it services|\bblog|без vpn|without (?:a )?vpn|"
                     r"no vpn|\bbans?\b|petition|campaign", re.I)
NOT_PROXY = re.compile(r"debug|developer|reverse proxy|load balanc|api gateway|ingress|service mesh|squid|haproxy|"
                       r"nginx|envoy|traefik|e-?mail|nospam|spam filter|card maker|proxy cards?|\bmtg\b|"
                       r"magic: the gathering|free ?fire|\bob\d\d\b|apk|game server|minecraft|velocity|"
                       r"bungeecord|proxy (?:vote|voting|statement|advisor)|shareholder|agentic|"
                       r"detection api|ip lookup|whois|\bproxy (?:check|test)er\b|handle proxy|\bdoi\b|"
                       r"drains?\b|sewer|plumb|toilet|government vpn|remote access|staff vpn|employee", re.I)
# "Unblocked games" sites: browser games re-hosted to get past school filters. Decided
# 2026-10-17 (round 6): these count as bypass sites. The title has to say "unblocked"
# as a word and show it is a games page (UNBLOCKED_GAMES); a games word alone (a
# publisher, an education site) is still not enough, see unblocked_games().
GAMES = re.compile(r"\bgames?\b|\bplay\b|clicker|\b\d+x\b", re.I)
UNBLOCKED_WORD = re.compile(r"\bunblocked\b", re.I)
GAMES_LABEL = re.compile(r"game|ubg", re.I)
# Not an unblocked-games page: a question or a how-to about one, news, a plugin, a tracker.
UNBLOCKED_NOT = re.compile(r"\?|how to|\bnews\b|\bblog\b|wordpress|plugin|tracker|review|agentic|"
                           r"software|developer|\bapi\b", re.I)
# The games publishers' and learning sites' own names: their pages are not bypass sites
# even if a title mentions "unblocked" (mirrors under other names still are).
GAMES_PUBLISHERS = frozenset({"poki", "crazygames", "coolmathgames", "coolmath", "miniclip", "kongregate",
                              "armorgames", "hoodamath", "abcya", "mathplayground", "y8", "friv", "kizi",
                              "addictinggames", "newgrounds", "itch", "roblox", "minecraft", "steampowered",
                              "epicgames", "khanacademy", "pbskids", "funbrain", "nitrotype", "prodigygame"})
PROXY_WORD = re.compile(r"prox|vpn|bypass|anonym|hide (?:my|your) ip|mirror", re.I)
WEAK_OK = re.compile(r"unblock|hid(?:e|ing) (?:my|your)|glype|censor|pirate ?bay|\btpb\b", re.I)
UNBLOCK_ONLY = re.compile(r"unblock", re.I)
# A bot check or loading screen says nothing about the site behind it.
CHALLENGE = re.compile(r"^\s*(?:loading\.*|just a moment\.*|attention required.*|security check.*|"
                       r"checking your browser.*|ddos-guard|安全检查.*|one moment, please\.*)\s*$", re.I)
_EMBEDDED_UNBLOCK = re.compile(r"(?<=[a-z])unblock", re.I)
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
    if (_P["ptitle"].search(own) or PTITLE2.search(own) or rec.get("pxy", 0) >= 3
            or rec.get("frame", 0) >= 1):
        return "proxy"
    # Paid proxy networks sell the same way round Pax's filter (a browser set to use
    # one resolves names at the proxy), like the VPNs the bypass list already holds.
    if _P["comm"].search(own) and PAID_PROXY.search(own):
        return "proxy"
    return "other"


def unblocked_games(rec: dict) -> bool:
    """Round 6: a re-hosted games page made to get past school filters ("Unblocked
    Games 76", "Slope Unblocked - Play Free"). The title says "unblocked" as a word
    (not "sunblock"), and either names games / play / clicker / "6x" or sits on a
    name that reads like games; never a question, news, a plugin or a publisher."""
    host = rec.get("host", "")
    title = _without_own_name(_EMBEDDED_UNBLOCK.sub(" ", rec.get("title") or ""), host)
    if not UNBLOCKED_WORD.search(title) or UNBLOCKED_NOT.search(title):
        return False
    if GAMBLE.search(title) or NOT_PROXY.search(title):
        return False
    lab = (pr.registrable_label(host) or "").lower()
    if lab in GAMES_PUBLISHERS:
        return False
    return bool(GAMES.search(title) or GAMES_LABEL.search(host))


def candidate_verdict(rec: dict) -> str:
    """Round 2 verdict for new candidates (see the module notes): `verdict`, minus
    pages that use "proxy" for something else, plus consumer VPN services and
    (round 6) unblocked-games pages."""
    title = rec.get("title") or ""
    if rec.get("st") == 200 and not rec.get("frame") and CHALLENGE.search(title):
        return "down"
    v = verdict(dict(rec, title=_EMBEDDED_UNBLOCK.sub(" ", title)))
    if v in ("proxy", "other") and unblocked_games(rec):
        return "proxy"
    if v == "proxy":
        # Proxy-engine code on the page is evidence on its own; a title or a word count is not
        # when the page is plainly about something else.
        if not rec.get("frame") and NOT_PROXY.search(title):
            return "other"
        own = _without_own_name(title, rec.get("host", ""))
        if (not rec.get("frame") and rec.get("pxy", 0) < 3 and GAMES.search(title)
                and not PROXY_WORD.search(own)):
            return "other"
        # Round 5: "unblock" as the only evidence (a drain service, a WordPress plugin,
        # one re-hosted game "X Unblocked", a news tracker) is not a proxy without
        # proxy code or proxy words.
        if (not rec.get("frame") and rec.get("pxy", 0) < 3 and not PROXY_WORD.search(own)
                and not VPN_WORD.search(own) and not PTITLE2.search(title)
                and UNBLOCK_ONLY.search(title)):
            return "other"
        # A few proxy words in the body alone (an IP checker, a fingerprint test, a list
        # of hosting sites) is not enough: the title has to say so too (round 4).
        if (not rec.get("frame") and rec.get("pxy", 0) < 10 and not PROXY_WORD.search(title)
                and not WEAK_OK.search(own)):
            return "other"
        return v
    if v != "other" or GAMBLE.search(title) or NOT_PROXY.search(title):
        return v
    own = _without_own_name(title, rec.get("host", ""))
    lab = (pr.registrable_label(rec.get("host", "")) or "").lower()
    if VPN_TITLE.search(title) and not VPN_NOT.search(title) and (VPN_WORD.search(own) or "vpn" in lab):
        return "proxy"
    return v


def check(names, qps: float = 8.0, workers: int = 32, timeout: float = 8.0, fetcher=fetch_home,
          links_out: dict | None = None, judge=verdict) -> dict:
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
            v = judge(rec)
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
