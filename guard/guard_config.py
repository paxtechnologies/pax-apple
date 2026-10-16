# SPDX-License-Identifier: GPL-3.0-only
"""Pure logic for `pax-guard`, the root enforcement daemon on a self-locked Mac.

Nothing here touches the system: every function takes text in and gives text
back, so all of it is unit-tested (guard/tests/). pax_guard.py does the I/O.

What it builds:
  * the managed block in /etc/hosts (marked, idempotent, de-duplicated, capped)
  * the pf anchor rules (public DoH/DoT resolvers, common VPN ports, except our
    own resolver)
  * the list of bypass apps to kill and quarantine (VPN clients, Tor, and the
    browsers Pax cannot manage by policy)
  * the ad/tracker domain list: HaGeZi Multi LIGHT (GPL-3.0, "shouldn't cause
    any real restrictions"), with a small allow-list of domains that break
    common sites.
  * v0.5: Pax's curated "bypass" (cloud PCs, remote browsers, web proxies; always
    on) and "remote desktop" (on unless switched off after the wait) lists, read
    from pax-dns/lists/*.txt (bundled as Resources/lists, installed as
    /Library/PaxGuard/bin/lists), plus HaGeZi's DoH/VPN/Tor/Proxy bypass list;
    remote-desktop ports in pf; virtual-machine apps quarantined.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

HOSTS_PATH = "/etc/hosts"
BEGIN = "# BEGIN PAX (managed by pax-guard; do not edit)"
END = "# END PAX"
# A sub-anchor of Apple's own "com.apple/*" anchor, which the stock /etc/pf.conf
# already evaluates, so Pax never edits /etc/pf.conf (macOS updates rewrite it).
PF_ANCHOR = "com.apple/250.org.paxpeace.pax"

# One 0.0.0.0 line per name (no IPv6 duplicate, to halve the size). HaGeZi Light
# in hosts format is ~147k names (~6 MB) on 2026-10-14; v0.5 adds ~15.5k HaGeZi
# bypass names and Pax's curated lists, so the cap went from 175k to 200k (~7 MB).
# The user's own blocked sites, DoH names and the bypass/remote-desktop lists
# always go in first and are never squeezed out by ads.
MAX_HOSTS_ENTRIES = 200_000

# ---------------------------------------------------------------- ad blocking
# HaGeZi Multi LIGHT, GPL-3.0 (github.com/hagezi/dns-blocklists-legacy, LICENSE
# checked 2026-10-14). We use the legacy *hosts* format because /etc/hosts only
# matches exact names: the hosts build lists the subdomains that matter
# ("Hosts (including possible subdomains)"), the wildcard build does not.
# Checked 2026-10-14: 146,520 entries, rebuilt daily.
ADS_LIST_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists-legacy@latest/hosts/light.txt"
ADS_LIST_MIRROR = "https://raw.githubusercontent.com/hagezi/dns-blocklists-legacy/main/hosts/light.txt"
# HaGeZi "Encrypted DNS servers only" (DoH hostnames) and DoH server IPs, GPL-3.0.
DOH_NAMES_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-onlydomains.txt"
DOH_IPS_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/ips/doh.txt"
ADS_LIST_NAME = "HaGeZi Multi LIGHT"
# v0.5: HaGeZi "Encrypted DNS/VPN/Tor/Proxy Bypass" (GPL-3.0). Checked
# 2026-10-14: 15,548 apex domains ("Domains (without subdomains)"), so in
# /etc/hosts it only blocks the listed names themselves (pax-dns blocks their
# subdomains too). Refreshed with the ad list, at most daily.
BYPASS_LIST_URL = ("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/"
                   "doh-vpn-proxy-bypass-onlydomains.txt")
BYPASS_LIST_MIRROR = ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
                      "doh-vpn-proxy-bypass-onlydomains.txt")
BYPASS_MIN_ENTRIES = 5_000
# A download that comes back far smaller than this is treated as broken and the
# previous copy is kept (same guard as pax-dns/scripts/load_lists.py).
ADS_MIN_ENTRIES = 10_000

# Domains in the list that break a site people use on purpose. An entry here
# (or in the user's Pax exceptions, or guard config "ads_allow") is never
# written to /etc/hosts, and it frees its subdomains too. Kept deliberately
# short: Light is built not to break sites, so add only what a real report shows.
ADS_ALLOWLIST = [
    "analytics.google.com",   # the Google Analytics dashboard itself (in Light 2026-10-14)
]

# Hostnames that must never be blocked, whatever a list says: Pax's own
# resolver and server are added at runtime from the config.
ALWAYS_ALLOW = ["doh.cleanbrowsing.org", "family-filter-dns.cleanbrowsing.org",
                "dns.paxmobile.org", "dns.paxpeace.com", "api.paxpeace.com",
                # v0.8.0: the local forwarder's fallback upstream (filtered: restricted content + SafeSearch).
                "family.adguard-dns.com"]

# ------------------------------------------------- v0.5 curated categories
# Pax's own lists live in pax-dns/lists/ (one source of truth for pax-dns and
# pax-guard). Looked up next to this file (installed: /Library/PaxGuard/bin/
# lists), then in Resources/lists (bundled app), then in the repo.
# v0.6: X (Twitter) stays readable, but its image and video servers are blocked,
# always on (project decision, 2026-10-15). Exact hostnames, as /etc/hosts needs. Avatars and
# link-preview cards go with them; text, replies and DMs still work.
X_MEDIA_NAMES = ["pbs.twimg.com", "video.twimg.com", "ton.twimg.com"]
# v0.7.0 (project decision, 2026-10-15): Bluesky the same way. bsky.app (the text site) and
# its API stay reachable; images/avatars, video and GIFs don't load.
BLUESKY_MEDIA_NAMES = ["cdn.bsky.app", "video.bsky.app", "video.cdn.bsky.app", "gifs.bsky.app"]
# v0.8.13 (project decision): both are always blocked, with no switch anywhere, and
# no exception frees them (they go with the restricted categories). Text stays readable.
ALWAYS_BLOCKED_MEDIA_NAMES = X_MEDIA_NAMES + BLUESKY_MEDIA_NAMES

CURATED_FILES = {"bypass": "cloud-pc-bypass.txt", "remote_desktop": "remote-desktop.txt",
                 # v0.8.1: media converters and media mirrors, always on and never
                 # freed by an exception (treated like restricted content).
                 "media_converters": "media-converters.txt",
                 "media_converter_rule": "media-converter-keywords.txt",
                 # v0.8.1 (project decision, 2026-10-15): AI services that let the user control a
                 # remote computer or browser (ChatGPT, Manus). Always on, never freed
                 # by an exception, like the media converters.
                 "remote_ai_browsers": "remote-ai-browsers.txt"}
# The site categories that are always on and that an exception never frees.
RESTRICTED_CATEGORIES = ("media_converters", "remote_ai_browsers")
_HERE = Path(__file__).resolve().parent
LIST_DIRS = [_HERE / "lists", _HERE.parent / "lists", _HERE.parent / "pax-dns" / "lists"]


def find_list(category: str, dirs: list[Path] | None = None) -> Path | None:
    name = CURATED_FILES[category]
    for d in (dirs if dirs is not None else LIST_DIRS):
        if (d / name).is_file():
            return d / name
    return None


def load_curated(category: str, dirs: list[Path] | None = None) -> list[str]:
    """Domains of a curated category ([] if the file is missing: pax-guard logs
    it, and the install script refuses to install without the lists)."""
    path = find_list(category, dirs)
    return parse_domain_list(path.read_text()) if path else []


def with_www(domains: list[str]) -> list[str]:
    """/etc/hosts matches exact names only: block each entry and www.<entry>."""
    out: list[str] = []
    for d in domains:
        out.append(d)
        if not d.startswith("www."):
            out.append(f"www.{d}")
    return out

# DoH endpoints by name (HaGeZi's longer list is merged in when it downloads).
# Plus Firefox's canary domain (blocking it makes Firefox turn its own DoH off)
# and iCloud Private Relay's documented network opt-out hosts.
BUILTIN_BYPASS_NAMES = [
    "dns.google", "dns.google.com", "dns64.dns.google",
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
    "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
    "doh.opendns.com", "doh.familyshield.opendns.com",
    "dns.nextdns.io", "chromium.dns.nextdns.io", "firefox.dns.nextdns.io",
    "dns.adguard-dns.com", "unfiltered.adguard-dns.com", "family.adguard-dns.com", "dns.adguard.com",
    "doh.mullvad.net", "dns.mullvad.net", "adblock.dns.mullvad.net", "base.dns.mullvad.net",
    "dns.controld.com", "freedns.controld.com",
    "dns0.eu", "zero.dns0.eu", "open.dns0.eu",
    "doh.dns.sb", "dns.alidns.com", "doh.pub", "dns.twnic.tw", "ordns.he.net",
    "doh.xfinity.com",
    "use-application-dns.net",
    "mask.icloud.com", "mask-h2.icloud.com",
]


def parse_domain_list(text: str) -> list[str]:
    """Domains from a HaGeZi 'wildcard domains' or a hosts-format list."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        parts = line.split()
        if len(parts) >= 2 and _is_ip(parts[0]):
            candidate = parts[1]
        elif len(parts) == 1:
            candidate = parts[0]
        else:
            continue
        candidate = candidate.strip(".").lower().lstrip("*.")
        if is_blockable_domain(candidate):
            out.append(candidate)
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")
_NEVER_BLOCK = {"localhost", "local", "broadcasthost"}


def is_blockable_domain(domain: str) -> bool:
    domain = (domain or "").strip(".").lower()
    if not domain or domain in _NEVER_BLOCK or _is_ip(domain):
        return False
    return bool(_DOMAIN_RE.match(domain))


def effective_ad_domains(ad_domains: list[str], allowlist: list[str] | None = None) -> list[str]:
    """Ad list minus the allow-list (an allowed domain also frees its subdomains)."""
    allow = {d.strip(".").lower() for d in (ADS_ALLOWLIST if allowlist is None else allowlist)}
    out: list[str] = []
    for d in ad_domains:
        d = d.strip(".").lower()
        if not is_blockable_domain(d):
            continue
        if any(d == a or d.endswith("." + a) for a in allow):
            continue
        out.append(d)
    return out


def is_protected(domain: str, protected: list[str]) -> bool:
    """True if blocking `domain` in /etc/hosts would break a protected host
    (the same name; hosts entries don't cascade to subdomains)."""
    d = domain.strip(".").lower()
    return any(d == p.strip(".").lower() for p in protected)


def hosts_domains(custom: list[str], ads: list[str] | None = None,
                  allowlist: list[str] | None = None,
                  bypass_names: list[str] | None = None,
                  protected: list[str] | None = None,
                  max_entries: int = MAX_HOSTS_ENTRIES,
                  categories: list[str] | None = None,
                  bypass_list: list[str] | None = None,
                  exceptions: list[str] | None = None,
                  restricted: list[str] | None = None,
                  restricted_exact: list[str] | None = None) -> list[str]:
    """What goes in /etc/hosts, in priority order, de-duplicated and capped:
      1. the user's blocked sites (each also as www.<site>)
      2. DoH / Private Relay / Firefox-canary names
      3. v0.5 curated categories that are on (each also as www.<name>), then
         v0.8.1 restricted categories (media converters, remote AI browsers),
         which exceptions never free, then (v0.8.7) `restricted_exact`: the
         ad-list names that are restricted content, exact names, kept whether
         ads are on or off and never freed by an exception or the ad allow-list
      4. v0.5 HaGeZi DoH/VPN/Tor/Proxy bypass names (apex names only)
      5. ad/tracker names (minus the allow-list)
    Protected names (our resolver and server) are never written. `exceptions`
    (the user's Pax exceptions, which waited 72 h) free entries in 3 and 4 the
    same way pax-dns does."""
    prot = list(ALWAYS_ALLOW) + list(protected or [])
    out: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        name = name.strip(".").lower()
        if (name not in seen and len(out) < max_entries and is_blockable_domain(name)
                and not is_protected(name, prot)):
            seen.add(name)
            out.append(name)

    for d in custom:
        d = d.strip(".").lower()
        add(d)
        if not d.startswith("www."):
            add(f"www.{d}")
    for d in BUILTIN_BYPASS_NAMES + list(bypass_names or []):
        add(d)
    exc = [e.strip(".").lower() for e in (exceptions or [])]

    def excepted(name: str) -> bool:
        n = name.strip(".").lower()
        return any(n == e or n.endswith("." + e) for e in exc)
    for d in with_www(list(categories or [])):
        if not excepted(d):
            add(d)
    for d in with_www(list(restricted or [])):
        add(d)
    for d in restricted_exact or []:
        add(d)
    for d in bypass_list or []:
        if not excepted(d):
            add(d)
    if ads:
        for d in effective_ad_domains(ads, allowlist):
            if len(out) >= max_entries:
                break
            add(d)
    return out


# v0.8.12: Pax Max switched off after set-up. Pax Image Blur asks for this name
# (Firefox's dns API, which reads /etc/hosts first) and goes quiet only when it
# gets exactly this address; any other answer, or none, keeps it blurring (so
# a missing or broken signal never switches the blur off).
PAX_MAX_OFF_NAME = "pax-max-off.guard.paxpeace.com"
PAX_MAX_OFF_ADDR = "127.80.77.0"


def hosts_block(domains: list[str], extra: list[tuple[str, str]] | tuple = ()) -> str:
    """The managed block, including its markers. Always ends with a newline.
    `extra` (v0.8.12): (address, name) lines such as the Pax Max off signal."""
    lines = [BEGIN,
             "# Pax blocks these for every app on this Mac. Removing Pax removes this block.",
             "#", ]
    lines += [f"{a} {n}" for a, n in extra]
    lines += [f"0.0.0.0 {d}" for d in domains]
    lines.append(END)
    return "\n".join(lines) + "\n"


_BLOCK_RE = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END) + r"\n?", re.S)


def strip_pax_block(hosts_text: str) -> str:
    """/etc/hosts with any Pax block removed (and no stray blank lines)."""
    out = _BLOCK_RE.sub("", hosts_text)
    out = re.sub(r"\n{3,}", "\n\n", out)
    if out and not out.endswith("\n"):
        out += "\n"
    return out


def render_hosts(hosts_text: str, domains: list[str], extra: list[tuple[str, str]] | tuple = ()) -> str:
    """The new /etc/hosts. Idempotent: rendering twice changes nothing, and the
    user's own entries outside the markers are kept exactly."""
    base = strip_pax_block(hosts_text)
    if base and not base.endswith("\n"):
        base += "\n"
    return base + hosts_block(domains, extra)


def hosts_needs_update(hosts_text: str, domains: list[str]) -> bool:
    return hosts_text != render_hosts(hosts_text, domains)


# --------------------------------------------------------------------- pf
# Public DoH/DoT resolvers, so a browser or app that hard-codes one cannot
# resolve around the system resolver. A short built-in set of well-known
# anycast addresses; HaGeZi's list (ips/doh.txt, ~1,400 IPs, GPL-3.0) is merged
# in daily. HaGeZi's list INCLUDES CleanBrowsing (185.228.168.168 etc.), so our
# own resolver's addresses are always removed from the block (allow_ips).
PUBLIC_DOH_IPS = [
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",   # Cloudflare
    "8.8.8.8", "8.8.4.4",                                                # Google
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10",          # Quad9
    "208.67.222.222", "208.67.220.220",                                  # OpenDNS
    "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16",      # AdGuard
    "76.76.2.0", "76.76.10.0",                                           # ControlD
    "45.90.28.0", "45.90.30.0",                                          # NextDNS
    "77.88.8.8", "77.88.8.1",                                            # Yandex
    "223.5.5.5", "223.6.6.6",                                            # AliDNS
    "101.101.101.101",                                                   # TWNIC
    "193.110.81.0", "185.253.5.0",                                       # dns0.eu
    "212.129.46.32",                                                     # ffmuc
]
# Our own resolver must stay reachable, whatever else is blocked. Family Filter
# IPs from https://cleanbrowsing.org/filters/ (2026-10-14); doh.cleanbrowsing.org
# resolved to 185.228.168.10 and 185.228.168.168 the same day, so both are kept
# open, and pax-guard adds whatever the resolver's hostname resolves to.
CLEANBROWSING_FAMILY_IPS = ["185.228.168.168", "185.228.169.168", "185.228.168.10"]
FALLBACK_PLAIN_DNS = ["185.228.168.168", "185.228.169.168"]   # Family Filter, plain DNS
# v0.8.0: AdGuard Family DoH, the local forwarder's fallback upstream. Resolved
# 2026-10-15 (family.adguard-dns.com A/AAAA). Only these "family" addresses are
# allowed; AdGuard's default (no content filtering) 94.140.14.14/15.15 stay blocked.
ADGUARD_FAMILY_IPS = ["94.140.14.15", "94.140.15.16", "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"]
LOCAL_DNS = "127.0.0.1"

# WireGuard, OpenVPN, IKEv2/IPsec. Blocking these does not touch normal browsing.
VPN_PORTS = {"udp": [51820, 1194, 500, 4500, 1701], "tcp": [1194, 1723]}
DOT_PORT = 853
# v0.5, only while the remote-desktop category is on: outbound connections to
# another computer's remote-desktop server, which name blocking can't stop when
# you type an IP address or run your own relay. RDP 3389, VNC / macOS Screen
# Sharing 5900, TeamViewer 5938, AnyDesk direct 7070, RustDesk 21115-21119,
# NoMachine 4000. (Parsec and Moonlight use wide UDP ranges shared with other
# software, so they're left to the name block.)
REMOTE_DESKTOP_PORTS = {"tcp": [3389, 5900, 5938, 7070, 21115, 21116, 21117, 21118, 21119, 4000],
                        "udp": [3389, 21116, 4000]}


def pf_rules(*, allow_ips: list[str] | None = None, doh_ips: list[str] | None = None,
             dns_only_ips: list[str] | None = None,
             system_dns: list[str] | None = None,
             vpn_ports: dict[str, list[int]] | None = None,
             remote_desktop: bool = False,
             local_dns: bool = False, root_only_upstream: bool = True) -> str:
    """Rules for the pax-guard pf anchor. Outbound only: nothing here blocks the
    Mac's normal traffic, DHCP, or port 53 to the router (the DNS profile
    already sends lookups over HTTPS).

    doh_ips (the curated built-in list): ports 53 and 443 blocked. These
    addresses serve DNS and nothing else, so blocking 443 breaks no website.
    dns_only_ips (HaGeZi's long list, merged daily): port 53 only. Some of those
    addresses are shared hosting or cloud load balancers (e.g. AWS Global
    Accelerator), so blocking 443 there could break ordinary sites; their DoH
    hostnames are blocked in /etc/hosts instead.

    system_dns: the DNS servers the current network handed out (`scutil --dns`).
    Plain DNS to them is always allowed, even if one is a public resolver like
    1.1.1.1: macOS needs it to find the DoH server, and blocking it would take
    the whole Mac offline on that network.

    v0.8.0 local_dns: pax-guard's forwarder on 127.0.0.1:53 is the only resolver.
    Loopback passes; DoH to the allowed upstreams (CleanBrowsing, AdGuard Family)
    is allowed for root only (the forwarder) when root_only_upstream; plain DNS
    (53) to anywhere off the Mac is blocked for everyone (the forwarder speaks DoH
    to pinned addresses, so it needs none). macOS pf matches `user` on sockets;
    if a pf build refuses it, pax-guard reloads with root_only_upstream=False,
    which still allows only the filtered upstreams."""
    if local_dns:
        return _pf_rules_local(allow_ips=allow_ips, doh_ips=doh_ips, dns_only_ips=dns_only_ips,
                               vpn_ports=vpn_ports, remote_desktop=remote_desktop,
                               root_only_upstream=root_only_upstream)
    allow = sorted(set(allow_ips if allow_ips is not None else CLEANBROWSING_FAMILY_IPS))
    doh = [ip for ip in sorted(set(doh_ips if doh_ips is not None else PUBLIC_DOH_IPS))
           if ip not in allow]
    dns_only = [ip for ip in sorted(set(dns_only_ips or [])) if ip not in allow and ip not in doh]
    ports = vpn_ports or VPN_PORTS
    lines = [f"# pax-guard anchor ({PF_ANCHOR}). Generated: do not edit."]
    if allow:
        lines.append(f"table <pax_allow> const {{ {' '.join(allow)} }}")
    if doh:
        lines.append(f"table <pax_doh> const {{ {' '.join(doh)} }}")
    if dns_only:
        lines.append(f"table <pax_dns> const {{ {' '.join(dns_only)} }}")
    sysdns = sorted({ip for ip in (system_dns or []) if _is_ip(ip)})
    if sysdns:
        lines.append(f"table <pax_sysdns> const {{ {' '.join(sysdns)} }}")
    if allow:
        lines += ["# Pax's own resolver stays reachable.",
                  "pass out quick proto { tcp udp } from any to <pax_allow>"]
    if sysdns:
        lines += ["# This network's DNS servers: plain DNS stays allowed (bootstrap for DoH).",
                  "pass out quick proto { tcp udp } from any to <pax_sysdns> port 53"]
    lines += ["# DNS-over-TLS / DNS-over-QUIC to anywhere.",
              f"block drop out quick proto {{ tcp udp }} from any to any port {DOT_PORT}"]
    if doh:
        lines += ["# Public DNS resolvers: DoH (443) and plain DNS (53) straight to them.",
                  "block drop out quick proto { tcp udp } from any to <pax_doh> port { 53 443 }"]
    if dns_only:
        lines += ["# Other known DNS servers: plain DNS only (443 left alone, see docstring).",
                  "block drop out quick proto { tcp udp } from any to <pax_dns> port 53"]
    lines.append("# Common VPN transports (WireGuard, OpenVPN, IKEv2/IPsec, L2TP, PPTP).")
    for proto in ("udp", "tcp"):
        pts = sorted(set(ports.get(proto, [])))
        if pts:
            lines.append(f"block drop out quick proto {proto} from any to any port "
                         f"{{ {' '.join(str(x) for x in pts)} }}")
    if remote_desktop:
        lines.append("# Remote desktop to other computers (category on; RDP, VNC, TeamViewer, "
                     "AnyDesk, RustDesk, NoMachine).")
        for proto in ("udp", "tcp"):
            pts = sorted(set(REMOTE_DESKTOP_PORTS.get(proto, [])))
            if pts:
                lines.append(f"block drop out quick proto {proto} from any to any port "
                             f"{{ {' '.join(str(x) for x in pts)} }}")
    return "\n".join(lines) + "\n"


def _port_rules(ports: dict[str, list[int]], remote_desktop: bool) -> list[str]:
    lines = ["# Common VPN transports (WireGuard, OpenVPN, IKEv2/IPsec, L2TP, PPTP)."]
    for proto in ("udp", "tcp"):
        pts = sorted(set(ports.get(proto, [])))
        if pts:
            lines.append(f"block drop out quick proto {proto} from any to any port "
                         f"{{ {' '.join(str(x) for x in pts)} }}")
    if remote_desktop:
        lines.append("# Remote desktop to other computers (category on; RDP, VNC, TeamViewer, "
                     "AnyDesk, RustDesk, NoMachine).")
        for proto in ("udp", "tcp"):
            pts = sorted(set(REMOTE_DESKTOP_PORTS.get(proto, [])))
            if pts:
                lines.append(f"block drop out quick proto {proto} from any to any port "
                             f"{{ {' '.join(str(x) for x in pts)} }}")
    return lines


def _pf_rules_local(*, allow_ips, doh_ips, dns_only_ips, vpn_ports, remote_desktop,
                    root_only_upstream) -> str:
    upstream = sorted(set(allow_ips if allow_ips is not None
                          else CLEANBROWSING_FAMILY_IPS + ADGUARD_FAMILY_IPS))
    doh = [ip for ip in sorted(set(doh_ips if doh_ips is not None else PUBLIC_DOH_IPS)) if ip not in upstream]
    dns_only = [ip for ip in sorted(set(dns_only_ips or [])) if ip not in upstream and ip not in doh]
    lines = [f"# pax-guard anchor ({PF_ANCHOR}), local DNS mode. Generated: do not edit.",
             f"table <pax_upstream> const {{ {' '.join(upstream)} }}"]
    if doh:
        lines.append(f"table <pax_doh> const {{ {' '.join(doh)} }}")
    if dns_only:
        lines.append(f"table <pax_dns> const {{ {' '.join(dns_only)} }}")
    lines += ["# The Mac talking to itself (apps -> 127.0.0.1:53, the Pax forwarder).",
              "pass quick on lo0 all"]
    if root_only_upstream:
        lines += ["# Only pax-guard's forwarder (root) may reach the filtered DoH upstreams.",
                  "pass out quick proto tcp from any to <pax_upstream> port 443 user root",
                  "block drop out quick proto { tcp udp } from any to <pax_upstream>"]
    else:
        lines += ["# The filtered DoH upstreams (any user: pf here can't match by user).",
                  "pass out quick proto tcp from any to <pax_upstream> port 443"]
    lines += ["# Plain DNS off this Mac: nobody (the forwarder speaks DoH to pinned addresses).",
              "block drop out quick proto { tcp udp } from any to any port 53",
              "# DNS-over-TLS / DNS-over-QUIC to anywhere.",
              f"block drop out quick proto {{ tcp udp }} from any to any port {DOT_PORT}"]
    if doh:
        lines += ["# Public DNS resolvers: DoH (443) straight to them.",
                  "block drop out quick proto { tcp udp } from any to <pax_doh> port 443"]
    lines += _port_rules(vpn_ports or VPN_PORTS, remote_desktop)
    return "\n".join(lines) + "\n"


# ------------------------------------------------------- v0.8 DNS settings
def parse_network_services(output: str) -> list[str]:
    """Enabled services from `networksetup -listallnetworkservices` (first line
    is a note; disabled services start with "*")."""
    out = []
    for i, line in enumerate(output.splitlines()):
        line = line.rstrip()
        if not line or (i == 0 and "asterisk" in line.lower()) or line.startswith("*"):
            continue
        out.append(line)
    return out


def parse_dns_servers(output: str) -> list[str]:
    """`networksetup -getdnsservers <service>`: IPs, or [] for "There aren't any"."""
    return [l.strip() for l in output.splitlines() if _is_ip(l.strip())]


def parse_scutil_dns(output: str) -> list[str]:
    """Nameserver IPs from `scutil --dns` ("nameserver[0] : 192.168.1.1")."""
    out: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("nameserver[") and ":" in line:
            ip = line.split(":", 1)[1].strip()
            if _is_ip(ip) and ip not in out:
                out.append(ip)
    return out


def merge_doh_ips(extra: list[str], base: list[str] | None = None) -> list[str]:
    """Merge a fetched DoH IP list (HaGeZi ips/doh.txt) with the built-in one,
    dropping anything that isn't a plain IPv4/IPv6 address."""
    out = list(base if base is not None else PUBLIC_DOH_IPS)
    seen = set(out)
    for raw in extra:
        ip = raw.strip()
        if ip and _is_ip(ip) and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


# ------------------------------------------------------------- bypass apps
@dataclass(frozen=True)
class BypassApp:
    name: str
    bundle_ids: tuple[str, ...]
    app_names: tuple[str, ...]       # "<name>.app" folder names, matched case-insensitively
    why: str
    verified: bool = False           # bundle ID confirmed via the Mac App Store lookup API


# Apps that carry traffic (or DNS) around the filter. `verified=True` bundle IDs
# come from the iTunes Search API (entity=macSoftware, 2026-10-14). The rest are
# vendor downloads Pax could not look up; the app-name match is what catches them.
BYPASS_APPS: list[BypassApp] = [
    BypassApp("Tor Browser", ("org.torproject.torbrowser",), ("Tor Browser",), "onion routing, own DNS"),
    BypassApp("Onion Browser", ("com.pentaloop.torbrowser",), ("Onion Browser",), "Tor", True),
    BypassApp("TOR Browser: VPN", ("com.roundcherryapps.vpnTor",), (), "Tor + VPN", True),
    BypassApp("Web Browser for TOR", ("tor.speed.browser",), (), "Tor", True),
    BypassApp("Orbot", ("org.torproject.orbot",), ("Orbot",), "Tor proxy", True),
    BypassApp("NordVPN", ("com.nordvpn.NordVPN",), ("NordVPN", "NordVPN IKE"), "VPN", True),
    BypassApp("ExpressVPN", ("com.expressvpn.iosvpn",), ("ExpressVPN",), "VPN", True),
    BypassApp("Surfshark", ("com.surfshark.vpnclient.macos",), ("Surfshark",), "VPN", True),
    BypassApp("Proton VPN", (), ("Proton VPN", "ProtonVPN"), "VPN"),
    BypassApp("Private Internet Access", ("com.privateinternetaccess.ios.PIA-VPN",),
              ("Private Internet Access", "PIA VPN"), "VPN", True),
    BypassApp("Mullvad VPN", (), ("Mullvad VPN", "Mullvad Browser"), "VPN / unmanaged browser"),
    BypassApp("Windscribe", (), ("Windscribe",), "VPN"),
    BypassApp("TunnelBear", (), ("TunnelBear",), "VPN"),
    BypassApp("CyberGhost", (), ("CyberGhost VPN", "CyberGhost"), "VPN"),
    BypassApp("IPVanish", (), ("IPVanish VPN", "IPVanish"), "VPN"),
    BypassApp("PureVPN", (), ("PureVPN",), "VPN"),
    BypassApp("VyprVPN", (), ("VyprVPN",), "VPN"),
    BypassApp("Hotspot Shield", ("com.anchorfree.hss-mac",), ("Hotspot Shield", "Hotspot Shield VPN"), "VPN", True),
    BypassApp("Betternet", ("com.betternet.macos",), ("Betternet",), "VPN", True),
    BypassApp("hide.me VPN", ("com.eventur.Hide.me",), ("hide.me VPN",), "VPN", True),
    BypassApp("Urban VPN", ("com.urban-vpn.mac",), ("Urban VPN Desktop", "Urban VPN"), "VPN", True),
    BypassApp("Turbo VPN", ("com.inconnecting.turbovpnformac",), ("Turbo VPN",), "VPN", True),
    BypassApp("X-VPN", ("com.mac.xvpn",), ("X-VPN",), "VPN", True),
    BypassApp("Planet VPN", ("com.atrix.rusvpn",), (), "VPN", True),
    BypassApp("Free VPN .org", ("org.freevpn.vpn",), (), "VPN", True),
    BypassApp("VPN Proxy Master", ("co.jialeisun.vpnmaster",), (), "VPN", True),
    BypassApp("VPNIFY", ("com.free.vpn.hotspot.secure.vpnify",), (), "VPN", True),
    BypassApp("VPN Unlimited", ("com.simplexsolutionsinc.vpnguard",), ("VPN Unlimited",), "VPN", True),
    BypassApp("Privada VPN", ("com.privada.vpn.app.ios",), ("PrivadoVPN",), "VPN", True),
    BypassApp("AdGuard VPN", ("com.adguard.ios.AdGuardVPN",), ("AdGuard VPN",), "VPN", True),
    BypassApp("VPN Lumos", ("bernikovich.vpn",), (), "VPN", True),
    BypassApp("Fair VPN", ("us.ultrasurf.fqcdn.ios",), (), "VPN", True),
    BypassApp("VPN cat", ("com.vpn.cat",), (), "VPN", True),
    BypassApp("Potato VPN", ("com.potatovpn",), (), "VPN", True),
    BypassApp("JumpJumpVPN", ("app.jumpjumpvpn.jumpjumpvpn",), (), "VPN", True),
    BypassApp("VPN: Super Unlimited", ("com.optimal.vpn.m",), (), "VPN", True),
    BypassApp("GhostGuard VPN", ("com.GhostGuardVPN",), (), "VPN", True),
    BypassApp("VPN-Z", ("com.krishnatechnoweb.vpnbrowser",), (), "VPN browser", True),
    BypassApp("WireGuard", ("com.wireguard.macos",), ("WireGuard",), "VPN tunnel", True),
    BypassApp("Xlarva", ("app.xlarva.apple",), (), "WireGuard client", True),
    BypassApp("AmneziaWG", ("org.amnezia.awg",), ("AmneziaWG", "AmneziaVPN"), "VPN tunnel", True),
    BypassApp("Passepartout", ("com.algoritmico.ios.Passepartout",), ("Passepartout",), "VPN tunnel", True),
    BypassApp("OpenVPN Connect", (), ("OpenVPN Connect",), "VPN tunnel"),
    BypassApp("Tunnelblick", (), ("Tunnelblick",), "VPN tunnel"),
    BypassApp("Outline", ("org.outline.macos.client",), (), "proxy tunnel", True),  # name clashes with a notes app
    BypassApp("Shadowrocket", ("com.liguangming.Shadowrocket",), ("Shadowrocket",), "proxy", True),
    BypassApp("Happ", ("su.ffg.happ",), ("Happ",), "proxy", True),
    BypassApp("Cloudflare WARP", (), ("Cloudflare WARP",), "DNS + tunnel"),
    BypassApp("Psiphon", (), ("Psiphon",), "circumvention proxy"),
    BypassApp("Lantern", (), ("Lantern",), "circumvention proxy"),
]

# Browsers Pax cannot manage by policy: they ship their own VPN or proxy, or
# ignore managed preferences. pax-guard treats them like a VPN client (killed
# and quarantined while Pax is on). Matched by app name; bundle IDs unverified.
UNMANAGEABLE_BROWSERS: list[BypassApp] = [
    BypassApp("Opera", (), ("Opera", "Opera GX", "Opera Air", "Opera Beta", "Opera Developer",
                           ), "built-in VPN (a proxy Pax can't lock)"),
    BypassApp("Vivaldi", (), ("Vivaldi", "Vivaldi Snapshot"),
              "reads Chromium policies (covered by the profile) but its built-in Proton "
              "VPN has no documented policy to turn it off yet"),
    BypassApp("Arc", (), ("Arc",), "no enterprise policy support"),
    BypassApp("Orion", (), ("Orion", "Orion RC"), "WebKit browser that installs Chrome/Firefox extensions, no policies"),
    BypassApp("SigmaOS", (), ("SigmaOS",), "no enterprise policy support"),
    BypassApp("Zen", (), ("Zen Browser",), "Firefox fork that ignores org.mozilla.firefox policies"),
    BypassApp("LibreWolf", (), ("LibreWolf",), "Firefox fork with its own policy location"),
    BypassApp("Waterfox", (), ("Waterfox",), "Firefox fork with its own policy location"),
    BypassApp("Floorp", (), ("Floorp",), "Firefox fork with its own policy location"),
    BypassApp("Firefox Developer Edition / Nightly", (),
              ("Firefox Developer Edition", "Firefox Nightly"), "separate preference domains"),
    BypassApp("Chrome Beta / Dev / Canary", (),
              ("Google Chrome Beta", "Google Chrome Dev", "Google Chrome Canary"),
              "pre-release channels; not confirmed to read com.google.Chrome policies"),
    BypassApp("Edge Beta / Dev / Canary", (),
              ("Microsoft Edge Beta", "Microsoft Edge Dev", "Microsoft Edge Canary"),
              "pre-release channels; not confirmed to read com.microsoft.Edge policies"),
    BypassApp("Brave Beta / Nightly", (), ("Brave Browser Beta", "Brave Browser Nightly"),
              "separate preference domains (com.brave.Browser.beta / .nightly)"),
    BypassApp("Thorium", (), ("Thorium",), "Chromium fork, policy domain unknown"),
    BypassApp("Epic Privacy Browser", (), ("Epic",), "built-in proxy"),
    BypassApp("Yandex Browser", (), ("Yandex",), "own DNS and proxy"),
    BypassApp("Aloha Browser", (), ("Aloha", "Aloha Browser"), "built-in VPN"),
    BypassApp("DuckDuckGo", (), ("DuckDuckGo",), "no enterprise policy support; has a VPN"),
]

# v0.8.1 (project decision, 2026-10-15): AI apps that let the user take over a remote
# computer or browser (ChatGPT's "Work" cloud browser, Manus). Their sites are
# blocked in DNS and /etc/hosts (remote-ai-browsers.txt); the desktop apps are
# killed and quarantined like the unmanageable browsers. com.openai.chat was
# confirmed with the Mac App Store lookup API (2026-10-15); the ChatGPT desktop
# download from openai.com uses the same bundle ID. Atlas and Manus are matched
# by app name (bundle IDs unverified).
REMOTE_AI_APPS: list[BypassApp] = [
    BypassApp("ChatGPT", ("com.openai.chat",), ("ChatGPT",),
              "remote AI browser: its cloud browser can be taken over", True),
    BypassApp("ChatGPT Atlas", ("com.openai.atlas",), ("ChatGPT Atlas",),
              "OpenAI's browser, with ChatGPT's agent built in"),
    BypassApp("Manus", (), ("Manus",), "remote AI computer"),
]

# v0.5: virtual machines. A VM is a second computer with its own DNS, its own
# browsers and no Pax policies, /etc/hosts or extension lockdown, so it gets
# around everything at once. Killed and quarantined like a VPN client. Bundle
# IDs marked verified come from the iTunes Search API (2026-10-14); the rest are
# vendor downloads matched mainly by app name.
VM_APPS: list[BypassApp] = [
    BypassApp("UTM", ("com.utmapp.UTM",), ("UTM", "UTM SE"), "QEMU / Apple Virtualization front-end", True),
    BypassApp("Parallels Desktop (App Store)", ("com.parallels.desktop.appstore",),
              ("Parallels Desktop",), "virtual machines", True),
    BypassApp("Parallels Desktop", ("com.parallels.desktop.console",), ("Parallels Desktop",),
              "virtual machines"),
    BypassApp("VMware Fusion", ("com.vmware.fusion",), ("VMware Fusion", "VMware Fusion Tech Preview"),
              "virtual machines"),
    BypassApp("VirtualBox", ("org.virtualbox.app.VirtualBox",), ("VirtualBox", "VirtualBoxVM"),
              "virtual machines"),
    BypassApp("virtualOS VM", ("com.github.yep.ios.virtualOS",), ("virtualOS",),
              "macOS virtual machines", True),
    BypassApp("VirtualBuddy", ("codes.rambo.VirtualBuddy",), ("VirtualBuddy",), "macOS virtual machines"),
    BypassApp("Tart", ("com.github.cirruslabs.tart",), ("tart",), "macOS/Linux VMs (cirruslabs)"),
    BypassApp("Veertu Desktop / Anka", (), ("Veertu Desktop", "Anka"), "virtual machines"),
    BypassApp("QEMU front-ends", (), ("QEMU", "QtEMU", "AQEMU", "Qemu Manager"),
              "QEMU graphical front-ends"),
]
# Processes that are a VM whatever launched them (QEMU ships as plain binaries,
# e.g. Homebrew's qemu-system-x86_64, so there is no .app to match). Killed only.
VM_PROCESS_PREFIXES = ("qemu-system-",)


def is_vm_process(executable_path: str) -> bool:
    base = executable_path.rsplit("/", 1)[-1].lower()
    return any(base.startswith(p) for p in VM_PROCESS_PREFIXES)


# NOT blocked: browsers whose Chromium/Firefox policies the Mac profile sets.
POLICY_MANAGED_BROWSERS = {
    "Google Chrome": "com.google.Chrome",
    "Microsoft Edge": "com.microsoft.Edge",
    "Brave Browser": "com.brave.Browser",
    "Chromium": "org.chromium.Chromium",
    "Firefox": "org.mozilla.firefox",
    "Safari": "(system; DNS + hosts + Private Relay off; extensions not manageable)",
}


def all_bypass_apps(include_browsers: bool = True, include_vms: bool = True) -> list[BypassApp]:
    """Remote AI apps are always included: like their sites, they can't be turned off."""
    return (list(BYPASS_APPS) + (list(UNMANAGEABLE_BROWSERS) if include_browsers else [])
            + list(REMOTE_AI_APPS) + (list(VM_APPS) if include_vms else []))


def is_bypass_app(app_folder_name: str, bundle_id: str | None,
                  apps: list[BypassApp] | None = None) -> BypassApp | None:
    """Match an installed app by bundle ID or by its .app folder name."""
    apps = apps if apps is not None else all_bypass_apps()
    name = app_folder_name[:-4] if app_folder_name.lower().endswith(".app") else app_folder_name
    lname = name.strip().lower()
    bid = (bundle_id or "").strip().lower()
    managed = {n.lower() for n in POLICY_MANAGED_BROWSERS}
    if lname in managed:
        return None
    for a in apps:
        if bid and bid in (b.lower() for b in a.bundle_ids):
            return a
        if lname in (n.lower() for n in a.app_names):
            return a
    return None


def connected_vpn_services(scutil_nc_list: str) -> list[str]:
    """Names of connected services in `scutil --nc list` output, e.g.
    '* (Connected)   1A2B... VPN (com.wireguard.macos) "Home"  [VPN/...]'."""
    out = []
    for line in scutil_nc_list.splitlines():
        if "(Connected)" not in line and "(Connecting)" not in line:
            continue
        first = line.find('"')
        second = line.find('"', first + 1)
        if first >= 0 and second > first:
            out.append(line[first + 1:second])
    return out


def app_bundle_of(executable_path: str) -> str | None:
    """'/Applications/Tor Browser.app/Contents/MacOS/firefox' -> '/Applications/Tor Browser.app'.
    Uses the OUTERMOST .app, so helpers inside a bundle map to the main app."""
    marker = ".app/"
    i = executable_path.find(marker)
    if i < 0:
        return None
    return executable_path[: i + 4]


# ------------------------------------------------- v0.8.7 user-blocked apps
# The user's own "Blocked apps" on the Mac (Settings > This Mac). pax-guard
# identifies an app by what survives renaming and copying: its bundle ID, and the
# identifier and Team ID sealed into its code signature (editing Info.plist in a
# copy doesn't change those). Apps are never blocked when they are Pax itself,
# Apple's own (system apps the Mac needs), or password managers (project decision,
# 2026-10-16). The same lists guard the iPhone picker (profile/app_blocks.py;
# a test keeps the two in step).
MAX_BLOCKED_APPS = 200
PAX_TEAM_ID = "Z94GSK7JA8"
NEVER_BLOCK_APP_PREFIXES = ("com.apple.", "org.paxmobile.", "org.paxpeace.")
# Password managers, Mac and iPhone. Bundle IDs from Apple's iTunes Search API
# (entity=software and macSoftware, country=gb), 2026-10-16; the vendor download
# builds (1Password 8, Bitwarden, KeePassXC) are their published bundle IDs.
PASSWORD_MANAGER_BUNDLE_IDS = frozenset({
    "com.1password.1password", "com.agilebits.onepassword7", "com.agilebits.onepassword-osx",
    "com.1password.safari",
    "com.8bit.bitwarden", "com.bitwarden.desktop",
    "com.lastpass.ilastpass", "com.lastpass.lastpass", "com.lastpass.lastpassforsafari",
    "com.dashlane.dashlanephonefinal",
    "me.proton.pass.ios", "me.proton.pass.catalyst", "me.proton.pass.electron",
    "com.keepassium.ios", "org.keepassxc.keepassxc",
    "com.markmcguill.strongbox", "com.markmcguill.strongbox.pro", "com.markmcguill.strongbox.mac",
    "in.sinew.walletx", "in.sinew.enpass-desktop",
    "com.callpod.keepermac.lite", "com.keepersecurity.safari.keeperfill",
    "com.nordpass.ios.app.password.manager", "com.nordpass.safari.app.password.manager",
})
# Matched against the app's name too, for builds whose bundle ID isn't above.
PASSWORD_MANAGER_NAMES = ("1password", "bitwarden", "lastpass", "dashlane", "proton pass", "keepass",
                          "strongbox", "enpass", "keeper password", "nordpass", "roboform")


@dataclass(frozen=True)
class AppIdentity:
    """Who an app is, as pax-guard (root) reads it from disk."""
    path: str
    bundle_id: str = ""
    name: str = ""
    executable: str = ""
    signing_id: str = ""          # codesign "Identifier=" (sealed in the signature)
    team_id: str = ""             # codesign "TeamIdentifier=" ("" when not set / ad hoc)
    apple: bool = False           # signed by Apple as part of macOS ("Software Signing")


def parse_codesign(out: str) -> dict:
    """`codesign -dv --verbose=2 <app>` (it writes to stderr) -> identifier, team, Apple?"""
    info = {"signing_id": "", "team_id": "", "apple": False}
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("Identifier="):
            info["signing_id"] = line.split("=", 1)[1].strip()
        elif line.startswith("TeamIdentifier="):
            v = line.split("=", 1)[1].strip()
            info["team_id"] = "" if v.lower() in ("not set", "") else v
        elif line == "Authority=Software Signing":
            info["apple"] = True
    return info


def app_protected_reason(ident: AppIdentity) -> str | None:
    """Why this app may never be blocked, or None."""
    bid = ident.bundle_id.lower()
    sid = ident.signing_id.lower()
    if ident.path.startswith("/System/") or ident.apple:
        return "part of macOS"
    for prefix in NEVER_BLOCK_APP_PREFIXES:
        if bid.startswith(prefix) or sid.startswith(prefix):
            return "Pax itself" if "pax" in prefix else "one of Apple's own apps"
    if ident.team_id == PAX_TEAM_ID:
        return "Pax itself"
    if bid in PASSWORD_MANAGER_BUNDLE_IDS or sid in PASSWORD_MANAGER_BUNDLE_IDS:
        return "a password manager"
    name = (ident.name or "").lower()
    if any(n in name for n in PASSWORD_MANAGER_NAMES):
        return "a password manager"
    return None


def app_entry(ident: AppIdentity, now: int) -> dict:
    return {"bundle_id": ident.bundle_id, "name": ident.name or ident.bundle_id,
            "signing_id": ident.signing_id, "team_id": ident.team_id,
            "executable": ident.executable, "path": ident.path, "added_at": int(now)}


def app_matches(ident: AppIdentity, entry: dict) -> bool:
    """Is this app (wherever it is, whatever it's called) one the user blocked?
      * the same bundle ID (renamed or copied: the bundle ID comes along);
      * the same signing identifier, from the same Team ID or with none (Info.plist
        edited in a copy: the sealed identifier stays; re-signed ad hoc keeping it);
      * unsigned / ad-hoc copies with the blocked app's program name.
    Entries are checked when they're added (app_protected_reason), so here only
    what a copy can't fake keeps an app safe: macOS's own signature, /System, and
    Pax's Team ID. (A bundle ID or name edited into a copy's Info.plist doesn't.)"""
    if ident.apple or ident.path.startswith("/System/") or ident.team_id == PAX_TEAM_ID:
        return False
    bid = (entry.get("bundle_id") or "").lower()
    if bid and ident.bundle_id.lower() == bid:
        return True
    sid = (entry.get("signing_id") or "").lower()
    team = entry.get("team_id") or ""
    if sid and ident.signing_id.lower() == sid and ident.team_id in ("", team):
        return True
    exe = entry.get("executable") or ""
    if exe and not ident.team_id and ident.executable == exe and exe.lower() not in _GENERIC_EXECUTABLES:
        return True
    return False


# Program names too common to identify an app on their own.
_GENERIC_EXECUTABLES = {"electron", "app", "main", "run", "launcher", "applet", "python", "java", "node"}


@dataclass
class GuardState:
    """What the daemon last wrote, so a cycle that changes nothing writes nothing."""
    hosts_digest: str = ""
    pf_digest: str = ""
    ad_domains: list[str] = field(default_factory=list)
    ads_fetched_at: int = 0


ADS_REFRESH_SECONDS = 24 * 3600
# v0.8.7: a failed ad-list download is tried again after an hour, not every cycle.
ADS_RETRY_SECONDS = 3600


def ads_due(now: int, state: GuardState, every: int = ADS_REFRESH_SECONDS) -> bool:
    return now - state.ads_fetched_at >= every


# v0.8.14: the Chrome extensions the current version allows (profile/mac_policies.py
# allowed_extension_ids("chrome"); a test keeps the two in step). A Mac set up with an
# older version keeps that version's list in its locked profile: pax-guard compares,
# and the app explains why an allowed extension shows as blocked. Read-only: nothing
# here changes the profile or loosens anything.
CHROME_ALLOWED_EXTENSIONS = {
    "aeblfdkhhhdcdjpifhhbdiojplfjncoa": "1Password",
    "nngceckbapebfimnlniiiahkandclblb": "Bitwarden",
    "hdokiejnpimakedhajhdlcegeplioahd": "LastPass",
    "fdjamakpfbbddfjaooikfcpapjohcfmg": "Dashlane",
    "ghmbeldphafepmbegfdlkpapadhbakde": "Proton Pass",
    "pejdijmoenmkgeppbflobdenhhabjlaj": "iCloud Passwords",
    "laookkfknpbbblfpciffpaejjkokdgca": "Momentum",
}
CHROME_MANAGED_PREFS = "/Library/Managed Preferences/com.google.Chrome.plist"
