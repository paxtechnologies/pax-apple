#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Generate a locked Pax configuration profile (.mobileconfig).

iOS / iPadOS profile (default) contains four payloads:

  1. com.apple.dnsSettings.managed   encrypted DNS (DoH) to a filtering resolver,
                                     ProhibitDisablement = true (supervised only)
  2. com.apple.applicationaccess     restrictions: no Erase All Content & Settings,
                                     no VPN creation, no iCloud Private Relay, no
                                     manual profile installs, blocked bypass apps
                                     and remote AI apps (ChatGPT, Manus; v0.8.1)
  3. com.apple.webcontent-filter     Apple's built-in content filter
                                     (AutoFilterEnabled) + custom deny-list URLs
                                     + media converters and remote AI
                                     browsers (v0.8.1)
  4. com.apple.profileRemovalPassword removal password (random, escrowed)

The top-level PayloadRemovalDisallowed = true means the profile can only be
removed with the removal password (supervised devices).

macOS variant (--platform macos) is DNS-only (+ removal password), for the Mac
used to set up the iPhone. See README for why it is weaker.

Mac self-lock variant (--self-lock, v0.4) is for "Protect this Mac": system-wide
encrypted DNS, iCloud Private Relay off, and managed browser policies for
Chrome, Edge, Brave and Firefox (mac_policies.py): browser DoH off or forced to
our resolver, OS resolver only, proxies locked to direct, Google SafeSearch and
YouTube strict Restricted Mode, chrome://flags blocked, custom URLBlocklist,
System-wide ad list on unless --no-adblock (v0.6.1: no uBlock extension).
Extensions: password managers only (allowed, never installed; v0.7.0). It has NO removal
password payload: once the everyday account is a Standard user, removing a
System-scope profile needs an administrator, and the only administrator's
password (paxadmin) is the secret Pax escrows. Private browsing stays allowed.

The removal password is NEVER printed. It is written only to the escrow JSON file
(mode 0600), which the Mac app uploads to the Pax server and then deletes.

Usage:
  python3 make_profile.py --out pax.mobileconfig --escrow-out escrow.json \
      [--platform ios|macos] \
      [--filter family|core | --resolver-url URL | --user-token TOKEN [--dns-base URL]] \
      [--block-app BUNDLE_ID ...] \
      [--block-url URL ...] [--no-default-app-blocks] [--org NAME] \
      [--fallback-denylist | --no-fallback-denylist]

--user-token (v0.3) points DNS at the user's own pax-dns path,
<dns-base>/u/<token>/dns-query (default base https://dns.paxpeace.com, or
$PAX_DNS_BASE), so their custom blocklist follows them to every device without a
new profile. The token is a secret: it is never printed (stdout shows it masked).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import plistlib
import re
import secrets
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bypass_apps import default_bundle_ids  # noqa: E402
from fallback_denylist import FALLBACK_DENYLIST_URLS  # noqa: E402
from media_converters import IOS_CONVERTER_URLS  # noqa: E402
from remote_ai_browsers import IOS_REMOTE_AI_APP_BUNDLE_IDS, IOS_REMOTE_AI_URLS  # noqa: E402
import app_blocks  # noqa: E402  (v0.8.7: the user's own blocked iPhone apps)
import mac_policies  # noqa: E402
# The restricted-content rules (common/pax_restricted.py; copied next to this
# file in Pax.app).
sys.path.append(str(Path(__file__).resolve().parent.parent / "common"))
import pax_restricted as pr  # noqa: E402

# Both URLs verified 2026-10-12 on https://cleanbrowsing.org/filters/
# (DNS-over-HTTPS rows).
# Family Filter (DEFAULT since v0.2): blocks restricted content, proxy/VPN
# domains and mixed-content sites such as Reddit (fully blocked), and forces
# SafeSearch on Google, Bing and YouTube.
# Core filter (--filter core, CleanBrowsing's narrower filter): blocks
# restricted content and forces Google/Bing SafeSearch, but leaves Reddit and
# VPN/proxy domains reachable. Its address is kept encoded in
# common/pax_restricted.py.
CLEANBROWSING_FAMILY_DOH = "https://doh.cleanbrowsing.org/doh/family-filter/"
CLEANBROWSING_CORE_DOH = pr.source("cb_core_doh")
FILTERS = {"family": CLEANBROWSING_FAMILY_DOH, "core": CLEANBROWSING_CORE_DOH}
DEFAULT_FILTER = "family"
DEFAULT_RESOLVER_URL = FILTERS[DEFAULT_FILTER]


# Per-user pax-dns (v0.3). Base overridable with --dns-base or $PAX_DNS_BASE.
DEFAULT_DNS_BASE = "https://dns.paxpeace.com"  # v0.8.8: Pax's own DoH filter
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")


def default_dns_base() -> str:
    return os.environ.get("PAX_DNS_BASE") or DEFAULT_DNS_BASE


def user_doh_url(token: str, base: str | None = None) -> str:
    """https://dns.paxpeace.com/u/<token>/dns-query (RFC 8484)."""
    token = (token or "").strip()
    if not _TOKEN_RE.match(token):
        raise ProfileError("user token must be 22-128 URL-safe characters (A-Z a-z 0-9 _ -)")
    base = (base or default_dns_base()).strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        raise ProfileError(f"DNS base must be an https:// URL without query, got {base!r}")
    return f"{base}/u/{token}/dns-query"


def mask_token_url(url: str) -> str:
    """For logs and stdout: https://dns.paxpeace.com/u/abcd…/dns-query."""
    return re.sub(r"/u/([A-Za-z0-9_-]{4})[A-Za-z0-9_-]+/", r"/u/\1…/", url)


def resolver_for(filter_name: str = DEFAULT_FILTER, resolver_url: str | None = None,
                 user_token: str | None = None, dns_base: str | None = None) -> str:
    """The DoH URL to use: --user-token, then --resolver-url, then --filter."""
    if user_token and resolver_url:
        raise ProfileError("give --user-token or --resolver-url, not both")
    if user_token:
        return user_doh_url(user_token, dns_base)
    if resolver_url:
        return _validate_resolver_url(resolver_url)
    try:
        return FILTERS[filter_name]
    except KeyError:
        raise ProfileError(
            f"unknown filter {filter_name!r}; choose one of {', '.join(sorted(FILTERS))}"
        ) from None

PAX_ID_PREFIX = "org.paxpeace.pax"
MAX_DENYLIST_URLS = 500  # Apple: "Limit the number of these URLs to no more than 500."
# v0.8.0 (project decision, 2026-10-15): Reddit's and Imgur's media hosts, always in the
# iPhone/iPad content filter so embeds don't load in other apps' web views
# (CleanBrowsing blocks them too; the Mac's local lists have them).
# v0.8.13 (project decision): X's and Bluesky's media servers are always blocked,
# with no switch, so they're built in too (same list as guard_config
# ALWAYS_BLOCKED_MEDIA_NAMES; a test checks). Before 0.8.13 the app sent them as
# custom blocks when its switches were on. x.com and bsky.app stay readable.
IOS_ALWAYS_BLOCKED_MEDIA_HOSTS = ["pbs.twimg.com", "video.twimg.com", "ton.twimg.com",
                                  "cdn.bsky.app", "video.bsky.app", "video.cdn.bsky.app", "gifs.bsky.app"]
IOS_BUILTIN_DENY_HOSTS = (["redd.it", "redditmedia.com", "redditstatic.com", "imgur.io"]
                          + IOS_ALWAYS_BLOCKED_MEDIA_HOSTS)
# v0.8.1: Apple's 500 is shared out as 11 media hosts (v0.8.13; 4 before) + 60
# media converters (media_converters.py, always) + 8 remote AI browsers
# (remote_ai_browsers.py, always) + 60 fallback URLs (fallback_denylist.py, with
# --user-token) + 361 custom blocks (368 before 0.8.13, when the 7 X/Bluesky hosts
# took custom slots instead). The full lists live in DNS; see docs/FILTER_LISTS.md.
MAX_CUSTOM_DENYLIST_URLS = (MAX_DENYLIST_URLS - len(IOS_BUILTIN_DENY_HOSTS) - len(IOS_CONVERTER_URLS)
                            - len(IOS_REMOTE_AI_URLS) - len(FALLBACK_DENYLIST_URLS))

# Password alphabet: lowercase + digits without look-alikes (0/o, 1/l/i).
# 6 groups x 5 chars from 31 symbols ~= 148 bits of entropy, and still typeable
# on an iPhone keyboard when the user finally removes the profile.
_PW_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_PW_GROUPS = 6
_PW_GROUP_LEN = 5


class ProfileError(ValueError):
    """Raised when the inputs would produce an invalid or unsafe profile."""
    code = "PAX-PROFILE-001"


class AppBlockProfileError(ProfileError):
    """v0.8.7: an app the user chose that Pax never blocks, or too many."""
    code = "PAX-PROFILE-004"


def generate_removal_password() -> str:
    groups = [
        "".join(secrets.choice(_PW_ALPHABET) for _ in range(_PW_GROUP_LEN))
        for _ in range(_PW_GROUPS)
    ]
    return "-".join(groups)


def _uuid() -> str:
    return str(uuid.uuid4()).upper()


def _validate_resolver_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProfileError(
            f"resolver URL must be an https:// DoH URL (RFC 8484), got {url!r}"
        )
    return url


def _validate_bundle_id(bid: str) -> str:
    bid = bid.strip()
    if not bid or " " in bid or "." not in bid:
        raise ProfileError(f"not a plausible bundle ID: {bid!r}")
    return bid


def _validate_block_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ProfileError(f"not a valid URL to block: {url!r}")
    return url


@dataclass
class ProfileOptions:
    platform: str = "ios"  # "ios" (iPhone/iPad) or "macos"
    resolver_url: str = DEFAULT_RESOLVER_URL
    custom_app_blocks: list[str] = field(default_factory=list)
    custom_url_blocks: list[str] = field(default_factory=list)
    # v0.8.1: URLs Apple's automatic filter lets through (PermittedURLs). Never a
    # site Pax always blocks: each host is checked like an exception request
    # (restricted content, media converters, CleanBrowsing Family) and refused
    # with PAX-DNS-010. `upstream_lookup` is the DoH lookup for that check
    # (default: CleanBrowsing Family); a failed lookup refuses.
    permitted_urls: list[str] = field(default_factory=list)
    upstream_lookup: object = None
    include_default_app_blocks: bool = True
    organization: str = "Pax"
    # Use the pre-iOS-15 key blacklistedAppBundleIDs as well. Apple's schema:
    # blacklistedAppBundleIDs iOS 9.3, deprecated 15.0; blockedAppBundleIDs iOS
    # 15.0+. Emitting both costs nothing and covers older devices.
    include_legacy_blacklist_key: bool = True
    removal_password: str | None = None  # generated when None
    profile_uuid: str | None = None  # generated when None
    # Built-in fallback DenyListURLs (fallback_denylist.py) for Apple's web filter.
    # iOS only (macOS has no built-in web filter). The CLI turns it on with
    # --user-token and --fallback-denylist.
    include_fallback_denylist: bool = False
    # v0.4 Mac self-lock ("Protect this Mac"). platform must be "macos".
    self_lock: bool = False
    # Self-lock only: system-wide ad/tracker list (v0.6.1: no uBlock extension).
    adblock: bool = True
    # Self-lock only: browser-level DoH URL. None = browser DoH off, so browsers
    # use the macOS resolver (already filtered by the DNS payload).
    browser_doh_url: str | None = None
    # v0.5, self-lock only. Pax Image Blur: Firefox from the local XPI, Chromium
    # browsers once a store ID exists. Off here for API compatibility; the CLI
    # (and so the app) turns it on only with --image-blur (v0.6: opt-in 'Pax Max').
    image_blur: bool = False
    # v0.8.12: Pax Max switchable after set-up. Firefox gets Pax Image Blur whatever
    # was chosen; pax-guard tells it whether to blur (an /etc/hosts signal it
    # writes only while Pax Max is off). Chromium browsers still follow image_blur.
    image_blur_switchable: bool = False
    blur_chrome_id: str | None = None
    blur_edge_id: str | None = None
    # v0.5: put the always-on bypass list in URLBlocklist / WebsiteFilter.
    block_bypass_sites: bool = True
    # v0.8.0, self-lock only. "local": no DNS payload; pax-guard's forwarder on
    # 127.0.0.1 does DNS (its lists, then CleanBrowsing, then AdGuard Family),
    # because a DoH payload would send lookups straight past it. "profile": the
    # v0.7 CleanBrowsing DoH payload. The CLI defaults to "local" with --self-lock.
    mac_dns: str = "profile"
    # v0.8.6: YouTube Restricted Mode (on by default). Off: the DNS payload sends
    # YouTube's own names (YOUTUBE_NAMES) to the network's resolver instead of the
    # filter, through Apple's per-domain OnDemandRules (EvaluateConnection +
    # NeverConnect), because CleanBrowsing Family forces Restricted Mode for them.
    # Every other name still goes to the filter; nothing else changes. On the Mac
    # with local DNS, pax-guard's switch does it and the browsers no longer carry
    # ForceYouTubeRestrict (it would override the switch).
    youtube_restricted: bool = True


# v0.8.6: the names YouTube's DNS-based Restricted Mode covers (same list as
# guard/dns_forwarder.py YOUTUBE_NAMES). Each also matches its subdomains on Apple's side.
YOUTUBE_NAMES = ["youtube.com", "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
                 "youtube.googleapis.com", "youtube-nocookie.com", "www.youtube-nocookie.com"]


@dataclass
class GeneratedProfile:
    profile: dict
    removal_password: str
    profile_identifier: str
    profile_uuid: str
    platform: str = "ios"

    def to_bytes(self) -> bytes:
        return plistlib.dumps(self.profile, fmt=plistlib.FMT_XML, sort_keys=True)

    def escrow_record(self) -> dict:
        return {
            "schema": "pax.escrow.v1",
            "profile_identifier": self.profile_identifier,
            "profile_uuid": self.profile_uuid,
            "platform": self.platform,
            "removal_password": self.removal_password,
            "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        }


def _payload(ptype: str, ident_suffix: str, display: str, body: dict) -> dict:
    p = {
        "PayloadType": ptype,
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{PAX_ID_PREFIX}.{ident_suffix}",
        "PayloadUUID": _uuid(),
        "PayloadDisplayName": display,
    }
    p.update(body)
    return p


def dns_payload(resolver_url: str, prohibit_disablement: bool = True, youtube_restricted: bool = True) -> dict:
    body = {
        "DNSSettings": {
            "DNSProtocol": "HTTPS",
            "ServerURL": _validate_resolver_url(resolver_url),
        },
        # Supervised-only key. Ignored (not an error) on unsupervised devices.
        "ProhibitDisablement": bool(prohibit_disablement),
    }
    if not youtube_restricted:
        # Apple: EvaluateConnection = "apply DNS Settings with per-domain exceptions";
        # NeverConnect = "don't use the DNS Settings for the specified domains". A rule
        # with no match keys applies on every network. Only YouTube's names leave the
        # filter; there is no AllowFailover, so everything else still never does.
        body["OnDemandRules"] = [{
            "Action": "EvaluateConnection",
            "ActionParameters": [{"Domains": list(YOUTUBE_NAMES), "DomainAction": "NeverConnect"}],
        }]
    return _payload("com.apple.dnsSettings.managed", "dns", "Pax filtered DNS", body)


def restrictions_payload(blocked_bundle_ids: list[str], include_legacy_key: bool) -> dict:
    body = {
        # All of these are supervised-only on iOS (see README "Supervision").
        "allowEraseContentAndSettings": False,
        "allowVPNCreation": False,
        "allowCloudPrivateRelay": False,
        "allowUIConfigurationProfileInstallation": False,
    }
    if blocked_bundle_ids:
        body["blockedAppBundleIDs"] = list(blocked_bundle_ids)
        if include_legacy_key:
            body["blacklistedAppBundleIDs"] = list(blocked_bundle_ids)
    return _payload(
        "com.apple.applicationaccess", "restrictions", "Pax restrictions", body
    )


def webfilter_payload(deny_urls: list[str], permitted_urls: list[str] | None = None) -> dict:
    body = {
        "FilterType": "BuiltIn",
        "AutoFilterEnabled": True,
        # No ContentFilterUUID on purpose: per Apple's schema that key scopes the
        # filter to *managed apps* carrying the same UUID (the unsupervised/user
        # enrollment path). On a supervised device we want it device-wide.
    }
    if deny_urls:
        body["DenyListURLs"] = list(deny_urls)
    if permitted_urls:
        body["PermittedURLs"] = list(permitted_urls)
    return _payload(
        "com.apple.webcontent-filter", "webfilter", "Pax content filter", body
    )


def removal_password_payload(password: str) -> dict:
    return _payload(
        "com.apple.profileRemovalPassword",
        "removalpassword",
        "Pax removal password",
        {"RemovalPassword": password},
    )


SELF_LOCK_ID_PREFIX = f"{PAX_ID_PREFIX}.macos-selflock"


def mac_restrictions_payload() -> dict:
    """macOS 12+: allowCloudPrivateRelay=false (Private Relay would carry Safari's
    DNS around the filter). Not supervised-only on macOS (Apple schema)."""
    return _payload("com.apple.applicationaccess", "mac-restrictions",
                    "Pax restrictions (Mac)", {"allowCloudPrivateRelay": False})


_EXT_ID_RE = re.compile(r"^[a-p]{32}$")


def _validate_extension_id(ext_id: str | None) -> str:
    """Chromium extension IDs are 32 letters a-p; '' means none."""
    ext_id = (ext_id or "").strip()
    if ext_id and not _EXT_ID_RE.match(ext_id):
        raise ProfileError(f"not a Chromium extension ID: {ext_id!r}")
    return ext_id


def _host_of(url: str) -> str:
    return (urlparse(_validate_block_url(url)).hostname or "").lower()


def build_mac_self_lock(opts: ProfileOptions) -> GeneratedProfile:
    profile_uuid = opts.profile_uuid or _uuid()
    identifier = f"{SELF_LOCK_ID_PREFIX}.{profile_uuid.lower()}"
    if opts.custom_app_blocks:
        raise ProfileError("app blocks on the Mac are enforced by pax-guard, not the profile")
    hosts = list(dict.fromkeys(_host_of(u) for u in opts.custom_url_blocks))
    if len(hosts) > MAX_DENYLIST_URLS:
        raise ProfileError(f"at most {MAX_DENYLIST_URLS} custom URL blocks")
    if opts.mac_dns not in ("local", "profile"):
        raise ProfileError("mac_dns must be 'local' or 'profile'")
    content = [mac_restrictions_payload()]
    if opts.mac_dns == "profile":
        content.insert(0, dns_payload(opts.resolver_url, prohibit_disablement=False,
                                      youtube_restricted=opts.youtube_restricted))
    browser_doh = _validate_resolver_url(opts.browser_doh_url) if opts.browser_doh_url else None
    blur_ids = {"chrome": _validate_extension_id(opts.blur_chrome_id or
                                                 mac_policies.BLUR_CHROME_WEBSTORE_ID),
                "edge": _validate_extension_id(opts.blur_edge_id or mac_policies.BLUR_EDGE_ADDONS_ID)}
    bypass = mac_policies.bypass_hosts() if opts.block_bypass_sites else []
    # v0.8.1: remote AI browsers (ChatGPT, Manus) in every managed browser too, always.
    bypass = bypass + [h for h in mac_policies.remote_ai_hosts() if h not in bypass]
    # v0.8.6: with local DNS, pax-guard enforces YouTube Restricted Mode for every
    # browser and app (and can switch it off); a browser policy would override that.
    youtube = (mac_policies.YOUTUBE_STRICT if opts.mac_dns == "profile" and opts.youtube_restricted
               else None)
    for domain, settings in mac_policies.all_browser_policies(
            doh_url=browser_doh, custom_hosts=hosts, adblock=opts.adblock,
            image_blur=opts.image_blur, blur_ids=blur_ids, bypass=bypass,
            blur_firefox=opts.image_blur_switchable,
            youtube_restrict=youtube).items():
        short = mac_policies.SHORT_NAMES[domain]
        content.append(_payload("com.apple.ManagedClient.preferences", f"browser.{short}",
                                f"Pax browser policy ({domain})",
                                mac_policies.managed_client_body(domain, settings)))
    # Own payload identifiers, so this profile never collides with an older Pax
    # DNS-only Mac profile (org.paxpeace.pax.dns) that may still be installed.
    for p in content:
        p["PayloadIdentifier"] = p["PayloadIdentifier"].replace(
            PAX_ID_PREFIX + ".", SELF_LOCK_ID_PREFIX + ".payload.", 1)
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": identifier,
        "PayloadUUID": profile_uuid,
        "PayloadDisplayName": "Pax (this Mac)",
        "PayloadDescription": (
            "Pax filters unwanted content on this Mac with encrypted DNS and browser "
            "policies. Removing it needs the Pax administrator password, which the Pax "
            "escrow service releases after your chosen wait."),
        "PayloadOrganization": opts.organization,
        "PayloadRemovalDisallowed": True,
        "PayloadScope": "System",
        "PayloadContent": content,
    }
    gp = GeneratedProfile(profile, "", identifier, profile_uuid, "macos")
    validate_profile(gp.profile, platform="macos", self_lock=True, local_dns=opts.mac_dns == "local")
    return gp


_CONVERTER_LIST_DIRS = [Path(__file__).resolve().parent.parent / "lists",
                        Path(__file__).resolve().parent.parent / "pax-dns" / "lists"]


def _converter_check() -> "pr.RestrictedCheck":
    """Restricted content + media converters + remote AI browsers (the full lists
    when they're next to us: Resources/lists in Pax.app, pax-dns/lists in the repo)."""
    names = {u.split("//", 1)[1] for u in IOS_CONVERTER_URLS + IOS_REMOTE_AI_URLS}
    rules = []
    for d in _CONVERTER_LIST_DIRS:
        if (d / "media-converters.txt").is_file():
            names |= set(pr.parse_domain_file((d / "media-converters.txt").read_text()))
            if (d / "media-converter-keywords.txt").is_file():
                rules.append(pr.parse_rule_file((d / "media-converter-keywords.txt").read_text()))
            if (d / "remote-ai-browsers.txt").is_file():
                names |= set(pr.parse_domain_file((d / "remote-ai-browsers.txt").read_text()))
            break
    return pr.RestrictedCheck(sets=[names], rules=rules)


def check_permitted_urls(urls: list[str], lookup=None) -> list[str]:
    """Validated PermittedURLs, or ProfileError (PAX-DNS-010) when any host is a
    site Pax always blocks. The iPhone's allowed URLs never include one."""
    out = []
    static = _converter_check()
    lookup = lookup or pr.doh_lookup(pr.CLEANBROWSING_FAMILY_DOH)
    for u in dict.fromkeys(urls):
        host = _host_of(u)
        try:
            pr.check_exception(host, static=static, lookup=lookup)
        except pr.RestrictedSite:
            raise ProfileError(f"{pr.RESTRICTED_CODE}: {pr.RESTRICTED_MESSAGE}") from None
        out.append(_validate_block_url(u))
    return out


def build_profile(opts: ProfileOptions) -> GeneratedProfile:
    if opts.platform not in ("ios", "macos"):
        raise ProfileError("platform must be 'ios' or 'macos'")
    if opts.self_lock:
        if opts.platform != "macos":
            raise ProfileError("--self-lock is macOS only")
        return build_mac_self_lock(opts)

    password = opts.removal_password or generate_removal_password()
    if len(password) < 20:
        raise ProfileError("removal password too short (min 20 chars)")
    profile_uuid = opts.profile_uuid or _uuid()
    identifier = f"{PAX_ID_PREFIX}.{opts.platform}.{profile_uuid.lower()}"

    apps: list[str] = []
    if opts.platform == "ios":
        if opts.include_default_app_blocks:
            apps.extend(default_bundle_ids())
        try:
            apps.extend(app_blocks.validate_custom_apps(list(opts.custom_app_blocks)))
        except app_blocks.AppBlockError as exc:
            raise AppBlockProfileError(str(exc)) from None
        # v0.8.1: remote AI apps (ChatGPT, Manus) are always blocked; the web
        # filter below doesn't reach native apps.
        apps.extend(IOS_REMOTE_AI_APP_BUNDLE_IDS)
        apps = list(dict.fromkeys(apps))  # de-duplicate, keep order
        custom = list(dict.fromkeys(_validate_block_url(u) for u in opts.custom_url_blocks))
        builtin = [_validate_block_url(h) for h in IOS_BUILTIN_DENY_HOSTS]
        custom = [u for u in custom if u not in builtin]
        if len(custom) > MAX_CUSTOM_DENYLIST_URLS:
            raise ProfileError(f"at most {MAX_CUSTOM_DENYLIST_URLS} custom URL blocks")
        converters = [u for u in IOS_CONVERTER_URLS if u not in custom and u not in builtin]
        remote_ai = [u for u in IOS_REMOTE_AI_URLS if u not in custom and u not in builtin]
        # Custom blocks first, then Pax's 11 media hosts, the 60 media converters,
        # the 8 remote AI browsers and (with --user-token) the fallback; the cap
        # above keeps all of them.
        urls = custom + builtin + converters + remote_ai
        if opts.include_fallback_denylist:
            room = MAX_DENYLIST_URLS - len(urls)
            extra = [u for u in FALLBACK_DENYLIST_URLS if u not in urls]
            urls.extend(extra[:room])
        if len(urls) > MAX_DENYLIST_URLS:
            raise ProfileError(f"at most {MAX_DENYLIST_URLS} web filter URLs")
        permitted = check_permitted_urls(opts.permitted_urls, opts.upstream_lookup) if opts.permitted_urls else []
        content = [
            dns_payload(opts.resolver_url, prohibit_disablement=True,
                        youtube_restricted=opts.youtube_restricted),
            restrictions_payload(apps, opts.include_legacy_blacklist_key),
            webfilter_payload(urls, permitted),
            removal_password_payload(password),
        ]
        description = (
            "Pax blocks unwanted content with filtered encrypted DNS and Apple's "
            "built-in web filter. Removing it requires a password held by the "
            "Pax escrow service and released after your chosen wait time."
        )
    else:
        if opts.custom_app_blocks or opts.custom_url_blocks:
            raise ProfileError("custom app/URL blocks are iOS-only in v0.1")
        # On macOS, ProhibitDisablement needs a supervised (MDM/ADE) Mac, so we
        # leave it out: a manually installed profile cannot lock DNS on a Mac.
        content = [
            dns_payload(opts.resolver_url, prohibit_disablement=False,
                        youtube_restricted=opts.youtube_restricted),
            removal_password_payload(password),
        ]
        description = (
            "Pax filtered DNS for this Mac. Removing it requires a password held "
            "by the Pax escrow service."
        )

    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": identifier,
        "PayloadUUID": profile_uuid,
        "PayloadDisplayName": "Pax",
        "PayloadDescription": description,
        "PayloadOrganization": opts.organization,
        "PayloadRemovalDisallowed": True,
        "PayloadContent": content,
    }
    if opts.platform == "macos":
        profile["PayloadScope"] = "System"
    gp = GeneratedProfile(profile, password, identifier, profile_uuid, opts.platform)
    validate_profile(gp.profile, platform=opts.platform)
    return gp


_REQUIRED_TOP = {
    "PayloadType": str,
    "PayloadVersion": int,
    "PayloadIdentifier": str,
    "PayloadUUID": str,
    "PayloadDisplayName": str,
    "PayloadContent": list,
}


def validate_profile(profile: dict, platform: str = "ios", self_lock: bool = False,
                     local_dns: bool = False) -> None:
    """Structural validation + plist round-trip. Raises ProfileError."""
    for key, typ in _REQUIRED_TOP.items():
        if not isinstance(profile.get(key), typ):
            raise ProfileError(f"top-level {key} missing or not {typ.__name__}")
    if profile["PayloadType"] != "Configuration":
        raise ProfileError("top-level PayloadType must be 'Configuration'")
    seen_uuids = {profile["PayloadUUID"]}
    seen_types = []
    for p in profile["PayloadContent"]:
        for key in ("PayloadType", "PayloadIdentifier", "PayloadUUID"):
            if not isinstance(p.get(key), str) or not p[key]:
                raise ProfileError(f"payload missing {key}: {p.get('PayloadType')}")
        if p["PayloadUUID"] in seen_uuids:
            raise ProfileError("duplicate PayloadUUID")
        seen_uuids.add(p["PayloadUUID"])
        seen_types.append(p["PayloadType"])
    if self_lock:
        if "com.apple.profileRemovalPassword" in seen_types:
            raise ProfileError("the Mac self-lock profile must not carry a removal password")
        if seen_types.count("com.apple.ManagedClient.preferences") < len(mac_policies.BROWSER_DOMAINS):
            raise ProfileError("browser policy payloads missing")
        if profile.get("PayloadScope") != "System":
            raise ProfileError("the Mac self-lock profile must be System scope")
    elif seen_types.count("com.apple.profileRemovalPassword") != 1:
        raise ProfileError("exactly one removal password payload required")
    if local_dns:
        if not self_lock or "com.apple.dnsSettings.managed" in seen_types:
            raise ProfileError("local DNS is for the Mac self-lock profile, without a DNS payload")
    elif "com.apple.dnsSettings.managed" not in seen_types:
        raise ProfileError("DNS payload required")
    if platform == "ios":
        for needed in ("com.apple.applicationaccess", "com.apple.webcontent-filter"):
            if needed not in seen_types:
                raise ProfileError(f"{needed} payload required on iOS")
    # Round-trip through plistlib: catches non-plist types (None, sets, ...).
    try:
        data = plistlib.dumps(profile, fmt=plistlib.FMT_XML)
        back = plistlib.loads(data)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProfileError(f"profile is not a valid property list: {exc}") from exc
    if back != profile:
        raise ProfileError("plist round-trip changed the profile")


def _write_private(path: Path, data: bytes) -> None:
    """Write a file readable only by the current user (0600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate a locked Pax .mobileconfig")
    ap.add_argument("--out", required=True, type=Path, help=".mobileconfig output path")
    ap.add_argument(
        "--escrow-out",
        type=Path,
        default=None,
        help="JSON file (0600) receiving the removal password for escrow "
        "(required except with --self-lock)",
    )
    ap.add_argument("--platform", choices=["ios", "macos"], default="ios")
    ap.add_argument("--macos", action="store_true", help="shorthand for --platform macos")
    ap.add_argument("--self-lock", action="store_true",
                    help="Mac self-lock profile (implies --platform macos): DNS + browser "
                    "policies, no removal password (v0.4, 'Protect this Mac')")
    ap.add_argument("--mac-dns", choices=["local", "profile"], default="local",
                    help="--self-lock: 'local' (default, v0.8: pax-guard's 127.0.0.1 forwarder, no DNS "
                    "payload) or 'profile' (v0.7: CleanBrowsing DoH payload)")
    ap.add_argument("--no-adblock", action="store_true",
                    help="--self-lock: turn the system-wide ad list off")
    ap.add_argument("--no-youtube-restricted", action="store_true",
                    help="v0.8.6: YouTube Restricted Mode off. YouTube's own names skip the filtered DNS "
                    "(Apple OnDemandRules NeverConnect); SafeSearch and every block stay. With --self-lock "
                    "and local DNS, pax-guard's switch decides instead")
    ap.add_argument("--image-blur", action="store_true",
                    help="--self-lock: force-install Pax Image Blur ('Pax Max', opt-in since v0.6)")
    ap.add_argument("--no-image-blur", action="store_true",
                    help="--self-lock: kept for compatibility; image blur is off unless --image-blur")
    ap.add_argument("--image-blur-switchable", action="store_true",
                    help="--self-lock (v0.8.12): install Pax Image Blur in Firefox either way, so pax-guard "
                    "can switch Pax Max on (instant) and off (after an hour) later")
    ap.add_argument("--blur-chrome-id", default=os.environ.get("PAX_BLUR_CHROME_ID") or None,
                    help="--self-lock: Chrome Web Store ID of Pax Image Blur (default "
                    "$PAX_BLUR_CHROME_ID; none until the unlisted listing exists)")
    ap.add_argument("--blur-edge-id", default=os.environ.get("PAX_BLUR_EDGE_ID") or None,
                    help="--self-lock: Edge Add-ons ID of Pax Image Blur ($PAX_BLUR_EDGE_ID)")
    dns = ap.add_mutually_exclusive_group()
    dns.add_argument(
        "--filter",
        choices=sorted(FILTERS),
        default=DEFAULT_FILTER,
        help="CleanBrowsing filter: family (default: restricted content, proxies/VPNs, Reddit; "
        "SafeSearch on Google/Bing/YouTube) or core (restricted content only)",
    )
    dns.add_argument(
        "--resolver-url",
        default=None,
        help="custom https:// DoH resolver URL (e.g. self-hosted pax-dns); overrides --filter",
    )
    dns.add_argument(
        "--user-token",
        default=None,
        help="per-user pax-dns token: DNS goes to <dns-base>/u/<token>/dns-query so the "
        "user's synced blocklist applies (secret; never printed)",
    )
    ap.add_argument(
        "--dns-base",
        default=None,
        help=f"base URL for --user-token (default $PAX_DNS_BASE or {DEFAULT_DNS_BASE})",
    )
    fb = ap.add_mutually_exclusive_group()
    fb.add_argument("--fallback-denylist", dest="fallback", action="store_true", default=None,
                    help="add the built-in fallback DenyListURLs (default with --user-token)")
    fb.add_argument("--no-fallback-denylist", dest="fallback", action="store_false",
                    help="leave the built-in fallback DenyListURLs out")
    ap.add_argument("--block-app", action="append", default=[], metavar="BUNDLE_ID")
    ap.add_argument("--block-url", action="append", default=[], metavar="URL")
    ap.add_argument("--no-default-app-blocks", action="store_true")
    ap.add_argument("--org", default="Pax")
    args = ap.parse_args(argv)

    platform = "macos" if (args.macos or args.self_lock) else args.platform
    if args.escrow_out is None and not args.self_lock:
        print("error: --escrow-out is required (except with --self-lock)", file=sys.stderr)
        return 2
    if args.dns_base and not args.user_token:
        print("error: --dns-base needs --user-token", file=sys.stderr)
        return 2
    fallback = args.fallback if args.fallback is not None else bool(args.user_token)
    try:
        resolver = resolver_for(args.filter, args.resolver_url, args.user_token, args.dns_base)
        gp = build_profile(
            ProfileOptions(
                platform=platform,
                resolver_url=resolver,
                custom_app_blocks=args.block_app,
                custom_url_blocks=args.block_url,
                include_default_app_blocks=not args.no_default_app_blocks,
                organization=args.org,
                include_fallback_denylist=fallback and platform == "ios",
                self_lock=args.self_lock,
                adblock=not args.no_adblock,
                image_blur=args.self_lock and args.image_blur and not args.no_image_blur,
                image_blur_switchable=bool(args.self_lock and args.image_blur_switchable),
                blur_chrome_id=args.blur_chrome_id,
                blur_edge_id=args.blur_edge_id,
                mac_dns=args.mac_dns,
                youtube_restricted=not args.no_youtube_restricted,
            )
        )
    except ProfileError as exc:
        # v0.7.0 support code (common/pax_errors.py); the Mac app reads it.
        print(f"error: {exc.code}: {exc}", file=sys.stderr)
        return 2

    # The profile itself contains the password (that is how iOS checks it), so it
    # is also written 0600 and should be deleted after installation.
    _write_private(args.out, gp.to_bytes())
    if args.escrow_out is not None and not args.self_lock:
        _write_private(args.escrow_out, json.dumps(gp.escrow_record(), indent=2).encode())
    # Deliberately no password in stdout/stderr.
    print(
        json.dumps(
            {
                "profile": str(args.out),
                "escrow": None if args.self_lock else str(args.escrow_out),
                "self_lock": bool(args.self_lock),
                "image_blur": bool(args.self_lock and args.image_blur and not args.no_image_blur),
                "image_blur_switchable": bool(args.self_lock and args.image_blur_switchable),
                "profile_identifier": gp.profile_identifier,
                "platform": platform,
                "resolver_url": mask_token_url(resolver),
                "mac_dns": args.mac_dns if args.self_lock else None,
                "per_user_dns": bool(args.user_token),
                "youtube_restricted": not args.no_youtube_restricted,
                "payloads": [p["PayloadType"] for p in gp.profile["PayloadContent"]],
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
