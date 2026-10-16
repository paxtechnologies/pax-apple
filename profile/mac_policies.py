# SPDX-License-Identifier: GPL-3.0-only
"""Managed browser policies for the Mac self-lock profile (v0.4).

Delivered as com.apple.ManagedClient.preferences payloads ("Forced" =
mandatory policy), which Chrome, Edge, Brave and Firefox read from
/Library/Managed Preferences/<domain>.plist on macOS.

Key names were checked on 2026-10-14 against:
  * Chromium policy definitions (components/policy/resources/templates/
    policy_definitions/Miscellaneous/{BuiltInDnsClientEnabled,DnsOverHttpsMode,
    DnsOverHttpsTemplates,ProxySettings,URLBlocklist,ForceGoogleSafeSearch,
    ForceYouTubeRestrict}.yaml, Extensions/ExtensionInstallForcelist.yaml).
    ProxyMode is deprecated in favour of ProxySettings, so we use ProxySettings.
  * Microsoft Edge policy reference (same names; plus ForceBingSafeSearch).
    Edge Secure Network (its built-in VPN) is unavailable on managed browsers,
    so any Edge policy turns it off.
  * Brave Help Center "Group Policy": TorDisabled, BraveVPNDisabled.
  * Mozilla policy-templates docs/index.md: EnterprisePoliciesEnabled (macOS),
    DNSOverHTTPS {Enabled, ProviderURL, Locked, Fallback}, Proxy {Mode, Locked},
    ExtensionSettings (installation_mode force_installed), BlockAboutConfig.
    Firefox has no SafeSearch policy; CleanBrowsing/pax-dns force it via DNS.

v0.7.0 (project decision, 2026-10-15): password managers only. Allowed (never
force-installed) in Chrome, Brave, Chromium and Edge, and in Firefox as
ExtensionSettings installation_mode "allowed": 1Password, Bitwarden, LastPass,
Dashlane, Proton Pass and Apple's iCloud Passwords (Apple Passwords). Momentum
and Video Speed Controller are no longer allowed (their IDs are kept below,
commented out). Pax Image Blur stays the only force-install (Pax Max).
Every ID below was checked on 2026-10-15 on the official store page (Chrome
Web Store page title; Edge Add-ons product API
microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/<id>, which gives
the name and developer; AMO API addons.mozilla.org/api/v5/addons/addon/<slug>/,
which gives the guid and author):
  * 1Password
      Chrome: aeblfdkhhhdcdjpifhhbdiojplfjncoa
        (https://chromewebstore.google.com/detail/aeblfdkhhhdcdjpifhhbdiojplfjncoa)
      Edge:   dppgmdbiimibapkepcbdbmkaabgiofem, developer "AgileBits Inc."
        (https://microsoftedge.microsoft.com/addons/detail/dppgmdbiimibapkepcbdbmkaabgiofem)
      Firefox: {d634138d-c276-4fc8-924b-40a0ea21d284}, author "1Password Devs"
        (https://addons.mozilla.org/en-US/firefox/addon/1password-x-password-manager/)
  * Bitwarden
      Chrome: nngceckbapebfimnlniiiahkandclblb
        (https://chromewebstore.google.com/detail/nngceckbapebfimnlniiiahkandclblb)
      Edge:   jbkfoedolllekgbhcbcoahefnbanhhlh, developer "Bitwarden Inc"
        (https://microsoftedge.microsoft.com/addons/detail/jbkfoedolllekgbhcbcoahefnbanhhlh)
      Firefox: {446900e4-71c2-419f-a6a7-df9c091e268b}, author "Bitwarden Inc."
        (https://addons.mozilla.org/en-US/firefox/addon/bitwarden-password-manager/)
  * LastPass
      Chrome: hdokiejnpimakedhajhdlcegeplioahd
        (https://chromewebstore.google.com/detail/hdokiejnpimakedhajhdlcegeplioahd)
      Edge:   bbcinlkgjjkejfdpemiealijmmooekmp, developer "LastPass US LP."
        (https://microsoftedge.microsoft.com/addons/detail/bbcinlkgjjkejfdpemiealijmmooekmp)
      Firefox: support@lastpass.com, author "LastPass"
        (https://addons.mozilla.org/en-US/firefox/addon/lastpass-password-manager/)
  * Dashlane
      Chrome: fdjamakpfbbddfjaooikfcpapjohcfmg
        (https://chromewebstore.google.com/detail/fdjamakpfbbddfjaooikfcpapjohcfmg)
      Edge:   gehmmocbbkpblljhkekmfhjpfbkclbph, developer "Dashlane"
        (https://microsoftedge.microsoft.com/addons/detail/gehmmocbbkpblljhkekmfhjpfbkclbph)
      Firefox: jetpack-extension@dashlane.com, author "Dashlane"
        (https://addons.mozilla.org/en-US/firefox/addon/dashlane/)
  * Proton Pass
      Chrome: ghmbeldphafepmbegfdlkpapadhbakde
        (https://chromewebstore.google.com/detail/ghmbeldphafepmbegfdlkpapadhbakde)
      Edge:   gcllgfdnfnllodcaambdaknbipemelie, developer "Proton AG"
        (https://microsoftedge.microsoft.com/addons/detail/gcllgfdnfnllodcaambdaknbipemelie;
         also given by Proton at https://proton.me/support/deploy-browser-extension)
      Firefox: 78272b6fa58f4a1abaac99321d503a20@proton.me, author "Proton"
        (https://addons.mozilla.org/en-US/firefox/addon/proton-pass/)
  * iCloud Passwords (Apple Passwords)
      Chrome: pejdijmoenmkgeppbflobdenhhabjlaj, offered by Apple Inc.
        (https://chromewebstore.google.com/detail/pejdijmoenmkgeppbflobdenhhabjlaj)
      Edge:   mfbcdcnpokpoajjciilocoachedjkima, developer "Apple Inc."
        (https://microsoftedge.microsoft.com/addons/detail/mfbcdcnpokpoajjciilocoachedjkima)
      Firefox: password-manager-firefox-extension@apple.com, author "Apple Inc."
        (https://addons.mozilla.org/en-US/firefox/addon/icloud-passwords/)
Edge allows both the Edge Add-ons ID and the Chrome Web Store ID of each
(Edge can install from the Chrome Web Store once "Allow extensions from other
stores" is on), so a password manager already installed either way keeps working.

v0.6.1 (project decision, 2026-10-15): uBlock Origin / uBO Lite removed everywhere; ad
blocking is the system-wide hosts/DNS ad list only. Allowed extensions are
Momentum + Video Speed Controller in Chromium browsers, none in Firefox
(superseded by v0.7.0 above).

Extensions are locked down (project decision, 2026-10-14): VPN/proxy extensions route
around DNS filtering. Chromium browsers get ExtensionInstallBlocklist ["*"]
(which also disables already-installed extensions not allowed), an allowlist
of uBlock Origin Lite + Momentum + Video Speed Controller, ExtensionAllowedTypes
["extension"], ExtensionDeveloperModeSettings 1 (no developer mode, so no
"Load unpacked"; Chrome 128+), BlockExternalExtensions, and ExtensionSettings
with "*" blocked and blocked_permissions ["proxy", "vpnProvider"] on every
allowed extension as a second layer (per-ID ExtensionSettings entries inherit
only installation_mode/update_url from "*", so each allowed ID repeats it).
Firefox gets ExtensionSettings "*" blocked + uBlock Origin force_installed.
Previously allowed extension IDs (removed in v0.7.0), checked 2026-10-14:
  * Momentum, Chrome Web Store: laookkfknpbbblfpciffpaejjkokdgca
    (https://chromewebstore.google.com/detail/laookkfknpbbblfpciffpaejjkokdgca,
    also linked from https://momentumdash.com/download)
  * Momentum, Edge Add-ons: jdoanlopeanabgejgmdncljhkdplcfed
    (developer "Momentum Dashboard Corp.", linked from momentumdash.com/download)
  * Video Speed Controller (igrigorik), Chrome Web Store: nffaoalbilbmmfgbnbgppjihopabppdk
    (linked from https://github.com/igrigorik/videospeed). There is no official
    Edge Add-ons build; the Edge store listings with that name are third-party
    clones, so none is allowed. Edge users can install the Chrome Web Store
    build (Edge allows other stores), so its Chrome ID is allowed in Edge too.

Private browsing (Incognito, InPrivate, Firefox private windows, guest mode)
is deliberately LEFT ON (the project's choice, 2026-10-14). DNS filtering, the
hosts block and these DoH/proxy locks still apply in private windows.

Ad blocking (default on) force-installs uBlock Origin Lite in Chromium browsers
and uBlock Origin in Firefox:
  * Chrome Web Store: ddkjiahejlhfcafbddmgiahcphecmpfh
    (https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh)
  * Edge Add-ons: cimighlppcgcoapaliogpjjdehbnofhn
    (https://microsoftedge.microsoft.com/addons/detail/ublock-origin-lite/cimighlppcgcoapaliogpjjdehbnofhn)
  * Firefox (AMO): uBlock0@raymondhill.net, slug ublock-origin

v0.5 additions:
  * Pax Image Blur (extension/ in this repo). Firefox: force-installed from a
    local file, file:///Library/PaxGuard/extensions/pax-image-blur.xpi, which
    pax-guard-install.sh puts there (Mozilla policy-templates: install_url may be
    a file:/// URL; private_browsing true, Firefox 136+). Release Firefox only
    installs SIGNED add-ons, so ship the AMO-unlisted-signed XPI (README).
    Chrome/Edge/Brave: Chromium only force-installs an extension from outside
    its store on macOS if the Mac is MDM-enrolled, joined to a domain via MCX or
    enrolled in Chrome Enterprise Core (ExtensionInstallForcelist policy text;
    Chromium base/enterprise_util_mac.mm checks `profiles status -type
    enrollment`). A profile you install yourself is not MDM enrollment, so a
    locally served update_url/CRX or a file:// update_url is refused. The plan is
    an UNLISTED Chrome Web Store listing: its ID goes in BLUR_CHROME_WEBSTORE_ID
    (placeholder, empty until it exists) or PAX_BLUR_CHROME_ID / --blur-chrome-id,
    and is force-installed with the Web Store update URL like uBO Lite. Edge
    gets its own Edge Add-ons ID if one exists (BLUR_EDGE_ADDONS_ID), else the
    Chrome Web Store ID (whether Edge accepts a Web Store ID by policy on an
    unmanaged Mac is unverified).
  * The always-on "bypass" category (pax-dns/lists/cloud-pc-bypass.txt: cloud
    PCs, remote browsers, web proxies) is added to Chromium URLBlocklist (a bare
    host blocks it and its subdomains) and Firefox WebsiteFilter, as a third
    layer next to DNS and /etc/hosts. The remote-desktop category is NOT put in
    the profile: it can be switched off from the server, and a profile can't
    change without reinstalling.
"""
from __future__ import annotations

from pathlib import Path

UBOL_CHROME_ID = "ddkjiahejlhfcafbddmgiahcphecmpfh"
UBOL_EDGE_ID = "cimighlppcgcoapaliogpjjdehbnofhn"
CHROME_UPDATE_URL = "https://clients2.google.com/service/update2/crx"
EDGE_UPDATE_URL = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
UBO_FIREFOX_ID = "uBlock0@raymondhill.net"
UBO_FIREFOX_URL = "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"

# v0.7.0: removed from the allow-list (password managers only). Kept here in
# case the maintainer wants them back; uncomment and add to allowed_extension_ids().
# v0.8.4 (project decision): Momentum is allowed again (never force-installed).
MOMENTUM_CHROME_ID = "laookkfknpbbblfpciffpaejjkokdgca"
MOMENTUM_EDGE_ID = "jdoanlopeanabgejgmdncljhkdplcfed"
# VSC_CHROME_ID = "nffaoalbilbmmfgbnbgppjihopabppdk"

# v0.7.0 password managers (sources in the module docstring). Allowed only,
# never force-installed.
ONEPASSWORD_CHROME_ID = "aeblfdkhhhdcdjpifhhbdiojplfjncoa"
ONEPASSWORD_EDGE_ID = "dppgmdbiimibapkepcbdbmkaabgiofem"
ONEPASSWORD_FIREFOX_ID = "{d634138d-c276-4fc8-924b-40a0ea21d284}"
BITWARDEN_CHROME_ID = "nngceckbapebfimnlniiiahkandclblb"
BITWARDEN_EDGE_ID = "jbkfoedolllekgbhcbcoahefnbanhhlh"
BITWARDEN_FIREFOX_ID = "{446900e4-71c2-419f-a6a7-df9c091e268b}"
LASTPASS_CHROME_ID = "hdokiejnpimakedhajhdlcegeplioahd"
LASTPASS_EDGE_ID = "bbcinlkgjjkejfdpemiealijmmooekmp"
LASTPASS_FIREFOX_ID = "support@lastpass.com"
DASHLANE_CHROME_ID = "fdjamakpfbbddfjaooikfcpapjohcfmg"
DASHLANE_EDGE_ID = "gehmmocbbkpblljhkekmfhjpfbkclbph"
DASHLANE_FIREFOX_ID = "jetpack-extension@dashlane.com"
PROTONPASS_CHROME_ID = "ghmbeldphafepmbegfdlkpapadhbakde"
PROTONPASS_EDGE_ID = "gcllgfdnfnllodcaambdaknbipemelie"
PROTONPASS_FIREFOX_ID = "78272b6fa58f4a1abaac99321d503a20@proton.me"
ICLOUD_PASSWORDS_CHROME_ID = "pejdijmoenmkgeppbflobdenhhabjlaj"
ICLOUD_PASSWORDS_EDGE_ID = "mfbcdcnpokpoajjciilocoachedjkima"
ICLOUD_PASSWORDS_FIREFOX_ID = "password-manager-firefox-extension@apple.com"

# name -> {"chrome": Web Store ID, "edge": Edge Add-ons ID, "firefox": AMO ID}
PASSWORD_MANAGERS: dict[str, dict[str, str]] = {
    "1Password": {"chrome": ONEPASSWORD_CHROME_ID, "edge": ONEPASSWORD_EDGE_ID,
                  "firefox": ONEPASSWORD_FIREFOX_ID},
    "Bitwarden": {"chrome": BITWARDEN_CHROME_ID, "edge": BITWARDEN_EDGE_ID,
                  "firefox": BITWARDEN_FIREFOX_ID},
    "LastPass": {"chrome": LASTPASS_CHROME_ID, "edge": LASTPASS_EDGE_ID,
                 "firefox": LASTPASS_FIREFOX_ID},
    "Dashlane": {"chrome": DASHLANE_CHROME_ID, "edge": DASHLANE_EDGE_ID,
                 "firefox": DASHLANE_FIREFOX_ID},
    "Proton Pass": {"chrome": PROTONPASS_CHROME_ID, "edge": PROTONPASS_EDGE_ID,
                    "firefox": PROTONPASS_FIREFOX_ID},
    "iCloud Passwords": {"chrome": ICLOUD_PASSWORDS_CHROME_ID, "edge": ICLOUD_PASSWORDS_EDGE_ID,
                         "firefox": ICLOUD_PASSWORDS_FIREFOX_ID},
}
# v0.5 Pax Image Blur. The Chrome Web Store / Edge Add-ons IDs are PLACEHOLDERS:
# empty until the maintainer publishes the unlisted listings (README "Pax Image Blur").
BLUR_FIREFOX_ID = "pax-image-blur@paxmobile.org"
BLUR_FIREFOX_XPI_URL = "file:///Library/PaxGuard/extensions/pax-image-blur.xpi"
BLUR_CHROME_WEBSTORE_ID = ""   # PLACEHOLDER: unlisted Chrome Web Store item ID
BLUR_EDGE_ADDONS_ID = ""       # PLACEHOLDER: Edge Add-ons item ID (optional)

# Second layer: extensions may not use these permissions even if allowed.
BLOCKED_PERMISSIONS = ["proxy", "vpnProvider"]

CHROME_DOMAIN = "com.google.Chrome"
EDGE_DOMAIN = "com.microsoft.Edge"
BRAVE_DOMAIN = "com.brave.Browser"
FIREFOX_DOMAIN = "org.mozilla.firefox"
# Chromium (incl. ungoogled-chromium) reads Chromium policies from its own domain.
CHROMIUM_DOMAIN = "org.chromium.Chromium"
BROWSER_DOMAINS = (CHROME_DOMAIN, EDGE_DOMAIN, BRAVE_DOMAIN, CHROMIUM_DOMAIN, FIREFOX_DOMAIN)
SHORT_NAMES = {CHROME_DOMAIN: "chrome", EDGE_DOMAIN: "edge", BRAVE_DOMAIN: "brave",
               CHROMIUM_DOMAIN: "chromium", FIREFOX_DOMAIN: "firefox"}

# Internal pages that can switch DNS/proxy behaviour behind the policies' back.
# URLBlocklist accepts chrome:// (and edge://) URLs; Brave maps brave:// to chrome://.
_CHROMIUM_INTERNAL_BLOCKS = [
    "chrome://flags", "chrome://net-internals", "chrome://net-export",
]
_EDGE_INTERNAL_BLOCKS = ["edge://flags", "edge://net-internals", "edge://net-export"]

# YouTube Restricted Mode: 0 off, 1 moderate, 2 strict.
YOUTUBE_STRICT = 2
# Bing SafeSearch (Edge): 0 none, 1 moderate, 2 strict.
BING_STRICT = 2


_HERE = Path(__file__).resolve().parent
LIST_DIRS = [_HERE / "lists", _HERE.parent / "lists", _HERE.parent / "pax-dns" / "lists"]


def bypass_hosts(dirs: list[Path] | None = None) -> list[str]:
    """The always-on "bypass" category (cloud PCs, remote browsers, proxies) from
    cloud-pc-bypass.txt; [] if the file isn't next to this script."""
    for d in (dirs if dirs is not None else LIST_DIRS):
        f = d / "cloud-pc-bypass.txt"
        if f.is_file():
            out = []
            for raw in f.read_text().splitlines():
                line = raw.strip().lower()
                if line and not line.startswith("#") and " " not in line and line not in out:
                    out.append(line)
            return out
    return []


def remote_ai_hosts(dirs: list[Path] | None = None) -> list[str]:
    """v0.8.1: the always-on remote AI browsers (ChatGPT, Manus) from
    remote-ai-browsers.txt, for URLBlocklist / WebsiteFilter. Falls back to
    remote_ai_browsers.py's hosts when the list isn't next to this script."""
    for d in (dirs if dirs is not None else LIST_DIRS):
        f = d / "remote-ai-browsers.txt"
        if f.is_file():
            out = []
            for raw in f.read_text().splitlines():
                line = raw.split("#", 1)[0].strip().lower()
                if line and " " not in line and line not in out:
                    out.append(line)
            return out
    from remote_ai_browsers import IOS_REMOTE_AI_HOSTS
    return list(IOS_REMOTE_AI_HOSTS)


# Chromium's documented URLBlocklist limit (entries past it are ignored).
CHROME_URL_BLOCKLIST_MAX = 1000


def _url_blocklist(custom_hosts: list[str]) -> list[str]:
    """Chrome URLBlocklist entries. A bare host 'example.com' blocks the host and
    all its subdomains, on every scheme (Chromium URL-filter format)."""
    out: list[str] = []
    for h in custom_hosts:
        h = h.strip().lower()
        if h and h not in out:
            out.append(h)
    return out


def chromium_policies(*, browser: str, doh_url: str | None, custom_hosts: list[str],
                      adblock: bool, blur_ids: dict[str, str] | None = None,
                      bypass: list[str] | None = None, youtube_restrict: int | None = YOUTUBE_STRICT) -> dict:
    """Mandatory policies for one Chromium browser ('chrome' | 'edge' | 'brave').

    doh_url=None: browser DoH off, so the browser uses macOS's resolver, which the
    profile's encrypted-DNS payload already points at the filter. With a URL the
    browser is forced to that resolver instead ('secure' mode, no fallback).
    BuiltInDnsClientEnabled=false makes Chromium resolve through the OS
    (getaddrinfo) rather than sending its own UDP queries to the DHCP DNS
    servers, which would skip the system-wide encrypted DNS and /etc/hosts.
    """
    if browser not in ("chrome", "edge", "brave", "chromium"):
        raise ValueError(f"unknown Chromium browser {browser!r}")
    p: dict = {
        "BuiltInDnsClientEnabled": False,
        "ForceGoogleSafeSearch": True,
        "ProxySettings": {"ProxyMode": "direct"},
    }
    # v0.8.6: None leaves YouTube to DNS (pax-guard's switch on a Mac with local DNS).
    if youtube_restrict is not None:
        p["ForceYouTubeRestrict"] = youtube_restrict
    if doh_url:
        p["DnsOverHttpsMode"] = "secure"
        p["DnsOverHttpsTemplates"] = doh_url
    else:
        p["DnsOverHttpsMode"] = "off"
    blocks = list(_CHROMIUM_INTERNAL_BLOCKS)
    if browser == "edge":
        blocks += _EDGE_INTERNAL_BLOCKS
        p["ForceBingSafeSearch"] = BING_STRICT
    if browser == "brave":
        p["TorDisabled"] = True          # Private Window with Tor bypasses DNS
        p["BraveVPNDisabled"] = True
    p["URLBlocklist"] = blocks + _url_blocklist(list(custom_hosts) + list(bypass or []))
    if len(p["URLBlocklist"]) > CHROME_URL_BLOCKLIST_MAX:
        # Chromium ignores entries past its limit; never ship a list it would cut.
        raise ValueError(f"URLBlocklist has {len(p['URLBlocklist'])} entries; "
                         f"Chromium takes at most {CHROME_URL_BLOCKLIST_MAX}")
    p.update(chromium_extension_policies(browser=browser, adblock=adblock, blur_ids=blur_ids))
    return p


def blur_entry(browser: str, blur_ids: dict[str, str] | None) -> tuple[str, str] | None:
    """(extension ID, update URL) of Pax Image Blur for a Chromium browser, or
    None while no store listing exists (see the module docstring)."""
    ids = blur_ids or {}
    if browser == "edge" and ids.get("edge"):
        return ids["edge"], EDGE_UPDATE_URL
    if ids.get("chrome"):
        return ids["chrome"], CHROME_UPDATE_URL
    return None


def allowed_extension_ids(browser: str) -> list[str]:
    """Extensions a user may keep or install (never force-installed).
    v0.7.0 (project decision, 2026-10-15): password managers only. Chrome, Brave and
    Chromium get the Chrome Web Store IDs; Edge gets its Edge Add-ons IDs and
    the Web Store IDs; Firefox gets the AMO IDs."""
    if browser == "firefox":
        return [pm["firefox"] for pm in PASSWORD_MANAGERS.values()]
    ids: list[str] = []
    for pm in PASSWORD_MANAGERS.values():
        if browser == "edge" and pm.get("edge"):
            ids.append(pm["edge"])
        ids.append(pm["chrome"])
    # v0.8.4: Momentum (new-tab dashboard) allowed again in Chromium browsers.
    if browser == "edge":
        ids.append(MOMENTUM_EDGE_ID)
    ids.append(MOMENTUM_CHROME_ID)
    return ids


def chromium_extension_policies(*, browser: str, adblock: bool,
                                blur_ids: dict[str, str] | None = None) -> dict:
    # `adblock` no longer touches extensions (v0.6.1): ads are blocked by DNS/hosts.
    allowed = allowed_extension_ids(browser)
    blur = blur_entry(browser, blur_ids)
    if blur and blur[0] not in allowed:
        allowed.append(blur[0])
    settings: dict = {"*": {"installation_mode": "blocked",
                            "blocked_permissions": list(BLOCKED_PERMISSIONS)}}
    for ext in allowed:
        settings[ext] = {"installation_mode": "allowed",
                         "blocked_permissions": list(BLOCKED_PERMISSIONS)}
    p: dict = {
        "ExtensionInstallBlocklist": ["*"],
        "ExtensionInstallAllowlist": list(allowed),
        "ExtensionAllowedTypes": ["extension"],
        "ExtensionDeveloperModeSettings": 1,   # Disallow: no "Load unpacked"
        "BlockExternalExtensions": True,
        "ExtensionSettings": settings,
    }
    force: list[str] = []
    if blur:
        force.append(f"{blur[0]};{blur[1]}")
        settings[blur[0]] = {"installation_mode": "force_installed", "update_url": blur[1],
                             "blocked_permissions": list(BLOCKED_PERMISSIONS)}
    if force:
        p["ExtensionInstallForcelist"] = force
    return p


def firefox_policies(*, doh_url: str | None, adblock: bool, image_blur: bool = False,
                     bypass: list[str] | None = None) -> dict:
    """Mandatory Firefox policies (macOS needs EnterprisePoliciesEnabled)."""
    if doh_url:
        doh = {"Enabled": True, "ProviderURL": doh_url, "Locked": True, "Fallback": False}
    else:
        # Off and locked: Firefox uses the macOS resolver (filtered encrypted DNS).
        doh = {"Enabled": False, "Locked": True}
    p: dict = {
        "EnterprisePoliciesEnabled": True,
        "DNSOverHTTPS": doh,
        "Proxy": {"Mode": "none", "Locked": True},
        # about:config could flip network.trr.* / proxy prefs.
        "BlockAboutConfig": True,
    }
    ext: dict = {"*": {"installation_mode": "blocked",
                       "blocked_install_message": "Pax allows only approved extensions."}}
    # v0.7.0: the password managers are allowed (not installed); everything
    # else stays blocked. Pax Max blur still force-installs when chosen.
    for ext_id in allowed_extension_ids("firefox"):
        ext[ext_id] = {"installation_mode": "allowed"}
    if image_blur:
        ext[BLUR_FIREFOX_ID] = {"installation_mode": "force_installed",
                                "install_url": BLUR_FIREFOX_XPI_URL,
                                "private_browsing": True}
    p["ExtensionSettings"] = ext
    if bypass:
        # Match patterns: the host and every subdomain, any scheme.
        block: list[str] = []
        for h in bypass:
            block += [f"*://{h}/*", f"*://*.{h}/*"]
        p["WebsiteFilter"] = {"Block": block}
    return p


def all_browser_policies(*, doh_url: str | None, custom_hosts: list[str],
                         adblock: bool, image_blur: bool = False,
                         blur_ids: dict[str, str] | None = None,
                         bypass: list[str] | None = None,
                         youtube_restrict: int | None = YOUTUBE_STRICT,
                         blur_firefox: bool = False) -> dict[str, dict]:
    """{preference domain: policy dict} for every supported browser.
    image_blur: Pax Image Blur in Firefox (local XPI) and, when blur_ids has a
    store ID, in the Chromium browsers. bypass: hosts for URLBlocklist /
    WebsiteFilter (v0.5). blur_firefox (v0.8.12): Firefox gets Pax Image Blur even
    with image_blur off, so pax-guard can switch Pax Max later."""
    ids = blur_ids if image_blur else None
    kw = dict(doh_url=doh_url, custom_hosts=custom_hosts, adblock=adblock, blur_ids=ids,
              bypass=bypass, youtube_restrict=youtube_restrict)
    return {
        CHROME_DOMAIN: chromium_policies(browser="chrome", **kw),
        EDGE_DOMAIN: chromium_policies(browser="edge", **kw),
        BRAVE_DOMAIN: chromium_policies(browser="brave", **kw),
        CHROMIUM_DOMAIN: chromium_policies(browser="chromium", **kw),
        FIREFOX_DOMAIN: firefox_policies(doh_url=doh_url, adblock=adblock, image_blur=image_blur or blur_firefox,
                                         bypass=bypass),
    }


def managed_client_body(domain: str, settings: dict) -> dict:
    """Body of a com.apple.ManagedClient.preferences payload for one domain."""
    return {"PayloadContent": {domain: {"Forced": [{"mcx_preference_settings": settings}]}}}
