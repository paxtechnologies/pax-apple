# SPDX-License-Identifier: GPL-3.0-only
"""Mac self-lock profile (v0.4): DNS + Private Relay off + browser policies."""
import json
import plistlib
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PROFILE_DIR = HERE.parent
sys.path.insert(0, str(PROFILE_DIR))

import make_profile as mp  # noqa: E402
import mac_policies as mpol  # noqa: E402

SCHEMA_DIR = PROFILE_DIR / "apple-schema"
TOKEN = "abcdefghijklmnopqrstuvwxyz0123"


def build(**kw):
    return mp.build_profile(mp.ProfileOptions(platform="macos", self_lock=True, **kw))


def browser(gp, domain):
    for p in gp.profile["PayloadContent"]:
        if p["PayloadType"] == "com.apple.ManagedClient.preferences" and domain in p["PayloadContent"]:
            forced = p["PayloadContent"][domain]["Forced"]
            assert len(forced) == 1
            return forced[0]["mcx_preference_settings"]
    raise AssertionError(f"no payload for {domain}")


def test_structure_no_removal_password_system_scope():
    gp = build()
    types = [p["PayloadType"] for p in gp.profile["PayloadContent"]]
    assert "com.apple.profileRemovalPassword" not in types
    assert types.count("com.apple.ManagedClient.preferences") == 5
    assert gp.profile["PayloadScope"] == "System"
    assert gp.profile["PayloadRemovalDisallowed"] is True
    assert gp.profile_identifier.startswith("org.paxpeace.pax.macos-selflock.")
    assert gp.removal_password == ""
    idents = [p["PayloadIdentifier"] for p in gp.profile["PayloadContent"]]
    assert len(set(idents)) == len(idents)
    assert all(i.startswith("org.paxpeace.pax.macos-selflock.payload.") for i in idents)


def test_dns_default_family_and_user_token():
    dns = {p["PayloadType"]: p for p in build().profile["PayloadContent"]}["com.apple.dnsSettings.managed"]
    assert dns["DNSSettings"] == {"DNSProtocol": "HTTPS", "ServerURL": mp.CLEANBROWSING_FAMILY_DOH}
    url = mp.user_doh_url(TOKEN, "https://dns.example.org")
    dns = {p["PayloadType"]: p for p in build(resolver_url=url).profile["PayloadContent"]}["com.apple.dnsSettings.managed"]
    assert dns["DNSSettings"]["ServerURL"] == "https://dns.example.org/u/%s/dns-query" % TOKEN


def test_private_relay_off():
    r = {p["PayloadType"]: p for p in build().profile["PayloadContent"]}["com.apple.applicationaccess"]
    assert r["allowCloudPrivateRelay"] is False


@pytest.mark.parametrize("domain", [mpol.CHROME_DOMAIN, mpol.EDGE_DOMAIN, mpol.BRAVE_DOMAIN,
                                    mpol.CHROMIUM_DOMAIN])
def test_chromium_policies(domain):
    p = browser(build(custom_url_blocks=["https://reddit.com/r/x", "example.org"]), domain)
    assert p["BuiltInDnsClientEnabled"] is False
    assert p["DnsOverHttpsMode"] == "off"
    assert "DnsOverHttpsTemplates" not in p
    assert p["ForceGoogleSafeSearch"] is True
    assert p["ForceYouTubeRestrict"] == 2
    assert p["ProxySettings"] == {"ProxyMode": "direct"}
    assert "ProxyMode" not in p  # deprecated policy
    assert "chrome://flags" in p["URLBlocklist"]
    assert "reddit.com" in p["URLBlocklist"] and "example.org" in p["URLBlocklist"]


def test_private_browsing_stays_allowed():
    """Project decision, 2026-10-14: keep Incognito / private windows / guest mode."""
    gp = build()
    for d in (mpol.CHROME_DOMAIN, mpol.EDGE_DOMAIN, mpol.BRAVE_DOMAIN):
        p = browser(gp, d)
        assert "IncognitoModeAvailability" not in p
        assert "BrowserGuestModeEnabled" not in p
    assert "DisablePrivateBrowsing" not in browser(gp, mpol.FIREFOX_DOMAIN)


def test_edge_and_brave_extras():
    gp = build()
    edge = browser(gp, mpol.EDGE_DOMAIN)
    assert edge["ForceBingSafeSearch"] == 2
    assert "edge://flags" in edge["URLBlocklist"]
    brave = browser(gp, mpol.BRAVE_DOMAIN)
    assert brave["TorDisabled"] is True and brave["BraveVPNDisabled"] is True


def test_no_ublock_anywhere_v061():
    """v0.6.1: ad blocking is system-wide (DNS/hosts); uBO is neither forced nor allowed."""
    for adblock in (True, False):
        gp = build(adblock=adblock)
        for d in (mpol.CHROME_DOMAIN, mpol.EDGE_DOMAIN, mpol.BRAVE_DOMAIN, mpol.CHROMIUM_DOMAIN):
            p = browser(gp, d)
            assert "ExtensionInstallForcelist" not in p
            assert p["ExtensionInstallBlocklist"] == ["*"]
            for ubol in (mpol.UBOL_CHROME_ID, mpol.UBOL_EDGE_ID):
                assert ubol not in p["ExtensionSettings"]
                assert ubol not in p["ExtensionInstallAllowlist"]
        ff = browser(gp, mpol.FIREFOX_DOMAIN)["ExtensionSettings"]
        assert ff["*"]["installation_mode"] == "blocked"
        assert mpol.UBO_FIREFOX_ID not in ff


CHROMIUMS = [mpol.CHROME_DOMAIN, mpol.EDGE_DOMAIN, mpol.BRAVE_DOMAIN, mpol.CHROMIUM_DOMAIN]


@pytest.mark.parametrize("domain", CHROMIUMS)
def test_extension_lockdown(domain):
    p = browser(build(), domain)
    assert p["ExtensionInstallBlocklist"] == ["*"]
    assert p["ExtensionAllowedTypes"] == ["extension"]
    assert p["ExtensionDeveloperModeSettings"] == 1
    assert p["BlockExternalExtensions"] is True
    es = p["ExtensionSettings"]
    assert es["*"] == {"installation_mode": "blocked", "blocked_permissions": ["proxy", "vpnProvider"]}
    # every per-ID entry repeats blocked_permissions (they don't inherit it from "*")
    for ext_id, cfg in es.items():
        assert cfg["blocked_permissions"] == ["proxy", "vpnProvider"], ext_id
    allow = set(p["ExtensionInstallAllowlist"])
    assert set(es) - {"*"} == allow


PM_CHROME = {"aeblfdkhhhdcdjpifhhbdiojplfjncoa", "nngceckbapebfimnlniiiahkandclblb",
             "hdokiejnpimakedhajhdlcegeplioahd", "fdjamakpfbbddfjaooikfcpapjohcfmg",
             "ghmbeldphafepmbegfdlkpapadhbakde", "pejdijmoenmkgeppbflobdenhhabjlaj"}
PM_EDGE = {"dppgmdbiimibapkepcbdbmkaabgiofem", "jbkfoedolllekgbhcbcoahefnbanhhlh",
           "bbcinlkgjjkejfdpemiealijmmooekmp", "gehmmocbbkpblljhkekmfhjpfbkclbph",
           "gcllgfdnfnllodcaambdaknbipemelie", "mfbcdcnpokpoajjciilocoachedjkima"}
PM_FIREFOX = {"{d634138d-c276-4fc8-924b-40a0ea21d284}", "{446900e4-71c2-419f-a6a7-df9c091e268b}",
              "support@lastpass.com", "jetpack-extension@dashlane.com",
              "78272b6fa58f4a1abaac99321d503a20@proton.me",
              "password-manager-firefox-extension@apple.com"}
MOMENTUM_CHROME = "laookkfknpbbblfpciffpaejjkokdgca"
MOMENTUM_EDGE = "jdoanlopeanabgejgmdncljhkdplcfed"
REMOVED = {"nffaoalbilbmmfgbnbgppjihopabppdk"}


def test_extension_allowlists_exact_v07_password_managers_only():
    gp = build()
    for d in (mpol.CHROME_DOMAIN, mpol.BRAVE_DOMAIN, mpol.CHROMIUM_DOMAIN):
        assert set(browser(gp, d)["ExtensionInstallAllowlist"]) == PM_CHROME | {MOMENTUM_CHROME}
    edge = set(browser(gp, mpol.EDGE_DOMAIN)["ExtensionInstallAllowlist"])
    assert edge == PM_EDGE | PM_CHROME | {MOMENTUM_CHROME, MOMENTUM_EDGE}


@pytest.mark.parametrize("domain", CHROMIUMS)
def test_momentum_and_vsc_removed_and_nothing_forced(domain):
    for image_blur in (False, True):
        p = browser(build(image_blur=image_blur), domain)
        assert not REMOVED & set(p["ExtensionInstallAllowlist"])
        assert not REMOVED & set(p["ExtensionSettings"])
        for ext_id in PM_CHROME | PM_EDGE | {MOMENTUM_CHROME, MOMENTUM_EDGE}:
            cfg = p["ExtensionSettings"].get(ext_id)
            if cfg:
                assert cfg["installation_mode"] == "allowed"
        # Only Pax Image Blur may ever be force-installed (and only with a store ID).
        assert "ExtensionInstallForcelist" not in p


def test_firefox_extension_lockdown():
    ff = browser(build(), mpol.FIREFOX_DOMAIN)["ExtensionSettings"]
    assert ff["*"]["installation_mode"] == "blocked"
    assert set(ff) == {"*"} | PM_FIREFOX
    for ext_id in PM_FIREFOX:
        assert ff[ext_id] == {"installation_mode": "allowed"}


def test_firefox_pax_max_is_the_only_force_install():
    ff = browser(build(image_blur=True), mpol.FIREFOX_DOMAIN)["ExtensionSettings"]
    forced = {k for k, v in ff.items() if v.get("installation_mode") == "force_installed"}
    assert forced == {mpol.BLUR_FIREFOX_ID}


def test_password_manager_ids_look_valid():
    import re
    for name, ids in mpol.PASSWORD_MANAGERS.items():
        assert re.fullmatch(r"[a-p]{32}", ids["chrome"]), name
        assert re.fullmatch(r"[a-p]{32}", ids["edge"]), name
        assert "@" in ids["firefox"] or re.fullmatch(r"\{[0-9a-f-]{36}\}", ids["firefox"]), name
    assert set(mpol.PASSWORD_MANAGERS) == {"1Password", "Bitwarden", "LastPass", "Dashlane",
                                           "Proton Pass", "iCloud Passwords"}


def test_developer_tools_left_alone():
    """ExtensionDeveloperModeSettings blocks unpacked loading without killing DevTools."""
    for d in CHROMIUMS:
        assert "DeveloperToolsAvailability" not in browser(build(), d)


def test_firefox_policies():
    ff = browser(build(), mpol.FIREFOX_DOMAIN)
    assert ff["EnterprisePoliciesEnabled"] is True
    assert ff["DNSOverHTTPS"] == {"Enabled": False, "Locked": True}
    assert ff["Proxy"] == {"Mode": "none", "Locked": True}
    assert ff["BlockAboutConfig"] is True


def test_browser_doh_can_be_forced_to_our_resolver():
    url = mp.user_doh_url(TOKEN, "https://dns.example.org")
    gp = build(browser_doh_url=url)
    c = browser(gp, mpol.CHROME_DOMAIN)
    assert c["DnsOverHttpsMode"] == "secure" and c["DnsOverHttpsTemplates"] == url
    ff = browser(gp, mpol.FIREFOX_DOMAIN)["DNSOverHTTPS"]
    assert ff == {"Enabled": True, "ProviderURL": url, "Locked": True, "Fallback": False}


def test_self_lock_rejects_ios_and_app_blocks():
    with pytest.raises(mp.ProfileError):
        mp.build_profile(mp.ProfileOptions(platform="ios", self_lock=True))
    with pytest.raises(mp.ProfileError):
        build(custom_app_blocks=["com.example.app"])


def test_validator_rejects_password_in_self_lock():
    gp = build()
    gp.profile["PayloadContent"].append(mp.removal_password_payload("x" * 30))
    with pytest.raises(mp.ProfileError):
        mp.validate_profile(gp.profile, platform="macos", self_lock=True)


def test_cli_self_lock(tmp_path):
    out = tmp_path / "mac.mobileconfig"
    r = subprocess.run([sys.executable, str(PROFILE_DIR / "make_profile.py"), "--self-lock",
                        "--out", str(out), "--block-url", "reddit.com", "--no-adblock"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    info = json.loads(r.stdout)
    assert info["self_lock"] is True and info["platform"] == "macos" and info["escrow"] is None
    prof = plistlib.loads(out.read_bytes())
    assert prof["PayloadIdentifier"] == info["profile_identifier"]
    assert (out.stat().st_mode & 0o777) == 0o600


def test_cli_escrow_out_still_required_without_self_lock(tmp_path):
    r = subprocess.run([sys.executable, str(PROFILE_DIR / "make_profile.py"),
                        "--out", str(tmp_path / "x.mobileconfig")], capture_output=True, text=True)
    assert r.returncode == 2


yaml = pytest.importorskip("yaml")
_TYPE_MAP = {"<string>": str, "<boolean>": bool, "<integer>": int, "<array>": list,
             "<dictionary>": dict}


def _check(obj, specs, path):
    by_key = {k["key"]: k for k in specs}
    for key, value in obj.items():
        if key.startswith("Payload") and key not in by_key:
            continue
        spec = by_key.get(key) or by_key.get("ANY")
        assert spec, f"{path}.{key} not in Apple schema"
        t = _TYPE_MAP.get(spec["type"])
        if t:
            assert isinstance(value, t), f"{path}.{key} should be {spec['type']}"
        if isinstance(value, dict) and spec.get("subkeys"):
            _check(value, spec["subkeys"], f"{path}.{key}")
        if isinstance(value, list) and spec.get("subkeys") and value and isinstance(value[0], dict):
            inner = spec["subkeys"][0]
            for item in value:
                _check(item, inner.get("subkeys", []), f"{path}.{key}[]")


def test_keys_exist_in_apple_schema():
    gp = build()
    top = yaml.safe_load((SCHEMA_DIR / "TopLevel.yaml").read_text())
    _check({k: v for k, v in gp.profile.items() if k != "PayloadContent"}, top["payloadkeys"], "Top")
    for p in gp.profile["PayloadContent"]:
        sch = yaml.safe_load((SCHEMA_DIR / f"{p['PayloadType']}.yaml").read_text())
        assert sch["payload"]["payloadtype"] == p["PayloadType"]
        _check(p, sch["payloadkeys"], p["PayloadType"])
    # Private Relay restriction is available on macOS (12+).
    aa = yaml.safe_load((SCHEMA_DIR / "com.apple.applicationaccess.yaml").read_text())
    spec = {k["key"]: k for k in aa["payloadkeys"]}["allowCloudPrivateRelay"]
    assert spec["supportedOS"]["macOS"]["introduced"] == "12.0"


# ------------------------------------------------------- v0.8.0 local DNS
def test_v08_local_dns_mode_drops_dns_payload_and_cli_defaults_to_it(tmp_path):
    import json
    import plistlib
    import subprocess
    import sys
    from pathlib import Path
    import make_profile as mp
    gp = mp.build_profile(mp.ProfileOptions(platform="macos", self_lock=True, mac_dns="local"))
    types = [p["PayloadType"] for p in gp.profile["PayloadContent"]]
    assert "com.apple.dnsSettings.managed" not in types and "com.apple.ManagedClient.preferences" in types
    out = tmp_path / "mac.mobileconfig"
    r = subprocess.run([sys.executable, str(Path(mp.__file__)), "--out", str(out), "--self-lock"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["mac_dns"] == "local"
    types = [p["PayloadType"] for p in plistlib.loads(out.read_bytes())["PayloadContent"]]
    assert "com.apple.dnsSettings.managed" not in types
    r = subprocess.run([sys.executable, str(Path(mp.__file__)), "--out", str(out), "--self-lock",
                        "--mac-dns", "profile"], capture_output=True, text=True)
    types = [p["PayloadType"] for p in plistlib.loads(out.read_bytes())["PayloadContent"]]
    assert "com.apple.dnsSettings.managed" in types
