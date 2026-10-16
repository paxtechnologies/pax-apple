# SPDX-License-Identifier: GPL-3.0-only
import json
import os
import plistlib
import stat
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PROFILE_DIR = HERE.parent
sys.path.insert(0, str(PROFILE_DIR))

import make_profile as mp  # noqa: E402
from bypass_apps import default_bundle_ids  # noqa: E402

SCHEMA_DIR = PROFILE_DIR / "apple-schema"


def payloads_by_type(profile: dict) -> dict:
    return {p["PayloadType"]: p for p in profile["PayloadContent"]}


@pytest.fixture
def ios_profile_files(tmp_path):
    out = tmp_path / "pax.mobileconfig"
    esc = tmp_path / "escrow.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(PROFILE_DIR / "make_profile.py"),
            "--out", str(out),
            "--escrow-out", str(esc),
            "--block-app", "com.example.custom",
            "--block-url", "badsite.example",
            "--block-url", "https://another.example/path",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return out, esc, proc


def test_cli_writes_parseable_profile_and_escrow(ios_profile_files):
    out, esc, proc = ios_profile_files
    profile = plistlib.loads(out.read_bytes())
    escrow = json.loads(esc.read_text())
    assert profile["PayloadType"] == "Configuration"
    assert escrow["schema"] == "pax.escrow.v1"
    assert escrow["profile_identifier"] == profile["PayloadIdentifier"]
    assert escrow["platform"] == "ios"
    rp = payloads_by_type(profile)["com.apple.profileRemovalPassword"]
    assert rp["RemovalPassword"] == escrow["removal_password"]


def test_password_never_printed(ios_profile_files):
    _out, esc, proc = ios_profile_files
    pw = json.loads(esc.read_text())["removal_password"]
    assert pw not in proc.stdout
    assert pw not in proc.stderr


def test_output_files_are_private(ios_profile_files):
    out, esc, _ = ios_profile_files
    for f in (out, esc):
        mode = stat.S_IMODE(os.stat(f).st_mode)
        assert mode == 0o600, oct(mode)


def test_dns_payload(ios_profile_files):
    profile = plistlib.loads(ios_profile_files[0].read_bytes())
    dns = payloads_by_type(profile)["com.apple.dnsSettings.managed"]
    assert dns["DNSSettings"]["DNSProtocol"] == "HTTPS"
    # v0.2: CleanBrowsing Family Filter is the default.
    assert dns["DNSSettings"]["ServerURL"] == "https://doh.cleanbrowsing.org/doh/family-filter/"
    assert dns["ProhibitDisablement"] is True


def test_default_filter_is_family():
    assert mp.DEFAULT_FILTER == "family"
    assert mp.DEFAULT_RESOLVER_URL == "https://doh.cleanbrowsing.org/doh/family-filter/"
    gp = mp.build_profile(mp.ProfileOptions())
    dns = payloads_by_type(gp.profile)["com.apple.dnsSettings.managed"]
    assert dns["DNSSettings"]["ServerURL"] == mp.CLEANBROWSING_FAMILY_DOH


def _run_cli(tmp_path, *extra):
    out = tmp_path / "p.mobileconfig"
    esc = tmp_path / "e.json"
    proc = subprocess.run(
        [sys.executable, str(PROFILE_DIR / "make_profile.py"),
         "--out", str(out), "--escrow-out", str(esc), *extra],
        capture_output=True, text=True,
    )
    return proc, out


@pytest.mark.parametrize(
    "args, expected",
    [
        ((), "https://doh.cleanbrowsing.org/doh/family-filter/"),
        (("--filter", "family"), "https://doh.cleanbrowsing.org/doh/family-filter/"),
        (("--filter", "core"), mp.CLEANBROWSING_CORE_DOH),
        (("--resolver-url", "https://dns.pax.example/dns-query"), "https://dns.pax.example/dns-query"),
    ],
)
def test_cli_filter_choice(tmp_path, args, expected):
    proc, out = _run_cli(tmp_path, *args)
    assert proc.returncode == 0, proc.stderr
    dns = payloads_by_type(plistlib.loads(out.read_bytes()))["com.apple.dnsSettings.managed"]
    assert dns["DNSSettings"]["ServerURL"] == expected
    assert json.loads(proc.stdout)["resolver_url"] == expected


def test_cli_filter_and_resolver_are_exclusive(tmp_path):
    proc, _ = _run_cli(tmp_path, "--filter", "core", "--resolver-url", "https://dns.pax.example/q")
    assert proc.returncode != 0


def test_cli_rejects_unknown_filter(tmp_path):
    proc, _ = _run_cli(tmp_path, "--filter", "strict")
    assert proc.returncode != 0


def test_resolver_for():
    assert mp.resolver_for("core") == mp.CLEANBROWSING_CORE_DOH
    assert mp.CLEANBROWSING_CORE_DOH.startswith("https://doh.cleanbrowsing.org/doh/")
    assert mp.resolver_for("family") == mp.CLEANBROWSING_FAMILY_DOH
    assert mp.resolver_for("core", "https://x.example/dns-query") == "https://x.example/dns-query"
    with pytest.raises(mp.ProfileError):
        mp.resolver_for("nope")
    with pytest.raises(mp.ProfileError):
        mp.resolver_for("family", "http://insecure.example/dns-query")


def test_restrictions_payload(ios_profile_files):
    profile = plistlib.loads(ios_profile_files[0].read_bytes())
    r = payloads_by_type(profile)["com.apple.applicationaccess"]
    assert r["allowEraseContentAndSettings"] is False
    assert r["allowVPNCreation"] is False
    assert r["allowCloudPrivateRelay"] is False
    assert r["allowUIConfigurationProfileInstallation"] is False
    for key in ("blockedAppBundleIDs", "blacklistedAppBundleIDs"):
        assert "com.miketigas.OnionBrowser" in r[key]
        assert "com.opera.OperaTouch" in r[key]
        assert "com.example.custom" in r[key]
        assert len(r[key]) == len(set(r[key]))
        assert set(default_bundle_ids()) <= set(r[key])


def test_webfilter_payload(ios_profile_files):
    profile = plistlib.loads(ios_profile_files[0].read_bytes())
    w = payloads_by_type(profile)["com.apple.webcontent-filter"]
    assert w["FilterType"] == "BuiltIn"
    assert w["AutoFilterEnabled"] is True
    assert "ContentFilterUUID" not in w  # would scope filter to managed apps only
    assert w["DenyListURLs"] == (["https://badsite.example", "https://another.example/path",
                                 # v0.8.0 built-ins: Reddit and Imgur media hosts
                                 "https://redd.it", "https://redditmedia.com", "https://redditstatic.com",
                                 "https://imgur.io"]
                                + [f"https://{h}" for h in mp.IOS_ALWAYS_BLOCKED_MEDIA_HOSTS]   # v0.8.13
                                + (mp.IOS_CONVERTER_URLS   # v0.8.1 media converters
                                                          + mp.IOS_REMOTE_AI_URLS))
    assert "PermittedURLs" not in w


def test_top_level_locked(ios_profile_files):
    profile = plistlib.loads(ios_profile_files[0].read_bytes())
    assert profile["PayloadRemovalDisallowed"] is True
    types = [p["PayloadType"] for p in profile["PayloadContent"]]
    assert sorted(types) == sorted(
        [
            "com.apple.dnsSettings.managed",
            "com.apple.applicationaccess",
            "com.apple.webcontent-filter",
            "com.apple.profileRemovalPassword",
        ]
    )
    uuids = [profile["PayloadUUID"]] + [p["PayloadUUID"] for p in profile["PayloadContent"]]
    assert len(uuids) == len(set(uuids))


def test_password_is_strong_and_random():
    pws = {mp.generate_removal_password() for _ in range(200)}
    assert len(pws) == 200
    for pw in pws:
        groups = pw.split("-")
        assert len(groups) == 6 and all(len(g) == 5 for g in groups)
        assert set(pw.replace("-", "")) <= set(mp._PW_ALPHABET)


def test_custom_resolver_parameter():
    gp = mp.build_profile(mp.ProfileOptions(resolver_url="https://dns.pax.example/dns-query"))
    dns = payloads_by_type(gp.profile)["com.apple.dnsSettings.managed"]
    assert dns["DNSSettings"]["ServerURL"] == "https://dns.pax.example/dns-query"


@pytest.mark.parametrize("bad", ["http://dns.example/dns-query", "dns.example", "https://"])
def test_resolver_must_be_https(bad):
    with pytest.raises(mp.ProfileError):
        mp.build_profile(mp.ProfileOptions(resolver_url=bad))


def test_no_default_app_blocks():
    gp = mp.build_profile(mp.ProfileOptions(include_default_app_blocks=False))
    r = payloads_by_type(gp.profile)["com.apple.applicationaccess"]
    # v0.8.1: the remote AI apps (ChatGPT, Manus) stay blocked even then.
    assert r["blockedAppBundleIDs"] == mp.IOS_REMOTE_AI_APP_BUNDLE_IDS


def test_denylist_limit():
    urls = [f"site{i}.example" for i in range(mp.MAX_DENYLIST_URLS + 1)]
    with pytest.raises(mp.ProfileError):
        mp.build_profile(mp.ProfileOptions(custom_url_blocks=urls))


def test_bad_bundle_id_rejected():
    with pytest.raises(mp.ProfileError):
        mp.build_profile(mp.ProfileOptions(custom_app_blocks=["not a bundle"]))


def test_macos_variant_dns_only(tmp_path):
    out, esc = tmp_path / "mac.mobileconfig", tmp_path / "mac.json"
    rc = mp.main(["--macos", "--out", str(out), "--escrow-out", str(esc)])
    assert rc == 0
    profile = plistlib.loads(out.read_bytes())
    types = {p["PayloadType"] for p in profile["PayloadContent"]}
    assert types == {"com.apple.dnsSettings.managed", "com.apple.profileRemovalPassword"}
    assert profile["PayloadScope"] == "System"
    dns = payloads_by_type(profile)["com.apple.dnsSettings.managed"]
    assert "ProhibitDisablement" not in dns or dns["ProhibitDisablement"] is False
    assert json.loads(esc.read_text())["platform"] == "macos"


def test_macos_rejects_ios_only_blocks():
    with pytest.raises(mp.ProfileError):
        mp.build_profile(mp.ProfileOptions(platform="macos", custom_app_blocks=["com.a.b"]))


def test_validate_catches_missing_password_payload():
    gp = mp.build_profile(mp.ProfileOptions())
    gp.profile["PayloadContent"] = [
        p for p in gp.profile["PayloadContent"]
        if p["PayloadType"] != "com.apple.profileRemovalPassword"
    ]
    with pytest.raises(mp.ProfileError):
        mp.validate_profile(gp.profile)


# --------------------------------------------------------------------------
# Check every emitted key against Apple's own schema (vendored YAML from
# github.com/apple/device-management) so a typo in a key name fails CI.
# --------------------------------------------------------------------------
yaml = pytest.importorskip("yaml")

_TYPE_MAP = {
    "<string>": str,
    "<boolean>": bool,
    "<integer>": int,
    "<array>": list,
    "<dictionary>": dict,
}


def _schema(ptype):
    return yaml.safe_load((SCHEMA_DIR / f"{ptype}.yaml").read_text())


def _check_keys(obj: dict, keyspecs: list, path: str):
    by_key = {k["key"]: k for k in keyspecs}
    for key, value in obj.items():
        if key.startswith("Payload") and key not in by_key:
            continue  # common payload keys live in CommonPayloadKeys.yaml
        assert key in by_key, f"{path}.{key} not in Apple schema"
        spec = by_key[key]
        expected = _TYPE_MAP.get(spec["type"])
        if expected:
            assert isinstance(value, expected), f"{path}.{key} should be {spec['type']}"
        if isinstance(value, dict) and spec.get("subkeys"):
            _check_keys(value, spec["subkeys"], f"{path}.{key}")


@pytest.mark.parametrize("platform", ["ios", "macos"])
def test_keys_exist_in_apple_schema(platform):
    gp = mp.build_profile(mp.ProfileOptions(platform=platform, custom_url_blocks=[] ))
    top = yaml.safe_load((SCHEMA_DIR / "TopLevel.yaml").read_text())
    _check_keys(
        {k: v for k, v in gp.profile.items() if k != "PayloadContent"},
        top["payloadkeys"],
        "TopLevel",
    )
    for p in gp.profile["PayloadContent"]:
        sch = _schema(p["PayloadType"])
        assert sch["payload"]["payloadtype"] == p["PayloadType"]
        _check_keys(p, sch["payloadkeys"], p["PayloadType"])


def test_supervised_only_keys_documented():
    """The README table of supervised-only keys must match Apple's schema."""
    readme = (PROFILE_DIR.parent / "README.md").read_text()
    r = _schema("com.apple.applicationaccess")
    by_key = {k["key"]: k for k in r["payloadkeys"]}
    for key in (
        "allowEraseContentAndSettings",
        "allowVPNCreation",
        "allowCloudPrivateRelay",
        "allowUIConfigurationProfileInstallation",
        "blockedAppBundleIDs",
        "blacklistedAppBundleIDs",
    ):
        assert by_key[key]["supportedOS"]["iOS"].get("supervised") is True, key
        assert f"`{key}`" in readme, f"{key} missing from README supervision table"
    dns = {k["key"]: k for k in _schema("com.apple.dnsSettings.managed")["payloadkeys"]}
    assert dns["ProhibitDisablement"]["supportedOS"]["iOS"]["supervised"] is True
    rp = _schema("com.apple.profileRemovalPassword")
    assert rp["payload"]["supportedOS"]["iOS"]["supervised"] is True


# ------------------------------------------------------------ v0.8.0 iPhone
def test_v08_ios_denylist_builtins_within_apple_cap():
    import make_profile as mp
    x_bsky = ["pbs.twimg.com", "video.twimg.com", "ton.twimg.com", "cdn.bsky.app", "video.bsky.app",
              "video.cdn.bsky.app", "gifs.bsky.app"]
    # v0.8.13: X/Bluesky media are built in, so every custom slot is the user's.
    assert mp.IOS_ALWAYS_BLOCKED_MEDIA_HOSTS == x_bsky
    custom = [f"site{i}.example" for i in range(mp.MAX_CUSTOM_DENYLIST_URLS)]
    gp = mp.build_profile(mp.ProfileOptions(custom_url_blocks=custom, include_fallback_denylist=True))
    deny = payloads_by_type(gp.profile)["com.apple.webcontent-filter"]["DenyListURLs"]
    assert len(deny) == mp.MAX_DENYLIST_URLS == 500
    for h in ["redd.it", "redditmedia.com", "redditstatic.com", "imgur.io"] + x_bsky:
        assert f"https://{h}" in deny, h
    # still the CleanBrowsing direct DoH profile on iPhone
    dns = payloads_by_type(gp.profile)["com.apple.dnsSettings.managed"]["DNSSettings"]
    assert dns["DNSProtocol"] == "HTTPS" and dns["ServerURL"].startswith("https://doh.cleanbrowsing.org/")
    import pytest
    with pytest.raises(mp.ProfileError):
        mp.build_profile(mp.ProfileOptions(custom_url_blocks=custom + ["one-too-many.example"]))
    # a custom entry that repeats a built-in doesn't use a slot twice
    gp = mp.build_profile(mp.ProfileOptions(custom_url_blocks=["imgur.io"]))
    assert payloads_by_type(gp.profile)["com.apple.webcontent-filter"]["DenyListURLs"].count("https://imgur.io") == 1


# ------------------------------------------------------------ v0.8.13
def test_v0813_x_and_bluesky_media_always_in_the_iphone_profile():
    """Pictures and video on X and Bluesky are always blocked: even a profile made
    with no custom blocks carries them, and there's no option to leave them out."""
    import sys
    from pathlib import Path
    import make_profile as mp
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "guard"))
    import guard_config as gc
    assert mp.IOS_ALWAYS_BLOCKED_MEDIA_HOSTS == gc.ALWAYS_BLOCKED_MEDIA_NAMES
    for kw in ({}, {"include_fallback_denylist": True}, {"youtube_restricted": False}):
        gp = mp.build_profile(mp.ProfileOptions(**kw))
        deny = payloads_by_type(gp.profile)["com.apple.webcontent-filter"]["DenyListURLs"]
        for h in gc.ALWAYS_BLOCKED_MEDIA_NAMES:
            assert deny.count(f"https://{h}") == 1, (kw, h)
        assert "https://x.com" not in deny and "https://bsky.app" not in deny
    # An old app sending them as custom blocks doesn't use a slot twice.
    gp = mp.build_profile(mp.ProfileOptions(custom_url_blocks=["pbs.twimg.com", "cdn.bsky.app"]))
    deny = payloads_by_type(gp.profile)["com.apple.webcontent-filter"]["DenyListURLs"]
    assert deny.count("https://pbs.twimg.com") == 1 and deny.count("https://cdn.bsky.app") == 1
    assert not [f for f in mp.ProfileOptions.__dataclass_fields__ if f.startswith(("x_", "bluesky"))]
