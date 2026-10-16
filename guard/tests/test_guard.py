# SPDX-License-Identifier: GPL-3.0-only
"""pax-guard: hosts block, pf rules, bypass apps, lists, cycle and uninstall.
No real Mac is touched: a fake System records every command."""
import json
import plistlib
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import guard_config as gc  # noqa: E402
import pax_guard as pg  # noqa: E402

STOCK_HOSTS = ("##\n# Host Database\n##\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n"
               "::1             localhost\n192.168.1.5 nas.local\n")


# ------------------------------------------------------------------ hosts
def test_hosts_block_is_idempotent_and_keeps_user_lines():
    domains = gc.hosts_domains(["blocked-example.com", "reddit.com"])
    once = gc.render_hosts(STOCK_HOSTS, domains)
    twice = gc.render_hosts(once, domains)
    assert once == twice
    assert once.startswith(STOCK_HOSTS)
    assert once.count(gc.BEGIN) == 1 and once.count(gc.END) == 1
    assert "0.0.0.0 reddit.com\n" in once and "0.0.0.0 www.reddit.com\n" in once
    assert not gc.hosts_needs_update(once, domains)


def test_hosts_block_replaced_not_appended():
    a = gc.render_hosts(STOCK_HOSTS, gc.hosts_domains(["a.example"]))
    b = gc.render_hosts(a, gc.hosts_domains(["b.example"]))
    assert "a.example" not in b and "0.0.0.0 b.example" in b
    assert gc.strip_pax_block(b) == STOCK_HOSTS


def test_hosts_block_survives_missing_trailing_newline():
    out = gc.render_hosts(STOCK_HOSTS.rstrip("\n"), ["x.example"])
    assert "nas.local\n# BEGIN PAX" in out


def test_hosts_priority_dedup_cap_and_protection():
    ads = [f"ad{i}.tracker.example" for i in range(100)] + ["reddit.com", "doh.cleanbrowsing.org"]
    out = gc.hosts_domains(["reddit.com"], ads=ads, allowlist=[], max_entries=60,
                           protected=["pax.example.org"])
    assert out[:2] == ["reddit.com", "www.reddit.com"]          # user first
    assert "dns.google" in out                                   # DoH names before ads
    assert len(out) == 60 and len(set(out)) == 60                # capped, unique
    assert "doh.cleanbrowsing.org" not in out                    # our resolver never blocked


def test_resolver_and_server_hosts_are_never_blocked():
    out = gc.hosts_domains(["doh.cleanbrowsing.org", "pax.example.org"], protected=["pax.example.org"])
    assert "doh.cleanbrowsing.org" not in out and "pax.example.org" not in out
    assert "www.pax.example.org" in out  # only the exact protected names are spared


def test_ads_allowlist_frees_subdomains():
    ads = ["analytics.google.com", "x.analytics.google.com", "ads.example.com"]
    assert gc.effective_ad_domains(ads) == ["ads.example.com"]
    assert gc.effective_ad_domains(ads, allowlist=["example.com"]) == [
        "analytics.google.com", "x.analytics.google.com"]


def test_bypass_names_include_canary_and_private_relay():
    out = gc.hosts_domains([])
    for name in ("use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com",
                 "dns.google", "cloudflare-dns.com", "dns.nextdns.io"):
        assert name in out


def test_parse_domain_list_formats():
    text = ("# Title: HaGeZi\n0.0.0.0 ads.example.com\n127.0.0.1 t.example.net # c\n"
            "plain.example.org\n0.0.0.0 localhost\n0.0.0.0 0.0.0.0\nnot a domain line here\n"
            "*.wild.example.com\n! adblock comment\n0.0.0.0 UPPER.Example.COM\n")
    assert gc.parse_domain_list(text) == [
        "ads.example.com", "t.example.net", "plain.example.org", "wild.example.com",
        "upper.example.com"]


def test_hosts_size_reasonable_for_real_list_size():
    ads = [f"t{i}.example.com" for i in range(200_000)]
    out = gc.hosts_domains(["reddit.com"], ads=ads)
    assert len(out) == gc.MAX_HOSTS_ENTRIES
    assert len(gc.hosts_block(out).encode()) < 8 * 1024 * 1024


# --------------------------------------------------------------------- pf
def test_pf_rules_block_dot_doh_vpn_but_allow_our_resolver():
    rules = gc.pf_rules(doh_ips=gc.PUBLIC_DOH_IPS + ["185.228.168.168"])
    lines = rules.splitlines()
    allow = next(l for l in lines if l.startswith("table <pax_allow>"))
    doh = next(l for l in lines if l.startswith("table <pax_doh>"))
    assert "185.228.168.168" in allow and "185.228.169.168" in allow
    assert "185.228.168.168" not in doh                # HaGeZi lists CleanBrowsing: removed
    assert "1.1.1.1" in doh and "8.8.8.8" in doh and "9.9.9.9" in doh
    i_pass = next(i for i, l in enumerate(lines) if l.startswith("pass out quick"))
    i_block = next(i for i, l in enumerate(lines) if l.startswith("block drop"))
    assert i_pass < i_block                             # allow is evaluated first
    assert "block drop out quick proto { tcp udp } from any to any port 853" in lines
    assert "block drop out quick proto { tcp udp } from any to <pax_doh> port { 53 443 }" in lines
    assert "block drop out quick proto udp from any to any port { 500 1194 1701 4500 51820 }" in lines
    assert "block drop out quick proto tcp from any to any port { 1194 1723 }" in lines
    assert all(not l.startswith(("block in", "block all", "block drop all")) for l in lines)
    assert "port 443" not in " ".join(l for l in lines if "<pax_doh>" not in l and l.startswith("block"))


def test_pf_long_list_only_blocks_port_53():
    rules = gc.pf_rules(dns_only_ips=["3.33.139.32", "1.1.1.1", "185.228.168.168"])
    lines = rules.splitlines()
    dns = next(l for l in lines if l.startswith("table <pax_dns>"))
    assert "3.33.139.32" in dns
    assert "1.1.1.1" not in dns          # already in the curated 443 list
    assert "185.228.168.168" not in dns  # our resolver
    assert "block drop out quick proto { tcp udp } from any to <pax_dns> port 53" in lines


def test_network_dns_servers_stay_reachable_on_port_53():
    out = ("DNS configuration\n\nresolver #1\n  nameserver[0] : 1.1.1.1\n  nameserver[1] : 192.168.1.1\n"
           "  if_index : 6 (en0)\nresolver #2\n  domain   : local\n  nameserver[0] : 1.1.1.1\n")
    servers = gc.parse_scutil_dns(out)
    assert servers == ["1.1.1.1", "192.168.1.1"]
    lines = gc.pf_rules(system_dns=servers).splitlines()
    i_pass = lines.index("pass out quick proto { tcp udp } from any to <pax_sysdns> port 53")
    i_block = next(i for i, l in enumerate(lines) if "<pax_doh>" in l and l.startswith("block"))
    assert i_pass < i_block
    assert "1.1.1.1" in next(l for l in lines if l.startswith("table <pax_sysdns>"))


def test_pf_rules_deterministic():
    assert gc.pf_rules() == gc.pf_rules()


def test_merge_doh_ips_filters_garbage():
    merged = gc.merge_doh_ips(["1.1.1.1", "203.0.113.9", "not-an-ip", "2001:db8::1", ""])
    assert merged.count("1.1.1.1") == 1 and "203.0.113.9" in merged and "2001:db8::1" in merged
    assert "not-an-ip" not in merged


def test_pf_anchor_is_under_apple_anchor():
    assert gc.PF_ANCHOR.startswith("com.apple/")


# ------------------------------------------------------------ bypass apps
@pytest.mark.parametrize("folder,bid", [
    ("Tor Browser.app", None), ("Opera.app", "com.operasoftware.Opera"), ("Opera GX.app", None),
    ("NordVPN.app", None), ("Whatever.app", "com.nordvpn.NordVPN"), ("WireGuard.app", None),
    ("Vivaldi.app", None), ("Arc.app", None), ("Orion.app", None), ("Google Chrome Canary.app", None),
    ("Proton VPN.app", None), ("Mullvad VPN.app", None), ("Tunnelblick.app", None),
])
def test_bypass_apps_detected(folder, bid):
    assert gc.is_bypass_app(folder, bid) is not None


@pytest.mark.parametrize("folder,bid", [
    ("Google Chrome.app", "com.google.Chrome"), ("Firefox.app", "org.mozilla.firefox"),
    ("Safari.app", "com.apple.Safari"), ("Microsoft Edge.app", "com.microsoft.edgemac"),
    ("Brave Browser.app", "com.brave.Browser"), ("Chromium.app", "org.chromium.Chromium"),
    ("Outline.app", "com.gorillized.outlinemac"), ("Pages.app", "com.apple.iWork.Pages"),
    ("Pax.app", "org.paxmobile.pax"),
])
def test_normal_apps_left_alone(folder, bid):
    assert gc.is_bypass_app(folder, bid) is None


def test_app_bundle_of_uses_outermost_app():
    assert gc.app_bundle_of("/Applications/Tor Browser.app/Contents/MacOS/firefox") == \
        "/Applications/Tor Browser.app"
    assert gc.app_bundle_of("/Applications/Opera.app/Contents/Frameworks/Opera Helper.app/"
                            "Contents/MacOS/Opera Helper") == "/Applications/Opera.app"
    assert gc.app_bundle_of("/usr/sbin/mDNSResponder") is None


def test_connected_vpn_services():
    out = ('Available network connection services in the current set (*=enabled):\n'
           '* (Disconnected)   A1 VPN (com.apple.IKEv2) "Work"  [VPN/IKEv2]\n'
           '* (Connected)      B2 VPN (com.wireguard.macos) "Home tunnel"  [VPN/WireGuard]\n')
    assert gc.connected_vpn_services(out) == ["Home tunnel"]


def test_verified_bundle_ids_look_sane():
    for a in gc.all_bypass_apps():
        for b in a.bundle_ids:
            assert " " not in b and "." in b
        assert a.bundle_ids or a.app_names


# ------------------------------------------------------------ the daemon
class FakeSystem(pg.System):
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.files: dict[str, str] = {gc.HOSTS_PATH: STOCK_HOSTS}
        self.commands: list[list[str]] = []
        self.stdin: list[str | None] = []
        self.urls: dict[str, bytes] = {}
        self.apps: dict[str, str | None] = {}
        self.procs: list[tuple[int, str]] = []
        self.killed: list[int] = []
        self.moved: list[tuple[str, str]] = []
        self.profiles_out = ""
        self.pf_loaded = ""
        self.t = 1_800_000_000
        self.fail_fetch = False
        self.pf_enabled = False

    def read(self, path):
        return self.files.get(path, "")

    def write_atomic(self, path, text, mode=0o644):
        self.files[path] = text

    def run(self, args, stdin=None, timeout=30):
        self.commands.append(args)
        self.stdin.append(stdin)
        if args[:2] == ["/usr/bin/profiles", "show"]:
            return 0, self.profiles_out
        if args[:1] == ["/sbin/pfctl"] and "-sr" in args:
            return 0, self.pf_loaded
        if args[:1] == ["/sbin/pfctl"] and "-f" in args:
            self.pf_loaded = stdin
            return 0, ""
        if args[:3] == ["/usr/sbin/scutil", "--nc", "list"]:
            return 0, ""
        if args == ["/sbin/pfctl", "-s", "info"]:
            return 0, "Status: Enabled for 0 days" if self.pf_enabled else "Status: Disabled"
        if args == ["/sbin/pfctl", "-E"]:
            self.pf_enabled = True
        return 0, ""

    def fetch(self, url, headers=None, timeout=20):
        if self.fail_fetch or url not in self.urls:
            raise OSError("offline")
        return self.urls[url]

    def resolve(self, host):
        return ["185.228.168.168"]

    def list_apps(self, dirs):
        return [p for p in self.apps if any(p.startswith(d + "/") for d in dirs)]

    def bundle_id(self, app_path):
        return self.apps.get(app_path)

    def processes(self):
        return list(self.procs)

    def kill(self, pid):
        self.killed.append(pid)

    def move(self, src, dst):
        self.moved.append((src, dst))
        self.apps.pop(src, None)

    def exists(self, path):
        return path in self.apps

    def home_of(self, user):
        return f"/Users/{user}" if user else None

    def now(self):
        return self.t


def make_guard(tmp_path, **cfg):
    sysm = FakeSystem(tmp_path)
    c = pg.GuardConfig(server_url="https://pax.example.org/", guard_token="g" * 30,
                       profile_identifier="org.paxpeace.pax.macos-selflock.abc", user="alex", **cfg)
    return pg.Guard(c, sysm, state_dir=tmp_path / "state", quarantine_dir=tmp_path / "q"), sysm


def remote(**kw):
    d = {"now": 0, "device_id": "d", "blocked": ["reddit.com"], "allowed": [], "adblock": True,
         "released": False}
    d.update(kw)
    return json.dumps(d).encode()


def ad_list(n=12_000):
    return ("# HaGeZi\n" + "\n".join(f"0.0.0.0 t{i}.ads.example" for i in range(n))).encode()


def test_cycle_applies_everything(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote()
    s.urls[gc.ADS_LIST_URL] = ad_list()
    s.profiles_out = "attribute: profileIdentifier: org.paxpeace.pax.macos-selflock.abc"
    s.apps = {"/Applications/Tor Browser.app": "org.torproject.torbrowser",
              "/Applications/Safari.app": "com.apple.Safari",
              "/Users/alex/Applications/NordVPN.app": "com.nordvpn.NordVPN"}
    s.procs = [(42, "/Applications/Tor Browser.app/Contents/MacOS/firefox"),
               (43, "/Applications/Safari.app/Contents/MacOS/Safari")]
    res = g.cycle()
    hosts = s.files[gc.HOSTS_PATH]
    assert "0.0.0.0 reddit.com" in hosts and "0.0.0.0 t5.ads.example" in hosts
    assert res["hosts_changed"] and res["pf_changed"]
    assert "table <pax_doh>" in s.pf_loaded
    assert s.killed == [42]
    moved_from = sorted(m[0] for m in s.moved)
    assert moved_from == ["/Applications/Tor Browser.app", "/Users/alex/Applications/NordVPN.app"]
    assert res["profile_installed"] is True
    # second cycle: nothing to rewrite, and pf is only enabled once
    res2 = g.cycle()
    assert not res2["hosts_changed"] and not res2["pf_changed"]
    assert s.commands.count(["/sbin/pfctl", "-E"]) == 1


def test_server_outage_keeps_last_lists(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote(blocked=["x.example"])
    g.cycle()
    s.fail_fetch = True
    g.cycle()
    assert "0.0.0.0 x.example" in s.files[gc.HOSTS_PATH]


def test_too_small_ad_list_is_rejected(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote()
    s.urls[gc.ADS_LIST_URL] = ad_list(50)
    g.cycle()
    assert "t5.ads.example" not in s.files[gc.HOSTS_PATH]


def test_ad_blocking_off_removes_ads_but_keeps_sites(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote()
    s.urls[gc.ADS_LIST_URL] = ad_list()
    g.cycle()
    assert "t5.ads.example" in s.files[gc.HOSTS_PATH]
    s.urls["https://pax.example.org/v1/guard/config"] = remote(adblock=False)
    g.cycle()
    hosts = s.files[gc.HOSTS_PATH]
    assert "t5.ads.example" not in hosts and "0.0.0.0 reddit.com" in hosts and "dns.google" in hosts


def test_ads_refreshed_daily_only(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote()
    s.urls[gc.ADS_LIST_URL] = ad_list()
    g.cycle()
    s.urls[gc.ADS_LIST_URL] = ad_list(13_000)
    s.t += 3600
    g.cycle()
    assert "t12500.ads.example" not in s.files[gc.HOSTS_PATH]
    s.t += 24 * 3600
    g.cycle()
    assert "t12500.ads.example" in s.files[gc.HOSTS_PATH]


def test_released_password_pauses_enforcement(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote(released=True)
    s.apps = {"/Applications/Tor Browser.app": "org.torproject.torbrowser"}
    assert g.cycle() == {"released": True}
    assert s.moved == [] and gc.BEGIN not in s.files[gc.HOSTS_PATH]


def test_missing_profile_alerts_at_most_hourly(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote()
    s.profiles_out = "There are no configuration profiles installed"
    s.commands.clear()
    # console user 501
    orig = s.run

    def run(args, stdin=None, timeout=30):
        if args[:2] == ["/usr/bin/stat", "-f"]:
            return 0, "501\n"
        return orig(args, stdin, timeout)
    s.run = run
    assert g.cycle()["profile_installed"] is False
    g.cycle()
    notes = [c for c in s.commands if c[:2] == ["/bin/launchctl", "asuser"]]
    assert len(notes) == 1 and notes[0][2] == "501"


def test_profile_unknown_is_not_missing(tmp_path):
    g, s = make_guard(tmp_path)

    def run(args, stdin=None, timeout=30):
        return 1, "error"
    s.run = run
    assert g.profile_installed() is None


def test_uninstall_strips_hosts_flushes_pf_and_restores_apps(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote()
    s.apps = {"/Applications/Opera.app": "com.operasoftware.Opera"}
    g.cycle()
    dest = s.moved[0][1]
    s.apps[dest] = "com.operasoftware.Opera"
    done = g.uninstall()
    assert s.files[gc.HOSTS_PATH] == STOCK_HOSTS
    assert ["/sbin/pfctl", "-a", gc.PF_ANCHOR, "-F", "all"] in s.commands
    assert s.moved[-1] == (dest, "/Applications/Opera.app")
    assert "hosts block removed" in done


def test_config_load_ignores_unknown_keys(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"server_url": "https://x/", "guard_token": "t", "future_key": 1}))
    c = pg.GuardConfig.load(p)
    assert c.server_url == "https://x/" and c.interval == pg.INTERVAL


def test_launchd_plist():
    plist = plistlib.loads((HERE.parent / "org.paxpeace.pax-guard.plist").read_bytes())
    assert plist["Label"] == pg.LABEL
    assert plist["KeepAlive"] is True and plist["RunAtLoad"] is True
    assert plist["ProgramArguments"] == ["/bin/sh", "/Library/PaxGuard/bin/pax-guard-launch.sh", "run"]  # v0.8.6
