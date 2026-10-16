# SPDX-License-Identifier: GPL-3.0-only
"""v0.5 pax-guard: curated bypass + remote-desktop categories in /etc/hosts,
HaGeZi's bypass list, remote-desktop ports in pf, and VM app quarantine."""
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import guard_config as gc  # noqa: E402
from test_guard import STOCK_HOSTS, ad_list, make_guard, remote  # noqa: E402

CFG_URL = "https://pax.example.org/v1/guard/config"


# ------------------------------------------------------------- curated lists
def test_curated_lists_found_in_repo_and_parsed():
    bypass = gc.load_curated("bypass")
    rd = gc.load_curated("remote_desktop")
    assert "sensepc.com" in bypass and "browserling.com" in bypass and "croxyproxy.com" in bypass
    assert "anydesk.com" in rd and "remotedesktop.google.com" in rd and "master1.teamviewer.com" in rd
    assert gc.find_list("bypass").parent.name == "lists"


def test_missing_list_dir_gives_empty_list(tmp_path):
    assert gc.load_curated("bypass", [tmp_path]) == []
    (tmp_path / "cloud-pc-bypass.txt").write_text("# c\nexample-cloudpc.test\n")
    assert gc.load_curated("bypass", [tmp_path]) == ["example-cloudpc.test"]


def test_hosts_order_categories_before_hagezi_before_ads():
    out = gc.hosts_domains(["mine.example"], ads=["ad.example"], categories=["cloud.example"],
                           bypass_list=["proxy.example"], allowlist=[])
    i = {d: n for n, d in enumerate(out)}
    assert i["mine.example"] < i["dns.google"] < i["cloud.example"] < i["www.cloud.example"] \
        < i["proxy.example"] < i["ad.example"]
    assert "www.proxy.example" not in out           # HaGeZi entries: apex only


def test_cap_never_squeezes_categories_out():
    ads = [f"t{i}.example.com" for i in range(250_000)]
    out = gc.hosts_domains([], ads=ads, categories=["cloud.example"], bypass_list=["proxy.example"])
    assert len(out) == gc.MAX_HOSTS_ENTRIES and "cloud.example" in out and "proxy.example" in out


def test_exceptions_free_category_entries():
    out = gc.hosts_domains([], categories=["browserstack.com", "shadow.tech"],
                           exceptions=["browserstack.com"])
    assert "browserstack.com" not in out and "www.browserstack.com" not in out
    assert "shadow.tech" in out


# ----------------------------------------------------------------------- pf
def test_pf_remote_desktop_ports_only_when_on():
    off = gc.pf_rules(remote_desktop=False)
    on = gc.pf_rules(remote_desktop=True)
    assert "3389" not in off and "5938" not in off
    assert "block drop out quick proto tcp from any to any port " \
           "{ 3389 4000 5900 5938 7070 21115 21116 21117 21118 21119 }" in on.splitlines()
    assert "block drop out quick proto udp from any to any port { 3389 4000 21116 }" in on.splitlines()


# ------------------------------------------------------------------ VM apps
@pytest.mark.parametrize("folder,bid", [
    ("UTM.app", "com.utmapp.UTM"), ("UTM.app", None), ("Renamed.app", "com.utmapp.UTM"),
    ("Parallels Desktop.app", "com.parallels.desktop.console"),
    ("Parallels Desktop.app", "com.parallels.desktop.appstore"),
    ("VMware Fusion.app", None), ("VirtualBox.app", "org.virtualbox.app.VirtualBox"),
    ("tart.app", None), ("x.app", "com.github.cirruslabs.tart"), ("VirtualBuddy.app", None),
    ("QEMU.app", None), ("virtualOS.app", "com.github.yep.ios.virtualOS"),
])
def test_vm_apps_detected(folder, bid):
    hit = gc.is_bypass_app(folder, bid)
    assert hit is not None and hit in gc.VM_APPS


@pytest.mark.parametrize("folder,bid", [
    ("Docker.app", "com.docker.docker"), ("Windows App.app", "com.microsoft.rdc.macos"),
    ("Xcode.app", "com.apple.dt.Xcode"), ("Quicken.app", "com.quicken.Quicken"),
])
def test_vm_list_leaves_other_apps_alone(folder, bid):
    assert gc.is_bypass_app(folder, bid) is None


def test_vm_processes():
    assert gc.is_vm_process("/opt/homebrew/bin/qemu-system-aarch64")
    assert gc.is_vm_process("/usr/local/Cellar/qemu/9.1/bin/qemu-system-x86_64")
    assert not gc.is_vm_process("/opt/homebrew/bin/qemu-img")
    assert not gc.is_vm_process("/usr/sbin/mDNSResponder")


# --------------------------------------------------------------- the daemon
def test_cycle_writes_categories_and_respects_server_switch(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls[CFG_URL] = remote()
    s.urls[gc.BYPASS_LIST_URL] = ("# HaGeZi\n" + "\n".join(f"p{i}.proxy.example" for i in range(6000))).encode()
    g.cycle()
    hosts = s.files[gc.HOSTS_PATH]
    for name in ("sensepc.com", "www.sensepc.com", "anydesk.com", "remotedesktop.google.com",
                 "p42.proxy.example"):
        assert f"0.0.0.0 {name}\n" in hosts, name
    assert "3389" in s.pf_loaded
    # remote desktop switched off on the server (after its wait)
    s.urls[CFG_URL] = remote(categories={"bypass": True, "remote_desktop": False})
    g.cycle()
    hosts = s.files[gc.HOSTS_PATH]
    assert "0.0.0.0 anydesk.com\n" not in hosts and "0.0.0.0 sensepc.com\n" in hosts
    assert "3389" not in s.pf_loaded
    assert g.remote_desktop_blocked is False


def test_older_server_without_categories_means_on(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls[CFG_URL] = remote()
    g.cycle()
    assert g.remote_desktop_blocked is True
    assert "0.0.0.0 teamviewer.com\n" in s.files[gc.HOSTS_PATH]


def test_small_hagezi_bypass_list_rejected(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls[CFG_URL] = remote()
    s.urls[gc.BYPASS_LIST_URL] = b"tiny.proxy.example\n"
    g.cycle()
    assert "tiny.proxy.example" not in s.files[gc.HOSTS_PATH]


def test_cycle_kills_qemu_and_quarantines_vm_apps(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls[CFG_URL] = remote()
    s.apps = {"/Applications/UTM.app": "com.utmapp.UTM",
              "/Applications/VMware Fusion.app": "com.vmware.fusion",
              "/Applications/Docker.app": "com.docker.docker"}
    s.procs = [(70, "/opt/homebrew/bin/qemu-system-aarch64"),
               (71, "/Applications/UTM.app/Contents/MacOS/UTM"),
               (72, "/opt/homebrew/bin/qemu-img")]
    res = g.cycle()
    assert sorted(s.killed) == [70, 71]
    assert sorted(m[0] for m in s.moved) == ["/Applications/UTM.app", "/Applications/VMware Fusion.app"]
    assert any("virtual machine qemu-system-aarch64" in a for a in res["apps"])


def test_hosts_keep_user_lines_with_categories(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls[CFG_URL] = remote()
    g.cycle()
    assert gc.strip_pax_block(s.files[gc.HOSTS_PATH]) == STOCK_HOSTS
    assert json.loads(s.files[str(tmp_path / "state" / "remote.json")])["blocked"] == ["reddit.com"]
