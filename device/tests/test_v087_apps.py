# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.7: `pax_device.py apps` lists the connected iPhone's own apps for the set-up
picker (installation_proxy Lookup of user apps, only the attributes the picker
shows), marks the ones Pax blocks anyway or never blocks, and writes icons from
SpringBoard when it can (best effort, time-boxed)."""
import json
import sys
import types
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pax_device  # noqa: E402
from test_seed import run_cmd  # noqa: E402

LOOKUP = {
    "com.example.game": {"CFBundleIdentifier": "com.example.game", "CFBundleDisplayName": "Game",
                         "CFBundleShortVersionString": "2.1"},
    "com.nordvpn.NordVPN": {"CFBundleIdentifier": "com.nordvpn.NordVPN", "CFBundleName": "NordVPN"},
    "com.8bit.bitwarden": {"CFBundleIdentifier": "com.8bit.bitwarden", "CFBundleDisplayName": "Bitwarden"},
    "com.example.chat": {"CFBundleIdentifier": "com.example.chat", "CFBundleDisplayName": "Chat"},
}


class FakeLD:
    paired = True

    async def close(self):
        pass


def install(monkeypatch, *, lookup=LOOKUP, fail_lookup=False, icons=True, paired=True):
    log = {"lookups": [], "icons": []}

    class IP:
        def __init__(self, ld):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def lookup(self, options=None):
            log["lookups"].append(options)
            if fail_lookup:
                raise ConnectionError("locked")
            return lookup

    class SB(IP):
        async def get_icon_pngdata(self, bid):
            log["icons"].append(bid)
            if not icons or bid == "com.example.chat":
                raise ConnectionError("no icon")
            return b"\x89PNG" + bid.encode()

    ip_mod = types.ModuleType("ip")
    ip_mod.InstallationProxyService = IP
    sb_mod = types.ModuleType("sb")
    sb_mod.SpringBoardServicesService = SB
    for name, mod in {"pymobiledevice3": types.ModuleType("pymobiledevice3"),
                      "pymobiledevice3.services": types.ModuleType("s"),
                      "pymobiledevice3.services.installation_proxy": ip_mod,
                      "pymobiledevice3.services.springboard": sb_mod}.items():
        monkeypatch.setitem(sys.modules, name, mod)
    ld = FakeLD()
    ld.paired = paired

    async def open_lockdown(_udid):
        return ld
    monkeypatch.setattr(pax_device, "open_lockdown", open_lockdown)
    return log


def test_lists_user_apps_with_only_the_picker_attributes(monkeypatch):
    log = install(monkeypatch)
    out = run_cmd(["apps", "--udid", "U"])
    assert log["lookups"] == [{"ApplicationType": "User", "ReturnAttributes": pax_device.APP_ATTRIBUTES}]
    names = [a["name"] for a in out["apps"]]
    assert names == ["Bitwarden", "Chat", "Game", "NordVPN"]          # sorted by name
    by = {a["bundle_id"]: a for a in out["apps"]}
    assert by["com.example.game"]["version"] == "2.1" and by["com.example.game"]["can_block"]
    assert by["com.nordvpn.NordVPN"]["pax_blocks"] is True             # bypass app: blocked anyway
    assert by["com.8bit.bitwarden"]["can_block"] is False and by["com.8bit.bitwarden"]["why_not"] == "a password manager"
    assert "com.openai.chat" in out["pax_blocked"] and out["max_custom"] == 200
    assert out["icons"] == 0 and log["icons"] == []                    # no icons unless asked


def test_icons_are_best_effort(monkeypatch, tmp_path):
    log = install(monkeypatch)
    out = run_cmd(["apps", "--udid", "U", "--icons-dir", str(tmp_path / "icons")])
    by = {a["bundle_id"]: a for a in out["apps"]}
    assert out["icons"] == 3
    assert Path(by["com.example.game"]["icon"]).read_bytes() == b"\x89PNG" + b"com.example.game"
    assert "icon" not in by["com.example.chat"]                        # that one failed; the rest carry on


def test_icon_time_budget(monkeypatch, tmp_path):
    install(monkeypatch)
    clock = {"t": 0.0}

    def tick():
        clock["t"] += pax_device.ICON_BUDGET_SECONDS
        return clock["t"]
    monkeypatch.setattr(pax_device.time, "monotonic", tick)
    out = run_cmd(["apps", "--udid", "U", "--icons-dir", str(tmp_path)])
    assert out["icons"] <= 1 and len(out["apps"]) == 4


def test_failures_are_coded_and_main_prints_json(monkeypatch, capsys):
    install(monkeypatch, fail_lookup=True)
    assert pax_device.main(["apps", "--udid", "U"]) == 1
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["code"] == "apps_failed" and out["error"].startswith("PAX-IOS-012")
    install(monkeypatch, paired=False)
    assert pax_device.main(["apps", "--udid", "U"]) == 1
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["code"] == "not_paired"


def test_selftest_knows_the_new_services():
    assert pax_device.SELFTEST_IMPORTS["pymobiledevice3.services.installation_proxy"] == ["InstallationProxyService"]
    assert ("pymobiledevice3.services.springboard", "SpringBoardServicesService") in pax_device.SELFTEST_METHODS


def test_the_bundled_app_carries_the_rules():
    build = (HERE.parents[1] / "mac-app" / "scripts" / "build-dmg.sh").read_text()
    assert '"$REPO/profile/app_blocks.py"' in build
    assert pax_device._app_blocks().MAX_CUSTOM_APP_BLOCKS == 200


@pytest.mark.parametrize("bad", ["../x", ".hidden"])
def test_icon_names_never_leave_the_folder(monkeypatch, tmp_path, bad):
    install(monkeypatch, lookup={bad: {"CFBundleIdentifier": bad, "CFBundleName": "X"}})
    out = run_cmd(["apps", "--udid", "U", "--icons-dir", str(tmp_path / "i")])
    assert out["icons"] == 0 and not (tmp_path / "x").exists()
