# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.37: `pax_device.py inspect` reads a plugged-in phone (read-only) so the Mac app can
recognise one Pax already protects, and install-profile reports MCInstall's
"must be installed using a device management tool" refusal as PAX-IOS-013 without the raw
error."""
import json
import sys
import types
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pax_device  # noqa: E402
from test_seed import run_cmd  # noqa: E402

PID = "org.paxpeace.pax.ios.1f2e3d4c-0000-4000-8000-00000000abcd"
DMC = "The profile must be installed using a device management tool."


class FakeLD:
    paired = True

    def __init__(self):
        self.closed = False

    async def get_value(self, domain=None, key=None):
        return "27.0.1" if key == "ProductVersion" else None

    async def close(self):
        self.closed = True


def install(monkeypatch, *, cfg=None, listing=None, paired=True, manual_error=None):
    log = {"calls": [], "installed": []}

    class MC:
        def __init__(self, ld):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get_cloud_configuration(self):
            log["calls"].append("get_cloud_configuration")
            return cfg

        async def get_profile_list(self):
            log["calls"].append("get_profile_list")
            return listing

        async def install_profile(self, data):
            log["calls"].append("install_profile")
            if manual_error:
                raise manual_error
            log["installed"].append(data)

        async def install_profile_silent(self, keybag, data):
            log["calls"].append("install_profile_silent")
            raise RuntimeError("not the supervisor")

        # Anything that would change the phone is recorded, so a test can prove inspect didn't.
        async def set_cloud_configuration(self, cfg):
            log["calls"].append("set_cloud_configuration")

        async def remove_profile(self, ident):
            log["calls"].append("remove_profile")

    mod = types.ModuleType("mc")
    mod.MobileConfigService = MC
    for name, m in {"pymobiledevice3": types.ModuleType("pymobiledevice3"),
                    "pymobiledevice3.services": types.ModuleType("s"),
                    "pymobiledevice3.services.mobile_config": mod}.items():
        monkeypatch.setitem(sys.modules, name, m)
    ld = FakeLD()
    ld.paired = paired

    async def open_lockdown(_udid):
        return ld
    monkeypatch.setattr(pax_device, "open_lockdown", open_lockdown)
    log["ld"] = ld
    return log


def test_inspect_recognises_a_pax_phone_and_changes_nothing(monkeypatch):
    log = install(monkeypatch,
                  cfg={"IsSupervised": True, "OrganizationName": "Pax (self-managed)"},
                  listing={"OrderedIdentifiers": ["com.example.wifi", PID],
                           "ProfileMetadata": {PID: {}, "com.example.wifi": {}}})
    out = run_cmd(["inspect", "--udid", "U"])
    assert out == {"supervised": True, "organization": "Pax (self-managed)", "pax_supervised": True,
                   "pax_profiles": [PID], "other_profiles": 1, "ios": "27.0.1"}
    assert set(log["calls"]) == {"get_cloud_configuration", "get_profile_list"}   # read-only
    assert log["ld"].closed
    assert "com.example.wifi" not in json.dumps(out)        # the user's other profiles stay private


def test_inspect_unprotected_and_other_supervisors(monkeypatch):
    install(monkeypatch, cfg={}, listing={})
    out = run_cmd(["inspect", "--udid", "U"])
    assert out["supervised"] is False and out["pax_profiles"] == [] and out["pax_supervised"] is False
    install(monkeypatch, cfg={"IsSupervised": True, "OrganizationName": "Acme MDM"},
            listing={"ProfileMetadata": {"com.acme.mdm": {}}})
    out = run_cmd(["inspect", "--udid", "U"])
    assert out["supervised"] is True and out["pax_supervised"] is False and out["pax_profiles"] == []
    assert out["other_profiles"] == 1


def test_inspect_needs_trust(monkeypatch):
    install(monkeypatch, cfg={}, listing={}, paired=False)
    with pytest.raises(pax_device.HelperError) as e:
        run_cmd(["inspect", "--udid", "U"])
    assert e.value.code == "not_paired"


def test_pax_profile_prefixes():
    assert pax_device.is_pax_phone_profile(PID)
    assert pax_device.is_pax_phone_profile("org.paxpeace.pax.ipados.x")
    assert not pax_device.is_pax_phone_profile("org.paxpeace.pax.appstore.x")
    assert not pax_device.is_pax_phone_profile("org.paxpeace.pax.macos.x")
    assert not pax_device.is_pax_phone_profile(None)
    assert pax_device.profile_identifiers({"ProfileMetadata": {"a": {}, "b": {}}}) == ["a", "b"]
    assert pax_device.profile_identifiers(None) == []


def test_needs_supervisor_markers():
    assert pax_device.needs_supervisor(f"ProfileError: {DMC}")
    assert pax_device.needs_supervisor("DMCFatalError (code 1)")
    assert not pax_device.needs_supervisor("ConnectionError: locked")
    assert not pax_device.needs_supervisor("")


def test_install_on_a_phone_supervised_by_another_key_is_pax_ios_013(monkeypatch, tmp_path):
    class ProfileError(Exception):
        pass
    log = install(monkeypatch, manual_error=ProfileError(f"{DMC} (DMCFatalError)"))
    cert = tmp_path / "c.der"
    cert.write_bytes(b"CERT")
    args = ["install-profile", "--udid", "U", "--cert", str(cert), "--key", str(tmp_path / "gone.der"),
            "--allow-manual"]
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(buffer=types.SimpleNamespace(read=lambda: b"PROFILE")))
    with pytest.raises(pax_device.HelperError) as e:
        run_cmd(args)
    assert e.value.code == "needs_supervisor"
    msg = str(e.value)
    assert msg.startswith("PAX-IOS-013")
    assert "DMCFatalError" not in msg and "ProfileError" not in msg and "device management tool" not in msg
    assert log["installed"] == []


def test_other_manual_install_failures_are_unchanged(monkeypatch, tmp_path):
    install(monkeypatch, manual_error=ConnectionError("phone locked"))
    cert = tmp_path / "c.der"
    cert.write_bytes(b"CERT")
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(buffer=types.SimpleNamespace(read=lambda: b"PROFILE")))
    with pytest.raises(ConnectionError):
        run_cmd(["install-profile", "--udid", "U", "--cert", str(cert), "--key", str(tmp_path / "gone.der"),
                 "--allow-manual"])


def test_main_prints_the_calm_message(monkeypatch, tmp_path, capsys):
    class ProfileError(Exception):
        pass
    install(monkeypatch, manual_error=ProfileError(DMC))
    cert = tmp_path / "c.der"
    cert.write_bytes(b"CERT")
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(buffer=types.SimpleNamespace(read=lambda: b"PROFILE")))
    rc = pax_device.main(["install-profile", "--udid", "U", "--cert", str(cert), "--key",
                          str(tmp_path / "gone.der"), "--allow-manual"])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 1 and out["ok"] is False and out["code"] == "needs_supervisor"
    assert out["error"].startswith("PAX-IOS-013") and "device management tool" not in out["error"]
