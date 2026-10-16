# SPDX-License-Identifier: GPL-3.0-only
"""Unit tests for Keep-my-data logic. No iPhone, no pymobiledevice3 needed."""
import hashlib
import io
import plistlib
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import seed  # noqa: E402
import pax_device  # noqa: E402

SKIPKEYS = HERE.parent.parent / "profile" / "apple-schema" / "skipkeys.yaml"


# ---------------- version gate ----------------

@pytest.mark.parametrize("version, mode", [
    ("17.0", "restored"), ("17.7.2", "restored"), ("18.6", "restored"), ("26.6.2", "restored"),
    ("27", "live"), ("27.0", "live"), ("27.0.1", "live"), ("27.2", "live"),
])
def test_supported_versions(version, mode):
    plan = seed.plan_for_version(version)
    assert plan.allowed and plan.mode == mode


@pytest.mark.parametrize("version, refusal", [
    ("16.7.10", "too_old"), ("15.0", "too_old"),
    ("28.0", "too_new"), ("28", "too_new"), ("30.1", "too_new"),
    (None, "unknown"), ("", "unknown"), ("27.x", "unknown"), ("0.1", "unknown"),
    ("27..1", "unknown"), (" ", "unknown"), ("२७.0", "unknown"),
])
def test_refused_versions(version, refusal):
    plan = seed.plan_for_version(version)
    assert not plan.allowed and plan.mode is None and plan.refusal == refusal
    assert "Clean" in plan.message


# ---------------- cloud configuration ----------------

def test_cloud_configuration_from_nothing():
    cfg = seed.plan_cloud_configuration(None, supervisor_cert_der=b"CERT", organization_magic="M")
    assert cfg["IsSupervised"] is True
    for k in ("CloudConfigurationUIComplete", "ConfigurationWasApplied", "PostSetupProfileWasInstalled"):
        assert cfg[k] is True
    assert cfg["AllowPairing"] is True
    assert cfg["ConfigurationSource"] == 0
    assert cfg["OrganizationName"] == seed.DEFAULT_ORGANIZATION
    assert cfg["OrganizationMagic"] == "M"
    assert cfg["SupervisorHostCertificates"] == [b"CERT"]
    assert "RestoreCompleted" in cfg["SkipSetup"]
    plistlib.dumps(cfg)  # serialisable as the phone expects


def test_cloud_configuration_keeps_existing_keys():
    current = {"SkipSetup": ["Custom"], "OrganizationName": "Existing", "OrganizationMagic": "X",
               "SupervisorHostCertificates": [b"OTHER"], "SomeFutureKey": 7, "IsSupervised": False}
    cfg = seed.plan_cloud_configuration(current, supervisor_cert_der=b"CERT")
    assert cfg["SomeFutureKey"] == 7
    assert cfg["OrganizationName"] == "Existing"
    assert cfg["OrganizationMagic"] == "X"
    assert cfg["SupervisorHostCertificates"] == [b"OTHER", b"CERT"]
    assert cfg["SkipSetup"][0] == "Custom" and len(cfg["SkipSetup"]) == len(set(cfg["SkipSetup"]))
    assert current["IsSupervised"] is False  # input not mutated


def test_cloud_configuration_cert_not_duplicated_and_optional():
    cfg = seed.plan_cloud_configuration({"SupervisorHostCertificates": [b"CERT"]}, supervisor_cert_der=b"CERT")
    assert cfg["SupervisorHostCertificates"] == [b"CERT"]
    cfg = seed.plan_cloud_configuration({})
    assert "SupervisorHostCertificates" not in cfg


def test_strict_mode_forbids_pairing():
    assert seed.plan_cloud_configuration({}, allow_pairing=False)["AllowPairing"] is False


def test_skip_panes_are_apple_keys():
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(SKIPKEYS.read_text())
    keys = set()

    def walk(node):
        if isinstance(node, dict):
            if "key" in node and isinstance(node["key"], str):
                keys.add(node["key"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(doc)
    missing = [p for p in seed.SKIP_SETUP_PANES if p not in keys]
    assert not missing, missing


def test_supervision_readers():
    assert seed.reads_supervised({"IsSupervised": True})
    assert not seed.reads_supervised({"IsSupervised": 1})
    assert not seed.reads_supervised(None)
    assert seed.host_cert_registered({"SupervisorHostCertificates": [b"a", b"b"]}, b"b")
    assert not seed.host_cert_registered({"SupervisorHostCertificates": [b"a"]}, b"b")
    assert not seed.host_cert_registered({}, None)


# ---------------- seed backup ----------------

def parse_mbdb(data: bytes):
    """Independent reader (same layout as TrollRestore's MbdbRecord.from_stream)."""
    d = io.BytesIO(data)
    assert d.read(6) == b"mbdb\x05\x00"
    recs = []

    def s():
        n = int.from_bytes(d.read(2), "big")
        return b"" if n == 0xFFFF else d.read(n)
    while d.tell() < len(data):
        domain, name, link, h, key = s().decode(), s().decode(), s(), s(), s()
        mode = int.from_bytes(d.read(2), "big")
        inode = int.from_bytes(d.read(8), "big")
        uid = int.from_bytes(d.read(4), "big"); gid = int.from_bytes(d.read(4), "big")
        d.read(12)
        size = int.from_bytes(d.read(8), "big")
        flags = d.read(1)[0]
        nprops = d.read(1)[0]
        for _ in range(nprops):
            s(); s()
        recs.append(dict(domain=domain, name=name, hash=h, mode=mode, inode=inode, uid=uid,
                         gid=gid, size=size, flags=flags))
    return recs


def test_live_seed_holds_only_supervision_domain(tmp_path):
    cfg = seed.plan_cloud_configuration({}, supervisor_cert_der=b"CERT")
    folder = seed.write_seed(tmp_path, "UDID-1", cfg, seed.MODE_LIVE, mtime=1, inode=42)
    assert folder == tmp_path / "UDID-1"
    names = sorted(p.name for p in folder.iterdir())
    content_name = hashlib.sha1(
        f"{seed.SUPERVISION_DOMAIN}-{seed.SUPERVISION_PATH}".encode()).hexdigest()
    assert names == sorted([content_name, "Info.plist", "Manifest.mbdb", "Manifest.plist", "Status.plist"])
    content = (folder / content_name).read_bytes()
    assert plistlib.loads(content)["IsSupervised"] is True
    recs = parse_mbdb((folder / "Manifest.mbdb").read_bytes())
    assert [r["name"] for r in recs] == ["", "Library", "Library/ConfigurationProfiles", seed.SUPERVISION_PATH]
    assert {r["domain"] for r in recs} == {seed.SUPERVISION_DOMAIN}
    f = recs[-1]
    assert f["mode"] == 0o100755 and f["inode"] == 42 and f["size"] == len(content)
    assert f["hash"] == hashlib.sha1(content).digest()
    assert all(r["uid"] == 501 and r["gid"] == 501 and r["flags"] == 4 for r in recs)
    assert all(r["mode"] == 0o040755 for r in recs[:-1])
    status = plistlib.loads((folder / "Status.plist").read_bytes())
    assert status["IsFullBackup"] is False and status["SnapshotState"] == "finished"
    manifest = plistlib.loads((folder / "Manifest.plist").read_bytes())
    assert manifest["Version"] == "9.1"
    # Keybag bytes as in TrollRestore sparserestore/backup.py
    assert hashlib.sha256(manifest["BackupKeyBag"]).hexdigest() == \
        "66ef3284ba61014d5943f135c258e288128dc01e2d69deb717aa411e45141045"


def test_restored_seed_adds_setup_preferences(tmp_path):
    folder = seed.write_seed(tmp_path, "U", seed.plan_cloud_configuration({}), seed.MODE_RESTORED,
                             mtime=1, inode=7)
    recs = parse_mbdb((folder / "Manifest.mbdb").read_bytes())
    assert {r["domain"] for r in recs} == {seed.SUPERVISION_DOMAIN, seed.SETUP_DOMAIN}
    setup_name = seed.backup_file_name(seed.SETUP_DOMAIN, seed.SETUP_PATH)
    assert plistlib.loads((folder / setup_name).read_bytes())["SetupDone"] is True
    inodes = [r["inode"] for r in recs if (r["mode"] & 0o170000) == 0o100000]
    assert len(inodes) == 2 and len(set(inodes)) == 2


def test_seed_refuses_existing_folder_and_bad_input(tmp_path):
    (tmp_path / "U").mkdir()
    with pytest.raises(FileExistsError):
        seed.write_seed(tmp_path, "U", {}, seed.MODE_LIVE)
    for bad in ("", "a/b", "..", "."):
        with pytest.raises(ValueError):
            seed.write_seed(tmp_path, bad, {}, seed.MODE_LIVE)
    with pytest.raises(ValueError):
        seed.write_seed(tmp_path, "V", {}, "full")


# ---------------- restore arguments ----------------

def test_restore_arguments_live_never_sends_system_files():
    args = seed.restore_arguments("U", Path("/tmp/s"), seed.MODE_LIVE)
    assert args == ["-u", "U", "restore", "--skip-apps", "--remove", "--reboot", "/tmp/s"]
    assert "--system" not in args and "--settings" not in args


def test_restore_arguments_restored():
    assert seed.restore_arguments("U", Path("/tmp/s"), seed.MODE_RESTORED) == \
        ["-u", "U", "restore", "--system", "--skip-apps", "--no-reboot", "/tmp/s"]
    with pytest.raises(ValueError):
        seed.restore_arguments("U", Path("/tmp/s"), None)


# ---------------- preflight ----------------

def good(**kw):
    base = dict(ios_version="27.2", paired="paired", find_my_on=False, backup_confirmed=True,
                battery_level=80, charging=False)
    base.update(kw)
    return seed.PreflightFacts(**base)


def test_preflight_ok():
    r = seed.evaluate_preflight(good())
    assert r.ok and r.mode == "live" and r.blocking == []


def test_preflight_find_my_on_blocks():
    assert not seed.evaluate_preflight(good(find_my_on=True)).ok


def test_preflight_find_my_unknown_asks_user():
    r = seed.evaluate_preflight(good(find_my_on=None))
    assert not r.ok and r.ask_user_find_my
    r = seed.evaluate_preflight(good(find_my_on=None, find_my_confirmed_off=True))
    assert r.ok


def test_preflight_backup_required():
    assert not seed.evaluate_preflight(good(backup_confirmed=False)).ok


@pytest.mark.parametrize("level, charging, ok", [
    (80, False, True), (50, False, True), (49, False, False), (49, True, True),
    (25, True, True), (19, True, False), (None, None, True),
])
def test_preflight_battery(level, charging, ok):
    assert seed.evaluate_preflight(good(battery_level=level, charging=charging)).ok is ok


@pytest.mark.parametrize("state", ["needs_trust", "locked", "denied", "unknown", None])
def test_preflight_needs_pairing(state):
    assert not seed.evaluate_preflight(good(paired=state)).ok


def test_preflight_ios28_refused():
    r = seed.evaluate_preflight(good(ios_version="28.0"))
    assert not r.ok and r.mode is None


def test_battery_from_lockdown():
    assert seed.battery_from_lockdown({"BatteryCurrentCapacity": 64, "BatteryIsCharging": True}) == (64, True)
    assert seed.battery_from_lockdown({"BatteryCurrentCapacity": 64, "ExternalConnected": False}) == (64, False)
    assert seed.battery_from_lockdown(None) == (None, None)
    assert seed.battery_from_lockdown({"BatteryCurrentCapacity": True}) == (None, None)


def test_verify_local_backup(tmp_path):
    assert not seed.verify_local_backup(tmp_path)[0]
    (tmp_path / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "uploading"}))
    assert not seed.verify_local_backup(tmp_path)[0]
    (tmp_path / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))
    assert not seed.verify_local_backup(tmp_path)[0]
    (tmp_path / "Manifest.db").write_bytes(b"x")
    assert seed.verify_local_backup(tmp_path) == (True, "finished")
    # v0.8.6: the host writes an empty Manifest.plist first; the device fills it at the end.
    (tmp_path / "Manifest.plist").write_bytes(b"")
    assert not seed.verify_local_backup(tmp_path)[0]
    (tmp_path / "Manifest.plist").write_bytes(plistlib.dumps({"Version": "10.0"}))
    assert seed.verify_local_backup(tmp_path) == (True, "finished")


# ---------------- helper CLI (no device) ----------------

def test_helper_parser():
    p = pax_device.build_parser()
    a = p.parse_args(["live-configure", "--udid", "U", "--cert", "c.der", "--forbid-pairing"])
    assert a.timeout == pax_device.LIVE_DEFAULT_TIMEOUT and a.forbid_pairing
    a = p.parse_args(["install-profile", "--udid", "U", "--cert", "c", "--key", "k", "--allow-manual"])
    assert a.allow_manual
    with pytest.raises(SystemExit):
        p.parse_args(["seed-restore"])


def test_restore_failure_classification():
    assert pax_device.classify_restore_failure("ERROR: Find My iPhone is enabled").code == "find_my_on"
    assert pax_device.classify_restore_failure("Device locked (-15)").code == "locked"
    assert pax_device.classify_restore_failure("boom").code == "restore_failed"


def test_helper_reports_json_error_without_device(capsys, monkeypatch):
    monkeypatch.setenv("PAX_IDEVICEBACKUP2", "/nonexistent")
    monkeypatch.setenv("PATH", "/nonexistent")

    async def boom(_a):
        raise pax_device.HelperError("x", "tool_missing")
    monkeypatch.setitem(pax_device.COMMANDS, "list", boom)
    assert pax_device.main(["list"]) == 1
    import json
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out == {"ok": False, "error": "x", "code": "tool_missing"}


def test_keybag_pem_roundtrip(tmp_path):
    crypto = pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as dt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pax test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(dt.datetime(2026, 1, 1)).not_valid_after(dt.datetime(2036, 1, 1))
            .sign(key, hashes.SHA256()))
    pem = pax_device._keybag_pem(cert.public_bytes(serialization.Encoding.DER),
                                 key.private_bytes(serialization.Encoding.DER,
                                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                                   serialization.NoEncryption()))
    assert x509.load_pem_x509_certificate(pem) == cert
    assert serialization.load_pem_private_key(pem, password=None).private_numbers() == key.private_numbers()


# ---------------- helper flows with a fake phone ----------------

class FakeLockdown:
    def __init__(self, version="27.2", paired=True, fmip=False):
        self.paired = paired
        self.values = {(None, "ProductVersion"): version, ("com.apple.fmip", "IsAssociated"): fmip}

    async def get_value(self, domain=None, key=None):
        return self.values.get((domain, key))

    async def close(self):
        pass


def install_fake_phone(monkeypatch, *, version="27.2", fail_sets=0, reject_cert=False):
    state = {"cfg": None, "sets": 0, "sent": []}
    ld = FakeLockdown(version)

    async def open_lockdown(_udid):
        return ld

    async def get_cfg(_ld):
        return state["cfg"]

    async def set_cfg(_ld, cfg):
        state["sets"] += 1
        state["sent"].append(cfg)
        if state["sets"] <= fail_sets:
            raise ConnectionError("MCInstall not ready")
        if reject_cert and cfg.get("SupervisorHostCertificates"):
            class ProfileError(Exception):
                pass
            raise ProfileError("rejected")
        state["cfg"] = cfg

    async def no_sleep(_s):
        pass
    monkeypatch.setattr(pax_device, "open_lockdown", open_lockdown)
    monkeypatch.setattr(pax_device, "cloud_configuration", get_cfg)
    monkeypatch.setattr(pax_device, "set_cloud_configuration", set_cfg)
    monkeypatch.setattr(pax_device.asyncio, "sleep", no_sleep)
    return state


def run_cmd(argv):
    import asyncio
    args = pax_device.build_parser().parse_args(argv)
    return asyncio.run(pax_device.COMMANDS[args.command](args))


def test_live_configure_retries_until_supervised(monkeypatch, tmp_path):
    cert = tmp_path / "c.der"
    cert.write_bytes(b"CERT")
    state = install_fake_phone(monkeypatch, fail_sets=3)
    out = run_cmd(["live-configure", "--udid", "U", "--cert", str(cert)])
    assert out["supervised"] is True and out["host_cert_registered"] is True
    assert out["attempts"] == 4 and state["sets"] == 4
    assert state["cfg"]["AllowPairing"] is True


def test_live_configure_falls_back_to_no_certificate(monkeypatch, tmp_path):
    cert = tmp_path / "c.der"
    cert.write_bytes(b"CERT")
    clock = {"t": 0.0}
    monkeypatch.setattr(pax_device.time, "monotonic", lambda: clock.__setitem__("t", clock["t"] + 5) or clock["t"])
    state = install_fake_phone(monkeypatch, reject_cert=True)
    out = run_cmd(["live-configure", "--udid", "U", "--cert", str(cert), "--timeout", "90"])
    assert out["supervised"] is True and out["host_cert_registered"] is False
    assert "SupervisorHostCertificates" not in state["cfg"]


def test_live_configure_gives_up(monkeypatch):
    clock = {"t": 0.0}
    monkeypatch.setattr(pax_device.time, "monotonic", lambda: clock.__setitem__("t", clock["t"] + 10) or clock["t"])
    install_fake_phone(monkeypatch, fail_sets=10_000)
    with pytest.raises(pax_device.HelperError) as e:
        run_cmd(["live-configure", "--udid", "U", "--timeout", "30"])
    assert e.value.code == "live_not_taken"


def test_live_configure_refuses_ios28(monkeypatch):
    install_fake_phone(monkeypatch, version="28.0")
    with pytest.raises(pax_device.HelperError) as e:
        run_cmd(["live-configure", "--udid", "U"])
    assert e.value.code == "refused_too_new"


def test_seed_restore_refuses_ios28_before_touching_phone(monkeypatch):
    state = install_fake_phone(monkeypatch, version="28.1")
    monkeypatch.setattr(pax_device, "mobilebackup2_restore", fail_restore)
    with pytest.raises(pax_device.HelperError) as e:
        run_cmd(["seed-restore", "--udid", "U"])
    assert e.value.code == "refused_too_new" and state["sets"] == 0


async def fail_restore(*_a, **_k):
    pytest.fail("must not restore")


def test_seed_restore_live_runs_no_system_restore_with_override(monkeypatch, tmp_path):
    """PAX_IDEVICEBACKUP2 (developer override) still runs idevicebackup2 with the v0.8.5 flags."""
    install_fake_phone(monkeypatch, version="27.2")
    tool = tmp_path / "idevicebackup2"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PAX_IDEVICEBACKUP2", str(tool))
    monkeypatch.setattr(pax_device, "mobilebackup2_restore", fail_restore)
    calls = []

    class Proc:
        returncode = 0
        stdout = stderr = ""

    def fake_run(cmd, **kw):
        calls.append(cmd)
        seed_dir = Path(cmd[-1]) / "U"
        assert (seed_dir / "Manifest.mbdb").exists()  # seed exists while restoring
        return Proc()
    monkeypatch.setattr(pax_device.subprocess, "run", fake_run)
    out = run_cmd(["seed-restore", "--udid", "U"])
    assert out["mode"] == "live" and out["next"] == "reconnect_then_live_configure"
    assert calls[0][:7] == [str(tool), "-u", "U", "restore", "--skip-apps", "--remove", "--reboot"]
    assert "--system" not in calls[0]
    assert not Path(calls[0][-1]).exists()  # temp seed removed afterwards


def test_seed_restore_skips_already_supervised(monkeypatch):
    state = install_fake_phone(monkeypatch)
    state["cfg"] = {"IsSupervised": True}
    monkeypatch.setattr(pax_device, "mobilebackup2_restore", fail_restore)
    assert run_cmd(["seed-restore", "--udid", "U"])["already_supervised"] is True


def test_seed_restore_find_my_on(monkeypatch):
    install_fake_phone(monkeypatch)

    async def open_lockdown(_u):
        return FakeLockdown(fmip=True)
    monkeypatch.setattr(pax_device, "open_lockdown", open_lockdown)
    with pytest.raises(pax_device.HelperError) as e:
        run_cmd(["seed-restore", "--udid", "U"])
    assert e.value.code == "find_my_on"


def test_live_configure_accepts_already_supervised(monkeypatch):
    state = install_fake_phone(monkeypatch)
    state["cfg"] = {"IsSupervised": True}
    out = run_cmd(["live-configure", "--udid", "U"])
    assert out["supervised"] is True and state["sets"] == 0
