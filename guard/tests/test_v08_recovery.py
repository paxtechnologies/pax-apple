# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0 Recovery-mode cheap wins (recovery-lock/DESIGN.md): FileVault recovery
key rotation + escrow (exit 38 = failure, validate before success, never lose a
printed key), the Intel firmware password through a terminal session, the
existing-MDM check and test-mode skip, the hash-chained tamper log and watch,
and Ed25519 against RFC 8032."""
import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ed25519  # noqa: E402
import local_escrow as le  # noqa: E402
import recovery_guard as rg  # noqa: E402
import tamper as tp  # noqa: E402

KEY = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"
KEY_PLIST = textwrap.dedent(f"""\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict><key>Change</key><true/><key>RecoveryKey</key><string>{KEY}</string></dict></plist>
    """)


class Cfg:
    rotate_recovery_key = True
    firmware_password = True
    mdm_managed = False
    testing_allow_extra_admins = False


class FakeSys:
    def __init__(self, fv="FileVault is On.", rotate_exit=0, rotate_out=KEY_PLIST, validate="true",
                 enrollment="Enrolled via DEP: No\nMDM enrollment: No\n", arm64=True, fw_check="Password Enabled: No"):
        self.fv, self.rotate_exit, self.rotate_out, self.validate = fv, rotate_exit, rotate_out, validate
        self.enrollment, self.arm64, self.fw_check = enrollment, arm64, fw_check
        self.calls = []
        self.stdin = []

    def run(self, args, stdin=None, timeout=30):
        self.calls.append(args)
        if args[:2] == ["/usr/bin/fdesetup", "status"]:
            return 0, self.fv
        if args[:2] == ["/usr/bin/profiles", "status"]:
            return 0, self.enrollment
        if args[:3] == ["/usr/sbin/sysctl", "-n", "hw.optional.arm64"]:
            return 0, "1" if self.arm64 else "0"
        if args[:2] == ["/usr/bin/uname", "-m"]:
            return 0, "arm64" if self.arm64 else "x86_64"
        if args[:2] == ["/usr/sbin/firmwarepasswd", "-check"]:
            return 0, self.fw_check
        return 0, ""

    def run_split(self, args, stdin=None, timeout=30):
        self.calls.append(args)
        self.stdin.append(stdin)
        if "changerecovery" in args:
            return self.rotate_exit, self.rotate_out, "" if self.rotate_exit == 0 else "error"
        if "validaterecovery" in args:
            return 0, self.validate + "\n", ""
        return 0, "", ""


def escrow(tmp_path):
    e = le.LocalEscrow(tmp_path / "escrow", require_root=False, boot_time=lambda: 1)
    e.deposit("paxadmin", "paxadmin-pw", wait_seconds=72 * 3600)
    return e


def guard(tmp_path, sysm, cfg=None, pty=None, events=None):
    state = {}
    st = {"load": lambda n, d: state.get(n, d), "save": lambda n, v: state.__setitem__(n, v)}
    ev = events if events is not None else []
    return rg.RecoveryGuard(sysm, escrow(tmp_path), cfg or Cfg(), st, log=lambda m: None,
                            tamper=lambda k, d: ev.append(k), pty_runner=pty or (lambda a, s: (0, "Correct"))), state


# ------------------------------------------------------------------- PRK
def test_rotation_escrows_key_after_validation(tmp_path):
    s = FakeSys()
    g, _ = guard(tmp_path, s)
    res = g.rotate_recovery_key()
    assert res["ok"]
    assert g.escrow.secret_for_guard("recovery_key") == KEY
    rotate = next(c for c in s.calls if "changerecovery" in c)
    assert rotate == ["/usr/bin/fdesetup", "changerecovery", "-personal", "-user", "paxadmin",
                      "-inputplist", "-outputplist"]
    assert "paxadmin-pw" in s.stdin[0] and "<key>Username</key>" in s.stdin[0]   # creds on stdin only
    assert KEY in s.stdin[1]                                                     # validaterecovery
    assert not any("paxadmin-pw" in " ".join(c) for c in s.calls)                 # never in argv


def test_exit_38_is_failure_and_old_key_kept(tmp_path):
    s = FakeSys(rotate_exit=38, rotate_out="")
    g, _ = guard(tmp_path, s)
    res = g.rotate_recovery_key()
    assert not res["ok"] and res["code"] == "PAX-MAC-012" and "38" in res["why"]
    assert g.escrow.secret_for_guard("recovery_key") is None


def test_printed_key_is_never_lost_even_if_validation_fails(tmp_path):
    ev = []
    s = FakeSys(validate="false")
    g, _ = guard(tmp_path, s, events=ev)
    res = g.rotate_recovery_key()
    assert not res["ok"] and res["code"] == "PAX-MAC-013"
    assert g.escrow.secret_for_guard("recovery_key") == KEY and "recovery_key_unverified" in ev
    s2 = FakeSys(rotate_exit=1)                  # failed exit but a key was printed
    g2, _ = guard(tmp_path / "b", s2)
    assert not g2.rotate_recovery_key()["ok"]
    assert g2.escrow.secret_for_guard("recovery_key") == KEY


def test_skips_filevault_off_managed_and_test_mode(tmp_path):
    g, _ = guard(tmp_path / "a", FakeSys(fv="FileVault is Off."))
    assert g.rotate_recovery_key()["skipped"] == "FileVault is off"
    g, _ = guard(tmp_path / "b", FakeSys(enrollment="Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\n"))
    assert "organisation" in g.rotate_recovery_key()["skipped"]
    c = Cfg()
    c.testing_allow_extra_admins = True
    g, _ = guard(tmp_path / "c", FakeSys(), cfg=c)
    assert "test mode" in g.rotate_recovery_key()["skipped"]
    c2 = Cfg()
    c2.rotate_recovery_key = False
    g, _ = guard(tmp_path / "d", FakeSys(), cfg=c2)
    assert "own key" in g.rotate_recovery_key()["skipped"]


def test_parse_enrollment_and_key():
    assert rg.parse_enrollment("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)")["dep"]
    assert rg.parse_enrollment("Enrolled via DEP: No\nMDM enrollment: No")["enrolled"] is False
    assert rg.parse_enrollment("MDM enrollment: Yes (User Approved)")["user_approved"]
    assert rg.parse_recovery_key("noise\n" + KEY_PLIST) == KEY
    assert rg.parse_recovery_key("<plist><dict><key>RecoveryKey</key><string>short</string></dict></plist>") is None


def test_maybe_run_backoff_and_apple_silicon_skip(tmp_path):
    s = FakeSys(rotate_exit=38, rotate_out="")
    g, state = guard(tmp_path, s)
    done = g.maybe_run(1000)
    assert not done["recovery_key"]["ok"] and done["recovery_key"]["next_at"] == 1000 + 3600
    assert done["firmware"]["skipped_permanent"]                  # arm64
    assert g.maybe_run(1500) == {}                                # backing off
    s.rotate_exit, s.rotate_out = 0, KEY_PLIST
    assert g.maybe_run(1000 + 3600)["recovery_key"]["ok"]
    assert g.maybe_run(99999) == {}


# -------------------------------------------------------------- firmware
def test_firmware_password_intel_only_escrowed_first(tmp_path):
    seen = []

    def pty(args, secret):
        seen.append((args, secret))
        # the password must already be escrowed when firmwarepasswd first runs
        assert g.escrow.secret_for_guard("firmware") == secret
        return 0, "Correct" if "-verify" in args else ""
    s = FakeSys(arm64=False)
    g, _ = guard(tmp_path, s, pty=pty)
    res = g.set_firmware_password()
    assert res["ok"]
    assert [a[0][1:] for a in seen] == [["-setpasswd"], ["-setmode", "command"], ["-verify"]]
    pw = seen[0][1]
    assert len(pw) == 16 and pw.isalnum()
    assert not any("full" in a[0] for a in seen)                  # never "full" mode
    g2, _ = guard(tmp_path / "as", FakeSys(arm64=True))
    assert "Apple silicon" in g2.set_firmware_password()["skipped"]
    g3, _ = guard(tmp_path / "set", FakeSys(arm64=False, fw_check="Password Enabled: Yes"))
    assert "on" in g3.set_firmware_password()["skipped"]          # never overwrite


def test_firmware_failure_forgets_unused_password(tmp_path):
    g, _ = guard(tmp_path, FakeSys(arm64=False), pty=lambda a, s: (1, "error"))
    assert g.set_firmware_password()["code"] == "PAX-MAC-014"
    assert g.escrow.secret_for_guard("firmware") is None


def test_run_pty_types_secret_at_prompts_and_hides_it(tmp_path):
    script = tmp_path / "fake_firmwarepasswd.py"
    script.write_text(textwrap.dedent("""\
        import getpass, sys
        a = getpass.getpass("Enter new password:")
        b = getpass.getpass("Re-enter new password:")
        print("Password changed" if a == b == "s3cretFW" else "mismatch")
        sys.exit(0 if a == b == "s3cretFW" else 1)
        """))
    code, out = rg.run_pty([sys.executable, str(script)], "s3cretFW", timeout=20)
    assert code == 0 and "Password changed" in out and "s3cretFW" not in out


# ----------------------------------------------------------------- tamper
def test_tamper_log_is_hash_chained(tmp_path):
    log = tp.TamperLog(tmp_path / "t.jsonl", clock=lambda: 1)
    log.append("baseline", {"a": 1})
    log.append("changed:admins", {"from": ["alex"], "to": ["alex", "eve"]})
    assert log.verify() == (True, 2)
    lines = (tmp_path / "t.jsonl").read_text().splitlines()
    doc = json.loads(lines[0])
    doc["detail"] = {"a": 2}
    lines[0] = json.dumps(doc, sort_keys=True)
    (tmp_path / "t.jsonl").write_text("\n".join(lines) + "\n")
    assert log.verify()[0] is False
    assert oct(os.stat(tmp_path / "t.jsonl").st_mode & 0o777) == "0o600"


class WatchSys:
    def __init__(self):
        self.out = {
            "admin": "GroupMembership: root paxadmin",
            "listUsers": "+-- 1111-2222\n+-- 11111111-2222-3333-4444-555555555555\n|   Volume Owner: Yes\n"
                         "+-- AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\n|   Volume Owner: No\n",
            "list": "alex,1234\npaxadmin,5678\n",
            "status": "FileVault is On.",
            "haspersonalrecoverykey": "true",
            "enrollment": "Enrolled via DEP: No\nMDM enrollment: No",
            "bputil": "Security Mode: Full Security\nNonce: 123\n",
        }
        self.files = {}

    def run(self, args, stdin=None, timeout=30):
        key = {"/Groups/admin": "admin", "listUsers": "listUsers", "list": "list", "status": "status",
               "haspersonalrecoverykey": "haspersonalrecoverykey", "enrollment": "enrollment", "-d": "bputil"}
        for k, v in key.items():
            if k in args:
                if v == "status" and "profiles" in args[0]:
                    continue
                return 0, self.out[v]
        return 0, ""

    def run_split(self, args, stdin=None, timeout=30):
        return 0, "true", ""

    def read(self, path):
        return self.files.get(path, "")


def test_tamper_watch_records_changes_once(tmp_path):
    s = WatchSys()
    state = {}
    st = {"load": lambda n, d: state.get(n, d), "save": lambda n, v: state.__setitem__(n, v)}
    log = tp.TamperLog(tmp_path / "t.jsonl")
    notes = []
    w = tp.TamperWatch(s, log, st, Cfg(), apple_silicon=True, guard_files=["/g.py"], logger=lambda m: None,
                       notify=notes.append)
    ev = w.check(1000)
    assert [e["kind"] for e in ev] == ["baseline"]
    base = state["tamper-baseline.json"]
    assert base["admins"] == ["paxadmin"] and base["volume_owners"] == ["11111111-2222-3333-4444-555555555555"]
    assert w.check(1100) == []                      # within 10 minutes: not re-checked
    s.out["admin"] = "GroupMembership: root paxadmin alex"
    s.out["status"] = "FileVault is Off."
    s.out["bputil"] = "Security Mode: Reduced Security\n"
    s.files["/g.py"] = "edited"
    kinds = sorted(e["kind"] for e in w.check(1000 + 601))
    assert kinds == ["changed:admins", "changed:filevault", "changed:guard_files", "changed:startup_security"]
    assert notes and w.check(1000 + 1300) == []      # each change logged once
    w.check(5000, skip_mdm=True, force=True)


def test_parsers():
    assert tp.parse_admins("GroupMembership: root alex paxadmin") == ["alex", "paxadmin"]
    assert tp.parse_fdesetup_list("alex,ABC\npaxadmin,DEF\n") == ["alex", "paxadmin"]


# ---------------------------------------------------------------- ed25519
@pytest.mark.parametrize("sk,pk,msg,sig", [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
])
def test_ed25519_rfc8032_vectors(sk, pk, msg, sig):
    sk, pk, msg, sig = bytes.fromhex(sk), bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
    assert ed25519.public_key(sk) == pk
    assert ed25519.sign(sk, msg) == sig
    assert ed25519.verify(pk, msg, sig)
    assert not ed25519.verify(pk, msg + b"x", sig)
    bad = bytearray(sig)
    bad[10] ^= 1
    assert not ed25519.verify(pk, msg, bytes(bad))
    # non-canonical S (S + L) is refused
    s = int.from_bytes(sig[32:], "little") + ed25519.L
    assert not ed25519.verify(pk, msg, sig[:32] + s.to_bytes(32, "little"))
    assert not ed25519.verify(pk[:31], msg, sig) and not ed25519.verify(pk, msg, sig[:63])
