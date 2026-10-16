# SPDX-License-Identifier: GPL-3.0-only
"""Closing the cheap Recovery-mode holes (v0.8.0; recovery-lock/DESIGN.md §7).

  * FileVault personal recovery key (PRK): pax-guard rotates it to a key the
    user has never seen and escrows the new key behind the same wait
    (§7.1). `fdesetup changerecovery -personal -user paxadmin -inputplist
    -outputplist`; the new key is read from stdout (never written to a file),
    stored in the escrow *before* anything else, then checked with
    `fdesetup validaterecovery`. Exit 38 is a failure (fdesetup refused; the old
    key stays valid). A rotation that printed a key but didn't validate keeps
    that key escrowed and raises an alarm: Pax never discards a key.
  * Intel Macs only: a firmware password (§7.3) set through a terminal session
    (firmwarepasswd has no non-interactive flag), mode `command` (asks only
    when starting from another disk; never `full`), escrowed first, then
    checked with `-verify`. Apple silicon has no firmware password: skipped.
    `-disable-reset-capability` is never used.
  * Existing MDM (§6): `profiles status -type enrollment`. On a Mac another
    organisation manages, or with the testing switch
    pax.testing.allowExtraAdmins, Pax does nothing MDM-related and leaves the
    recovery key and firmware alone (an organisation may escrow them itself;
    a rented Mac belongs to its provider).

Not done, on purpose: local MDM / Recovery Lock (needs real-Mac tests T1-T3
first), and removing the user's secure token (§7.2: can make a Mac unbootable).
"""
from __future__ import annotations

import os
import plistlib
import pty
import re
import secrets
import select
import string
import subprocess
import time

FDESETUP = "/usr/bin/fdesetup"
FIRMWAREPASSWD = "/usr/sbin/firmwarepasswd"
PROFILES = "/usr/bin/profiles"
EXIT_FDESETUP_PREFLIGHT = 38


def creds_plist(user: str, password: str) -> str:
    return plistlib.dumps({"Username": user, "Password": password}, fmt=plistlib.FMT_XML).decode()


def recovery_plist(key: str) -> str:
    return plistlib.dumps({"Password": key}, fmt=plistlib.FMT_XML).decode()


def parse_recovery_key(stdout: str) -> str | None:
    """The new key from -outputplist on stdout (a plist; tolerate leading noise)."""
    start = stdout.find("<?xml")
    if start < 0:
        start = stdout.find("<plist")
    if start < 0:
        return None
    try:
        data = plistlib.loads(stdout[start:].encode())
    except Exception:  # noqa: BLE001
        return None
    key = data.get("RecoveryKey") if isinstance(data, dict) else None
    if isinstance(key, str) and re.fullmatch(r"[A-Z0-9]{4}(-[A-Z0-9]{4}){5}", key.strip()):
        return key.strip()
    return None


def parse_enrollment(output: str) -> dict:
    """`profiles status -type enrollment` ->
    {"enrolled": bool, "dep": bool, "user_approved": bool, "known": bool}."""
    out = {"enrolled": False, "dep": False, "user_approved": False, "known": False}
    for line in output.splitlines():
        low = line.strip().lower()
        if low.startswith("enrolled via dep:"):
            out["known"] = True
            out["dep"] = low.split(":", 1)[1].strip().startswith("yes")
        elif low.startswith("mdm enrollment:"):
            out["known"] = True
            val = low.split(":", 1)[1].strip()
            out["enrolled"] = val.startswith("yes")
            out["user_approved"] = "user approved" in val
    out["enrolled"] = out["enrolled"] or out["dep"]
    return out


def is_apple_silicon(run) -> bool:
    code, out = run(["/usr/sbin/sysctl", "-n", "hw.optional.arm64"])
    if code == 0 and out.strip() == "1":
        return True
    code, out = run(["/usr/bin/uname", "-m"])
    return code == 0 and out.strip() == "arm64"


def generate_firmware_password(length: int = 16) -> str:
    # Letters and digits only: firmware prompts are keyboard-layout sensitive,
    # and l/1/O/0 are left out so it can be read off a screen.
    alphabet = "".join(c for c in string.ascii_letters + string.digits if c not in "lI1O0o")
    return "".join(secrets.choice(alphabet) for _ in range(length))


def run_pty(args: list[str], secret: str, timeout: float = 30.0,
            prompt=re.compile(rb"password[^\n:]*:\s*$", re.I)) -> tuple[int, str]:
    """Run an interactive tool in a pseudo-terminal, typing `secret` at every
    password prompt. Returns (exit code, output with the secret removed)."""
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                                start_new_session=True)
    except OSError as exc:
        os.close(master)
        os.close(slave)
        return 127, str(exc)
    os.close(slave)
    buf = b""
    pending = b""
    deadline = time.monotonic() + timeout
    try:
        while True:
            if time.monotonic() > deadline:
                proc.kill()
                return 124, (buf.decode("utf-8", "replace") + "\n[timed out]").replace(secret, "•••")
            r, _, _ = select.select([master], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    if proc.poll() is not None:
                        break
                    continue
                buf += chunk
                pending += chunk
                if prompt.search(pending):
                    os.write(master, secret.encode() + b"\n")
                    pending = b""
            elif proc.poll() is not None:
                break
        code = proc.wait(timeout=5)
    finally:
        os.close(master)
    return code, buf.decode("utf-8", "replace").replace(secret, "•••")


class RecoveryGuard:
    """Runs from the guard cycle. `sys` is pax_guard.System (or a fake); `escrow`
    is LocalEscrow; `tamper(kind, detail)` records an event."""

    def __init__(self, system, escrow, cfg, state, log=print, tamper=lambda k, d: None, pty_runner=run_pty):
        self.sys = system
        self.escrow = escrow
        self.cfg = cfg
        self.state = state            # {"load": fn(name, default), "save": fn(name, value)}
        self.log = log
        self.tamper = tamper
        self.run_pty = pty_runner

    # -------------------------------------------------------------- MDM
    def enrollment(self) -> dict:
        code, out = self.sys.run([PROFILES, "status", "-type", "enrollment"], timeout=20)
        info = parse_enrollment(out) if code == 0 else {"enrolled": False, "known": False}
        return info

    def mdm_skip_reason(self) -> str | None:
        """Why Pax must leave MDM-related things (and the recovery key/firmware)
        alone, or None."""
        if getattr(self.cfg, "testing_allow_extra_admins", False):
            return "test mode (pax.testing.allowExtraAdmins)"
        if getattr(self.cfg, "mdm_managed", False):
            return "this Mac is managed by an organisation"
        info = self.enrollment()
        if info.get("enrolled"):
            return "this Mac is managed by an organisation"
        return None

    # -------------------------------------------------------------- PRK
    def filevault_on(self) -> bool:
        code, out = self.sys.run([FDESETUP, "status"], timeout=20)
        return code == 0 and "FileVault is On" in out

    def validate_key(self, key: str) -> bool:
        code, out, _err = self.sys.run_split([FDESETUP, "validaterecovery", "-inputplist"],
                                             stdin=recovery_plist(key), timeout=60)
        return code == 0 and out.strip().lower().endswith("true")

    def rotate_recovery_key(self) -> dict:
        """One rotation attempt. Returns {"ok": bool, "code": str|None, ...}."""
        if not getattr(self.cfg, "rotate_recovery_key", True):
            return {"ok": False, "skipped": "turned off at set-up (you keep your own key)"}
        why = self.mdm_skip_reason()
        if why:
            return {"ok": False, "skipped": why}
        if not self.filevault_on():
            return {"ok": False, "skipped": "FileVault is off"}
        password = self.escrow.secret_for_guard("paxadmin")
        if not password:
            return {"ok": False, "code": "PAX-MAC-012", "why": "no paxadmin password in escrow"}
        code, out, err = self.sys.run_split(
            [FDESETUP, "changerecovery", "-personal", "-user", "paxadmin", "-inputplist", "-outputplist"],
            stdin=creds_plist("paxadmin", password), timeout=120)
        key = parse_recovery_key(out)
        if key:
            # Escrow first, whatever happens next: a printed key is never lost.
            self.escrow.deposit("recovery_key", key, replace=True)
        if code == EXIT_FDESETUP_PREFLIGHT:
            self.log("PAX-MAC-012 fdesetup refused to rotate the recovery key (exit 38); the old key stays valid")
            return {"ok": False, "code": "PAX-MAC-012", "why": "fdesetup exit 38", "key_escrowed": bool(key)}
        if code != 0 or not key:
            self.log(f"PAX-MAC-012 recovery key rotation failed (exit {code}): {err.strip()[-160:]}")
            if key:
                self.tamper("recovery_key_unverified", {"exit": code})
            return {"ok": False, "code": "PAX-MAC-012", "why": f"exit {code}", "key_escrowed": bool(key)}
        if not self.validate_key(key):
            self.log("PAX-MAC-013 the rotated recovery key did not validate; it is kept in escrow")
            self.tamper("recovery_key_unverified", {"validated": False})
            return {"ok": False, "code": "PAX-MAC-013", "key_escrowed": True}
        self.log("FileVault recovery key rotated and escrowed behind your wait")
        return {"ok": True, "key_escrowed": True}

    # --------------------------------------------------------- firmware
    def firmware_status(self) -> str:
        code, out = self.sys.run([FIRMWAREPASSWD, "-check"], timeout=20)
        if code != 0:
            return "unknown"
        return "on" if "Password Enabled: Yes" in out else ("off" if "Password Enabled: No" in out else "unknown")

    def set_firmware_password(self) -> dict:
        if not getattr(self.cfg, "firmware_password", True):
            return {"ok": False, "skipped": "turned off at set-up"}
        if is_apple_silicon(self.sys.run):
            return {"ok": False, "skipped": "Apple silicon has no firmware password"}
        why = self.mdm_skip_reason()
        if why:
            return {"ok": False, "skipped": why}
        status = self.firmware_status()
        if status != "off":
            # Already set (by someone else) or unknown: never overwrite.
            return {"ok": False, "skipped": f"firmware password is {status}"}
        pw = generate_firmware_password()
        self.escrow.deposit("firmware", pw, replace=True)          # escrow first
        code, out = self.run_pty([FIRMWAREPASSWD, "-setpasswd"], pw)
        if code != 0:
            if self.firmware_status() == "off":
                self.escrow.forget("firmware")
            self.log(f"PAX-MAC-014 setting the firmware password failed (exit {code})")
            return {"ok": False, "code": "PAX-MAC-014"}
        mcode, _ = self.run_pty([FIRMWAREPASSWD, "-setmode", "command"], pw)
        vcode, vout = self.run_pty([FIRMWAREPASSWD, "-verify"], pw)
        if vcode != 0 or "correct" not in vout.lower() or "incorrect" in vout.lower():
            self.log("PAX-MAC-014 the firmware password did not verify; it is kept in escrow")
            self.tamper("firmware_unverified", {"setmode_exit": mcode})
            return {"ok": False, "code": "PAX-MAC-014", "escrowed": True}
        self.log("Firmware password set (mode: command) and escrowed behind your wait")
        return {"ok": True, "mode_exit": mcode}

    def delete_firmware_password(self) -> bool:
        """At removal (after the wait), with the escrowed password."""
        pw = self.escrow.secret_for_guard("firmware")
        if not pw or self.firmware_status() != "on":
            return False
        code, _ = self.run_pty([FIRMWAREPASSWD, "-delete"], pw)
        return code == 0

    # -------------------------------------------------------------- cycle
    def maybe_run(self, now: int) -> dict:
        """Once, retrying with backoff (1 h, then 6 h). Records the outcome."""
        st = self.state["load"]("recovery.json", {})
        done = {}
        for task, fn in (("recovery_key", self.rotate_recovery_key), ("firmware", self.set_firmware_password)):
            t = st.get(task, {})
            if t.get("ok") or t.get("skipped_permanent"):
                continue
            if now < int(t.get("next_at", 0)):
                continue
            try:
                res = fn()
            except Exception as exc:  # noqa: BLE001
                res = {"ok": False, "code": "PAX-MAC-012" if task == "recovery_key" else "PAX-MAC-014",
                       "why": type(exc).__name__}
            tries = int(t.get("tries", 0)) + 1
            res["tries"] = tries
            res["at"] = now
            if not res.get("ok"):
                if res.get("skipped") and "Apple silicon" in res["skipped"]:
                    res["skipped_permanent"] = True
                res["next_at"] = now + (3600 if tries < 3 else 6 * 3600)
            st[task] = res
            done[task] = res
        if done:
            self.state["save"]("recovery.json", st)
        return done
