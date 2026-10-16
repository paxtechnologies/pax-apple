# SPDX-License-Identifier: GPL-3.0-only
"""Tamper evidence (v0.8.0; recovery-lock/DESIGN.md §7.4).

pax-guard keeps an append-only, hash-chained log at
/Library/PaxGuard/state/tamper.jsonl (root 0600). Each line holds the SHA-256
of the line before it, so an edit or a deleted line breaks the chain (`verify`).
A determined root user can still rewrite the whole file: the point is that
whatever gets through is visible, not forensics.

Watched (baseline at install, re-checked every 10 minutes):
  admins            members of the admin group
  paxadmin          the Pax administrator still exists
  volume_owners     `diskutil apfs listUsers /` volume owners
  secure_token      `fdesetup list` (FileVault-enabled users)
  filevault         `fdesetup status`
  recovery_key      `fdesetup haspersonalrecoverykey` (+ hourly
                    `validaterecovery` against the escrowed key)
  mdm               `profiles status -type enrollment` (skipped on a managed
                    Mac or in test mode)
  startup_security  `bputil -d` (Apple silicon) policy digest
  firmware          `firmwarepasswd -check` (Intel)
  guard_files       SHA-256 of pax-guard's own files and launchd plist
Clock events (backwards / unexplained forward jumps) come from the escrow.

On a change: record it, show it in the app, never punish. The one signal that
blocks anything is the clock going backwards (it holds an early release).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

SNAPSHOT_INTERVAL = 600
VALIDATE_INTERVAL = 3600


class TamperLog:
    def __init__(self, path: Path, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        try:
            with open(self.path, "rb") as fh:
                lines = fh.read().splitlines()
            return json.loads(lines[-1])["hash"] if lines else "0" * 64
        except (OSError, ValueError, KeyError, IndexError):
            return "0" * 64

    def append(self, kind: str, detail) -> dict:
        with self._lock:
            entry = {"ts": int(self.clock()), "kind": kind, "detail": detail, "prev": self._last_hash()}
            body = json.dumps(entry, sort_keys=True)
            entry["hash"] = hashlib.sha256(body.encode()).hexdigest()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
            finally:
                os.close(fd)
            return entry

    def entries(self, limit: int = 50) -> list[dict]:
        try:
            lines = self.path.read_text().splitlines()
        except OSError:
            return []
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def verify(self) -> tuple[bool, int]:
        """(chain intact, number of entries)."""
        try:
            lines = self.path.read_text().splitlines()
        except OSError:
            return True, 0
        prev = "0" * 64
        for i, line in enumerate(lines):
            try:
                e = json.loads(line)
                h = e.pop("hash")
            except (ValueError, KeyError):
                return False, i
            if e.get("prev") != prev or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
                return False, i
            prev = h
        return True, len(lines)


# ---------------------------------------------------------------- parsing
def parse_admins(out: str) -> list[str]:
    if "GroupMembership:" not in out:
        return []
    return sorted(set(out.split("GroupMembership:", 1)[1].split()) - {"root"})


def parse_volume_owners(out: str) -> list[str]:
    """UUIDs of volume owners from `diskutil apfs listUsers /`."""
    owners, current = [], None
    for line in out.splitlines():
        s = line.strip().lstrip("+|-").strip()
        if len(s) == 36 and s.count("-") == 4:
            current = s
        elif s.lower().startswith("volume owner:") and current:
            if s.split(":", 1)[1].strip().lower().startswith("yes"):
                owners.append(current)
    return sorted(set(owners))


def parse_fdesetup_list(out: str) -> list[str]:
    return sorted(line.split(",", 1)[0].strip() for line in out.splitlines() if "," in line)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


class TamperWatch:
    def __init__(self, system, log: TamperLog, state, cfg, escrow=None, apple_silicon: bool | None = None,
                 guard_files: list[str] | None = None, logger=print, notify=lambda t: None):
        self.sys = system
        self.log = log
        self.state = state
        self.cfg = cfg
        self.escrow = escrow
        self.apple_silicon = apple_silicon
        self.guard_files = guard_files or []
        self.logger = logger
        self.notify = notify

    def _out(self, args: list[str], timeout: int = 20) -> str | None:
        code, out = self.sys.run(args, timeout=timeout)
        return out if code == 0 else None

    def snapshot(self, validate: bool = False, skip_mdm: bool = False) -> dict:
        snap: dict = {}
        out = self._out(["/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
        if out is not None:
            snap["admins"] = parse_admins(out)
        out = self._out(["/usr/bin/dscl", ".", "-read", "/Users/paxadmin", "UniqueID"])
        snap["paxadmin"] = "present" if out is not None else "missing"
        out = self._out(["/usr/sbin/diskutil", "apfs", "listUsers", "/"])
        if out is not None:
            snap["volume_owners"] = parse_volume_owners(out)
        out = self._out(["/usr/bin/fdesetup", "list"])
        if out is not None:
            snap["secure_token"] = parse_fdesetup_list(out)
        out = self._out(["/usr/bin/fdesetup", "status"])
        if out is not None:
            snap["filevault"] = "on" if "FileVault is On" in out else "off"
        out = self._out(["/usr/bin/fdesetup", "haspersonalrecoverykey"])
        if out is not None:
            snap["recovery_key"] = "present" if out.strip().lower().endswith("true") else "none"
        if validate and self.escrow is not None and snap.get("recovery_key") == "present":
            key = None
            try:
                key = self.escrow.secret_for_guard("recovery_key")
            except Exception:  # noqa: BLE001
                key = None
            if key:
                from recovery_guard import recovery_plist
                code, o, _e = self.sys.run_split(["/usr/bin/fdesetup", "validaterecovery", "-inputplist"],
                                                 stdin=recovery_plist(key), timeout=60)
                snap["recovery_key_matches_escrow"] = bool(code == 0 and o.strip().lower().endswith("true"))
        if not skip_mdm:
            out = self._out(["/usr/bin/profiles", "status", "-type", "enrollment"])
            if out is not None:
                snap["mdm"] = digest(" ".join(out.split()))
        if self.apple_silicon:
            out = self._out(["/usr/bin/bputil", "-d"], timeout=30)
            if out is not None:
                pol = [l.strip() for l in out.splitlines() if ":" in l and "Nonce" not in l and "Hash" not in l]
                snap["startup_security"] = digest("\n".join(pol))
        elif self.apple_silicon is False:
            out = self._out(["/usr/sbin/firmwarepasswd", "-check"])
            if out is not None:
                snap["firmware"] = "on" if "Password Enabled: Yes" in out else "off"
        h = hashlib.sha256()
        for f in self.guard_files:
            h.update(self.sys.read(f).encode())
        if self.guard_files:
            snap["guard_files"] = h.hexdigest()[:16]
        return snap

    def check(self, now: int, skip_mdm: bool = False, force: bool = False) -> list[dict]:
        meta = self.state["load"]("tamper-meta.json", {})
        if not force and now - int(meta.get("snap_at", 0)) < SNAPSHOT_INTERVAL:
            return []
        validate = force or now - int(meta.get("validate_at", 0)) >= VALIDATE_INTERVAL
        snap = self.snapshot(validate=validate, skip_mdm=skip_mdm)
        base = self.state["load"]("tamper-baseline.json", None)
        events = []
        if base is None:
            events.append(self.log.append("baseline", snap))
            base = {}
        else:
            for k, v in snap.items():
                if k in base and base[k] != v:
                    events.append(self.log.append(f"changed:{k}", {"from": base[k], "to": v}))
        base.update(snap)
        self.state["save"]("tamper-baseline.json", base)
        meta["snap_at"] = now
        if validate:
            meta["validate_at"] = now
        self.state["save"]("tamper-meta.json", meta)
        for e in events:
            if e["kind"] != "baseline":
                self.logger(f"PAX-GUARD-011 tamper: {e['kind']}")
        if any(e["kind"] != "baseline" for e in events):
            self.notify("Pax noticed a change to this Mac's security settings. Open Pax to see it.")
        return events

    def rebaseline(self, keys: list[str]) -> None:
        """After Pax itself changes something (e.g. rotating the key)."""
        base = self.state["load"]("tamper-baseline.json", {}) or {}
        for k in keys:
            base.pop(k, None)
        self.state["save"]("tamper-baseline.json", base)
