# SPDX-License-Identifier: GPL-3.0-only
"""The "Keep my data" set-up, step by step: a port of the Mac's SetupCoordinator
(mac-app/Sources/PaxCore/SetupCoordinator.swift) and the Keep-my-data parts of
SetupModel. The order is the safety:

  1. account + turn-off wait + trusted person on the server (nothing touches the phone)
  2. preflight (iOS version, Trust, Find My off, backup, battery) -> seed restore
     iOS 17-26: the phone restarts supervised;  iOS 27: it restarts into Setup and the
     live configuration is sent once it's back and trusted
  3. CONFIRM supervision by reading it back. Nothing below runs without it.
  4. profile + removal password (never shown)
  5. ESCROW FIRST: the device and its password go to the Pax server
  6. only then the locked profile is installed, and checked
  7. the supervision key is destroyed, whatever happened
If 6 fails after 5, the server holds an unused password; the reverse order could lock a
phone with nobody holding the password.

Every method is synchronous; the window runs them on a worker thread."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from . import choices as ch
from . import identity as idm
from . import profile_maker
from .account import AccountProvider, AccountResult
from .escrow import EscrowClient, dns_healthy
from .helper import HelperFailed

PROFILE_PREFIX = "org.paxpeace.pax.ios."


class SetupFailed(Exception):
    """A calm, classified failure. ``code`` is a PAX-* support code where one exists."""

    def __init__(self, code: str, message: str, technical: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.technical = technical


@dataclass
class Device:
    udid: str
    name: str
    product_type: str
    ios: Optional[str]
    paired: bool
    supervised: Optional[bool] = None

    @property
    def word(self) -> str:
        return ch.device_word(self.product_type)

    @staticmethod
    def from_helper(d: dict) -> "Device":
        return Device(udid=str(d["udid"]), name=str(d.get("name") or "iPhone"),
                      product_type=str(d.get("product_type") or "iPhone"), ios=d.get("ios"),
                      paired=bool(d.get("paired")), supervised=d.get("supervised"))


@dataclass
class Preflight:
    mode: Optional[str]
    ok: bool
    blocking: list[str]
    warnings: list[str]
    ask_user_find_my: bool
    battery: Optional[int] = None


@dataclass
class SessionLog:
    lines: list[str] = field(default_factory=list)

    def add(self, mark: str, text: str) -> None:
        self.lines.append(f"{mark} {text}")


class SetupSession:
    def __init__(self, runner: Any, escrow: EscrowClient, data_dir: Path,
                 dns_health: Callable[[str], bool] = dns_healthy,
                 sleep: Callable[[float], None] = time.sleep,
                 on_event: Optional[Callable[[dict], None]] = None):
        self.runner = runner
        self.escrow = escrow
        self.data_dir = Path(data_dir)
        self.dns_health = dns_health
        self.sleep = sleep
        self.on_event = on_event
        self.log = SessionLog()
        self.identity: Optional[idm.SupervisionIdentity] = None
        self.mode: Optional[str] = None
        self.backup_path: Optional[str] = None
        self.supervised = False
        self.escrowed_device_id: Optional[str] = None

    # --- helper ------------------------------------------------------------------
    def _helper(self, args: list[str], stdin: Optional[bytes] = None) -> dict:
        try:
            return self.runner.run(args, stdin=stdin, on_event=self.on_event)
        except HelperFailed as exc:
            self.log.add("\u2717", f"{args[0]}: {exc.code}")
            msg = for_pc(exc.message)
            raise SetupFailed(_support_code(exc.code, msg), msg, exc.code) from None

    # --- 1. find the phone, account ------------------------------------------------
    def find_devices(self) -> list[Device]:
        return [Device.from_helper(d) for d in self._helper(["list"]).get("devices", [])]

    def ensure_account(self, provider: AccountProvider, choices: ch.SetupChoices) -> AccountResult:
        """Account, then the turn-off wait and the trusted person (Mac: registerAccount).
        The person's own sites go on the synced list (best effort, as on the Mac)."""
        res = provider.ensure(self.escrow)
        if res.state != "ready":
            return res
        self.escrow.set_wait(choices.wait_days)
        if choices.partner_email:
            self.escrow.set_partner(choices.partner_email)
        for site in choices.blocked_sites:
            try:
                self.escrow.block_site(site)
            except Exception:  # noqa: BLE001
                pass
        self.log.add("\u2713", "Account ready")
        return res

    # --- 2. preflight, backup, seed restore ---------------------------------------
    def preflight(self, device: Device, choices: ch.SetupChoices) -> Preflight:
        args = ["preflight", "--udid", device.udid]
        if choices.find_my_confirmed_off:
            args.append("--find-my-confirmed-off")
        if self.backup_path or choices.backup_confirmed:
            args.append("--backup-confirmed")
        r = self._helper(args)
        return Preflight(mode=r.get("mode"), ok=bool(r.get("ok", True)) and not r.get("blocking"),
                         blocking=list(r.get("blocking") or []), warnings=list(r.get("warnings") or []),
                         ask_user_find_my=bool(r.get("ask_user_find_my")),
                         battery=(r.get("facts") or {}).get("battery_level"))

    def backup(self, device: Device) -> str:
        folder = self.data_dir / "Backups"
        folder.mkdir(parents=True, exist_ok=True)
        self.log.add("\u2026", "Backing up to this PC")
        r = self._helper(["backup", "--udid", device.udid, "--dir", str(folder)])
        self.backup_path = str(r.get("backup") or folder)
        self.log.add("\u2713", "Backup saved and checked")
        return self.backup_path

    def start(self, device: Device, pre: Preflight, choices: ch.SetupChoices) -> dict:
        """Creates the supervision identity and restores the seed (Mac: keepDataStart)."""
        if not pre.ok or not pre.mode:
            raise SetupFailed("PAX-IOS-011", (pre.blocking or ["Keep my data isn't available."])[0],
                              "; ".join(pre.blocking))
        if self.identity is None:
            self.identity = idm.create(self.data_dir / "identity")
        args = ["seed-restore", "--udid", device.udid, "--cert", str(self.identity.certificate)]
        if choices.forbid_pairing:
            args.append("--forbid-pairing")
        self.log.add("\u2026", "Restoring the supervision settings")
        r = self._helper(args)
        self.mode = r.get("mode") or pre.mode
        if r.get("already_supervised"):
            self.supervised = True
            self.log.add("\u2713", "Already supervised. Skipping to protection.")
        else:
            self.log.add("\u2713", "Settings restored. The phone is restarting.")
        return r

    def connect_once(self, device: Device) -> str:
        """One attempt (at most one Pair request): paired | trust_requested | locked |
        not_found | denied."""
        try:
            return str(self._helper(["connect", "--udid", device.udid]).get("state") or "not_found")
        except SetupFailed:
            return "not_found"

    @staticmethod
    def poll_again(state: str) -> bool:
        # Mac: PhoneConnectState.pollAgain. Never poll while Trust is showing: a Pair sent
        # while the passcode is typed cancels the dialog.
        return state in ("not_found", "locked")

    # --- 3. confirm supervision ---------------------------------------------------
    def confirm(self, device: Device, choices: ch.SetupChoices) -> dict:
        if self.identity is None:
            raise SetupFailed("PAX-IOS-011", "Start again: the set-up was interrupted.")
        cert = str(self.identity.certificate)
        if self.mode == "live":
            self.log.add("\u2026", "Supervising while the phone waits in Setup")
            args = ["live-configure", "--udid", device.udid, "--cert", cert]
            if choices.forbid_pairing:
                args.append("--forbid-pairing")
            self._helper(args)
        st = self._helper(["status", "--udid", device.udid, "--cert", cert])
        if not st.get("supervised"):
            raise SetupFailed("PAX-IOS-007", "The phone doesn't report itself as supervised, so Pax hasn't "
                              "stored a password or installed anything. Nothing is locked. Try again.")
        self.supervised = True
        self.log.add("\u2713", "Supervised")
        return st

    # --- 4-7. profile, escrow, install --------------------------------------------
    def lock_and_escrow(self, device: Device, choices: ch.SetupChoices) -> str:
        """Returns "installed" or "pending_user" (tap Install in Settings, then
        ``verify_installed``). The supervision key is destroyed on every path."""
        if self.identity is None:
            raise SetupFailed("PAX-IOS-011", "Start again: the set-up was interrupted.")
        ident = self.identity
        try:
            st = self._helper(["status", "--udid", device.udid, "--cert", str(ident.certificate)])
            if not st.get("supervised"):
                raise SetupFailed("PAX-IOS-007", "The phone isn't supervised any more. Nothing was locked.")
            self.log.add("\u2713", "Supervision confirmed")

            token = None
            if choices.dns_base:
                if not self.dns_health(choices.dns_base):
                    raise SetupFailed("PAX-DNS-012", "Pax's filter isn't answering right now, so Pax won't lock "
                                      "your phone to it. Nothing was changed. Try again in a few minutes.")
                self.escrow.set_dns_settings(choices.youtube_restricted)
                token = self.escrow.dns_info()["token"]
            prof = profile_maker.generate(user_token=token, dns_base=choices.dns_base,
                                          blocked_sites=choices.blocked_sites[:50],
                                          youtube_restricted=True if choices.dns_base else choices.youtube_restricted)

            self.log.add("\u2026", "Handing the removal password to Pax")
            dev = self.escrow.register_device(
                name=device.name, platform="ios", profile_identifier=prof.identifier,
                removal_password=prof.removal_password, support_release=choices.support_release,
                trial=choices.trial, hardware_id=ch.hardware_id(device.udid))
            self.escrowed_device_id = dev.get("device_id") or dev.get("id")
            self.log.add("\u2713", "Password escrowed")

            self.log.add("\u2026", "Installing protection")
            r = self._helper(["install-profile", "--udid", device.udid, "--cert", str(ident.certificate),
                              "--key", str(ident.private_key), "--allow-manual"], stdin=prof.data)
            prof = None  # noqa: F841  (drop the bytes holding the password)
            if r.get("pending_user"):
                return "pending_user"
            if not self.verify_installed(device):
                raise SetupFailed("PAX-PROFILE-003", "The Pax profile was sent but couldn't be found on the phone.")
            return "installed"
        finally:
            idm.destroy_private_key(ident)

    def verify_installed(self, device: Device) -> bool:
        ids = self._helper(["profiles", "--udid", device.udid]).get("identifiers") or []
        ok = any(str(i).startswith(PROFILE_PREFIX) for i in ids)
        if ok:
            self.log.add("\u2713", "Protection installed")
        return ok


def for_pc(message: str) -> str:
    """The shared helper was written for the Mac; say "PC" on Windows."""
    return (message or "").replace("This Mac", "This PC").replace("this Mac", "this PC")


def _support_code(helper_code: str, message: str = "") -> str:
    """Mac: PaxErrorClassifier for a HelperFailure (a PAX code in the message wins, then
    backup_incomplete, then the generic helper code)."""
    import re
    m = re.search(r"PAX-[A-Z]+-\d{3}", message or "")
    if m:
        return m.group(0)
    if helper_code.startswith("refused_"):
        return "PAX-IOS-006"
    return "PAX-IOS-009" if helper_code == "backup_incomplete" else "PAX-IOS-010"


def classify(exc: BaseException) -> tuple[str, str]:
    """(support code, calm message) for anything a step can raise."""
    from .escrow import EscrowError
    if isinstance(exc, SetupFailed):
        return exc.code, exc.message
    if isinstance(exc, EscrowError):
        if exc.status == 0:
            return "PAX-NET-001", exc.message
        try:
            from pax_errors import escrow_code  # common/pax_errors.py
            return escrow_code(exc.status, exc.code, exc.message), exc.message
        except ImportError:
            return "PAX-ESCROW-005", exc.message
    return "PAX-APP-000", "Something went wrong."
