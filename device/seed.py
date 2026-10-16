# SPDX-License-Identifier: GPL-3.0-only
"""Pure logic for Pax "Keep my data" supervision. Nothing in this module talks
to an iPhone, so all of it is unit-tested (see tests/test_seed.py).

What it decides and builds:

* which method a given iOS version gets (``plan_for_version``):
    17-26  -> "restored": restore a tiny backup holding CloudConfigurationDetails.plist
              with system files (RestoreSystemFiles = true), then restart.
    27.x   -> "live":     restore the same tiny backup WITHOUT system files
              (skip apps, remove, reboot), then, while the phone sits in
              Setup Assistant, send SetCloudConfiguration over MCInstall.
    <17, >=28, unreadable -> refused; the app falls back to Clean mode.
* the cloud configuration dictionary Pax sends (``plan_cloud_configuration``)
* the tiny MobileBackup2 "seed" backup folder (``write_seed``)
* the MobileBackup2 Restore options for each method (``restore_options``), sent by
  pymobiledevice3's Mobilebackup2 implementation in the bundled helper (v0.8.6), and
  the equivalent idevicebackup2 arguments (``restore_arguments``) for the optional
  PAX_IDEVICEBACKUP2 override
* the preflight verdict (``evaluate_preflight``)

Method credit: the iOS 27 sequence (no-system restore + live SetCloudConfiguration
during Setup) was documented by attention awareness
(https://attentionawareness.com/blog/supervise-iphone-ios-27-without-erasing) and
tested there on one iPhone SE (2nd gen) running iOS 27.2. Pax re-implements the
method from that description; it does not contain attention awareness code (their
Mac app is AGPL-3.0-only). See THIRD_PARTY_NOTICES.md.

The Manifest.mbdb writer and the backup scaffold values (Status.plist,
Manifest.plist and its BackupKeyBag) are ported from TrollRestore
(https://github.com/JJTech0130/TrollRestore, sparserestore/mbdb.py and backup.py,
commit 082f2520556b9aa8e2b8d6661b81a954ee35966b), MIT licence,
Copyright 2024 James Gill (JJTech0130). See THIRD_PARTY_NOTICES.md.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
import plistlib
import secrets
import uuid
from base64 import b64decode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# --------------------------------------------------------------------------
# Version gate
# --------------------------------------------------------------------------

OLDEST_SUPPORTED_MAJOR = 17
NEWEST_SUPPORTED_MAJOR = 27
FIRST_LIVE_MAJOR = 27  # iOS 27: backups no longer carry supervision status

MODE_RESTORED = "restored"
MODE_LIVE = "live"


@dataclass(frozen=True)
class VersionPlan:
    mode: Optional[str]  # MODE_RESTORED, MODE_LIVE or None (refused)
    major: Optional[int]
    refusal: Optional[str] = None  # "too_old" | "too_new" | "unknown"
    message: str = ""

    @property
    def allowed(self) -> bool:
        return self.mode is not None


def major_version(version: Optional[str]) -> Optional[int]:
    """First number of an iOS version string; None for anything that does not read
    cleanly (never guess an older version)."""
    if not version or not isinstance(version, str):
        return None
    parts = version.strip().split(".")
    if not all(p.isdigit() and p.isascii() for p in parts):
        return None
    major = int(parts[0])
    return major if major > 0 else None


def plan_for_version(version: Optional[str]) -> VersionPlan:
    major = major_version(version)
    if major is None:
        return VersionPlan(None, None, "unknown",
                           "Pax couldn't read this iPhone's iOS version, so Keep my data is off. "
                           "Use Clean set-up.")
    if major < OLDEST_SUPPORTED_MAJOR:
        return VersionPlan(None, major, "too_old",
                           f"Keep my data needs iOS {OLDEST_SUPPORTED_MAJOR} or later. "
                           "Update the iPhone or use Clean set-up.")
    if major > NEWEST_SUPPORTED_MAJOR:
        return VersionPlan(None, major, "too_new",
                           f"Keep my data hasn't been tested on iOS {major}. Apple may have changed "
                           "how supervision is restored, so Pax won't risk your data. Use Clean set-up.")
    mode = MODE_LIVE if major >= FIRST_LIVE_MAJOR else MODE_RESTORED
    return VersionPlan(mode, major)


# --------------------------------------------------------------------------
# Cloud configuration
# --------------------------------------------------------------------------

# Setup Assistant panes to skip: iPhone-relevant keys from Apple's device-management
# schema (other/skipkeys.yaml, MIT, vendored in profile/apple-schema/; a test checks
# every key is listed there). Skipping only affects panes the phone would otherwise show; on iOS 27
# the "Restore Completed" screen still appears in some runs (see README).
SKIP_SETUP_PANES = [
    "Accessibility", "AccessibilityAppearance", "ActionButton", "AppleID", "Appearance", "AppStore", "Biometric",
    "CameraButton", "DeviceFeaturesTour", "DeviceToDeviceMigration", "Diagnostics", "DisplayTone",
    "EnableLockdownMode", "HomeButtonSensitivity", "iCloudDiagnostics", "iCloudStorage",
    "iMessageAndFaceTime", "Intelligence", "Keyboard", "LiquidGlass", "Location", "MessagingActivationUsingPhoneNumber", "Multitasking",
    "OnBoarding", "OSShowcase", "Passcode", "Payment", "Privacy", "Restore",
    "RestoreCompleted", "Safety", "SafetyAndHandling", "ScreenTime", "SIMSetup", "Siri", "SoftwareUpdate",
    "SpokenLanguage", "TapToSetup", "TermsOfAddress", "Tips", "TOS", "UnlockWithWatch", "UpdateCompleted",
    "Wallpaper", "WatchMigration", "Welcome", "WebContentFiltering", "Zoom",
]

DEFAULT_ORGANIZATION = "Pax (self-managed)"
IDENTITY_KEYS = ("OrganizationMagic", "SupervisorHostCertificates")


def plan_cloud_configuration(
    current: Optional[dict[str, Any]],
    *,
    organization: str = DEFAULT_ORGANIZATION,
    supervisor_cert_der: Optional[bytes] = None,
    allow_pairing: bool = True,
    organization_magic: Optional[str] = None,
) -> dict[str, Any]:
    """The cloud configuration Pax writes: everything the phone already holds, with
    supervision turned on.

    * IsSupervised, CloudConfigurationUIComplete, ConfigurationWasApplied and
      PostSetupProfileWasInstalled = true; ConfigurationSource = 0 (the values in the
      tested no-erase runs).
    * SupervisorHostCertificates gains the Pax supervision certificate when given, so
      the profile can be installed silently. Without it the phone is still supervised
      and the profile is installed by tapping Install in Settings.
    * AllowPairing stays true by default so Finder backups keep working. False is the
      optional "strict" mode: only a supervisor host can pair, which also blocks the
      same no-erase trick being used to unsupervise the phone (Pax deletes its key,
      so after set-up no computer can pair; Finder backups stop).
    """
    cfg: dict[str, Any] = dict(current or {})
    cfg["IsSupervised"] = True
    for flag in ("CloudConfigurationUIComplete", "ConfigurationWasApplied",
                 "PostSetupProfileWasInstalled"):
        cfg[flag] = True
    cfg["AllowPairing"] = bool(allow_pairing)
    cfg["ConfigurationSource"] = 0
    cfg.setdefault("OrganizationName", organization)
    if not cfg.get("OrganizationMagic"):
        cfg["OrganizationMagic"] = organization_magic or str(uuid.uuid4()).upper()
    if supervisor_cert_der:
        certs = [bytes(c) for c in cfg.get("SupervisorHostCertificates") or []]
        if bytes(supervisor_cert_der) not in certs:
            certs.append(bytes(supervisor_cert_der))
        cfg["SupervisorHostCertificates"] = certs
    existing = [p for p in (cfg.get("SkipSetup") or []) if isinstance(p, str)]
    cfg["SkipSetup"] = list(dict.fromkeys(existing + SKIP_SETUP_PANES))
    return cfg


def reads_supervised(cfg: Optional[dict[str, Any]]) -> bool:
    return bool(cfg) and cfg.get("IsSupervised") is True


def host_cert_registered(cfg: Optional[dict[str, Any]], cert_der: Optional[bytes]) -> bool:
    if not cfg or not cert_der:
        return False
    return bytes(cert_der) in [bytes(c) for c in cfg.get("SupervisorHostCertificates") or []]


# --------------------------------------------------------------------------
# Seed backup (MobileBackup2, Manifest.mbdb format)
# --------------------------------------------------------------------------

SUPERVISION_DOMAIN = "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles"
SUPERVISION_PATH = "Library/ConfigurationProfiles/CloudConfigurationDetails.plist"
SETUP_DOMAIN = "ManagedPreferencesDomain"
SETUP_PATH = "mobile/com.apple.purplebuddy.plist"
SETUP_PREFERENCES = {"SetupDone": True, "SetupFinishedAllSteps": True, "UserChoseLanguage": True}
MOBILE_UID = 501  # "mobile"; owner/group used in the tested runs

S_IFDIR = 0o040000
S_IFREG = 0o100000
MODE_755 = 0o755

# ---- ported from TrollRestore sparserestore (MIT, (c) 2024 James Gill) ----

# BackupKeyBag that TrollRestore writes into Manifest.plist (sparserestore/backup.py).
# The backup is not encrypted; iOS only needs a well-formed keybag.
BACKUP_KEYBAG = b64decode(
    "VkVSUwAAAAQAAAAFVFlQRQAAAAQAAAABVVVJRAAAABDud41d1b9NBICR1BH9JfVtSE1D"
    "SwAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAV1JBUAAA"
    "AAQAAAAAU0FMVAAAABRY5Ne2bthGQ5rf4O3gikep1e6tZUlURVIAAAAEAAAnEFVVSUQA"
    "AAAQB7R8awiGR9aba1UuVahGPENMQVMAAAAEAAAAAVdSQVAAAAAEAAAAAktUWVAAAAAE"
    "AAAAAFdQS1kAAAAoN3kQAJloFg+ukEUY+v5P+dhc/Welw/oucsyS40UBh67ZHef5ZMk9"
    "UVVVSUQAAAAQgd0cg0hSTgaxR3PVUbcEkUNMQVMAAAAEAAAAAldSQVAAAAAEAAAAAktU"
    "WVAAAAAEAAAAAFdQS1kAAAAoMiQTXx0SJlyrGJzdKZQ+SfL124w+2Tf/3d1R2i9yNj9z"
    "ZCHNJhnorVVVSUQAAAAQf7JFQiBOS12JDD7qwKNTSkNMQVMAAAAEAAAAA1dSQVAAAAAE"
    "AAAAAktUWVAAAAAEAAAAAFdQS1kAAAAoSEelorROJA46ZUdwDHhMKiRguQyqHukotrxh"
    "jIfqiZ5ESBXX9txi51VVSUQAAAAQfF0G/837QLq01xH9+66vx0NMQVMAAAAEAAAABFdS"
    "QVAAAAAEAAAAAktUWVAAAAAEAAAAAFdQS1kAAAAol0BvFhd5bu4Hr75XqzNf4g0fMqZA"
    "ie6OxI+x/pgm6Y95XW17N+ZIDVVVSUQAAAAQimkT2dp1QeadMu1KhJKNTUNMQVMAAAAE"
    "AAAABVdSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAo2N2DZarQ6GPoWRgTiy/t"
    "djKArOqTaH0tPSG9KLbIjGTOcLodhx23xFVVSUQAAAAQQV37JVZHQFiKpoNiGmT6+ENM"
    "QVMAAAAEAAAABldSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAofe2QSvDC2cV7"
    "Etk4fSBbgqDx5ne/z1VHwmJ6NdVrTyWi80Sy869DM1VVSUQAAAAQFzkdH+VgSOmTj3yE"
    "cfWmMUNMQVMAAAAEAAAAB1dSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAo7kLY"
    "PQ/DnHBERGpaz37eyntIX/XzovsS0mpHW3SoHvrb9RBgOB+WblVVSUQAAAAQEBpgKOz9"
    "Tni8F9kmSXd0sENMQVMAAAAEAAAACFdSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kA"
    "AAAo5mxVoyNFgPMzphYhm1VG8Fhsin/xX+r6mCd9gByF5SxeolAIT/ICF1VVSUQAAAAQ"
    "rfKB2uPSQtWh82yx6w4BoUNMQVMAAAAEAAAACVdSQVAAAAAEAAAAA0tUWVAAAAAEAAAA"
    "AFdQS1kAAAAo5iayZBwcRa1c1MMx7vh6lOYux3oDI/bdxFCW1WHCQR/Ub1MOv+QaYFVV"
    "SUQAAAAQiLXvK3qvQza/mea5inss/0NMQVMAAAAEAAAACldSQVAAAAAEAAAAA0tUWVAA"
    "AAAEAAAAAFdQS1kAAAAoD2wHX7KriEe1E31z7SQ7/+AVymcpARMYnQgegtZD0Mq2U55u"
    "xwNr2FVVSUQAAAAQ/Q9feZxLS++qSe/a4emRRENMQVMAAAAEAAAAC1dSQVAAAAAEAAAA"
    "A0tUWVAAAAAEAAAAAFdQS1kAAAAocYda2jyYzzSKggRPw/qgh6QPESlkZedgDUKpTr4Z"
    "Z8FDgd7YoALY1g=="
)


@dataclass
class MbdbRecord:
    """One Manifest.mbdb record (format as in TrollRestore sparserestore/mbdb.py)."""
    domain: str
    filename: str
    mode: int
    inode: int = 0
    user_id: int = 0
    group_id: int = 0
    mtime: int = 0
    size: int = 0
    hash: bytes = b""
    link: str = ""
    key: bytes = b""
    flags: int = 4
    properties: list = field(default_factory=list)

    def to_bytes(self) -> bytes:
        def s(value: bytes) -> bytes:
            return len(value).to_bytes(2, "big") + value

        out = bytearray()
        out += s(self.domain.encode())
        out += s(self.filename.encode())
        out += s(self.link.encode())
        out += s(self.hash)
        out += s(self.key)
        out += self.mode.to_bytes(2, "big")
        out += self.inode.to_bytes(8, "big")
        out += self.user_id.to_bytes(4, "big")
        out += self.group_id.to_bytes(4, "big")
        for _ in range(3):  # mtime, atime, ctime
            out += self.mtime.to_bytes(4, "big")
        out += self.size.to_bytes(8, "big")
        out += self.flags.to_bytes(1, "big")
        out += len(self.properties).to_bytes(1, "big")
        for name, value in self.properties:
            out += s(name.encode()) + s(value.encode())
        return bytes(out)


def mbdb_bytes(records: list[MbdbRecord]) -> bytes:
    return b"mbdb\x05\x00" + b"".join(r.to_bytes() for r in records)


def status_plist() -> bytes:
    return plistlib.dumps({
        "BackupState": "new",
        "Date": _dt.datetime(1970, 1, 1),
        "IsFullBackup": False,
        "SnapshotState": "finished",
        "UUID": "00000000-0000-0000-0000-000000000000",
        "Version": "2.4",
    })


def manifest_plist() -> bytes:
    return plistlib.dumps({
        "BackupKeyBag": BACKUP_KEYBAG,
        "Lockdown": {},
        "SystemDomainsVersion": "20.0",
        "Version": "9.1",
    })

# ---- end of TrollRestore port ----


def backup_file_name(domain: str, path: str) -> str:
    return hashlib.sha1(f"{domain}-{path}".encode()).hexdigest()


def _domain_records(domain: str, path: str, contents: bytes, inode: int, mtime: int) -> list[MbdbRecord]:
    """Domain root, each parent folder, then the file."""
    recs = [MbdbRecord(domain, "", S_IFDIR | MODE_755, 0, MOBILE_UID, MOBILE_UID, mtime)]
    parent = ""
    for part in path.split("/")[:-1]:
        parent = f"{parent}/{part}" if parent else part
        recs.append(MbdbRecord(domain, parent, S_IFDIR | MODE_755, 0, MOBILE_UID, MOBILE_UID, mtime))
    recs.append(MbdbRecord(domain, path, S_IFREG | MODE_755, inode, MOBILE_UID, MOBILE_UID, mtime,
                           size=len(contents), hash=hashlib.sha1(contents).digest()))
    return recs


def write_seed(root: Path, udid: str, cloud_configuration: dict[str, Any], mode: str,
               *, mtime: Optional[int] = None, inode: Optional[int] = None) -> Path:
    """Write the tiny seed backup to ``root/<udid>/`` and return that folder.

    "live" (iOS 27): the configuration-profiles domain alone.
    "restored" (iOS 17-26): also the managed Setup Assistant preferences
    (SetupDone etc.) so the phone does not re-run Setup after the restart.
    """
    if mode not in (MODE_LIVE, MODE_RESTORED):
        raise ValueError(f"unknown mode {mode!r}")
    if not udid or "/" in udid or udid in (".", ".."):
        raise ValueError("bad udid")
    folder = Path(root) / udid
    if folder.exists():
        raise FileExistsError(folder)
    mtime = int(_dt.datetime.now().timestamp()) if mtime is None else mtime
    inode = secrets.randbits(63) if inode is None else inode

    content = plistlib.dumps(cloud_configuration, fmt=plistlib.FMT_XML)
    records = _domain_records(SUPERVISION_DOMAIN, SUPERVISION_PATH, content, inode, mtime)
    files = {backup_file_name(SUPERVISION_DOMAIN, SUPERVISION_PATH): content}
    if mode == MODE_RESTORED:
        setup = plistlib.dumps(SETUP_PREFERENCES, fmt=plistlib.FMT_XML)
        records += _domain_records(SETUP_DOMAIN, SETUP_PATH, setup, (inode + 1) % (1 << 63), mtime)
        files[backup_file_name(SETUP_DOMAIN, SETUP_PATH)] = setup
    files.update({
        "Manifest.mbdb": mbdb_bytes(records),
        "Status.plist": status_plist(),
        "Manifest.plist": manifest_plist(),
        "Info.plist": plistlib.dumps({}),
    })
    folder.mkdir(parents=True, mode=0o700)
    for name, data in files.items():
        (folder / name).write_bytes(data)
    return folder


# --------------------------------------------------------------------------
# Restore options (v0.8.6: pymobiledevice3's Mobilebackup2, no idevicebackup2)
# --------------------------------------------------------------------------
#
# Up to v0.8.5 Pax ran libimobiledevice's idevicebackup2 (>= 1.3):
#   iOS 17-26: idevicebackup2 -u UDID restore --system --skip-apps --no-reboot SEED
#   iOS 27:    idevicebackup2 -u UDID restore --skip-apps --remove --reboot SEED
# v0.8.6 sends the same MobileBackup2 "Restore" request itself, over pymobiledevice3's
# DeviceLink. This is exactly what idevicebackup2 puts in that request (read from
# tools/idevicebackup2.c, CMD_RESTORE, libimobiledevice 1.3.0 and master), flag by flag:
#
#   idevicebackup2 flag   Restore option / host action        iOS 17-26     iOS 27
#   --------------------  ----------------------------------  ------------  ------------
#   --system              RestoreSystemFiles (always sent)    true          false
#   --no-reboot/--reboot  RestoreShouldReboot                 false         NOT SENT (1)
#   (no --copy)           RestoreDontCopyBackup               true          true
#   (no --settings)       RestorePreserveSettings             true          true
#   --remove              RemoveItemsNotRestored (always)     false         true
#   --skip-apps           host does NOT write /iTunesRestore/
#                         RestoreApplications.plist (2)       skipped       skipped
#   (no --password)       Password                            not sent      not sent
#   (default source)      SourceIdentifier = TargetIdentifier = the phone's UDID
#
# (1) idevicebackup2 only ever sends RestoreShouldReboot = false (for --no-reboot);
#     --reboot just clears that flag, so the key is left out and the phone uses its
#     default, which is to reboot. pymobiledevice3's high-level restore() always sends
#     the key (reboot=True would send RestoreShouldReboot = true), so Pax does NOT call
#     restore(): it sends this exact dictionary through the same service's DeviceLink
#     (pax_device.mobilebackup2_restore) and the iOS 27 request carries no
#     RestoreShouldReboot key at all, as in the tested runs.
# (2) skip-apps is not part of the request: it is the host not writing the app list
#     to /iTunesRestore over AFC. Pax never writes it.
#
# Before sending, idevicebackup2 refuses a backup whose Status.plist doesn't say
# SnapshotState = finished; pax_device does the same (``verify_local_backup``).

RESTORE_FLAGS = {
    # mode -> the idevicebackup2 flags the v0.8.5 helper passed (documentation and tests)
    MODE_RESTORED: ("--system", "--skip-apps", "--no-reboot"),
    MODE_LIVE: ("--skip-apps", "--remove", "--reboot"),
}


def restore_options(mode: str) -> dict[str, bool]:
    """The MobileBackup2 Restore options for ``mode``, key for key what idevicebackup2
    sends for the flags in RESTORE_FLAGS (see the table above)."""
    if mode not in RESTORE_FLAGS:
        raise ValueError(f"unknown mode {mode!r}")
    return idevicebackup2_options(RESTORE_FLAGS[mode])


def idevicebackup2_options(flags: tuple[str, ...] | list[str]) -> dict[str, bool]:
    """A line-by-line model of idevicebackup2's CMD_RESTORE option building, so the
    mapping above is derived from the flags rather than typed twice."""
    known = {"--system", "--no-reboot", "--reboot", "--copy", "--settings", "--remove", "--skip-apps"}
    unknown = set(flags) - known
    if unknown:
        raise ValueError(f"unsupported idevicebackup2 flags {sorted(unknown)}")
    no_reboot = False
    for flag in flags:                      # later flags win, as in its argv loop
        if flag == "--no-reboot":
            no_reboot = True
        elif flag == "--reboot":
            no_reboot = False
    opts: dict[str, bool] = {"RestoreSystemFiles": "--system" in flags}
    if no_reboot:
        opts["RestoreShouldReboot"] = False
    if "--copy" not in flags:
        opts["RestoreDontCopyBackup"] = True
    opts["RestorePreserveSettings"] = "--settings" not in flags
    opts["RemoveItemsNotRestored"] = "--remove" in flags
    return opts


def restore_writes_app_list(mode: str) -> bool:
    """False for both methods: --skip-apps, so no /iTunesRestore/RestoreApplications.plist."""
    return "--skip-apps" not in RESTORE_FLAGS[mode]


def restore_request(udid: str, mode: str) -> dict[str, Any]:
    """The whole DeviceLink process message Pax sends to com.apple.mobilebackup2."""
    return {"MessageName": "Restore", "TargetIdentifier": udid, "SourceIdentifier": udid,
            "Options": restore_options(mode)}


def restore_arguments(udid: str, seed_root: Path, mode: str) -> list[str]:
    """idevicebackup2 (libimobiledevice >= 1.3) arguments, used only when the developer
    override PAX_IDEVICEBACKUP2 points at an idevicebackup2 binary.

    restored (<=26): --system --skip-apps --no-reboot, then Pax restarts the phone.
    live (27):      --skip-apps --remove --reboot, and NO --system: on iOS 27 a
                    restore with system files lost photos and signed out the
                    Apple Account in attention awareness's tests.
    """
    if mode not in RESTORE_FLAGS:
        raise ValueError(f"unknown mode {mode!r}")
    return ["-u", udid, "restore", *RESTORE_FLAGS[mode], str(seed_root)]


# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------

MIN_BATTERY_UNPLUGGED = 50
MIN_BATTERY_ALWAYS = 20


@dataclass
class PreflightFacts:
    ios_version: Optional[str] = None
    paired: Optional[str] = None  # "paired" | "needs_trust" | "locked" | "denied" | "unknown"
    find_my_on: Optional[bool] = None  # None = could not read
    find_my_confirmed_off: bool = False  # user ticked the box
    backup_confirmed: bool = False  # Pax backup verified, or user's own recent backup
    battery_level: Optional[int] = None
    charging: Optional[bool] = None
    already_supervised: Optional[bool] = None
    backup_encryption_on: Optional[bool] = None


@dataclass
class PreflightResult:
    mode: Optional[str]
    blocking: list[str]
    warnings: list[str]
    ask_user_find_my: bool = False

    @property
    def ok(self) -> bool:
        return self.mode is not None and not self.blocking

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "ok": self.ok, "blocking": self.blocking,
                "warnings": self.warnings, "ask_user_find_my": self.ask_user_find_my}


def evaluate_preflight(f: PreflightFacts) -> PreflightResult:
    plan = plan_for_version(f.ios_version)
    blocking: list[str] = []
    warnings: list[str] = []
    ask_find_my = False
    if not plan.allowed:
        blocking.append(plan.message)

    if f.paired != "paired":
        blocking.append({
            "needs_trust": "Unlock the iPhone and tap Trust, then enter the passcode.",
            "locked": "Unlock the iPhone.",
            "denied": "The iPhone said Don't Trust. Unplug it, plug it back in and tap Trust.",
        }.get(f.paired or "", "Pax can't talk to the iPhone yet. Unlock it, tap Trust and check the cable."))

    if f.find_my_on is True:
        blocking.append("Find My is on. Settings > [your name] > Find My > Find My iPhone: off. "
                        "The iPhone refuses the restore while it's on.")
    elif f.find_my_on is None and not f.find_my_confirmed_off:
        ask_find_my = True
        blocking.append("Pax couldn't read Find My. Confirm you've turned it off.")

    if not f.backup_confirmed:
        blocking.append("Make a backup first and confirm it finished.")

    if f.battery_level is None:
        warnings.append("Couldn't read the battery. Keep the iPhone charging.")
    elif f.battery_level < MIN_BATTERY_ALWAYS:
        blocking.append(f"Battery is at {f.battery_level}%. Charge to at least {MIN_BATTERY_UNPLUGGED}%.")
    elif f.battery_level < MIN_BATTERY_UNPLUGGED and not f.charging:
        blocking.append(f"Battery is at {f.battery_level}%. Plug in to charge, or charge to "
                        f"{MIN_BATTERY_UNPLUGGED}% first.")

    if f.already_supervised:
        warnings.append("This iPhone is already supervised. Pax will skip supervision and only "
                        "install the profile (you'll tap Install in Settings).")
    if f.backup_encryption_on:
        warnings.append("Encrypted local backups are on. That's fine for your safety backup; if the "
                        "seed restore asks for a password, it is your backup password.")
    return PreflightResult(plan.mode, blocking, warnings, ask_find_my)


def battery_from_lockdown(values: Optional[dict[str, Any]]) -> tuple[Optional[int], Optional[bool]]:
    """Level and charging state from the lockdown domain com.apple.mobile.battery."""
    if not isinstance(values, dict):
        return None, None
    level = values.get("BatteryCurrentCapacity")
    level = int(level) if isinstance(level, (int, float)) and not isinstance(level, bool) else None
    charging = values.get("BatteryIsCharging")
    if not isinstance(charging, bool):
        ext = values.get("ExternalConnected")
        charging = ext if isinstance(ext, bool) else None
    return level, charging


def verify_local_backup(folder: Path) -> tuple[bool, str]:
    """A MobileBackup2 backup folder that finished: Status.plist says the snapshot
    finished, Manifest.plist is a real plist (the device writes it at the end; the
    host only creates an empty placeholder at the start) and a manifest exists.
    Also used on the seed before it is restored, as idevicebackup2 did."""
    folder = Path(folder)
    status = folder / "Status.plist"
    if not status.exists():
        return False, "Status.plist missing"
    try:
        info = plistlib.loads(status.read_bytes())
    except Exception as exc:  # noqa: BLE001
        return False, f"Status.plist unreadable: {exc}"
    if info.get("SnapshotState") != "finished":
        return False, f"snapshot state {info.get('SnapshotState')!r}"
    if not (folder / "Manifest.db").exists() and not (folder / "Manifest.mbdb").exists():
        return False, "manifest missing"
    manifest_plist = folder / "Manifest.plist"
    if manifest_plist.exists():
        try:
            if not isinstance(plistlib.loads(manifest_plist.read_bytes()), dict):
                return False, "Manifest.plist is not a dictionary"
        except Exception as exc:  # noqa: BLE001
            return False, f"Manifest.plist unreadable: {exc}"
    return True, "finished"


def cert_der_from_file(path: os.PathLike | str) -> bytes:
    return Path(path).read_bytes()
