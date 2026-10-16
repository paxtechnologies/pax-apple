#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pax device helper: the USB side of "Keep my data" set-up.

The Mac app calls one subcommand at a time and reads ONE JSON object from the last
line of stdout: {"ok": true, ...} or {"ok": false, "error": "...", "code": "..."}.
Nothing here prints a password, a key or a profile.

Subcommands
  list                               USB iPhones/iPads: udid, name, type, iOS, paired
  preflight  --udid U [--find-my-confirmed-off] [--backup-confirmed]
                                     facts + verdict (see seed.evaluate_preflight)
  backup     --udid U --dir D        full local backup (MobileBackup2), verified
  seed-restore --udid U --cert C.der [--org NAME] [--forbid-pairing]
                                     iOS 17-26: system-files restore of the seed, skip
                                                apps, no reboot; then Pax restarts it
                                     iOS 27:    no system files, skip apps, remove,
                                                reboot; phone reboots into Setup
                                     (exact options: seed.py, "Restore options")
  connect    --udid U                one connection attempt after the restart. Sends
                                     at most ONE Pair request (never on a timer: a Pair
                                     sent while the user types the passcode cancels
                                     the Trust dialog). state: paired | trust_requested
                                     | locked | not_found | denied
  live-configure --udid U --cert C.der [--org NAME] [--forbid-pairing] [--timeout 90]
                                     iOS 27, phone in Setup: SetCloudConfiguration over
                                     com.apple.mobile.MCInstall, retried every 2 s, then
                                     read back with GetCloudConfiguration
  status     --udid U [--cert C.der] supervised? host cert registered? Find My?
  install-profile --udid U --cert C.der --key K.der [--allow-manual]  (profile on stdin)
                                     silent install (Escalate + InstallProfileSilent);
                                     with --allow-manual falls back to InstallProfile,
                                     which the user finishes in Settings
  profiles   --udid U                installed profile identifiers
  apps       --udid U [--icons-dir D] (v0.8.7) the user's installed apps for the set-up
                                     picker: bundle ID, name, version, whether Pax blocks it
                                     anyway or never can; with --icons-dir each home-screen
                                     icon as D/<bundle id>.png (best effort, time-boxed)
  selftest   [--expect-pymobiledevice3 V] [--expect-arch A]
                                     no iPhone needed: imports everything the commands
                                     use, checks the pymobiledevice3 API Pax relies on,
                                     builds both seeds and a keybag. Run by the release
                                     build against the signed helper inside Pax.app.

Runtime (v0.8.6): Pax.app ships its own Python (python-build-standalone CPython 3.12,
universal2) with pymobiledevice3 (GPL-3.0-or-later) and its dependencies in
Contents/Resources/device/python, so nothing is installed on the Mac. Backup and the
seed restore use pymobiledevice3's own Mobilebackup2 implementation: no idevicebackup2,
no Homebrew. Developers can still run this file with any Python that has
`pip install -r device/requirements.txt`. PAX_IDEVICEBACKUP2=/path/to/idevicebackup2
is an optional advanced override that makes backup and seed-restore run that binary
with the same flags as v0.8.5.

NOT TESTED ON HARDWARE. See README "What is untested".
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import seed  # noqa: E402

LIVE_RETRY_INTERVAL = 2.0
LIVE_DEFAULT_TIMEOUT = 90.0
# The pymobiledevice3 release the bundled helper is built and tested with
# (device/requirements-bundle.txt). mobilebackup2_restore uses Mobilebackup2Service's
# device_link() and _backup_lock(), so `selftest` checks they are still there.
PINNED_PYMOBILEDEVICE3 = "11.32.0"
PROGRESS_STEP = 5.0  # percent between progress events


class HelperError(Exception):
    def __init__(self, message: str, code: str = "error"):
        super().__init__(message)
        self.code = code


def emit(**fields: Any) -> None:
    """Progress line (not the result)."""
    print(json.dumps({"event": fields}), flush=True)


def idevicebackup2_override() -> Optional[str]:
    """PAX_IDEVICEBACKUP2: optional developer override (v0.8.6). Unset, which is the
    default, means pymobiledevice3's own Mobilebackup2. Pax never looks for
    idevicebackup2 on PATH or in Homebrew any more."""
    chosen = (os.environ.get("PAX_IDEVICEBACKUP2") or "").strip()
    if not chosen:
        return None
    if os.path.isfile(chosen) and os.access(chosen, os.X_OK):
        return chosen
    raise HelperError(f"PAX_IDEVICEBACKUP2 is set, but {chosen} isn't a program Pax can run. "
                      "Unset it to use Pax's built-in backup.", "tool_missing")


def progress_reporter(phase: str):
    """A pymobiledevice3 progress callback that emits at most one event per 5 %."""
    last = {"pct": -PROGRESS_STEP}

    def report(value: Any) -> None:
        try:
            pct = float(value)
        except (TypeError, ValueError):
            return
        if pct >= last["pct"] + PROGRESS_STEP or (pct >= 100 and last["pct"] < 100):
            last["pct"] = pct
            emit(phase=phase, percent=round(pct, 1))
    return report


def classify_restore_failure(output: str) -> HelperError:
    low = output.lower()
    if "find my" in low or "fmip" in low:
        return HelperError("Find My is still on, so the iPhone refused the restore. Turn it off in "
                           "Settings > [your name] > Find My, then try again.", "find_my_on")
    if "password" in low and "backup" in low:
        return HelperError("The iPhone asked for a backup password.", "backup_password")
    if "device locked" in low or "passcode" in low:
        return HelperError("Unlock the iPhone and try again.", "locked")
    tail = "\n".join(output.strip().splitlines()[-5:])
    return HelperError(f"The restore failed: {tail or 'no output'}", "restore_failed")


# --------------------------------------------------------------------------
# pymobiledevice3 wrappers (imported lazily so `seed` tests need no device stack)
# --------------------------------------------------------------------------

async def usb_udids() -> list[str]:
    from pymobiledevice3.usbmux import list_devices
    return [d.serial for d in await list_devices() if getattr(d, "is_usb", True)]


async def open_lockdown(udid: str):
    from pymobiledevice3.lockdown import create_using_usbmux
    return await create_using_usbmux(serial=udid, autopair=False)


async def require_paired(udid: str):
    ld = await open_lockdown(udid)
    if not getattr(ld, "paired", False):
        await _close(ld)
        raise HelperError("This Mac isn't trusted by the iPhone yet. Unlock it and tap Trust.",
                          "not_paired")
    return ld


async def _close(ld) -> None:
    try:
        await ld.close()
    except Exception:  # noqa: BLE001
        pass


async def get_value(ld, domain: Optional[str], key: Optional[str]) -> Any:
    try:
        return await ld.get_value(domain=domain, key=key)
    except Exception:  # noqa: BLE001  (missing domain, locked, unpaired)
        return None


async def cloud_configuration(ld) -> Optional[dict[str, Any]]:
    from pymobiledevice3.services.mobile_config import MobileConfigService
    async with MobileConfigService(ld) as mc:
        return await mc.get_cloud_configuration()


async def set_cloud_configuration(ld, cfg: dict[str, Any]) -> None:
    from pymobiledevice3.services.mobile_config import MobileConfigService
    async with MobileConfigService(ld) as mc:
        await mc.set_cloud_configuration(cfg)


async def restart(ld) -> None:
    from pymobiledevice3.services.diagnostics import DiagnosticsService
    async with DiagnosticsService(ld) as diag:
        await diag.restart()


async def mobilebackup2_backup(ld, target: Path) -> None:
    """Full local backup into target/<udid> (what `idevicebackup2 backup --full` did)."""
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
    service = Mobilebackup2Service(ld)
    try:
        await service.backup(full=True, backup_directory=target,
                             progress_callback=progress_reporter("backup_progress"))
    finally:
        try:
            await service.close()
        except Exception:  # noqa: BLE001
            pass


async def mobilebackup2_restore(ld, seed_root: Path, udid: str, mode: str) -> dict[str, Any]:
    """Restore the seed at seed_root/<udid> with EXACTLY the Restore request
    idevicebackup2 sent for this mode (seed.restore_request; flag-by-flag table in
    seed.py). pymobiledevice3's Mobilebackup2Service.restore() can't leave
    RestoreShouldReboot out, which iOS 27 needs to match the tested runs, so the
    request goes through the same service's DeviceLink, sync lock and dl_loop instead.

    Once the phone has answered the request successfully, an error while letting go of
    the sync lock is ignored (the phone may already be rebooting), as idevicebackup2
    ignored it. Returns the request that was sent."""
    from pymobiledevice3.services.afc import AfcService
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
    from pymobiledevice3.services.notification_proxy import NotificationProxyService

    ok, why = seed.verify_local_backup(Path(seed_root) / udid)
    if not ok:  # idevicebackup2: "Cannot ensure we restore from a successful backup"
        raise HelperError(f"Pax's set-up file wasn't complete ({why}). Nothing was sent.", "seed_invalid")
    if seed.restore_writes_app_list(mode):  # both methods skip apps; never write the app list
        raise HelperError("internal: restore would re-install apps", "unexpected")
    request = seed.restore_request(udid, mode)
    service = Mobilebackup2Service(ld)
    answered = False
    try:
        async with service.device_link(Path(seed_root)) as dl, \
                NotificationProxyService(ld) as notifications, \
                AfcService(ld) as afc, \
                service._backup_lock(afc, notifications):
            await dl.send_process_message(request)
            await dl.dl_loop(progress_reporter("restore_progress"))
            answered = True
    except Exception as exc:  # noqa: BLE001
        if not answered:
            raise
        emit(phase="restore_cleanup_ignored", reason=f"{type(exc).__name__}"[:100])
    finally:
        try:
            await service.close()
        except Exception:  # noqa: BLE001
            pass
    return request


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

async def cmd_list(_a) -> dict:
    devices = []
    for udid in await usb_udids():
        entry: dict[str, Any] = {"udid": udid}
        try:
            ld = await open_lockdown(udid)
            entry["paired"] = bool(getattr(ld, "paired", False))
            entry["ios"] = await get_value(ld, None, "ProductVersion")
            entry["product_type"] = await get_value(ld, None, "ProductType")
            entry["name"] = await get_value(ld, None, "DeviceName") or "iPhone"
            if entry["paired"]:
                try:
                    entry["supervised"] = seed.reads_supervised(await cloud_configuration(ld))
                except Exception:  # noqa: BLE001
                    entry["supervised"] = None
            await _close(ld)
        except Exception as exc:  # noqa: BLE001
            entry["error"] = type(exc).__name__
        devices.append(entry)
    return {"devices": devices}


async def pair_state(udid: str) -> str:
    from pymobiledevice3 import exceptions as ex
    try:
        ld = await open_lockdown(udid)
    except ex.PasswordRequiredError:
        return "locked"
    except Exception:  # noqa: BLE001
        return "unknown"
    state = "paired" if getattr(ld, "paired", False) else "needs_trust"
    await _close(ld)
    return state


async def cmd_preflight(a) -> dict:
    facts = seed.PreflightFacts(find_my_confirmed_off=a.find_my_confirmed_off,
                                backup_confirmed=a.backup_confirmed)
    facts.paired = await pair_state(a.udid)
    ld = await open_lockdown(a.udid)
    try:
        facts.ios_version = await get_value(ld, None, "ProductVersion")
        if facts.paired == "paired":
            fmip = await get_value(ld, "com.apple.fmip", "IsAssociated")
            facts.find_my_on = fmip if isinstance(fmip, bool) else None
            facts.battery_level, facts.charging = seed.battery_from_lockdown(
                await get_value(ld, "com.apple.mobile.battery", None))
            enc = await get_value(ld, "com.apple.mobile.backup", "WillEncrypt")
            facts.backup_encryption_on = enc if isinstance(enc, bool) else None
            try:
                facts.already_supervised = seed.reads_supervised(await cloud_configuration(ld))
            except Exception:  # noqa: BLE001
                facts.already_supervised = None
    finally:
        await _close(ld)
    verdict = seed.evaluate_preflight(facts)
    return {"facts": facts.__dict__, **verdict.to_dict()}


async def cmd_backup(a) -> dict:
    tool = idevicebackup2_override()
    target = Path(a.dir).expanduser()
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    emit(phase="backup_started", dir=str(target))
    if tool:
        proc = subprocess.run([tool, "-u", a.udid, "backup", "--full", str(target)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise classify_restore_failure(proc.stdout + proc.stderr)
    else:
        ld = await require_paired(a.udid)
        try:
            await mobilebackup2_backup(ld, target)
        except HelperError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise classify_restore_failure(f"{type(exc).__name__}: {exc}") from exc
        finally:
            await _close(ld)
    ok, why = seed.verify_local_backup(target / a.udid)
    if not ok:
        raise HelperError(f"The backup didn't finish ({why}).", "backup_incomplete")
    return {"backup": str(target / a.udid), "verified": True}


async def cmd_seed_restore(a) -> dict:
    cert = seed.cert_der_from_file(a.cert) if a.cert else None
    ld = await require_paired(a.udid)
    try:
        plan = seed.plan_for_version(await get_value(ld, None, "ProductVersion"))
        if not plan.allowed:
            raise HelperError(plan.message, f"refused_{plan.refusal}")
        if await get_value(ld, "com.apple.fmip", "IsAssociated") is True:
            raise HelperError("Find My is on. Turn it off first.", "find_my_on")
        current = await cloud_configuration(ld)
    finally:
        await _close(ld)
    if seed.reads_supervised(current):
        return {"mode": plan.mode, "already_supervised": True, "next": "protect"}

    cfg = seed.plan_cloud_configuration(current, organization=a.org, supervisor_cert_der=cert,
                                        allow_pairing=not a.forbid_pairing)
    tool = idevicebackup2_override()
    root = Path(tempfile.mkdtemp(prefix="pax-seed-"))
    try:
        seed.write_seed(root, a.udid, cfg, plan.mode)
        # Re-read the version right before writing to the phone: never send a seed
        # built for the other method.
        ld = await require_paired(a.udid)
        try:
            again = seed.plan_for_version(await get_value(ld, None, "ProductVersion"))
            if again.mode != plan.mode:
                raise HelperError("The iPhone's iOS version changed during set-up. Nothing was sent.",
                                  "version_changed")
            emit(phase="restore_started", mode=plan.mode,
                 engine="idevicebackup2" if tool else "pymobiledevice3")
            if tool:
                proc = subprocess.run([tool, *seed.restore_arguments(a.udid, root, plan.mode)],
                                      capture_output=True, text=True)
                if proc.returncode != 0:
                    raise classify_restore_failure(proc.stdout + proc.stderr)
            else:
                try:
                    await mobilebackup2_restore(ld, root, a.udid, plan.mode)
                except HelperError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    raise classify_restore_failure(f"{type(exc).__name__}: {exc}") from exc
        finally:
            await _close(ld)
        emit(phase="restore_finished", mode=plan.mode)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    if plan.mode == seed.MODE_RESTORED:
        ld = await require_paired(a.udid)
        try:
            await restart(ld)
        except Exception as exc:  # noqa: BLE001
            raise HelperError(f"The restore worked but Pax couldn't restart the iPhone ({exc}). "
                              "Restart it yourself to finish.", "restart_failed") from exc
        finally:
            await _close(ld)
        return {"mode": plan.mode, "next": "reconnect_then_verify"}
    return {"mode": plan.mode, "next": "reconnect_then_live_configure"}


async def cmd_connect(a) -> dict:
    """One attempt; the app calls it again. At most one Pair per call."""
    from pymobiledevice3 import exceptions as ex
    if a.udid not in await usb_udids():
        return {"state": "not_found"}
    try:
        ld = await open_lockdown(a.udid)
    except ex.PasswordRequiredError:
        return {"state": "locked"}
    except Exception as exc:  # noqa: BLE001
        return {"state": "not_found", "detail": type(exc).__name__}
    try:
        if getattr(ld, "paired", False):
            return {"state": "paired"}
        try:
            await ld.pair(timeout=0)  # ONE Pair request, no waiting loop
            return {"state": "paired"}
        except ex.PairingDialogResponsePendingError:
            return {"state": "trust_requested"}
        except ex.UserDeniedPairingError:
            return {"state": "denied"}
        except ex.PasswordRequiredError:
            return {"state": "locked"}
        except ex.PairingError as exc:
            return {"state": "trust_requested", "detail": type(exc).__name__}
    finally:
        await _close(ld)


async def cmd_live_configure(a) -> dict:
    cert = seed.cert_der_from_file(a.cert) if a.cert else None
    started = time.monotonic()
    deadline = started + a.timeout
    attempt, last = 0, ""
    with_cert = cert
    while True:
        attempt += 1
        try:
            ld = await require_paired(a.udid)
            try:
                plan = seed.plan_for_version(await get_value(ld, None, "ProductVersion"))
                if not plan.allowed:
                    raise HelperError(plan.message, f"refused_{plan.refusal}")
                current = await cloud_configuration(ld)
                if seed.reads_supervised(current):
                    # Already took it (an earlier attempt, or the phone reports the
                    # restored configuration). MCInstall refuses a second set (14002).
                    after = current
                else:
                    cfg = seed.plan_cloud_configuration(current, organization=a.org,
                                                        supervisor_cert_der=with_cert,
                                                        allow_pairing=not a.forbid_pairing)
                    await set_cloud_configuration(ld, cfg)
                    after = await cloud_configuration(ld)
            finally:
                await _close(ld)
            if seed.reads_supervised(after):
                return {"supervised": True, "attempts": attempt,
                        "host_cert_registered": seed.host_cert_registered(after, cert),
                        "organization": (after or {}).get("OrganizationName")}
            last = "The iPhone acknowledged the setting but still reads as not supervised."
        except HelperError as exc:
            if exc.code.startswith("refused_"):
                raise
            last = str(exc)
        except Exception as exc:  # noqa: BLE001  (MCInstall refuses for a few seconds after boot)
            last = f"{type(exc).__name__}: {exc}"
            # If the phone rejects the dictionary with our host certificate, fall back to
            # the shape that was tested on iOS 27.2 (no SupervisorHostCertificates). The
            # profile is then installed by tapping Install in Settings.
            if with_cert and "ProfileError" in last and time.monotonic() > started + a.timeout / 2:
                with_cert = None
                emit(phase="retrying_without_host_certificate")
        emit(phase="live_configure_retry", attempt=attempt, reason=last[:200])
        if time.monotonic() + LIVE_RETRY_INTERVAL > deadline:
            raise HelperError("The iPhone restarted but didn't take the supervision setting. Keep it "
                              "unlocked and connected; if it shows Restore Completed, don't tap "
                              f"Continue. Then try again. ({last[:200]})", "live_not_taken")
        await asyncio.sleep(LIVE_RETRY_INTERVAL)


async def cmd_status(a) -> dict:
    cert = seed.cert_der_from_file(a.cert) if a.cert else None
    ld = await require_paired(a.udid)
    try:
        cfg = await cloud_configuration(ld)
        fmip = await get_value(ld, "com.apple.fmip", "IsAssociated")
        version = await get_value(ld, None, "ProductVersion")
    finally:
        await _close(ld)
    return {"supervised": seed.reads_supervised(cfg),
            "host_cert_registered": seed.host_cert_registered(cfg, cert),
            "organization": (cfg or {}).get("OrganizationName"),
            "allow_pairing": (cfg or {}).get("AllowPairing"),
            "find_my_on": fmip if isinstance(fmip, bool) else None,
            "ios": version}


def _keybag_pem(cert_der: bytes, key_der: bytes) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_der_x509_certificate(cert_der)
    key = serialization.load_der_private_key(key_der, password=None)
    return (cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()))


async def cmd_install_profile(a) -> dict:
    from pymobiledevice3.services.mobile_config import MobileConfigService
    profile = sys.stdin.buffer.read()
    if not profile:
        raise HelperError("No profile on stdin.", "no_profile")
    keybag_dir = Path(tempfile.mkdtemp(prefix="pax-kb-"))
    keybag = keybag_dir / "keybag.pem"
    silent_error = ""
    try:
        have_key = Path(a.key).exists()
        if have_key:
            fd = os.open(keybag, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, _keybag_pem(Path(a.cert).read_bytes(), Path(a.key).read_bytes()))
            finally:
                os.close(fd)
        ld = await require_paired(a.udid)
        try:
            try:
                if not have_key:
                    # The key is destroyed after a first attempt; a retry can only
                    # hand the profile to Settings.
                    raise HelperError("supervision key already destroyed", "no_key")
                async with MobileConfigService(ld) as mc:
                    await mc.install_profile_silent(keybag, profile)
                return {"installed": True, "method": "silent"}
            except Exception as exc:  # noqa: BLE001
                silent_error = f"{type(exc).__name__}: {exc}"[:300]
                if not a.allow_manual:
                    raise HelperError(f"Silent install failed: {silent_error}", "silent_failed") from exc
            async with MobileConfigService(ld) as mc:
                await mc.install_profile(profile)
            return {"installed": False, "method": "manual", "pending_user": True,
                    "silent_error": silent_error}
        finally:
            await _close(ld)
    finally:
        try:
            keybag.write_bytes(b"\0" * 4096)
        except OSError:
            pass
        shutil.rmtree(keybag_dir, ignore_errors=True)


async def cmd_profiles(a) -> dict:
    from pymobiledevice3.services.mobile_config import MobileConfigService
    ld = await require_paired(a.udid)
    try:
        async with MobileConfigService(ld) as mc:
            listing = await mc.get_profile_list()
    finally:
        await _close(ld)
    ids = list((listing or {}).get("OrderedIdentifiers") or (listing or {}).get("ProfileMetadata", {}).keys())
    return {"identifiers": ids}


# v0.8.7: the set-up app picker. Only what the picker shows is asked for, so the
# answer stays small (a full Lookup carries every app's entitlements).
APP_ATTRIBUTES = ["CFBundleIdentifier", "CFBundleDisplayName", "CFBundleName", "CFBundleShortVersionString"]
ICON_BUDGET_SECONDS = 20.0
MAX_ICONS = 400


def _app_blocks():
    """profile/app_blocks.py: next to device/ in the repo and in Pax.app's Resources."""
    here = Path(__file__).resolve().parent
    for d in (here.parent / "profile", here / "profile"):
        if (d / "app_blocks.py").exists() and str(d) not in sys.path:
            sys.path.append(str(d))
    import app_blocks
    return app_blocks


async def cmd_apps(a) -> dict:
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    ab = _app_blocks()
    ld = await require_paired(a.udid)
    try:
        try:
            async with InstallationProxyService(ld) as ip:
                found = await ip.lookup({"ApplicationType": "User", "ReturnAttributes": APP_ATTRIBUTES})
        except Exception as exc:  # noqa: BLE001
            raise HelperError(f"PAX-IOS-012: couldn't read the iPhone's apps ({type(exc).__name__})",
                              "apps_failed") from None
        rows = ab.app_rows(found or {})
        icons = 0
        if a.icons_dir and rows:
            icons = await _write_icons(ld, rows, Path(a.icons_dir))
    finally:
        await _close(ld)
    return {"apps": rows, "pax_blocked": ab.pax_blocked_ids(), "max_custom": ab.MAX_CUSTOM_APP_BLOCKS,
            "icons": icons}


async def _write_icons(ld, rows: list[dict], folder: Path) -> int:
    """Home-screen icons from SpringBoard, one PNG per app, until the time budget runs
    out. Icons are a nicety: any failure leaves the picker with names only."""
    from pymobiledevice3.services.springboard import SpringBoardServicesService
    folder.mkdir(parents=True, exist_ok=True)
    done = 0
    deadline = time.monotonic() + ICON_BUDGET_SECONDS
    try:
        async with SpringBoardServicesService(ld) as sb:
            for row in rows[:MAX_ICONS]:
                if time.monotonic() > deadline:
                    break
                bid = row["bundle_id"]
                if "/" in bid or bid.startswith("."):
                    continue
                try:
                    png = await asyncio.wait_for(sb.get_icon_pngdata(bid), timeout=3)
                except Exception:  # noqa: BLE001
                    continue
                if png:
                    (folder / f"{bid}.png").write_bytes(png)
                    row["icon"] = str(folder / f"{bid}.png")
                    done += 1
    except Exception:  # noqa: BLE001
        pass
    return done


# Everything the commands import from pymobiledevice3, with the names they use.
SELFTEST_IMPORTS = {
    "pymobiledevice3.usbmux": ["list_devices"],
    "pymobiledevice3.lockdown": ["create_using_usbmux"],
    "pymobiledevice3.exceptions": ["PasswordRequiredError", "PairingDialogResponsePendingError",
                                   "UserDeniedPairingError", "PairingError"],
    "pymobiledevice3.services.mobile_config": ["MobileConfigService"],
    "pymobiledevice3.services.installation_proxy": ["InstallationProxyService"],
    "pymobiledevice3.services.springboard": ["SpringBoardServicesService"],
    "pymobiledevice3.services.diagnostics": ["DiagnosticsService"],
    "pymobiledevice3.services.mobilebackup2": ["Mobilebackup2Service"],
    "pymobiledevice3.services.afc": ["AfcService"],
    "pymobiledevice3.services.notification_proxy": ["NotificationProxyService"],
    "pymobiledevice3.osu.os_utils": ["get_os_utils"],
    "cryptography.x509": ["load_der_x509_certificate"],
    "cryptography.hazmat.primitives.serialization": ["load_der_private_key"],
}
# Imported by pymobiledevice3 on macOS only (pymobiledevice3.osu.posix_util).
SELFTEST_DARWIN_IMPORTS = {"ioregistry.ioentry": ["get_io_services_by_type"]}
# Methods Pax calls on those classes (a pymobiledevice3 update that drops one fails here).
SELFTEST_METHODS = {
    ("pymobiledevice3.services.mobilebackup2", "Mobilebackup2Service"):
        ["backup", "device_link", "_backup_lock", "close"],
    ("pymobiledevice3.services.mobile_config", "MobileConfigService"):
        ["get_cloud_configuration", "set_cloud_configuration", "install_profile_silent",
         "install_profile", "get_profile_list"],
    ("pymobiledevice3.services.diagnostics", "DiagnosticsService"): ["restart"],
    ("pymobiledevice3.services.installation_proxy", "InstallationProxyService"): ["lookup"],
    ("pymobiledevice3.services.springboard", "SpringBoardServicesService"): ["get_icon_pngdata"],
}


def _selftest_keybag() -> None:
    """Exercise cryptography's compiled module (signed under the hardened runtime)."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pax selftest")])
    now = dt.datetime(2026, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    pem = _keybag_pem(cert.public_bytes(serialization.Encoding.DER),
                      key.private_bytes(serialization.Encoding.DER,
                                        serialization.PrivateFormat.TraditionalOpenSSL,
                                        serialization.NoEncryption()))
    if x509.load_pem_x509_certificate(pem) != cert:
        raise HelperError("keybag round trip failed", "selftest_failed")


async def cmd_selftest(a) -> dict:
    import importlib
    from importlib import metadata
    problems: list[str] = []
    imports = dict(SELFTEST_IMPORTS)
    if sys.platform == "darwin":
        imports.update(SELFTEST_DARWIN_IMPORTS)
    for module, names in imports.items():
        try:
            mod = importlib.import_module(module)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"import {module}: {type(exc).__name__}: {exc}")
            continue
        problems += [f"{module}.{n} missing" for n in names if not hasattr(mod, n)]
    for (module, cls), methods in SELFTEST_METHODS.items():
        try:
            klass = getattr(importlib.import_module(module), cls)
        except Exception:  # noqa: BLE001  (already reported)
            continue
        problems += [f"{cls}.{m} missing" for m in methods if not callable(getattr(klass, m, None))]
    try:
        # pymobiledevice3's per-OS layer (usbmux socket, pair records). On macOS this also
        # asks IOKit for USB devices through ctypes, which must work under the hardened runtime.
        from pymobiledevice3.osu.os_utils import get_os_utils
        os_utils = get_os_utils()
        if sys.platform == "darwin":
            os_utils.usb_devices_seen_by_host()
    except Exception as exc:  # noqa: BLE001
        problems.append(f"os utils: {type(exc).__name__}: {exc}")
    try:
        ab = _app_blocks()          # v0.8.7: the app picker's rules ship in Resources/profile
        if not ab.pax_blocked_ids() or ab.protected_reason("com.apple.Preferences") is None:
            problems.append("app_blocks: wrong rules")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"app_blocks: {type(exc).__name__}: {exc}")
    try:
        _selftest_keybag()
    except Exception as exc:  # noqa: BLE001
        problems.append(f"keybag: {type(exc).__name__}: {exc}")
    # Both seeds build and pass the same check the restore makes before sending.
    with tempfile.TemporaryDirectory(prefix="pax-selftest-") as tmp:
        for mode in (seed.MODE_RESTORED, seed.MODE_LIVE):
            cfg = seed.plan_cloud_configuration({}, organization_magic="SELFTEST")
            folder = seed.write_seed(Path(tmp) / mode, "SELFTEST", cfg, mode)
            ok, why = seed.verify_local_backup(folder)
            if not ok:
                problems.append(f"seed {mode}: {why}")
    if seed.restore_options(seed.MODE_LIVE).get("RestoreSystemFiles") is not False \
            or "RestoreShouldReboot" in seed.restore_options(seed.MODE_LIVE):
        problems.append("iOS 27 restore options are wrong")
    try:
        versions = {d: metadata.version(d) for d in ("pymobiledevice3", "cryptography")}
    except metadata.PackageNotFoundError as exc:
        versions = {}
        problems.append(f"package metadata missing: {exc}")
    if a.expect_pymobiledevice3 and versions.get("pymobiledevice3") != a.expect_pymobiledevice3:
        problems.append(f"pymobiledevice3 {versions.get('pymobiledevice3')} != {a.expect_pymobiledevice3}")
    machine = platform.machine()
    if a.expect_arch and machine != a.expect_arch:
        problems.append(f"running as {machine}, expected {a.expect_arch}")
    if problems:
        raise HelperError("Self-test failed: " + "; ".join(problems)[:1500], "selftest_failed")
    import ssl
    return {"selftest": "passed", "python": platform.python_version(), "arch": machine,
            "executable": sys.executable, "prefix": sys.prefix,
            "bundled": Path(sys.prefix).name == "python" and Path(sys.prefix).parent.name == "device",
            "writes_bytecode": not sys.dont_write_bytecode, "isolated": bool(sys.flags.isolated),
            "openssl": ssl.OPENSSL_VERSION, **versions}


COMMANDS = {
    "list": cmd_list, "preflight": cmd_preflight, "backup": cmd_backup,
    "seed-restore": cmd_seed_restore, "connect": cmd_connect,
    "live-configure": cmd_live_configure, "status": cmd_status,
    "install-profile": cmd_install_profile, "profiles": cmd_profiles, "apps": cmd_apps,
    "selftest": cmd_selftest,
}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Pax device helper (Keep my data)")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    p = sub.add_parser("preflight")
    p.add_argument("--udid", required=True)
    p.add_argument("--find-my-confirmed-off", action="store_true")
    p.add_argument("--backup-confirmed", action="store_true")
    p = sub.add_parser("backup")
    p.add_argument("--udid", required=True)
    p.add_argument("--dir", required=True)
    for name in ("seed-restore", "live-configure"):
        p = sub.add_parser(name)
        p.add_argument("--udid", required=True)
        p.add_argument("--cert", help="supervision certificate (DER) to register")
        p.add_argument("--org", default=seed.DEFAULT_ORGANIZATION)
        p.add_argument("--forbid-pairing", action="store_true",
                       help="AllowPairing=false: no other computer can pair (strict)")
        if name == "live-configure":
            p.add_argument("--timeout", type=float, default=LIVE_DEFAULT_TIMEOUT)
    p = sub.add_parser("connect")
    p.add_argument("--udid", required=True)
    p = sub.add_parser("status")
    p.add_argument("--udid", required=True)
    p.add_argument("--cert")
    p = sub.add_parser("install-profile")
    p.add_argument("--udid", required=True)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--allow-manual", action="store_true")
    p = sub.add_parser("profiles")
    p.add_argument("--udid", required=True)
    p = sub.add_parser("apps")
    p.add_argument("--udid", required=True)
    p.add_argument("--icons-dir", help="write each app's icon as <bundle id>.png here")
    p = sub.add_parser("selftest")
    p.add_argument("--expect-pymobiledevice3", help="fail unless this pymobiledevice3 version is loaded")
    p.add_argument("--expect-arch", help="fail unless running as this architecture (arm64, x86_64)")
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        out = asyncio.run(COMMANDS[args.command](args))
        print(json.dumps({"ok": True, **out}, default=str), flush=True)
        return 0
    except HelperError as exc:
        print(json.dumps({"ok": False, "error": str(exc), "code": exc.code}), flush=True)
        return 1
    except ImportError as exc:
        print(json.dumps({"ok": False, "code": "dependency_missing",
                          "error": f"Part of Pax's iPhone helper is missing ({exc}). Reinstall Pax "
                                   "(developers: pip install -r device/requirements.txt)."}), flush=True)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "code": "unexpected",
                          "error": f"{type(exc).__name__}: {exc}"[:500]}), flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
