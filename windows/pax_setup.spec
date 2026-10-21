# -*- mode: python ; coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-only
# PyInstaller (onedir) for "Pax for iPhone set-up" on Windows:
#   dist/PaxSetup/PaxSetup.exe    the window (tkinter, no console)
#   dist/PaxSetup/pax-helper.exe  device/pax_device.py, unchanged, as a console program the
#                                 window starts hidden (CREATE_NO_WINDOW), like the Mac app
#                                 starts its bundled Python helper
# Both share one _internal folder. Build from the repo root:
#   pyinstaller --noconfirm --distpath dist --workpath build windows/pax_setup.spec
import os
import re
from pathlib import Path

from PyInstaller.utils.hooks import copy_metadata

REPO = Path(SPECPATH).resolve().parent
WIN = REPO / "windows"
PATHEX = [str(WIN), str(REPO / "device"), str(REPO / "profile"), str(REPO / "common")]
ICON = WIN / "build" / "pax.ico"
icon = str(ICON) if ICON.exists() else None

brand = [
    (str(REPO / "mac-app/Resources/fonts/PaxInter-Medium.ttf"), "mac-app/Resources/fonts"),
    (str(REPO / "mac-app/Resources/fonts/PaxFrauncesSoft-Regular.ttf"), "mac-app/Resources/fonts"),
    (str(REPO / "mac-app/Resources/branding/pax-white.png"), "mac-app/Resources/branding"),
    (str(REPO / "LICENSE"), "."),
    (str(REPO / "THIRD_PARTY_NOTICES.md"), "."),
    (str(REPO / "docs/DEPENDENCIES.md"), "docs"),
    (str(REPO / "licenses"), "licenses"),
]
if icon:
    brand.append((icon, "windows/build"))

# Everything device/pax_device.py imports from pymobiledevice3 (pax_device.SELFTEST_IMPORTS)
# plus the Windows OS layer. PyInstaller finds most of these on its own; listing them keeps a
# pymobiledevice3 refactor from silently dropping one (the CI selftest would catch it too).
helper_hidden = [
    "pymobiledevice3.usbmux", "pymobiledevice3.lockdown", "pymobiledevice3.exceptions",
    "pymobiledevice3.services.mobile_config", "pymobiledevice3.services.installation_proxy",
    "pymobiledevice3.services.springboard", "pymobiledevice3.services.diagnostics",
    "pymobiledevice3.services.mobilebackup2", "pymobiledevice3.services.afc",
    "pymobiledevice3.services.notification_proxy", "pymobiledevice3.services.device_link",
    "pymobiledevice3.osu.os_utils", "pymobiledevice3.osu.win_util",
    "win32security", "win32api", "winreg", "app_blocks", "seed",
]
# Each bundled package's .dist-info (its version for `pax-helper.exe selftest`, and its licence
# files, as on the Mac where every wheel's licence ships in its .dist-info folder).
metadata = []
for line in (WIN / "requirements-windows.in").read_text().splitlines():
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==", line.strip())
    if m:
        try:
            metadata += copy_metadata(m.group(1))
        except Exception:  # noqa: BLE001  (a package without metadata: reported by the selftest)
            pass

excludes = ["IPython", "fastapi", "uvicorn", "PIL", "av", "matplotlib", "numpy", "pytest"]

a_app = Analysis([str(WIN / "app_main.py")], pathex=PATHEX, datas=brand,
                 hiddenimports=["make_profile", "pax_restricted", "pax_errors", "win32crypt",
                                "pax_windows.gui", "pax_windows.selftest"],
                 excludes=excludes, noarchive=False)
a_helper = Analysis([str(WIN / "helper_main.py")], pathex=PATHEX, datas=metadata,
                    hiddenimports=helper_hidden, excludes=excludes + ["tkinter"], noarchive=False)

pyz_app = PYZ(a_app.pure)
pyz_helper = PYZ(a_helper.pure)

exe_app = EXE(pyz_app, a_app.scripts, [], exclude_binaries=True, name="PaxSetup",
              console=False, icon=icon, upx=False, version=None)
exe_helper = EXE(pyz_helper, a_helper.scripts, [], exclude_binaries=True, name="pax-helper",
                 console=True, icon=icon, upx=False)

coll = COLLECT(exe_app, a_app.binaries, a_app.datas,
               exe_helper, a_helper.binaries, a_helper.datas,
               strip=False, upx=False, name="PaxSetup")
