# SPDX-License-Identifier: GPL-3.0-only
"""`PaxSetup.exe --selftest-out FILE`: no phone needed. Checks the parts of the window app
that CI can check on a Windows runner (the USB side has its own `pax-helper.exe selftest`,
which is device/pax_device.py's selftest): the profile builds with the shared generator,
a supervision identity is made and destroyed, the wording rules hold, the brand files are
in the bundle and tkinter starts."""
from __future__ import annotations

import json
import platform
import plistlib
import sys
import tempfile
from pathlib import Path


def run() -> dict:
    from . import VERSION, choices, driver, identity, paths, profile_maker, wording
    problems: list[str] = []
    paths.add_shared_paths()
    try:
        prof = profile_maker.generate(user_token="SELFTEST" * 3, dns_base=choices.DEFAULT_DNS_BASE)
        p = plistlib.loads(prof.data)
        if not prof.identifier.startswith("org.paxpeace.pax.ios.") or not p.get("PayloadRemovalDisallowed"):
            problems.append("profile: wrong shape")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"profile: {type(exc).__name__}: {exc}")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            ident = identity.create(Path(tmp))
            identity.destroy_private_key(ident)
            if ident.private_key.exists() or not ident.certificate.exists():
                problems.append("identity: key not destroyed")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"identity: {type(exc).__name__}: {exc}")
    for rel in (("mac-app", "Resources", "branding", "pax-white.png"),
                ("mac-app", "Resources", "fonts", "PaxInter-Medium.ttf")):
        if not paths.resource(*rel).exists():
            problems.append(f"missing {'/'.join(rel)}")
    if driver.classify(None, False).state != "missing":
        problems.append("driver: classify")
    if "{wait}" not in wording.AGREEMENT:
        problems.append("wording: agreement")
    try:
        import tkinter
        r = tkinter.Tk()
        r.withdraw()
        r.update_idletasks()
        r.destroy()
    except Exception as exc:  # noqa: BLE001
        problems.append(f"tkinter: {type(exc).__name__}: {exc}")
    helper = paths.helper_command()[0]
    if paths.frozen() and not Path(helper).exists():
        problems.append("pax-helper.exe missing")
    return {"ok": not problems, "problems": problems, "version": VERSION,
            "python": platform.python_version(), "frozen": paths.frozen(), "platform": sys.platform}


def main(out: str) -> int:
    result = run()
    Path(out).write_text(json.dumps(result))
    return 0 if result["ok"] else 1
