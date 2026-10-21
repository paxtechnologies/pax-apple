# SPDX-License-Identifier: GPL-3.0-only
"""Where things are, in a source checkout and in the frozen (PyInstaller) app."""
from __future__ import annotations

import os
import sys
from pathlib import Path

SHARED = ("device", "profile", "common")


def frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def repo_root() -> Path:
    """The repo checkout (source) or the unpacked bundle folder (frozen)."""
    if frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parents[2]


def add_shared_paths() -> None:
    """Make device/seed.py, device/pax_device.py, profile/make_profile.py and
    common/pax_restricted.py importable. In the frozen app they are already inside the
    bundle; in a checkout they sit next to windows/."""
    root = repo_root()
    for name in SHARED:
        d = root / name
        if d.is_dir() and str(d) not in sys.path:
            sys.path.insert(0, str(d))


def resource(*parts: str) -> Path:
    return repo_root().joinpath(*parts)


def data_dir() -> Path:
    """Per-user folder for Pax's own files (backups, the short-lived supervision key).
    %LOCALAPPDATA%\\Pax on Windows; PAX_DATA_DIR overrides it (tests)."""
    override = os.environ.get("PAX_DATA_DIR")
    if override:
        base = Path(override)
    elif os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"]) / "Pax"
    else:
        base = Path.home() / ".local" / "share" / "pax-windows"
    base.mkdir(parents=True, exist_ok=True)
    return base


def helper_command() -> list[str]:
    """How to start the USB helper (device/pax_device.py) as its own process, like the
    Mac app does: pax-helper.exe next to PaxSetup.exe when frozen, else this Python."""
    if frozen():
        exe = Path(sys.executable).with_name("pax-helper.exe")
        return [str(exe)]
    return [sys.executable, str(Path(__file__).resolve().parents[1] / "helper_main.py")]
