# SPDX-License-Identifier: GPL-3.0-only
"""Is Apple's device driver here? On Windows, pymobiledevice3 reaches the iPhone through
Apple Mobile Device Service (AMDS), which listens on 127.0.0.1:27015. It comes with
Apple's "Apple Devices" app from the Microsoft Store, or with iTunes. Pax doesn't ship
Apple's driver (it isn't Pax's to redistribute); it detects it and guides the person.

Detection, as pymobiledevice3.osu.win_util does it: the service's registry key
(HKLM\\SYSTEM\\CurrentControlSet\\Services\\Apple Mobile Device Service, ImagePath),
plus a connect to the port to see it is actually running."""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Callable, Optional

AMDS_KEY = r"SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service"
AMDS_ADDRESS = ("127.0.0.1", 27015)
STORE_PRODUCT_ID = "9NP83LWLPZ9K"          # Apple Devices (Apple Inc.), Microsoft Store
STORE_URI = f"ms-windows-store://pdp/?ProductId={STORE_PRODUCT_ID}"
STORE_WEB = f"https://apps.microsoft.com/detail/{STORE_PRODUCT_ID.lower()}"


@dataclass(frozen=True)
class DriverStatus:
    state: str                 # "ok" | "missing" | "stopped"
    source: Optional[str]      # "apple_devices" | "itunes" | None

    @property
    def ok(self) -> bool:
        return self.state == "ok"


def classify(image_path: Optional[str], port_open: bool) -> DriverStatus:
    source = None
    if image_path:
        source = "apple_devices" if "windowsapps" in image_path.lower() else "itunes"
    if port_open:
        return DriverStatus("ok", source)
    if image_path:
        return DriverStatus("stopped", source)
    return DriverStatus("missing", None)


def read_image_path() -> Optional[str]:
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AMDS_KEY) as key:
            return str(winreg.QueryValueEx(key, "ImagePath")[0])
    except OSError:
        return None


def port_open(address: tuple[str, int] = AMDS_ADDRESS, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection(address, timeout=timeout):
            return True
    except OSError:
        return False


def check(reader: Callable[[], Optional[str]] = read_image_path,
          probe: Callable[[], bool] = port_open) -> DriverStatus:
    return classify(reader(), probe())


def open_store() -> None:
    import os
    import webbrowser
    try:
        os.startfile(STORE_URI)          # type: ignore[attr-defined]  (Windows only)
    except (AttributeError, OSError):
        webbrowser.open(STORE_WEB)
