# SPDX-License-Identifier: GPL-3.0-only
"""Build windows/build/pax.ico from the Mac app icon PNGs (mac-app/Resources/AppIcon.iconset),
so no binary icon is kept twice in the repo. Needs Pillow (build only)."""
from pathlib import Path

from PIL import Image

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "mac-app" / "Resources" / "AppIcon.iconset" / "icon_256x256.png"
OUT = Path(__file__).resolve().parent / "build" / "pax.ico"

if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    Image.open(SRC).convert("RGBA").save(OUT, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64),
                                                     (128, 128), (256, 256)])
    print(f"wrote {OUT}")
