#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Render the Pax Peace app icon (v0.8.16 brand: a soft Fraunces "p" on navy,
branding/pax-icon-navy-1024.png from the brand kit) into
mac-app/Resources/AppIcon.iconset (16-1024, @1x/@2x), AppIcon.png and
AppIcon.icns (PNG-in-ICNS, the format iconutil writes).

The artwork sits on Apple's macOS icon grid: 824 px of a 1024 px canvas, centred,
with a soft shadow, so it lines up with other Mac apps in the Dock.

  pip install pillow
  python3 mac-app/Resources/branding/render_icons.py

build-dmg.sh prefers `iconutil -c icns AppIcon.iconset` on macOS and falls back to
the committed AppIcon.icns.
"""
import io
import struct
from pathlib import Path

from PIL import Image, ImageFilter

HERE = Path(__file__).resolve().parent
ART = HERE / "pax-icon-navy-1024.png"
RES = HERE.parent
ICONSET = RES / "AppIcon.iconset"
ICNS = RES / "AppIcon.icns"
SIZES = [16, 32, 128, 256, 512]
# ICNS chunk type for each pixel size (PNG payloads).
ICNS_TYPES = [(b"icp4", 16), (b"icp5", 32), (b"ic11", 32), (b"ic12", 64), (b"ic07", 128),
              (b"ic13", 256), (b"ic08", 256), (b"ic14", 512), (b"ic09", 512), (b"ic10", 1024)]
GRID = 824          # artwork size on the 1024 canvas (macOS icon grid)


def master() -> Image.Image:
    art = Image.open(ART).convert("RGBA").resize((GRID, GRID), Image.LANCZOS)
    canvas = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    off = (1024 - GRID) // 2
    # Soft drop shadow from the artwork's own shape.
    alpha = art.split()[3]
    shadow = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    shade = Image.new("RGBA", art.size, (16, 24, 34, 90))
    shadow.paste(shade, (off, off + 12), alpha)
    shadow = shadow.filter(ImageFilter.GaussianBlur(14))
    canvas = Image.alpha_composite(canvas, shadow)
    canvas.alpha_composite(art, (off, off))
    return canvas


def png(img: Image.Image, px: int) -> bytes:
    out = io.BytesIO()
    img.resize((px, px), Image.LANCZOS).save(out, "PNG", optimize=True)
    return out.getvalue()


def main() -> None:
    m = master()
    ICONSET.mkdir(exist_ok=True)
    cache = {px: png(m, px) for px in {16, 32, 64, 128, 256, 512, 1024}}
    for s in SIZES:
        (ICONSET / f"icon_{s}x{s}.png").write_bytes(cache[s])
        (ICONSET / f"icon_{s}x{s}@2x.png").write_bytes(cache[s * 2])
    chunks = b"".join(t + struct.pack(">I", len(cache[px]) + 8) + cache[px] for t, px in ICNS_TYPES)
    ICNS.write_bytes(b"icns" + struct.pack(">I", len(chunks) + 8) + chunks)
    (RES / "AppIcon.png").write_bytes(cache[1024])
    print(f"wrote {ICONSET} ({len(SIZES) * 2} PNGs), {ICNS} ({ICNS.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
