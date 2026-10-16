#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Render pax-icon.svg into mac-app/Resources/AppIcon.iconset (16-1024, @1x/@2x)
and mac-app/Resources/AppIcon.icns (PNG-in-ICNS, the format iconutil writes).

  pip install cairosvg   # or have rsvg-convert on PATH
  python3 mac-app/Resources/branding/render_icons.py

build-dmg.sh prefers `iconutil -c icns AppIcon.iconset` on macOS and falls back to
the committed AppIcon.icns.
"""
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SVG = HERE / "pax-icon.svg"
RES = HERE.parent
ICONSET = RES / "AppIcon.iconset"
ICNS = RES / "AppIcon.icns"
SIZES = [16, 32, 128, 256, 512]
# ICNS chunk type for each pixel size (PNG payloads).
ICNS_TYPES = [(b"icp4", 16), (b"icp5", 32), (b"ic11", 32), (b"ic12", 64), (b"ic07", 128),
              (b"ic13", 256), (b"ic08", 256), (b"ic14", 512), (b"ic09", 512), (b"ic10", 1024)]


def render(px: int) -> bytes:
    try:
        import cairosvg  # type: ignore
        return cairosvg.svg2png(url=str(SVG), output_width=px, output_height=px)
    except ImportError:
        if shutil.which("rsvg-convert"):
            return subprocess.run(["rsvg-convert", "-w", str(px), "-h", str(px), str(SVG)],
                                  check=True, capture_output=True).stdout
        sys.exit("need cairosvg (pip install cairosvg) or rsvg-convert")


def main() -> None:
    ICONSET.mkdir(exist_ok=True)
    cache = {px: render(px) for px in {16, 32, 64, 128, 256, 512, 1024}}
    for s in SIZES:
        (ICONSET / f"icon_{s}x{s}.png").write_bytes(cache[s])
        (ICONSET / f"icon_{s}x{s}@2x.png").write_bytes(cache[s * 2])
    chunks = b"".join(t + struct.pack(">I", len(cache[px]) + 8) + cache[px] for t, px in ICNS_TYPES)
    ICNS.write_bytes(b"icns" + struct.pack(">I", len(chunks) + 8) + chunks)
    (RES / "AppIcon.png").write_bytes(cache[1024])
    print(f"wrote {ICONSET} ({len(SIZES) * 2} PNGs), {ICNS} ({ICNS.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
