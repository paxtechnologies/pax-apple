#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.20: prove a build runs on macOS 12 Monterey without a Monterey Mac.

CI runners only run newer macOS, so this reads the Mach-O files themselves:

  * every Mach-O slice (both arches of a universal file) must say it runs on
    macOS 12.0 or older (LC_BUILD_VERSION minos, or LC_VERSION_MIN_MACOSX on old
    tools); Pax's own executables must say exactly 12.0 (--exact);
  * a library loaded strongly (LC_LOAD_DYLIB / LC_REEXPORT_DYLIB) must exist on
    macOS 12: anything Apple added in macOS 13 or later (Charts, the Swift regex
    runtime, Observation, ...) may only be weak-linked (LC_LOAD_WEAK_DYLIB), where a
    missing library is simply skipped at launch instead of crashing.
    System frameworks not on the list below fail too, so a new dependency gets checked
    once by a person before it ships.

Symbol-level safety (a macOS 13 function inside a framework that macOS 12 has) is
enforced by the compiler: with the deployment target at 12.0 Swift refuses any call to
a newer API outside `if #available`, and those calls are weak references.

usage: check-macos-min.py [--max 12.0] [--exact PATH ...] PATH ...   (files or folders)
exit 0 = all good; 1 = a problem (each one printed); 2 = no Mach-O found.
Pure Python (no otool), so the tests run on Linux too.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys

MH_MAGIC_64, MH_CIGAM_64, MH_MAGIC, MH_CIGAM = 0xFEEDFACF, 0xCFFAEDFE, 0xFEEDFACE, 0xCEFAEDFE
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
LC_REQ_DYLD = 0x80000000
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32
PLATFORM_MACOS = 1
CPU_NAMES = {0x01000007: "x86_64", 0x0100000C: "arm64", 7: "i386", 12: "arm"}

STRONG = {LC_LOAD_DYLIB: "load", LC_REEXPORT_DYLIB: "reexport", LC_LOAD_UPWARD_DYLIB: "upward",
          LC_LAZY_LOAD_DYLIB: "lazy"}

# Added in macOS 13 or later: never strongly linked.
NEWER_THAN_12 = (
    "/System/Library/Frameworks/Charts.framework/",
    "/System/Library/Frameworks/SwiftData.framework/",
    "/System/Library/Frameworks/Observation.framework/",
    "/System/Library/Frameworks/SwiftUICore.framework/",
    "/System/Library/Frameworks/AppIntents.framework/",
    "/System/Library/Frameworks/BackgroundAssets.framework/",
    "/System/Library/Frameworks/ExtensionFoundation.framework/",
    "/System/Library/Frameworks/ExtensionKit.framework/",
    "/System/Library/Frameworks/SafetyKit.framework/",
    "/System/Library/Frameworks/TipKit.framework/",
    "/System/Library/Frameworks/Translation.framework/",
    "/System/Library/Frameworks/CoreTransferable.framework/",
    "/System/Library/Frameworks/DeveloperToolsSupport.framework/",
    "/usr/lib/swift/libswift_StringProcessing.dylib",
    "/usr/lib/swift/libswift_RegexParser.dylib",
    "/usr/lib/swift/libswiftObservation.dylib",
    "/usr/lib/swift/libswiftSynchronization.dylib",
    "/usr/lib/swift/libswiftDistributed.dylib",
    "/usr/lib/swift/libswift_Builtin_float.dylib",
)

# Present on macOS 12 (or older). Anything else under /System/Library fails until a
# person has checked it and added it here.
KNOWN_ON_12 = {
    "AppKit", "ApplicationServices", "Carbon", "Cocoa", "Combine", "CoreData", "CoreFoundation",
    "CoreGraphics", "CoreImage", "CoreServices", "CoreText", "CryptoKit",
    "DiskArbitration", "Foundation", "IOKit", "ImageIO", "LocalAuthentication",
    "Network", "OSLog", "QuartzCore", "Security", "ServiceManagement", "SwiftUI",
    "SystemConfiguration", "UniformTypeIdentifiers", "UserNotifications", "CFNetwork", "GSS",
    "Kerberos", "Tcl", "Tk", "AudioToolbox", "CoreAudio", "Accelerate", "Metal",
    "CoreVideo", "CoreMedia", "AVFoundation", "WebKit", "Symbols", "OpenDirectory", "CoreWLAN",
}
KNOWN_USR_LIB_PREFIXES = ("/usr/lib/libSystem", "/usr/lib/libobjc", "/usr/lib/libc++", "/usr/lib/libz",
                          "/usr/lib/libbz2", "/usr/lib/liblzma", "/usr/lib/libncurses", "/usr/lib/libedit",
                          "/usr/lib/libffi", "/usr/lib/libiconv", "/usr/lib/libsqlite3", "/usr/lib/libxml2",
                          "/usr/lib/libexpat", "/usr/lib/libcompression", "/usr/lib/libresolv",
                          "/usr/lib/libpanel", "/usr/lib/libform", "/usr/lib/libmenu", "/usr/lib/libutil",
                          "/usr/lib/libpam", "/usr/lib/libcurl", "/usr/lib/libbsm")


def _ver(v: int) -> str:
    return f"{v >> 16}.{(v >> 8) & 0xFF}" + (f".{v & 0xFF}" if v & 0xFF else "")


def parse_version(s: str) -> int:
    parts = [int(x) for x in s.split(".")] + [0, 0]
    return (parts[0] << 16) | (parts[1] << 8) | parts[2]


def slices(data: bytes):
    """Yields (arch, offset, size) for a thin or fat Mach-O; nothing for anything else."""
    if len(data) < 8:
        return
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        n = struct.unpack(">I", data[4:8])[0]
        if n > 64:          # a Java class file shares 0xCAFEBABE; it has a version here
            return
        pos = 8
        for _ in range(n):
            if magic == FAT_MAGIC:
                cpu, _sub, off, size, _al = struct.unpack(">iiIII", data[pos:pos + 20]); pos += 20
            else:
                cpu, _sub, off, size, _al, _r = struct.unpack(">iiQQII", data[pos:pos + 32]); pos += 32
            yield CPU_NAMES.get(cpu & 0xFFFFFFFF, hex(cpu & 0xFFFFFFFF)), off, size
        return
    le = struct.unpack("<I", data[:4])[0]
    if le in (MH_MAGIC_64, MH_MAGIC) or magic in (MH_MAGIC_64, MH_MAGIC):
        endian = "<" if le in (MH_MAGIC_64, MH_MAGIC) else ">"
        cpu = struct.unpack(endian + "i", data[4:8])[0]
        yield CPU_NAMES.get(cpu & 0xFFFFFFFF, hex(cpu & 0xFFFFFFFF)), 0, len(data)


def read_slice(data: bytes, off: int, size: int) -> dict:
    """minos (int or None) and the dylibs it loads [(kind, path)] for one slice."""
    d = data[off:off + size]
    le = struct.unpack("<I", d[:4])[0]
    endian = "<" if le in (MH_MAGIC_64, MH_MAGIC) else ">"
    magic = struct.unpack(endian + "I", d[:4])[0]
    is64 = magic == MH_MAGIC_64
    _m, _cpu, _sub, _ft, ncmds, _sz, _fl = struct.unpack(endian + "IiiIIII", d[:28])
    pos = 32 if is64 else 28
    out = {"minos": None, "platform": None, "dylibs": []}
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack(endian + "II", d[pos:pos + 8])
        if cmdsize < 8:
            raise ValueError("bad load command size")
        if cmd == LC_BUILD_VERSION:
            platform, minos = struct.unpack(endian + "II", d[pos + 8:pos + 16])
            out["platform"], out["minos"] = platform, minos
        elif cmd == LC_VERSION_MIN_MACOSX and out["minos"] is None:
            out["platform"] = PLATFORM_MACOS
            out["minos"] = struct.unpack(endian + "I", d[pos + 8:pos + 12])[0]
        elif cmd in STRONG or cmd == LC_LOAD_WEAK_DYLIB:
            name_off = struct.unpack(endian + "I", d[pos + 8:pos + 12])[0]
            raw = d[pos + name_off:pos + cmdsize]
            path = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
            out["dylibs"].append(("weak" if cmd == LC_LOAD_WEAK_DYLIB else STRONG[cmd], path))
        pos += cmdsize
    return out


def strong_dylib_problem(path: str) -> str | None:
    for p in NEWER_THAN_12:
        if path == p or path.startswith(p):
            return "needs macOS 13 or later but is strongly linked (it must be weak-linked)"
    if path.startswith(("@rpath/", "@loader_path/", "@executable_path/")):
        return None      # inside the bundle; checked as its own file
    if path.startswith("/System/Library/Frameworks/") or path.startswith("/System/Library/PrivateFrameworks/"):
        name = path.split("/")[4].removesuffix(".framework")
        if name in KNOWN_ON_12:
            return None
        return ("is not on the list of frameworks known to exist on macOS 12; check when Apple "
                "added it and add it to KNOWN_ON_12 (or weak-link it)")
    if path.startswith("/usr/lib/swift/"):
        return None      # Swift runtime libraries on macOS 12; the newer ones are listed above
    if path.startswith(KNOWN_USR_LIB_PREFIXES):
        return None
    if path.startswith("/usr/lib/"):
        return "is a system library not checked for macOS 12; add it to KNOWN_USR_LIB_PREFIXES once checked"
    return "is outside the bundle and the system (a build machine path?)"


def check_file(path: str, max_minos: int, exact: bool) -> tuple[list[str], int]:
    with open(path, "rb") as f:
        head = f.read(8)
        if len(head) < 8:
            return [], 0
        data = head + f.read()
    found = list(slices(data))
    problems = []
    for arch, off, size in found:
        try:
            info = read_slice(data, off, size)
        except (struct.error, ValueError) as e:
            problems.append(f"{path} [{arch}]: can't read the Mach-O ({e})")
            continue
        m = info["minos"]
        if m is None:
            problems.append(f"{path} [{arch}]: no minimum macOS version in the file")
        elif info["platform"] != PLATFORM_MACOS:
            problems.append(f"{path} [{arch}]: built for platform {info['platform']}, not macOS")
        elif exact and m != max_minos:
            problems.append(f"{path} [{arch}]: minimum macOS {_ver(m)}, expected exactly {_ver(max_minos)}")
        elif m > max_minos:
            problems.append(f"{path} [{arch}]: minimum macOS {_ver(m)} is newer than {_ver(max_minos)}")
        for kind, lib in info["dylibs"]:
            if kind == "weak":
                continue
            why = strong_dylib_problem(lib)
            if why:
                problems.append(f"{path} [{arch}]: {lib} {why}")
    return problems, len(found)


def walk(paths):
    for p in paths:
        if os.path.isdir(p) and not os.path.islink(p):
            for d, dirs, fs in os.walk(p):
                dirs.sort()
                for f in sorted(fs):
                    full = os.path.join(d, f)
                    if not os.path.islink(full) and os.path.isfile(full):
                        yield full
        elif os.path.isfile(p):
            yield p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--max", default="12.0", help="newest allowed minimum macOS (default 12.0)")
    ap.add_argument("--exact", action="append", default=[], help="a file whose minimum must equal --max")
    ap.add_argument("--require-arch", action="append", default=[],
                    help="each --exact file must contain this arch (repeatable)")
    ap.add_argument("paths", nargs="*")
    a = ap.parse_args(argv)
    limit = parse_version(a.max)
    exact = {os.path.realpath(p) for p in a.exact}
    problems, files, slices_seen = [], 0, 0
    for p in list(dict.fromkeys(list(walk(a.paths)) + a.exact)):
        is_exact = os.path.realpath(p) in exact
        probs, n = check_file(p, limit, is_exact)
        if n:
            files += 1
            slices_seen += n
            problems += probs
            if is_exact and a.require_arch:
                with open(p, "rb") as f:
                    archs = {s[0] for s in slices(f.read())}
                for want in a.require_arch:
                    if want not in archs:
                        problems.append(f"{p}: has no {want} slice")
        elif is_exact:
            problems.append(f"{p}: not a Mach-O file")
    for x in problems:
        print("FAIL", x)
    if not files:
        print("no Mach-O files found")
        return 2
    print(f"checked {files} Mach-O files ({slices_seen} slices): "
          + ("all run on macOS " + _ver(limit) if not problems else f"{len(problems)} problem(s)"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
