#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pieces of the bundled iPhone-helper runtime build (v0.8.6) that are plain file work,
kept here so they are unit-tested (device/tests/test_helper_runtime.py) instead of
living in shell. mac-app/scripts/build-device-helper.sh drives them:

  prune DIR                 remove what the helper never uses from an extracted
                            python-build-standalone tree (DIR is its `python/` folder)
  merge ARM64 X86_64 OUT    one universal2 tree: every Mach-O pair becomes a fat
                            binary with `lipo -create`; everything else must be the same
                            in both trees (a few known per-arch text files excepted)
  verify-universal DIR      every Mach-O in DIR has both arm64 and x86_64 (lipo -archs)
  list-macho DIR            NUL-separated Mach-O paths, dylibs and modules first and
                            the executables last (the order codesign needs)
  executables DIR           NUL-separated Mach-O executables (they get entitlements)
  pin NAME                  the pinned version of NAME in device/requirements-bundle.in
  runtime KEY [ARCH]        a value from device/helper-runtime.json
  guard-manifest DIR --team TEAM|- --out FILE
                            v0.8.6: runtime-manifest.json for pax-guard's own copy of the
                            runtime (guard/guard_runtime.py): every file except
                            site-packages, with its SHA-256, size and mode. Run after every
                            Mach-O is signed (signing changes them) and before the app is.

Only the standard library is used, so any Python 3.9+ can run it.
"""
from __future__ import annotations

import filecmp
import fnmatch
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RUNTIME_JSON = REPO / "device" / "helper-runtime.json"
BUNDLE_IN = REPO / "device" / "requirements-bundle.in"
ARCHS = ("arm64", "x86_64")
PYVER = "3.12"

# Paths (relative to the python/ folder, fnmatch patterns) the helper never needs.
# Tk/Tcl, IDLE, the test suite, headers, pip and the other tools go; the interpreter,
# libpython, the stdlib and lib-dynload stay.
PRUNE = [
    "include", "share", "lib/pkgconfig",
    "lib/tcl*", "lib/tk*", "lib/itcl*", "lib/thread*", "lib/libtcl*", "lib/libtk*",
    f"lib/python{PYVER}/test", f"lib/python{PYVER}/idlelib", f"lib/python{PYVER}/tkinter",
    f"lib/python{PYVER}/turtledemo", f"lib/python{PYVER}/turtle.py", f"lib/python{PYVER}/ensurepip",
    f"lib/python{PYVER}/lib2to3", f"lib/python{PYVER}/pydoc_data", f"lib/python{PYVER}/config-*",
    f"lib/python{PYVER}/lib-dynload/_tkinter*", f"lib/python{PYVER}/lib-dynload/_test*",
    f"lib/python{PYVER}/lib-dynload/xxlimited*", f"lib/python{PYVER}/lib-dynload/_xx*",
    f"lib/python{PYVER}/site-packages/*",
]
KEEP_BIN = {f"python{PYVER}"}
# Text files that legitimately differ per architecture: the arm64 copy is kept.
ALLOWED_DIFFERENT = [
    f"lib/python{PYVER}/_sysconfigdata_*.py",
    f"lib/python{PYVER}/site-packages/*.dist-info/RECORD",
    f"lib/python{PYVER}/site-packages/*.dist-info/WHEEL",
]

MH_MAGICS = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
FAT_MAGICS = {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}
MH_EXECUTE = 2


def is_macho(path: Path) -> bool:
    """Thin or fat Mach-O. A fat header is told apart from a Java class file
    (same magic) by its small architecture count."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return False
    if head[:4] in MH_MAGICS:
        return True
    if head[:4] in FAT_MAGICS and len(head) == 8:
        return 0 < struct.unpack(">I", head[4:])[0] < 32
    return False


def macho_filetype(path: Path) -> Optional[int]:
    """MH_EXECUTE (2), MH_DYLIB (6), MH_BUNDLE (8)... of the first slice."""
    with open(path, "rb") as f:
        data = f.read(4096)
    magic = data[:4]
    if magic in FAT_MAGICS:
        offset = struct.unpack(">I", data[16:20])[0]
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(16)
        magic = data[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return struct.unpack("<I", data[12:16])[0]
    if magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return struct.unpack(">I", data[12:16])[0]
    return None


def _rel_files(root: Path) -> dict[str, Path]:
    out = {}
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files) + [x for x in dirs if (Path(d) / x).is_symlink()]:
            p = Path(d) / name
            out[p.relative_to(root).as_posix()] = p
    return out


def _matches(rel: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(rel, pat) for pat in patterns)


def prune(root: Path) -> list[str]:
    """Remove PRUNE paths, every bin/ entry but the interpreter, and __pycache__."""
    root = Path(root)
    if not (root / "bin" / f"python{PYVER}").exists():
        raise SystemExit(f"{root} doesn't look like a python-build-standalone python/ folder")
    removed = []
    for entry in sorted((root / "bin").iterdir()):
        if entry.name not in KEEP_BIN:
            entry.unlink() if entry.is_symlink() or entry.is_file() else shutil.rmtree(entry)
            removed.append(f"bin/{entry.name}")
    for d, dirs, files in os.walk(root, topdown=True):
        here = Path(d)
        for name in list(dirs) + list(files):
            p = here / name
            rel = p.relative_to(root).as_posix()
            if name == "__pycache__" or _matches(rel, PRUNE):
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p)
                    if name in dirs:
                        dirs.remove(name)
                else:
                    p.unlink()
                removed.append(rel)
    return removed


def run_lipo(out: Path, a: Path, b: Path) -> None:
    subprocess.run(["lipo", "-create", str(a), str(b), "-output", str(out)], check=True)


def lipo_archs(path: Path) -> set[str]:
    r = subprocess.run(["lipo", "-archs", str(path)], capture_output=True, text=True, check=True)
    return set(r.stdout.split())


def merge(arm: Path, x86: Path, out: Path, lipo: Callable[[Path, Path, Path], None] = run_lipo) -> dict:
    """Merge two single-arch trees into `out`. Raises SystemExit on anything that
    would leave one architecture without a file it needs."""
    arm, x86, out = Path(arm), Path(x86), Path(out)
    if out.exists():
        raise SystemExit(f"{out} already exists")
    a_files, x_files = _rel_files(arm), _rel_files(x86)
    problems, stats = [], {"lipo": 0, "same": 0, "arm64_copy": 0, "symlink": 0}
    for rel in sorted(set(a_files) | set(x_files)):
        a, x = a_files.get(rel), x_files.get(rel)
        if a is None or x is None:
            problems.append(f"only in {'x86_64' if a is None else 'arm64'}: {rel}")
            continue
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if a.is_symlink() or x.is_symlink():
            if not (a.is_symlink() and x.is_symlink() and os.readlink(a) == os.readlink(x)):
                problems.append(f"symlink differs: {rel}")
                continue
            target = os.readlink(a)
            if os.path.isabs(target) or ".." in Path(target).parts:
                problems.append(f"symlink leaves its folder: {rel} -> {target}")
                continue
            os.symlink(target, dest)
            stats["symlink"] += 1
            continue
        if filecmp.cmp(a, x, shallow=False):
            shutil.copy2(a, dest)
            stats["same"] += 1
        elif is_macho(a) and is_macho(x):
            lipo(dest, a, x)
            shutil.copymode(a, dest)
            stats["lipo"] += 1
        elif _matches(rel, ALLOWED_DIFFERENT):
            shutil.copy2(a, dest)
            stats["arm64_copy"] += 1
        else:
            problems.append(f"differs between architectures: {rel}")
    if problems:
        shutil.rmtree(out, ignore_errors=True)
        raise SystemExit("merge failed:\n  " + "\n  ".join(problems[:50]))
    return stats


def list_macho(root: Path) -> list[Path]:
    """Mach-O files under root, libraries and modules first, executables last."""
    found = [p for p in _rel_files(Path(root)).values() if not p.is_symlink() and p.is_file() and is_macho(p)]
    return sorted(found, key=lambda p: (macho_filetype(p) == MH_EXECUTE, str(p)))


def executables(root: Path) -> list[Path]:
    return [p for p in list_macho(root) if macho_filetype(p) == MH_EXECUTE]


def verify_universal(root: Path, archs: Callable[[Path], set[str]] = lipo_archs) -> list[str]:
    bad = []
    files = list_macho(root)
    if not files:
        return [f"no Mach-O files under {root}"]
    for p in files:
        have = archs(p)
        if not set(ARCHS) <= have:
            bad.append(f"{p}: {sorted(have)}")
    return bad


def pin(name: str, text: Optional[str] = None) -> str:
    text = BUNDLE_IN.read_text() if text is None else text
    m = re.search(rf"^{re.escape(name)}==(\S+)\s*$", text, re.M | re.I)
    if not m:
        raise SystemExit(f"{name} is not pinned in {BUNDLE_IN.name}")
    return m.group(1)


def runtime(key: str, arch: Optional[str] = None):
    data = json.loads(RUNTIME_JSON.read_text())
    if key in ("url", "sha256"):
        return data["archives"][arch][key]
    if key == "wheel_platform":
        return data["wheel_platform"][arch]
    return data[key]


# v0.8.6: pax-guard needs the interpreter and the standard library only.
GUARD_EXCLUDE = [f"lib/python{PYVER}/site-packages", f"lib/python{PYVER}/site-packages/*"]


def guard_manifest(root: Path, team_id: Optional[str]) -> dict:
    """The manifest guard_runtime.py checks pax-guard's runtime copy against."""
    sys.path.insert(0, str(REPO / "guard"))
    import guard_runtime as grt
    root = Path(root)
    files, links = [], []
    for rel, p in sorted(_rel_files(root).items()):
        if _matches(rel, GUARD_EXCLUDE):
            continue
        if p.is_symlink():
            target = os.readlink(p)
            if target.startswith("/") or os.path.normpath(os.path.join(os.path.dirname(rel), target)).split("/")[0] == "..":
                raise SystemExit(f"symlink {rel} points outside the runtime: {target}")
            links.append({"path": rel, "target": target})
            continue
        if not p.is_file():
            continue
        import hashlib
        files.append({"path": rel, "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                      "size": p.stat().st_size, "mode": p.stat().st_mode & 0o777, "macho": is_macho(p)})
    m = {"schema": grt.SCHEMA, "interpreter": f"bin/python{PYVER}",
         "python_version": str(runtime("python_version")) if RUNTIME_JSON.exists() else PYVER,
         "team_id": team_id or None, "files": files, "symlinks": links}
    m["digest"] = grt.manifest_digest(m)
    grt.validate_manifest(m)
    return m


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd == "prune":
        print(f"pruned {len(prune(Path(args[0])))} paths")
    elif cmd == "merge":
        print(json.dumps(merge(Path(args[0]), Path(args[1]), Path(args[2]))))
    elif cmd == "verify-universal":
        bad = verify_universal(Path(args[0]))
        if bad:
            print("not universal:\n  " + "\n  ".join(bad), file=sys.stderr)
            return 1
        print(f"universal: {len(list_macho(Path(args[0])))} Mach-O files have arm64 + x86_64")
    elif cmd in ("list-macho", "executables"):
        paths = list_macho(Path(args[0])) if cmd == "list-macho" else executables(Path(args[0]))
        sys.stdout.write("".join(f"{p}\0" for p in paths))
    elif cmd == "pin":
        print(pin(args[0]))
    elif cmd == "runtime":
        print(runtime(args[0], args[1] if len(args) > 1 else None))
    elif cmd == "guard-manifest":
        team = args[args.index("--team") + 1] if "--team" in args else "-"
        m = guard_manifest(Path(args[0]), None if team in ("", "-") else team)
        Path(args[args.index("--out") + 1]).write_text(json.dumps(m, sort_keys=True, indent=0) + "\n")
        print(f"runtime manifest: {len(m['files'])} files, {sum(f['macho'] for f in m['files'])} Mach-O, "
              f"{sum(f['size'] for f in m['files']) // 1024} KB, team {m['team_id'] or 'none (not Developer ID)'}")
    else:
        print(f"unknown command {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
