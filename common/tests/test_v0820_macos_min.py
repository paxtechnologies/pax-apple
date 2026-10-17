# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.20: Pax runs on macOS 12 Monterey. mac-app/scripts/check-macos-min.py reads every
Mach-O in the build (both arches) and fails on a minimum newer than 12.0 or a strongly
linked library that only exists on macOS 13+."""
import importlib.util
import json
import struct
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("check_macos_min", REPO / "mac-app" / "scripts" / "check-macos-min.py")
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)

ARM64, X86_64 = 0x0100000C, 0x01000007


def dylib_cmd(path: str, cmd: int) -> bytes:
    name = path.encode() + b"\0"
    size = (24 + len(name) + 7) // 8 * 8
    return struct.pack("<IIIIII", cmd, size, 24, 0, 0x10000, 0x10000) + name.ljust(size - 24, b"\0")


def macho(cpu: int, minos: str | None = "12.0", libs=(), platform: int = 1, old_style=False) -> bytes:
    cmds = b""
    if minos is not None and not old_style:
        cmds += struct.pack("<IIIIII", cm.LC_BUILD_VERSION, 24, platform, cm.parse_version(minos),
                            cm.parse_version("15.0"), 0)
    if minos is not None and old_style:
        cmds += struct.pack("<IIII", cm.LC_VERSION_MIN_MACOSX, 16, cm.parse_version(minos), 0)
    for kind, path in libs:
        cmds += dylib_cmd(path, kind)
    ncmds = (1 if minos is not None else 0) + len(libs)
    header = struct.pack("<IiiIIIII", cm.MH_MAGIC_64, cpu, 0, 2, ncmds, len(cmds), 0, 0)
    return header + cmds


def fat(*slices: bytes) -> bytes:
    out = struct.pack(">II", cm.FAT_MAGIC, len(slices))
    off = 4096
    body = b""
    for s in slices:
        cpu = struct.unpack("<i", s[4:8])[0]
        out += struct.pack(">iiIII", cpu, 0, off + len(body), len(s), 12)
        body += s.ljust((len(s) + 4095) // 4096 * 4096, b"\0")
    return out.ljust(off, b"\0") + body


SYS = [(cm.LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"),
       (cm.LC_LOAD_DYLIB, "/System/Library/Frameworks/SwiftUI.framework/Versions/A/SwiftUI"),
       (cm.LC_LOAD_DYLIB, "/usr/lib/swift/libswiftCore.dylib")]


def run(tmp_path, files: dict, *extra):
    for name, data in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return cm.main([*extra, str(tmp_path)])


def test_universal_app_built_for_12_passes(tmp_path, capsys):
    app = fat(macho(ARM64, "12.0", SYS), macho(X86_64, "12.0", SYS))
    rc = run(tmp_path, {"Pax.app/Contents/MacOS/Pax": app,
                        "Pax.app/Contents/Resources/info.json": json.dumps({"a": 1}).encode()},
             "--exact", str(tmp_path / "Pax.app/Contents/MacOS/Pax"),
             "--require-arch", "arm64", "--require-arch", "x86_64")
    assert rc == 0, capsys.readouterr().out
    assert "2 slices" in capsys.readouterr().out


def test_one_arch_built_for_13_fails(tmp_path, capsys):
    app = fat(macho(ARM64, "12.0", SYS), macho(X86_64, "13.0", SYS))
    assert run(tmp_path, {"Pax": app}) == 1
    out = capsys.readouterr().out
    assert "[x86_64]: minimum macOS 13.0 is newer than 12.0" in out and "[arm64]" not in out


def test_exact_needs_12_not_older(tmp_path, capsys):
    assert run(tmp_path, {"Pax": macho(ARM64, "11.0")}, "--exact", str(tmp_path / "Pax")) == 1
    assert "expected exactly 12.0" in capsys.readouterr().out


def test_older_libraries_are_fine(tmp_path):
    # The bundled Python: arm64 11.0, x86_64 10.9 (old LC_VERSION_MIN_MACOSX).
    py = fat(macho(ARM64, "11.0", [(cm.LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib")]),
             macho(X86_64, "10.9", [(cm.LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib")], old_style=True))
    assert run(tmp_path, {"python3.12": py, "lib/_ssl.so": macho(ARM64, "11.0")}) == 0


def test_strong_link_to_a_macos13_library_fails_weak_is_fine(tmp_path, capsys):
    strong = macho(ARM64, "12.0", SYS + [(cm.LC_LOAD_DYLIB, "/usr/lib/swift/libswift_StringProcessing.dylib")])
    assert run(tmp_path, {"a": strong}) == 1
    assert "must be weak-linked" in capsys.readouterr().out
    weak = macho(ARM64, "12.0", SYS + [
        (cm.LC_LOAD_WEAK_DYLIB, "/usr/lib/swift/libswift_StringProcessing.dylib"),
        (cm.LC_LOAD_WEAK_DYLIB, "/System/Library/Frameworks/Charts.framework/Versions/A/Charts")])
    (tmp_path / "a").unlink()
    assert run(tmp_path, {"b": weak}) == 0


def test_unknown_framework_needs_a_person(tmp_path, capsys):
    m = macho(ARM64, "12.0", [(cm.LC_LOAD_DYLIB, "/System/Library/Frameworks/NewThing.framework/NewThing")])
    assert run(tmp_path, {"a": m}) == 1
    assert "KNOWN_ON_12" in capsys.readouterr().out


def test_missing_minimum_or_other_platform_fails(tmp_path, capsys):
    assert run(tmp_path, {"a": macho(ARM64, None)}) == 1
    assert "no minimum macOS version" in capsys.readouterr().out
    (tmp_path / "a").unlink()
    assert run(tmp_path, {"b": macho(ARM64, "12.0", platform=2)}) == 1   # iOS


def test_missing_arch_and_no_macho(tmp_path, capsys):
    assert run(tmp_path, {"Pax": macho(ARM64)}, "--exact", str(tmp_path / "Pax"),
               "--require-arch", "x86_64") == 1
    assert "has no x86_64 slice" in capsys.readouterr().out
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "x.txt").write_text("hello")
    assert cm.main([str(empty)]) == 2


def test_java_class_file_is_not_fat(tmp_path):
    cls = struct.pack(">IHH", 0xCAFEBABE, 0, 65) + b"\0" * 32    # class file version 65
    assert list(cm.slices(cls)) == []


def test_build_targets_monterey():
    """Package.swift, build-dmg.sh and the helper wheels all target macOS 12."""
    pkg = (REPO / "mac-app" / "Package.swift").read_text()
    assert "platforms: [.macOS(.v12)]" in pkg
    dmg = (REPO / "mac-app" / "scripts" / "build-dmg.sh").read_text()
    assert "apple-macosx13" not in dmg and dmg.count("apple-macosx12.0") == 4
    assert "<key>LSMinimumSystemVersion</key><string>12.0</string>" in dmg
    rt = json.loads((REPO / "device" / "helper-runtime.json").read_text())
    assert rt["wheel_platform"] == {"arm64": "macosx_12_0_arm64", "x86_64": "macosx_12_0_x86_64"}
    wf = (REPO / ".github" / "workflows" / "build-dmg.yml").read_text()
    assert "check-macos-min.py" in wf
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    assert "check-macos-min.py" in ci
