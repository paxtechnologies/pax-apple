# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.6: how the iPhone helper is bundled into Pax.app (mac-app/scripts/helper_runtime.py,
build-device-helper.sh, build-dmg.sh, the Build DMG workflow) and what users are told.
The macOS-only parts (lipo, codesign, notarisation) run in the Build DMG workflow; here
the file logic runs with fakes."""
import json
import os
import plistlib
import re
import struct
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
DEVICE = HERE.parent
REPO = DEVICE.parent
SCRIPTS = REPO / "mac-app" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(DEVICE))

import helper_runtime as hr  # noqa: E402
import lock_bundle  # noqa: E402
import pax_device  # noqa: E402

VERSION = "0.8.20"


def macho(filetype=6, cpu=0x0100000C):
    """A minimal thin 64-bit little-endian Mach-O header."""
    return b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIII", cpu, 0, filetype, 0, 0, 0) + b"\0" * 32


def fat(*slices):
    head = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(slices))
    offset = 4096
    table, body = b"", b""
    for s in slices:
        table += struct.pack(">IIIII", 0, 0, offset + len(body), len(s), 12)
        body += s
    return (head + table).ljust(offset, b"\0") + body


# ---------------- Mach-O detection ----------------

def test_is_macho(tmp_path):
    cases = {"thin": macho(), "fat": fat(macho(), macho()), "text": b"#!/bin/sh\n",
             "java": b"\xca\xfe\xba\xbe\x00\x00\x00\x34rest", "empty": b""}
    for name, data in cases.items():
        (tmp_path / name).write_bytes(data)
    assert {n for n in cases if hr.is_macho(tmp_path / n)} == {"thin", "fat"}
    assert hr.macho_filetype(tmp_path / "thin") == 6
    (tmp_path / "exe").write_bytes(fat(macho(2), macho(2)))
    assert hr.macho_filetype(tmp_path / "exe") == hr.MH_EXECUTE


def fake_tree(root: Path, arch: str):
    py = root / "python"
    files = {
        "bin/python3.12": macho(2, 0x0100000C if arch == "arm64" else 0x01000007) + arch.encode(),
        "lib/libpython3.12.dylib": macho(6) + arch.encode(),
        "lib/python3.12/os.py": b"# os\n",
        f"lib/python3.12/_sysconfigdata__darwin_darwin.py": f"ARCH={arch!r}\n".encode(),
        "lib/python3.12/lib-dynload/_tkinter.cpython-312-darwin.so": macho(8) + arch.encode(),
        "lib/python3.12/test/test_os.py": b"",
        "lib/python3.12/idlelib/x.py": b"",
        "lib/python3.12/__pycache__/os.cpython-312.pyc": b"pyc",
        "lib/python3.12/site-packages/pip/__init__.py": b"",
        "lib/libtcl9.0.dylib": macho(6),
        "lib/tcl9.0/init.tcl": b"",
        "include/python3.12/Python.h": b"",
        "share/man/man1/python3.1": b"",
        "bin/pip3": b"#!/x\n",
        "bin/idle3.12": b"#!/x\n",
    }
    for rel, data in files.items():
        p = py / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    os.symlink("python3.12", py / "bin" / "python3")
    return py


def test_prune_keeps_the_interpreter_and_stdlib(tmp_path):
    py = fake_tree(tmp_path, "arm64")
    hr.prune(py)
    left = sorted(p.relative_to(py).as_posix() for p in py.rglob("*") if p.is_file() or p.is_symlink())
    assert left == ["bin/python3.12", "lib/libpython3.12.dylib", "lib/python3.12/_sysconfigdata__darwin_darwin.py",
                    "lib/python3.12/os.py"]


def test_prune_refuses_a_wrong_folder(tmp_path):
    with pytest.raises(SystemExit):
        hr.prune(tmp_path)


def fake_lipo(out, a, b):
    out.write_bytes(fat(a.read_bytes(), b.read_bytes()))


def test_merge_makes_fat_binaries_and_checks_the_rest(tmp_path):
    a, x = fake_tree(tmp_path / "a", "arm64"), fake_tree(tmp_path / "x", "x86_64")
    hr.prune(a), hr.prune(x)
    for root in (a, x):   # a universal2 wheel: the same fat file in both trees
        (root / "lib/python3.12/site-packages").mkdir(parents=True, exist_ok=True)
        (root / "lib/python3.12/site-packages/_rust.abi3.so").write_bytes(fat(macho(), macho()))
    stats = hr.merge(a, x, tmp_path / "u" / "python", lipo=fake_lipo)
    assert stats == {"lipo": 2, "same": 2, "arm64_copy": 1, "symlink": 0}
    u = tmp_path / "u" / "python"
    assert hr.is_macho(u / "bin/python3.12") and (u / "bin/python3.12").read_bytes()[:4] == b"\xca\xfe\xba\xbe"
    assert b"'arm64'" in (u / "lib/python3.12/_sysconfigdata__darwin_darwin.py").read_bytes()
    assert [p.name for p in hr.list_macho(u)][-1] == "python3.12"        # executables last
    assert [p.name for p in hr.executables(u)] == ["python3.12"]
    archs = {str(p): {"arm64", "x86_64"} for p in hr.list_macho(u)}
    assert hr.verify_universal(u, archs=lambda p: archs[str(p)]) == []
    assert hr.verify_universal(u, archs=lambda p: {"arm64"})


@pytest.mark.parametrize("damage", ["only_arm", "text_differs", "macho_vs_text", "symlink"])
def test_merge_refuses_anything_one_arch_would_miss(tmp_path, damage):
    a, x = fake_tree(tmp_path / "a", "arm64"), fake_tree(tmp_path / "x", "x86_64")
    if damage == "only_arm":
        (a / "lib/python3.12/site-packages/mod.so").parent.mkdir(parents=True, exist_ok=True)
        (a / "lib/python3.12/site-packages/mod.so").write_bytes(macho())
    elif damage == "text_differs":
        (x / "lib/python3.12/os.py").write_bytes(b"# other\n")
    elif damage == "macho_vs_text":
        (x / "lib/libpython3.12.dylib").write_bytes(b"not a binary")
    else:
        os.remove(x / "bin" / "python3")
        os.symlink("/usr/bin/python3", x / "bin" / "python3")
    with pytest.raises(SystemExit):
        hr.merge(a, x, tmp_path / "u", lipo=fake_lipo)
    assert not (tmp_path / "u").exists()


def test_merge_rejects_symlinks_leaving_the_tree(tmp_path):
    a, x = fake_tree(tmp_path / "a", "arm64"), fake_tree(tmp_path / "x", "x86_64")
    for root in (a, x):
        os.symlink("../../etc", root / "lib" / "escape")
    with pytest.raises(SystemExit):
        hr.merge(a, x, tmp_path / "u", lipo=fake_lipo)


# ---------------- pins ----------------

def test_runtime_pins_are_complete():
    data = json.loads(hr.RUNTIME_JSON.read_text())
    assert data["python_exe"] == "python3.12" and data["python_version"].startswith("3.12.")
    for arch in hr.ARCHS:
        url, sha = hr.runtime("url", arch), hr.runtime("sha256", arch)
        assert url.startswith("https://github.com/astral-sh/python-build-standalone/releases/download/")
        assert data["release"] in url and data["python_version"] in url.replace("%2B", "+")
        assert ("aarch64" if arch == "arm64" else "x86_64") + "-apple-darwin-install_only" in url
        assert re.fullmatch(r"[0-9a-f]{64}", sha)
        assert hr.runtime("wheel_platform", arch) == f"macosx_12_0_{arch}"


def test_bundle_lock_matches_its_input_and_has_hashes():
    pins = dict(lock_bundle.pins((DEVICE / "requirements-bundle.in").read_text()))
    lock = (DEVICE / "requirements-bundle.txt").read_text()
    locked = dict(re.findall(r"^([a-z0-9][a-z0-9._-]*)==(\S+) \\$", lock, re.M))
    assert locked == pins
    blocks = re.split(r"\n(?=[a-z0-9])", lock.split("\n\n", 1)[1].strip())
    for block in blocks:
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", block), block[:40]
    assert "pymobiledevice3" in pins and "cryptography" in pins


def test_helper_and_bundle_pin_the_same_pymobiledevice3():
    pinned = hr.pin("pymobiledevice3")
    assert pinned == pax_device.PINNED_PYMOBILEDEVICE3
    assert f"pymobiledevice3=={pinned}" in (DEVICE / "requirements.txt").read_text()


@pytest.mark.parametrize("name, ok", [
    ("cryptography-48.0.1-cp311-abi3-macosx_10_9_universal2.whl", True),
    ("psutil-7.2.2-cp36-abi3-macosx_11_0_arm64.whl", True),
    ("cffi-2.1.1-cp312-cp312-macosx_10_15_x86_64.whl", True),
    ("idna-3.20-py3-none-any.whl", True),
    ("cffi-2.1.1-cp313-cp313-macosx_11_0_arm64.whl", False),
    ("cffi-2.1.1-cp312-cp312-manylinux_2_17_x86_64.whl", False),
    ("cryptography-50.0.2-cp314-cp314t-macosx_11_0_arm64.whl", False),
    ("pkg-1.0.tar.gz", False),
])
def test_lock_only_hashes_wheels_the_bundle_can_use(name, ok):
    assert lock_bundle.wanted(name) is ok


def test_lock_render_format():
    text = lock_bundle.render([("a", "1", ["0" * 64, "1" * 64]), ("b", "2", ["2" * 64])])
    assert "a==1 \\\n    --hash=sha256:" + "0" * 64 + " \\\n    --hash=sha256:" + "1" * 64 + "\nb==2" in text


# ---------------- signing, packaging and the release check ----------------

def test_entitlements_are_minimal():
    ent = plistlib.loads((REPO / "mac-app/Resources/helper-python.entitlements").read_bytes())
    assert ent == {"com.apple.security.cs.allow-unsigned-executable-memory": True}


def test_build_dmg_bundles_and_signs_the_helper():
    s = (SCRIPTS / "build-dmg.sh").read_text()
    assert "build-device-helper.sh" in s and "helper-python.entitlements" in s
    assert "--options runtime --timestamp" in s and "list-macho" in s
    assert "$SCRIPT_DIR/install-helper.sh" not in s
    assert "helper_check" in s and "selftest" in s and " list " in s
    readme_txt = s.split("Read me first.txt")[1].split("TXT\n")[1]
    assert "Terminal" not in readme_txt and "install-helper" not in readme_txt


def test_helper_build_is_pinned_and_checked():
    s = (SCRIPTS / "build-device-helper.sh").read_text()
    for needle in ("--require-hashes", "--no-deps", "--only-binary=:all:", "shasum -a 256",
                   "verify-universal", "unchecked-hash", "selftest", "arch -x86_64"):
        assert needle in s, needle


def test_workflow_runs_the_signed_helper_and_checks_notarisation():
    wf = (REPO / ".github/workflows/build-dmg.yml").read_text()
    assert f'PAX_VERSION: "{VERSION}"' in wf
    check = wf.split("name: Check the bundled iPhone helper")[1].split("- uses: actions/upload-artifact")[0]
    for needle in ("run_helper arm64 selftest", "run_helper arm64 list", "run_helper x86_64 selftest",
                   "lipo -archs", "Developer ID Application", "Timestamp=", "runtime",
                   "Notarized Developer ID", "Pax-${PAX_VERSION}.zip", "hdiutil attach",
                   "allow-unsigned-executable-memory"):
        assert needle in check, needle
    # the check runs before the release step can publish anything
    assert wf.index("Check the bundled iPhone helper") < wf.index("Sign and publish the release")


def test_swift_and_build_agree_on_the_interpreter_path():
    swift = (REPO / "mac-app/Sources/PaxCore/KeepDataSupervision.swift").read_text()
    exe = json.loads(hr.RUNTIME_JSON.read_text())["python_exe"]
    assert f'relativePython = "device/python/bin/{exe}"' in swift
    assert 'bundledArguments = ["-I", "-B"]' in swift
    assert f"device/python/bin/{exe}" in (SCRIPTS / "build-dmg.sh").read_text()


# ---------------- what users are told ----------------

USER_DOCS = ["## Build and open the DMG", "### Device helper (Keep my data)", "**Set-up modes**"]


def readme_section(text, heading):
    start = text.index(heading)
    nxt = re.search(r"\n#{2,3} ", text[start + len(heading):])
    return text[start:start + len(heading) + (nxt.start() if nxt else len(text))]


def test_user_set_up_docs_need_no_terminal():
    readme = (REPO / "README.md").read_text()
    for heading in USER_DOCS:
        section = readme_section(readme, heading)
        assert "install-helper" not in section, heading
        assert "brew install" not in section, heading
    assert "no Terminal step" in readme


def test_install_helper_stays_for_developers_only():
    s = (SCRIPTS / "install-helper.sh").read_text()
    assert "developers" in s.lower()
    for path in ("docs/ERROR_CODES.md", "common/pax_errors.py", "mac-app/Sources/PaxCore/PaxError.swift"):
        assert "install-helper" not in (REPO / path).read_text(), path


def test_versions_are_current():
    assert (REPO / "README.md").read_text().startswith(f"# Pax Peace (Apple), v{VERSION}")
    assert f'VERSION="${{PAX_VERSION:-{VERSION}}}"' in (SCRIPTS / "build-dmg.sh").read_text()
    assert f'?? "{VERSION}"' in (REPO / "mac-app/Sources/Pax/Theme.swift").read_text()
    assert f'__version__ = "{VERSION}"' in (REPO / "server/pax_server/__init__.py").read_text()
    assert f'__version__ = "{VERSION}"' in (REPO / "pax-dns/pax_dns/__init__.py").read_text()
    assert f'VERSION = "{VERSION}"' in (REPO / "guard/pax_guard.py").read_text()
    # v0.8.14: no CHANGELOG or old release notes in the repo (and no links to them).
    assert not (REPO / "CHANGELOG.md").exists()
    assert not (REPO / "docs/RELEASE_NOTES_OLDER.md").exists()
    assert "What's new in v" not in (REPO / "README.md").read_text()


def test_dependencies_doc_lists_every_bundled_package_and_licence():
    doc = (REPO / "docs/DEPENDENCIES.md").read_text()
    for name, version in lock_bundle.pins((DEVICE / "requirements-bundle.in").read_text()):
        assert f"[{name}](https://pypi.org/project/{name}/{version}/) {version}" in doc, name
    assert "python-build-standalone" in doc and "GPL-3.0-compatible" in doc
