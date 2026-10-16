# SPDX-License-Identifier: GPL-3.0-only
"""v0.7.0 support codes: unique, well-formed, documented, and the same in Python,
Swift and every script that prints one."""
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent
REPO = COMMON.parent
sys.path.insert(0, str(COMMON))

import pax_errors as pe  # noqa: E402

SWIFT = REPO / "mac-app" / "Sources" / "PaxCore" / "PaxError.swift"
DOCS = REPO / "docs" / "ERROR_CODES.md"
JARGON = re.compile(r"\b(DoH|DNS|pf|MDM|supervis\w*|cfgutil|launchctl|launchd|dscl|SecureToken|escrow|"
                    r"profile identifier|stack|exception|HTTP|401|500)\b", re.I)


def test_codes_unique_and_well_formed():
    codes = [c.code for c in pe.CODES]
    assert len(codes) == len(set(codes))
    for c in pe.CODES:
        assert pe.CODE_RE.match(c.code), c.code
        assert c.message and c.action and c.cause, c.code


def test_numbers_are_unique_per_area():
    seen = {}
    for c in pe.CODES:
        _, area, num = c.code.split("-")
        assert (area, num) not in seen
        seen[(area, num)] = c


def test_messages_are_short_calm_and_jargon_free():
    for c in pe.CODES:
        assert len(c.message) <= 90, c.code
        assert len(c.action) <= 120, c.code
        assert not JARGON.search(c.message), (c.code, c.message)
        assert c.message.endswith("."), c.code


def test_every_code_is_documented():
    text = DOCS.read_text()
    for c in pe.CODES:
        assert f"`{c.code}`" in text, c.code
        assert c.cause.replace("|", "\\|") in text


def test_generated_files_are_current():
    r = subprocess.run([sys.executable, str(COMMON / "gen_error_codes.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_swift_catalog_matches_python_table():
    swift = SWIFT.read_text()
    block = swift[swift.index("// BEGIN GENERATED"):swift.index("// END GENERATED")]
    assert re.findall(r'code: "(PAX-[A-Z]+-\d{3})"', block) == [c.code for c in pe.CODES]


def test_every_code_used_anywhere_exists():
    """Scripts, guard log lines, make_profile and the Swift classifier only use
    codes that are in the table (so docs cover them)."""
    known = set(pe.BY_CODE)
    files = [*(REPO / "mac-app" / "Sources").rglob("*.swift"), *(REPO / "guard").rglob("*.py"),
             *(REPO / "guard" / "scripts").glob("*.sh"), REPO / "profile" / "make_profile.py",
             *(REPO / "server" / "pax_server").glob("*.py"), *(REPO / "mac-app" / "scripts").glob("*.sh")]
    for f in files:
        if "tests" in f.parts:
            continue
        for code in re.findall(r"PAX-[A-Z]+-\d{3}", f.read_text()):
            assert code in known, f"{code} in {f}"


def test_required_failure_points_are_mapped():
    """The maintainer's list: launchctl error 5 / quarantine, leftover paxadmin, the
    extra-admin preflight, cfgutil failures, escrow and network errors."""
    install = (REPO / "guard" / "scripts" / "pax-guard-install.sh").read_text()
    assert "PAX-GUARD-003: launchctl bootstrap failed" in install
    for code in ("PAX-GUARD-001", "PAX-GUARD-002", "PAX-GUARD-004", "PAX-GUARD-005"):
        assert code in install
    swift = SWIFT.read_text()
    for needle in ('"PAX-GUARD-003"', '"PAX-MAC-004"', '"PAX-MAC-003"', '"PAX-IOS-001"', '"PAX-IOS-002"',
                   '"PAX-ESCROW-001"', '"PAX-ESCROW-003"', '"PAX-NET-001"', '"PAX-NET-002"'):
        assert needle in swift, needle
    assert "bootstrap" in pe.get("PAX-GUARD-003").cause and "quarantine" in pe.get("PAX-GUARD-003").cause


def test_escrow_code_mapping():
    assert pe.escrow_code(401) == "PAX-ESCROW-001"
    assert pe.escrow_code(400, "bad_request", "wait time must be between 3 days and 365 days") == "PAX-ESCROW-002"
    assert pe.escrow_code(429) == "PAX-ESCROW-006"
    assert pe.escrow_code(425) == "PAX-ESCROW-007"
    assert pe.escrow_code(503) == "PAX-ESCROW-004"
    assert pe.escrow_code(404) == "PAX-ESCROW-005"


def test_line_and_unknown():
    assert pe.line("PAX-GUARD-003", "error 5").startswith("PAX-GUARD-003: ")
    assert pe.get("PAX-NOPE-999").code == "PAX-APP-000"
    assert pe.CODE_IN_TEXT.search("pax-guard-install: PAX-GUARD-003: x").group(0) == "PAX-GUARD-003"
