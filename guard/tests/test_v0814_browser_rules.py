# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.14: pax-guard notices when the Chrome rules macOS applies (from a profile
installed by an older version) allow fewer extensions than this version would.
It only reports; it never changes the profile."""
import plistlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "guard"))
sys.path.insert(0, str(REPO / "guard" / "tests"))
sys.path.insert(0, str(REPO / "profile"))
import guard_config as gc  # noqa: E402
import mac_policies as mp  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402

MOMENTUM = "laookkfknpbbblfpciffpaejjkokdgca"


def write(path, allowed):
    settings = {"*": {"installation_mode": "blocked"}}
    for ext in allowed:
        settings[ext] = {"installation_mode": "allowed"}
    path.write_bytes(plistlib.dumps({"ExtensionInstallBlocklist": ["*"], "ExtensionInstallAllowlist": allowed,
                                     "ExtensionSettings": settings}, fmt=plistlib.FMT_BINARY))


def test_list_matches_the_profile_generator():
    assert list(gc.CHROME_ALLOWED_EXTENSIONS) == mp.allowed_extension_ids("chrome")


def test_older_profile_without_momentum_is_reported(tmp_path, monkeypatch):
    prefs = tmp_path / "mp" / "com.google.Chrome.plist"
    prefs.parent.mkdir()
    write(prefs, [e for e in gc.CHROME_ALLOWED_EXTENSIONS if e != MOMENTUM])
    monkeypatch.setattr(gc, "CHROME_MANAGED_PREFS", str(prefs))
    g, _ = local_guard(tmp_path)
    before = prefs.read_bytes()
    assert g.browser_rules() == {"browser": "Chrome", "outdated": True, "missing": ["Momentum"]}
    assert prefs.read_bytes() == before   # only reported, never changed


def test_allowlist_without_extension_settings_entry_counts_as_outdated(tmp_path, monkeypatch):
    prefs = tmp_path / "com.google.Chrome.plist"
    allowed = list(gc.CHROME_ALLOWED_EXTENSIONS)
    prefs.write_bytes(plistlib.dumps({"ExtensionInstallBlocklist": ["*"], "ExtensionInstallAllowlist": allowed,
                                      "ExtensionSettings": {"*": {"installation_mode": "blocked"}}}))
    monkeypatch.setattr(gc, "CHROME_MANAGED_PREFS", str(prefs))
    g, _ = local_guard(tmp_path)
    assert g.browser_rules()["missing"] == list(gc.CHROME_ALLOWED_EXTENSIONS.values())


def test_current_profile_is_up_to_date(tmp_path, monkeypatch):
    prefs = tmp_path / "com.google.Chrome.plist"
    write(prefs, list(gc.CHROME_ALLOWED_EXTENSIONS))
    monkeypatch.setattr(gc, "CHROME_MANAGED_PREFS", str(prefs))
    g, _ = local_guard(tmp_path)
    assert g.browser_rules() == {"browser": "Chrome", "outdated": False, "missing": []}
    assert g.status_summary()["browser_rules"]["outdated"] is False


def test_nothing_to_compare(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "CHROME_MANAGED_PREFS", str(tmp_path / "missing.plist"))
    g, _ = local_guard(tmp_path)
    assert g.browser_rules() is None
    (tmp_path / "junk.plist").write_text("not a plist")
    monkeypatch.setattr(gc, "CHROME_MANAGED_PREFS", str(tmp_path / "junk.plist"))
    assert g.browser_rules() is None
