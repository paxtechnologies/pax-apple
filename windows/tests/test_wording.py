# SPDX-License-Identifier: GPL-3.0-only
"""Wording rules for everything the Windows set-up shows. Matched words are read from
common/pax_restricted.py at run time, never written here."""
import re
from pathlib import Path

import pax_restricted as pr
from pax_windows import wording as W

WINDOWS = Path(__file__).resolve().parents[1]


def all_strings():
    out = []
    for name in dir(W):
        if name.startswith("_"):
            continue
        v = getattr(W, name)
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, (list, tuple)):
            out += [x for x in v if isinstance(x, str)]
        elif isinstance(v, dict):
            out += [x for x in v.values() if isinstance(x, str)]
    return out


def test_turn_off_wait_wording():
    text = " ".join(all_strings())
    assert "turn-off wait" in text.lower()
    for s in all_strings():
        low = s.lower()
        assert "unlock" not in low, s
        assert "strict" not in low, s        # never the strongest-set-up name in visible copy
        assert "partner" not in low, s       # "someone you trust" / "trusted person"
    assert "Someone you trust" in W.TRUSTED_LABEL and "trusted person" in W.SUPPORT_DETAIL


def test_no_restricted_words_in_copy_or_code():
    words = [w.lower() for w in pr.data()["lookup_rule"]["words"]]
    files = list((WINDOWS / "pax_windows").glob("*.py")) + [WINDOWS / "installer.iss"]
    for f in files:
        low = f.read_text(encoding="utf-8").lower()
        for w in words:
            assert not re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", low), (f.name, "restricted word")


def test_says_it_is_phone_only():
    assert "doesn't filter or protect this PC" in W.NOT_FOR_PC
    assert "restore" in W.LIMITS_NOTE and "still removes" in W.LIMITS_NOTE


def test_find_my_and_passcode():
    assert "Find My is off" in W.FIND_MY_OFF
    # The passcode stays on: the phone asks for it after the restart and for Trust.
    assert "Keep your passcode on" in W.PASSCODE_NOTE


def test_trial_and_support_lines_match_the_mac():
    # mac-app/Sources/PaxCore/TrialDay.swift setUpLine, SupportRelease.swift setUpCheckbox
    assert W.TRIAL_LINE.startswith("First time setting up Pax? Your first 24 hours are a trial day")
    assert W.SUPPORT_CHECKBOX == "Allow verified support release (recommended)"
    assert W.WAIT_TITLE == "How long should turning Pax off take?"


def test_format_placeholders_fill():
    for s in all_strings():
        s.format(device="iPhone", name="Demo", ios="27.2", email="a@b.co", wait="3 days")
