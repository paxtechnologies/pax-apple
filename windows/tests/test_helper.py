# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from pax_windows.helper import HelperFailed, HelperRunner, parse_output

WINDOWS = Path(__file__).resolve().parents[1]


def test_parse_output_takes_the_last_result():
    lines = ['{"event": {"phase": "x"}}\n', "noise\n", '{"ok": true, "a": 1}\n', '{"event": {"phase": "y"}}\n']
    assert parse_output(lines) == {"ok": True, "a": 1}
    assert parse_output([])["code"] == "no_answer"


def fake_helper(tmp_path, body):
    p = tmp_path / "fake.py"
    p.write_text(textwrap.dedent(body))
    return HelperRunner([sys.executable, str(p)], timeout=60)


def test_runner_events_stdin_and_result(tmp_path):
    r = fake_helper(tmp_path, """
        import json, sys
        print(json.dumps({"event": {"phase": "restore_progress", "percent": 40.0}}), flush=True)
        data = sys.stdin.buffer.read()
        print(json.dumps({"ok": True, "args": sys.argv[1:], "got": len(data)}))
    """)
    events = []
    out = r.run(["install-profile", "--udid", "U"], stdin=b"x" * 100000, on_event=events.append)
    assert out["args"] == ["install-profile", "--udid", "U"] and out["got"] == 100000
    assert events == [{"phase": "restore_progress", "percent": 40.0}]


def test_runner_failure(tmp_path):
    r = fake_helper(tmp_path, """
        import json
        print(json.dumps({"ok": False, "code": "find_my_on", "error": "Find My is on."}))
    """)
    with pytest.raises(HelperFailed) as e:
        r.run(["preflight"])
    assert e.value.code == "find_my_on"


def test_helper_main_runs_the_shared_helper():
    """helper_main.py is device/pax_device.py unchanged (no pymobiledevice3 needed for
    an argument error)."""
    p = subprocess.run([sys.executable, str(WINDOWS / "helper_main.py"), "nonsense"], capture_output=True, text=True)
    assert p.returncode != 0 and "invalid choice" in p.stderr


@pytest.mark.skipif(importlib.util.find_spec("pymobiledevice3") is None, reason="pymobiledevice3 not installed")
def test_helper_selftest():
    p = subprocess.run([sys.executable, str(WINDOWS / "helper_main.py"), "selftest",
                        "--expect-pymobiledevice3", "11.32.0"], capture_output=True, text=True, timeout=300)
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out["ok"], out
