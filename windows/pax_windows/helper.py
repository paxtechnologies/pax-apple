# SPDX-License-Identifier: GPL-3.0-only
"""Runs the USB helper (device/pax_device.py, shared with the Mac) as its own process
and reads its one-JSON-object answer, exactly as the Mac app does
(mac-app/Sources/PaxCore/KeepDataSupervision.swift). Progress lines ({"event": ...})
are passed to a callback as they arrive."""
from __future__ import annotations

import json
import os
import subprocess
import threading
from typing import Any, Callable, Optional

from . import paths

EventSink = Callable[[dict], None]


class HelperFailed(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def parse_output(lines: list[str]) -> dict:
    """The result is the last line that is a JSON object without "event"."""
    for line in reversed(lines):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and "event" not in obj:
            return obj
    return {"ok": False, "code": "no_answer", "error": "Pax's iPhone helper gave no answer."}


class HelperRunner:
    """Calls one pax_device.py subcommand at a time."""

    def __init__(self, command: Optional[list[str]] = None, timeout: float = 3600.0):
        self.command = command or paths.helper_command()
        self.timeout = timeout

    def run(self, args: list[str], stdin: Optional[bytes] = None,
            on_event: Optional[EventSink] = None) -> dict:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        proc = subprocess.Popen(self.command + args, stdin=subprocess.PIPE if stdin is not None else
                                subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=flags, env=env)
        if stdin is not None:
            def feed():
                try:
                    proc.stdin.write(stdin)       # type: ignore[union-attr]
                    proc.stdin.close()            # type: ignore[union-attr]
                except OSError:
                    pass
            threading.Thread(target=feed, daemon=True).start()
        err_chunks: list[bytes] = []
        threading.Thread(target=lambda: err_chunks.append(proc.stderr.read()), daemon=True).start()  # type: ignore[union-attr]
        lines: list[str] = []
        timer = threading.Timer(self.timeout, proc.kill)
        timer.start()
        try:
            for raw in proc.stdout:               # type: ignore[union-attr]
                line = raw.decode("utf-8", "replace")
                lines.append(line)
                if on_event and line.startswith('{"event"'):
                    try:
                        on_event(json.loads(line)["event"])
                    except (ValueError, KeyError):
                        pass
            proc.wait()
        finally:
            timer.cancel()
        result = parse_output(lines)
        if not result.get("ok"):
            raise HelperFailed(str(result.get("code") or "error"), str(result.get("error") or "Unknown error"))
        return result


class DemoHelperRunner:
    """Canned answers (PAX_DEMO=1 and the tests): an iPhone on iOS 27.2 that needs Trust
    once after the restart, then takes the live configuration. Same script as the Mac's
    DemoHelperRunner."""

    def __init__(self, ios: str = "27.2", product_type: str = "iPhone12,8"):
        self.ios = ios
        self.product_type = product_type
        self.connect_calls = 0
        self.calls: list[str] = []
        self.installed: list[str] = []
        self.installed_profiles: list[bytes] = []
        self.supervised_after_restore = True

    def run(self, args: list[str], stdin: Optional[bytes] = None,
            on_event: Optional[EventSink] = None) -> dict:
        import time
        time.sleep(float(os.environ.get("PAX_DEMO_DELAY", "0")))
        cmd = args[0]
        self.calls.append(cmd)
        major = int(self.ios.split(".")[0])
        mode = "live" if major >= 27 else "restored"
        out: dict[str, Any]
        if cmd == "list":
            out = {"devices": [{"udid": "00008110-DEMO", "name": "Demo iPhone", "product_type": self.product_type,
                                "ios": self.ios, "paired": True, "supervised": False}]}
        elif cmd == "preflight":
            blocking = [] if "--backup-confirmed" in args else ["Make a backup first and confirm it finished."]
            out = {"mode": mode, "ok": not blocking, "blocking": blocking, "warnings": [],
                   "ask_user_find_my": False, "facts": {"battery_level": 82, "find_my_on": False}}
        elif cmd == "backup":
            if on_event:
                on_event({"phase": "backup_progress", "percent": 50.0})
            out = {"backup": "demo-backup/00008110-DEMO", "verified": True}
        elif cmd == "seed-restore":
            out = {"mode": mode, "next": "reconnect"}
        elif cmd == "connect":
            self.connect_calls += 1
            n = self.connect_calls
            out = {"state": "not_found" if n < 3 else ("trust_requested" if n == 3 else "paired")}
        elif cmd in ("live-configure", "status"):
            out = {"supervised": self.supervised_after_restore, "host_cert_registered": True, "find_my_on": False}
        elif cmd == "install-profile":
            import plistlib
            self.installed.append(plistlib.loads(stdin or b"")["PayloadIdentifier"])
            self.installed_profiles.append(stdin or b"")
            out = {"installed": True, "method": "silent"}
        elif cmd == "profiles":
            out = {"identifiers": list(self.installed)}
        else:
            raise HelperFailed("unknown", "unknown command")
        return {"ok": True, **out}
