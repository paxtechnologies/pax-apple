# SPDX-License-Identifier: GPL-3.0-only
"""The socket the Pax app talks to (v0.8.0): /var/run/pax-guard.sock.

One JSON object per line in, one JSON object per line back, then the
connection closes. The socket is 0666 so the everyday (Standard) account's app
can reach it; nothing on it can weaken Pax faster than the wait allows:

  status                      everything Home needs (protection, DNS, lists,
                              escrow, updates, tamper count)
  escrow.status / escrow.request {reason: remove|locked_out} / escrow.cancel /
  escrow.reveal (only after the wait) / escrow.emergency {reason} /
  escrow.set_wait {seconds} (longer now, shorter after the current wait)
  escrow.end_trial (v0.8.18: "Start my wait now", ends the trial day early)
  blocklist.get / blocklist.add {domain} / blocklist.unblock {domain} (waits) /
  blocklist.allow {domain} (waits) / blocklist.remove_allow {domain} /
  blocklist.cancel {request_id}
  update.status / update.now
  tamper.list
  dns.status
  apps.get / apps.add {path} / apps.unblock {bundle_id} (waits) /
  apps.cancel {request_id}                                (v0.8.7, local escrow)
  settings.get / settings.set {youtube_restricted: bool}   (v0.8.6)
                            / {adblock: bool}               (v0.8.7, local escrow)
                            / {family_layer: bool}          (v0.8.18, local escrow:
                              on at once; off waits like a removal)
  X and Bluesky media are always blocked (v0.8.13): settings.set refuses
  x_media / bluesky_media false with PAX-DNS-016
  paxmax.get / paxmax.on (instant) / paxmax.off (partner first, then a fixed
  hour; refused offline) / paxmax.cancel {request_id}    (v0.8.12, local escrow)

The exceptions to "nothing faster than the wait": YouTube Restricted Mode
(v0.8.6) and "Ads and trackers" (v0.8.7) switch at once in both directions,
without a partner email (the maintainer's decision, 2026-10-16). Neither is
restricted-content protection: only YouTube's own names, or only the ad names,
change, and the ad-list names that are restricted content stay blocked. Each
change is logged to the tamper log.

Secrets never travel except in escrow.reveal's answer after the wait.
Answers: {"ok": true, ...} or {"ok": false, "code": "PAX-...", "error": "..."}.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time

SOCKET_PATH = "/var/run/pax-guard.sock"
MAX_REQUEST = 16 * 1024
SOL_LOCAL, LOCAL_PEERCRED = 0, 1          # macOS <sys/un.h>


def peer_uid(conn: socket.socket) -> int | None:
    try:
        if hasattr(socket, "SO_PEERCRED"):                  # Linux (tests)
            data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            return struct.unpack("3i", data)[1]
        data = conn.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, 76)    # struct xucred
        return struct.unpack_from("Ii", data)[1]
    except OSError:
        return None


class RateLimit:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.hits: list[float] = []
        self.lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self.lock:
            self.hits = [t for t in self.hits if now - t < 60]
            if len(self.hits) >= self.per_minute:
                return False
            self.hits.append(now)
            return True


class IPCServer:
    def __init__(self, handler, path: str = SOCKET_PATH, log=print, mode: int = 0o666):
        self.handler = handler            # fn(request dict, uid) -> dict
        self.path = path
        self.log = log
        self.mode = mode
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(self.path)
        os.chmod(self.path, self.mode)
        s.listen(16)
        self._sock = s
        threading.Thread(target=self._loop, name="pax-ipc", daemon=True).start()
        self.log(f"app socket ready at {self.path}")

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                if self._stop.is_set():
                    return
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(15)
        try:
            buf = b""
            while b"\n" not in buf and len(buf) < MAX_REQUEST:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n", 1)[0]
            try:
                req = json.loads(line or b"{}")
                if not isinstance(req, dict):
                    raise ValueError
            except ValueError:
                resp = {"ok": False, "code": "PAX-GUARD-012", "error": "bad request"}
            else:
                try:
                    resp = self.handler(req, peer_uid(conn))
                except Exception as exc:  # noqa: BLE001 - never kill the socket thread
                    self.log(f"PAX-GUARD-012 app request failed: {type(exc).__name__}")
                    resp = {"ok": False, "code": "PAX-GUARD-012", "error": "pax-guard couldn't answer"}
            conn.sendall(json.dumps(resp).encode() + b"\n")
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass


def request(req: dict, path: str = SOCKET_PATH, timeout: float = 15) -> dict:
    """Client side (tests, `pax_guard.py ask`)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall(json.dumps(req).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf)
    finally:
        s.close()
