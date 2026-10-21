# SPDX-License-Identifier: GPL-3.0-only
"""Client for the Pax server (server/ in this repo), the same calls the Mac makes
(mac-app/Sources/PaxCore/EscrowClient.swift, ListSync.swift, Blocklist.swift).
Standard library only. Never logs a token, a password or an email address."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

from . import VERSION
from .choices import WaitLimits

# transport(method, url, headers, body_bytes_or_None, timeout) -> (status, body_bytes)
Transport = Callable[[str, str, dict, Optional[bytes], float], tuple[int, bytes]]


def urllib_transport(method: str, url: str, headers: dict, body: Optional[bytes],
                     timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (https URL from settings)
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() or b""


class EscrowError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class EscrowClient:
    def __init__(self, base_url: str, token: Optional[str] = None,
                 transport: Transport = urllib_transport, timeout: float = 30.0):
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.token = token
        self.transport = transport
        self.timeout = timeout

    def _send(self, method: str, path: str, body: Optional[dict] = None, auth: bool = True,
              timeout: Optional[float] = None) -> Any:
        headers = {"Accept": "application/json", "User-Agent": f"PaxWindowsSetup/{VERSION}"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            status, raw = self.transport(method, self.base_url + path, headers, data,
                                         timeout or self.timeout)
        except OSError as exc:      # no network, DNS failure, TLS, timeout
            raise EscrowError(0, "network", f"Pax couldn't reach its server ({type(exc).__name__}).") from None
        obj: Any = None
        if raw:
            try:
                obj = json.loads(raw)
            except ValueError:
                obj = None
        if not 200 <= status < 300:
            err = obj if isinstance(obj, dict) else {}
            raise EscrowError(status, str(err.get("error") or f"http_{status}"),
                              str(err.get("message") or f"Server error {status}"))
        return obj if obj is not None else {}

    # --- account -------------------------------------------------------------
    def health(self) -> dict:
        return self._send("GET", "v1/health", auth=False, timeout=10)

    def wait_limits(self) -> WaitLimits:
        try:
            return WaitLimits.from_health(self.health())
        except EscrowError:
            return WaitLimits.legacy_server()

    def register_account(self, email: str) -> dict:
        return self._send("POST", "v1/accounts", {"email": email}, auth=False)

    def start_sign_in(self, email: str) -> None:
        self._send("POST", "v1/accounts/signin/start", {"email": email}, auth=False)

    def sign_in(self, email: str, code: str, label: str = "Windows PC") -> dict:
        return self._send("POST", "v1/accounts/signin",
                          {"email": email, "code": code.strip().replace(" ", ""), "label": label[:100]},
                          auth=False)

    def account_summary(self) -> dict:
        return self._send("GET", "v1/accounts/me")

    def set_wait(self, days: int) -> dict:
        return self._send("PUT", "v1/accounts/me/wait", {"wait_days": int(days)})

    def set_partner(self, email: Optional[str]) -> dict:
        return self._send("PUT", "v1/accounts/me/partner", {"email": email})

    # --- DNS (Pax's own filter) ---------------------------------------------
    def dns_info(self) -> dict:
        return self._send("GET", "v1/dns")

    def set_dns_settings(self, youtube_restricted: bool) -> dict:
        return self._send("PUT", "v1/dns/settings", {"youtube_restricted": bool(youtube_restricted)})

    def block_site(self, domain: str) -> dict:
        return self._send("POST", "v1/blocklist", {"domain": domain})

    # --- device --------------------------------------------------------------
    def register_device(self, *, name: str, platform: str, profile_identifier: str,
                        removal_password: str, support_release: bool, trial: bool,
                        hardware_id: Optional[str]) -> dict:
        body: dict[str, Any] = {"name": name[:100] or "iPhone", "platform": platform,
                                "profile_identifier": profile_identifier,
                                "removal_password": removal_password,
                                "support_release": bool(support_release)}
        if trial and hardware_id:
            body["trial"] = True
            body["hardware_id"] = hardware_id
        return self._send("POST", "v1/devices", body)


def dns_healthy(base: str, transport: Transport = urllib_transport) -> bool:
    """PaxDNS.isHealthy: <base>/health answers 200 with "ok": true. A locked profile can't
    be changed later, so a phone is never locked to a filter that isn't answering."""
    url = base.strip().rstrip("/") + "/health"
    try:
        status, raw = transport("GET", url, {"User-Agent": f"PaxWindowsSetup/{VERSION}"}, None, 15)
        return status == 200 and json.loads(raw or b"{}").get("ok") is True
    except (OSError, ValueError):
        return False
