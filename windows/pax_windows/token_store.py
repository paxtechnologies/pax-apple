# SPDX-License-Identifier: GPL-3.0-only
"""Keeps the account token on this PC, encrypted for the signed-in Windows user with
DPAPI (the Mac keeps it in the Keychain). Anywhere else, memory only."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


class MemoryTokenStore:
    def __init__(self):
        self._t: Optional[str] = None

    def load(self) -> Optional[str]:
        return self._t

    def save(self, token: str) -> None:
        self._t = token

    def clear(self) -> None:
        self._t = None


class DpapiTokenStore:
    def __init__(self, folder: Path, server: str):
        import hashlib
        tag = hashlib.sha256(server.encode()).hexdigest()[:12]
        self.path = Path(folder) / f"account-{tag}.bin"

    def load(self) -> Optional[str]:
        try:
            import win32crypt  # type: ignore[import-not-found]
            blob = self.path.read_bytes()
            return win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1].decode()
        except Exception:  # noqa: BLE001  (missing file, other user, damaged)
            return None

    def save(self, token: str) -> None:
        import win32crypt  # type: ignore[import-not-found]
        blob = win32crypt.CryptProtectData(token.encode(), "Pax account", None, None, None, 0)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, self.path)

    def clear(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass


def default_store(folder: Path, server: str):
    if os.name == "nt":
        try:
            import win32crypt  # noqa: F401  # type: ignore[import-not-found]
            return DpapiTokenStore(folder, server)
        except ImportError:
            pass
    return MemoryTokenStore()
