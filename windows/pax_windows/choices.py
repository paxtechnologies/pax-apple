# SPDX-License-Identifier: GPL-3.0-only
"""The set-up choices and the small rules around them, ported from the Mac
(mac-app/Sources/Pax/SetupModel.swift WaitChoice, PaxCore/ListSync.swift WaitLimits,
TurnOffWait.swift, TrialDay.swift). Pure logic: unit-tested on any machine."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from . import wording

DAY = 86_400
WAIT_PRESETS = (1, 3, 7)          # "1 day", "3 days" (recommended), "7 days"
DEFAULT_WAIT_DAYS = 3
TRIAL_DEFAULT = True              # TrialDay.setUpDefault
SUPPORT_RELEASE_DEFAULT = True    # VerifiedSupportRelease.setUpDefault
DEFAULT_SERVER = "https://api.paxpeace.com/"
DEFAULT_DNS_BASE = "https://dns.paxpeace.com"


@dataclass(frozen=True)
class WaitLimits:
    """What the server accepts (GET /v1/health wait_limits)."""
    min_seconds: int
    max_seconds: int

    @staticmethod
    def standard() -> "WaitLimits":
        return WaitLimits(DAY, 365 * DAY)

    @staticmethod
    def legacy_server() -> "WaitLimits":
        # A server older than 0.8.9 (no wait_limits): 3 to 365 days.
        return WaitLimits(3 * DAY, 365 * DAY)

    @staticmethod
    def from_health(obj: Optional[dict[str, Any]]) -> "WaitLimits":
        w = (obj or {}).get("wait_limits") if isinstance(obj, dict) else None
        try:
            lo, hi = int(w["min_wait_seconds"]), int(w["max_wait_seconds"])  # type: ignore[index]
        except (TypeError, KeyError, ValueError):
            return WaitLimits.legacy_server()
        if lo <= 0 or hi < lo:
            return WaitLimits.legacy_server()
        return WaitLimits(lo, hi)

    @property
    def day_range(self) -> tuple[int, int]:
        lo = max(1, -(-self.min_seconds // DAY))          # round up
        hi = max(lo, self.max_seconds // DAY)
        return lo, hi

    def allows(self, days: int) -> bool:
        lo, hi = self.day_range
        return lo <= days <= hi

    def presets(self) -> list[int]:
        return [d for d in WAIT_PRESETS if self.allows(d)]

    def clamp(self, days: int) -> int:
        lo, hi = self.day_range
        return min(max(int(days), lo), hi)


def choice_title(days: int) -> str:
    """A set-up choice's label: "1 day", "3 days", "7 days"."""
    return "1 day" if days == 1 else f"{days} days"


def duration_days(days: int) -> str:
    """The wait in the agreement: "24 hours", "3 days"."""
    return "24 hours" if days == 1 else f"{days} days"


def parse_custom_days(text: str, limits: WaitLimits) -> Optional[int]:
    """The Custom field: a whole number of days the server accepts, else None."""
    t = (text or "").strip()
    if not t.isdigit():
        return None
    days = int(t)
    return days if limits.allows(days) else None


def device_word(product_type: Optional[str]) -> str:
    return "iPad" if (product_type or "").startswith("iPad") else "iPhone"


def agreement_text(device: str, wait_days: int) -> str:
    return wording.AGREEMENT.format(device=device, wait=duration_days(wait_days))


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def email_looks_valid(email: Optional[str]) -> bool:
    return bool(email) and bool(_EMAIL.match(email.strip()))


def code_looks_valid(code: Optional[str]) -> bool:
    c = (code or "").strip().replace(" ", "")
    return c.isdigit() and len(c) == 6


def hardware_id(raw: Optional[str]) -> Optional[str]:
    """TrialDay.hardwareID: hex SHA-256 of "pax-hw-v1:" + the lower-cased identifier. The
    Mac app without Apple Configurator sends the phone's UDID here, so Windows does the
    same and the server counts the trial day from the same phone's first set-up."""
    t = (raw or "").strip().lower()
    if not t:
        return None
    return hashlib.sha256(("pax-hw-v1:" + t).encode()).hexdigest()


@dataclass
class SetupChoices:
    """Everything the person chooses in the guided steps."""
    wait_days: int = DEFAULT_WAIT_DAYS
    partner_email: Optional[str] = None
    support_release: bool = SUPPORT_RELEASE_DEFAULT
    trial: bool = TRIAL_DEFAULT
    agreed: bool = False
    find_my_confirmed_off: bool = False
    backup_confirmed: bool = False
    forbid_pairing: bool = False           # Advanced "strict" (off, untested), as on the Mac
    dns_base: Optional[str] = DEFAULT_DNS_BASE
    youtube_restricted: bool = True
    blocked_sites: list[str] = field(default_factory=list)

    def ready_to_protect(self, backup_done: bool) -> list[str]:
        """What's still missing before "Protect my iPhone" (empty = ready)."""
        missing = []
        if not self.find_my_confirmed_off:
            missing.append("find_my")
        if not (backup_done or self.backup_confirmed):
            missing.append("backup")
        if not self.agreed:
            missing.append("agreement")
        return missing
