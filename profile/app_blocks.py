# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.7: the user's own blocked iPhone/iPad apps (set-up only).

The Mac app lists the connected iPhone's apps (device/pax_device.py `apps`), the
user picks some or types a bundle ID, and the choices go into the locked
profile's blockedAppBundleIDs next to Pax's own lists (bypass_apps.py,
remote_ai_browsers.py). The supervision key is deleted after set-up, so the list
can't change until the iPhone is set up again.

Never blocked, whatever is typed (project decision): Apple's own apps (some
are needed to keep the phone working, and Settings is how the user reaches
everything else) and password managers. The lists match
guard/guard_config.py's for the Mac; a test keeps them in step.

Stdlib only: it runs in Pax.app's bundled Python and in CI."""
from __future__ import annotations

import re

from bypass_apps import default_bundle_ids
from remote_ai_browsers import IOS_REMOTE_AI_APP_BUNDLE_IDS

# blockedAppBundleIDs has no documented size limit; Pax keeps the user's own part
# to a size people can review on one screen (Pax's own ~30 aren't counted).
MAX_CUSTOM_APP_BLOCKS = 200

NEVER_BLOCK_PREFIXES = ("com.apple.", "org.paxmobile.", "org.paxpeace.")
# Same set as guard_config.PASSWORD_MANAGER_BUNDLE_IDS (iTunes Search API, 2026-10-16).
PASSWORD_MANAGER_BUNDLE_IDS = frozenset({
    "com.1password.1password", "com.agilebits.onepassword7", "com.agilebits.onepassword-osx",
    "com.1password.safari",
    "com.8bit.bitwarden", "com.bitwarden.desktop",
    "com.lastpass.ilastpass", "com.lastpass.lastpass", "com.lastpass.lastpassforsafari",
    "com.dashlane.dashlanephonefinal",
    "me.proton.pass.ios", "me.proton.pass.catalyst", "me.proton.pass.electron",
    "com.keepassium.ios", "org.keepassxc.keepassxc",
    "com.markmcguill.strongbox", "com.markmcguill.strongbox.pro", "com.markmcguill.strongbox.mac",
    "in.sinew.walletx", "in.sinew.enpass-desktop",
    "com.callpod.keepermac.lite", "com.keepersecurity.safari.keeperfill",
    "com.nordpass.ios.app.password.manager", "com.nordpass.safari.app.password.manager",
})
PASSWORD_MANAGER_NAMES = ("1password", "bitwarden", "lastpass", "dashlane", "proton pass", "keepass",
                          "strongbox", "enpass", "keeper password", "nordpass", "roboform")

# Reverse-DNS: letters, digits, hyphens, dots; at least two parts. (Team-prefixed
# IDs such as Keeper's "D4D2433BGC" listing aren't bundle IDs and are refused.)
_BUNDLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9_-]*)+$")


class AppBlockError(ValueError):
    """A choice that can't go in the profile. `code` is the support code."""

    def __init__(self, message: str, code: str = "PAX-PROFILE-004"):
        super().__init__(message)
        self.code = code


def pax_blocked_ids() -> list[str]:
    """What Pax blocks on every iPhone anyway (shown as "already blocked")."""
    return list(dict.fromkeys(default_bundle_ids() + list(IOS_REMOTE_AI_APP_BUNDLE_IDS)))


def protected_reason(bundle_id: str, name: str = "") -> str | None:
    bid = (bundle_id or "").strip().lower()
    for prefix in NEVER_BLOCK_PREFIXES:
        if bid.startswith(prefix):
            return "Pax itself" if "pax" in prefix else "one of Apple's own apps"
    if bid in PASSWORD_MANAGER_BUNDLE_IDS:
        return "a password manager"
    if any(n in (name or "").lower() for n in PASSWORD_MANAGER_NAMES):
        return "a password manager"
    return None


def validate_custom_apps(bundle_ids: list[str], names: dict[str, str] | None = None) -> list[str]:
    """The user's choices, checked: plausible bundle IDs, none protected, de-duplicated,
    at most MAX_CUSTOM_APP_BLOCKS not counting apps Pax blocks anyway."""
    names = names or {}
    pax = {b.lower() for b in pax_blocked_ids()}
    out: list[str] = []
    seen: set[str] = set()
    for raw in bundle_ids:
        bid = (raw or "").strip()
        if not _BUNDLE_ID.match(bid):
            raise AppBlockError(f"not an app ID: {bid!r}")
        why = protected_reason(bid, names.get(bid, ""))
        if why:
            raise AppBlockError(f"{bid} can't be blocked: it's {why}")
        key = bid.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(bid)
    if sum(1 for b in out if b.lower() not in pax) > MAX_CUSTOM_APP_BLOCKS:
        raise AppBlockError(f"at most {MAX_CUSTOM_APP_BLOCKS} of your own apps")
    return out


def app_rows(lookup: dict, pax_ids: list[str] | None = None) -> list[dict]:
    """installation_proxy Lookup result -> sorted rows for the picker."""
    pax = {b.lower() for b in (pax_ids if pax_ids is not None else pax_blocked_ids())}
    rows = []
    for bid, info in (lookup or {}).items():
        if not isinstance(info, dict):
            info = {}
        bid = str(info.get("CFBundleIdentifier") or bid)
        name = str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or bid)
        why = protected_reason(bid, name)
        rows.append({"bundle_id": bid, "name": name,
                     "version": str(info.get("CFBundleShortVersionString") or ""),
                     "pax_blocks": bid.lower() in pax,
                     "can_block": why is None, "why_not": why or ""})
    rows.sort(key=lambda r: (r["name"].lower(), r["bundle_id"]))
    return rows
