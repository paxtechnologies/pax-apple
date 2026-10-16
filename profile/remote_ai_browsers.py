# SPDX-License-Identifier: GPL-3.0-only
"""Remote AI browsers for the iPhone/iPad profile (v0.8.1, project decision 2026-10-15).

Project rule (2026-10-15): an AI service that lets the user control a remote computer or
browser is blocked. ChatGPT's "Work" cloud browser is a remote computer the user
can take over, which goes round every filter on the phone. The takeover stream
couldn't be told apart from the rest of ChatGPT, so the whole service is
blocked. Manus (a cloud-computer agent) falls under the same rule. openai.com
itself (docs, API) stays reachable; only its chat.* hosts are listed.

Two layers, because Apple's web filter (com.apple.webcontent-filter
DenyListURLs) only covers WebKit (Safari and in-app web views), not native apps:
  * IOS_REMOTE_AI_URLS go in DenyListURLs, always (they share Apple's 500 with
    the custom blocks; see make_profile.MAX_CUSTOM_DENYLIST_URLS).
  * IOS_REMOTE_AI_APP_BUNDLE_IDS go in blockedAppBundleIDs
    (com.apple.applicationaccess, supervised only), always, even when the
    default bypass-app list is turned off.
The full list (pax-dns/lists/remote-ai-browsers.txt) is enforced by DNS too.
See docs/FILTER_LISTS.md.
"""
from __future__ import annotations

IOS_REMOTE_AI_HOSTS: list[str] = [
    "chatgpt.com",
    "chat.openai.com",
    "ios.chat.openai.com",
    "android.chat.openai.com",
    "desktop.chat.openai.com",
    "oaiusercontent.com",
    "oaistatic.com",
    "manus.im",
]
IOS_REMOTE_AI_URLS: list[str] = [f"https://{h}" for h in IOS_REMOTE_AI_HOSTS]

# (bundle ID, App Store name, how it was checked). Both confirmed with Apple's
# iTunes lookup API (https://itunes.apple.com/lookup?bundleId=...&country=gb,
# 2026-10-15); profile/refresh_bypass_apps.py re-checks them before a release.
IOS_REMOTE_AI_APPS: list[tuple[str, str, str]] = [
    ("com.openai.chat", "ChatGPT", "remote-ai"),
    ("tech.butterfly.app", "Manus - AI Agent & Automation", "remote-ai"),
]
IOS_REMOTE_AI_APP_BUNDLE_IDS: list[str] = [bid for bid, _n, _r in IOS_REMOTE_AI_APPS]
