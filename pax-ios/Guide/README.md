<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Pax for iPhone and iPad: interim guide app

A small app that can go on the App Store now, while the full Screen Time app (`pax-ios/`)
waits for Apple's Family Controls (Distribution) entitlement. Same bundle id
(`org.paxpeace.pax`), so the full app replaces it as an update later.

What it does:

* **The guide is the home screen.** What you'll need (a Mac with macOS 13 or later, a cable,
  a backup), then nine numbered steps that follow Pax for Mac's iPhone path: get Pax on the
  Mac, choose "iPhone or iPad", plug in, choose what to block, choose the turn-off wait, turn
  off Find My, click "Protect my iPhone", turn Find My back on, check you're protected.
  Step 1 shares or copies the Mac download link
  (`https://github.com/paxtechnologies/pax-apple/releases/latest/download/Pax.dmg`, the link
  paxpeace.com uses).
* **"Check you're protected"** (`Sources/Core/ProtectionCheck.swift`). Looks up four X and
  Bluesky media hosts and one everyday name through the system resolver. Pax's DoH filter
  always answers those media hosts with `0.0.0.0` / `::` (always blocked, every account, even
  an unknown token: `guard_config.ALWAYS_BLOCKED_MEDIA_NAMES`), public DNS with real
  addresses. All four blocked: **Protected by Pax**. All four real and the everyday name
  resolves: **Not protected**. Nothing resolves: **Couldn't check (offline)**. Anything mixed:
  **Couldn't check**. No server change needed. A device set up on CleanBrowsing directly
  (Advanced) shows "Not protected" with a line saying this check can't confirm that filter.
* Quieter extras at the bottom: good to know, "Pax without a Mac" (no dates), links.

No entitlements, no extensions, no accounts, no analytics, nothing stored or sent
(`Resources/PrivacyInfo.xcprivacy`: no tracking, no data collected). Brand v2 "Dusk/Air":
logo and icon from the brand kit, fonts are the Mac app's OFL instances (`Resources/Fonts/OFL.txt`).

```sh
brew install xcodegen && xcodegen generate   # PaxGuide.xcodeproj, scheme "Pax"
```

CI: `.github/workflows/ios.yml`, job `guide` (build, tests, simulator screenshots as the
`guide-screenshots` artifact). Launch arguments `-PaxScrollToStep N` and `-PaxRunCheck` exist
only for those screenshots.
