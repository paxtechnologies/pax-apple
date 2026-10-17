# macOS 12 Monterey (v0.8.20)

Pax runs on **macOS 12 Monterey or later**, on Intel or Apple silicon. Until v0.8.19 it needed
macOS 13 Ventura.

**Hardware testing on a real Monterey Mac is still pending.** GitHub's runners only run newer macOS,
so CI proves Monterey support by reading the build itself (see "How CI checks it"). Run the
checklist at the end of this page on a real Monterey Mac (Intel, and Apple silicon if you have one)
before telling people it is tested.

## What changed

* The app is built for macOS 12 (`Package.swift` `.macOS(.v12)`, `--triple *-apple-macosx12.0`,
  `LSMinimumSystemVersion` 12.0). Swift refuses any macOS 13 API outside `if #available`, so the
  compiler is the first check.
* The macOS 13-only SwiftUI the app used now has a Monterey path (`mac-app/Sources/Pax/Compat.swift`,
  `PaxApp.swift`). On macOS 13 and later nothing looks or works differently.
* The settings app is called System Preferences on Monterey, with profiles in their own Profiles
  pane. Pax's instructions, and the pane it opens when you approve the Pax profile, follow the Mac's
  own version (`PaxCore/SystemSettingsPlace.swift`).
* The iPhone helper's wheels are picked for `macosx_12_0` (the pinned wheels are all built for
  macOS 10.9–11.0, so nothing changed in them).

## What behaves differently on macOS 12

| Where | macOS 13 and later | macOS 12 |
| --- | --- | --- |
| "Your own sites" box at set-up, support code box | grows to 4 lines as you type | one line; longer text scrolls inside it (pasting works the same) |
| Pax › Settings… (⌘,) with the window closed | reopens the window | reopens the window through AppKit's "new window" action (same result, untested on hardware) |
| Approving the Pax profile | System Settings › Privacy & Security › Profiles (13–14) or General › Device Management (15+) | System Preferences › Profiles |
| Window size | the window can't shrink below its content (contentMinSize) | the same limit, from the content's minimum frame |

Protection itself is identical: the same profile, the same pax-guard, the same filter, the same
turn-off wait, the same partner email. Nothing fails open on Monterey.

## Components checked for Monterey

* **Bundled Python** (python-build-standalone CPython 3.12, universal2): its arm64 half needs
  macOS 11.0 and its x86_64 half 10.9 or so; every compiled wheel in the helper is tagged
  macOS 10.9–11.0. The CI check reads all of them.
* **pax-guard**: uses `/etc/hosts`, `pf` (`pfctl`), `networksetup`, `scutil`, `dscl`,
  `dseditgroup`, `profiles show/remove`, `fdesetup`, `codesign`, `launchctl bootstrap/kickstart`,
  `curl`, `bputil`/`firmwarepasswd`: all present with the same options on macOS 12. It is a plain
  LaunchDaemon plist, not `SMAppService` (macOS 13+), so it installs the same way. Monterey has no
  "Background item added" notice.
* **The Pax profile**: `com.apple.applicationaccess` `allowCloudPrivateRelay` (macOS 12+),
  `com.apple.ManagedClient.preferences` browser policies (any macOS), and the optional
  `com.apple.dnsSettings.managed` DoH payload (macOS 11+). No key needs macOS 13. Pax uses no
  Network Extension.
* **DoH/DoT certificates**: Monterey's last update was in 2024, so its root certificates are frozen.
  The resolvers Pax uses chain to roots Monterey has today. If a resolver ever moves to a root
  Monterey doesn't have, that resolver fails its check and pax-guard moves on to the next one, and
  in the end to SERVFAIL. It never falls back to unfiltered DNS.
* **iPhone or iPad set-up** ("Keep my data") talks to the phone through macOS's own `usbmuxd` with
  the bundled pymobiledevice3, so it doesn't need Apple Configurator. Not yet tried on Monterey with
  an iOS 17–27 phone.
* **Clean set-up** needs `cfgutil` from Apple Configurator. The App Store version now needs a newer
  macOS (15.7 or later for 2.21), so on Monterey this only works if you already own Apple
  Configurator 2.16 (the last one for macOS 12.4+). The same is true on Ventura and Sonoma today.
  "Keep my data" is the default and doesn't need it.
* **Building**: still needs a Mac with Xcode 15+ or its Command Line Tools (macOS 13.5 or later).
  The app it builds runs on macOS 12.

## How CI checks it

* `ci.yml` (mac-app job): after `swift build && swift test`, `mac-app/scripts/check-macos-min.py`
  reads the debug binary.
* `build-dmg.yml` (Check the bundle): `LSMinimumSystemVersion` must be 12.0, and
  `check-macos-min.py` reads **every Mach-O in Pax.app, both arches**: Pax's own executable must
  say exactly macOS 12.0 (`LC_BUILD_VERSION` minos); everything else (the bundled Python and its
  modules) must say 12.0 or older; no library that only exists on macOS 13+ (Charts, the Swift regex
  runtime, Observation, ...) may be loaded strongly; a system framework the script doesn't know
  fails until someone checks it. A macOS 13 function inside a framework Monterey has is caught by
  the compiler and is a weak reference.
* Tests: `common/tests/test_v0820_macos_min.py`.

## Monterey hardware checklist (pending)

On macOS 12.7.x, Intel (and Apple silicon if possible). Write pass/fail + one line next to each.

1. The DMG opens without a Gatekeeper warning; Pax launches; the window can't shrink below its content.
2. Welcome › This Mac: all three steps; the "Your own sites" box accepts a long comma list.
3. Lock it in: the approval screen says System Preferences and Profiles; System Preferences opens on
   Profiles; installing "Pax (this Mac)" works and Pax carries on.
4. After set-up: Standard user, `paxadmin` hidden, pax-guard running
   (`sudo launchctl print system/org.paxpeace.pax-guard` as paxadmin), DNS 127.0.0.1, a blocked site
   doesn't load in Safari, Chrome and Firefox; Private Relay greyed out.
5. Settings › Advanced: filter "pax", filter lists version shown; turn the Wi-Fi off and on, it still filters.
6. Close the window, press ⌘, : the window comes back on Settings.
7. Turn off: the turn-off wait starts, partner emailed, cancel works.
8. Update: a newer signed version installs itself (pax-guard), Pax relaunches.
9. iPhone "Keep my data" with an iOS 26 or 27 phone: the phone is found, supervised and filtered.
10. Paste a support code (long text) into the support code box: it fits and is accepted.
