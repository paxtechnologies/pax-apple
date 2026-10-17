# Pax Peace roadmap

v0.5 adds Pax Image Blur, cloud-PC/remote-browser/remote-desktop blocking, VM quarantine and shareable
universal builds. v0.4 added "Protect this Mac". v0.3 did content filtering for iPhone and iPad, set up from a Mac without erasing the
phone (iOS 17–27), with the CleanBrowsing Family Filter, plus a personal blocklist synced to every
device through the new pax-dns resolver, and a DMG build. Next, roughly in order:

## 0-. v0.5 follow-ups
* Publish Pax Image Blur as an **unlisted Chrome Web Store** item (and Edge Add-ons), then fill in
  `BLUR_CHROME_WEBSTORE_ID` / `BLUR_EDGE_ADDONS_ID`; sign the Firefox build through AMO (unlisted) in CI.
* Check on real browsers: blur latency, false-positive rate on ordinary sites, YouTube/Netflix frames
  (MSE video should be readable; DRM video isn't), Firefox `private_browsing` force-enable.
* Extension: CSS background images and `<canvas>`; sync the allowlist with the account (with the
  72 h wait for additions); a larger model (MobileNetV2 Mid) behind a setting.
* Grow the cloud-PC / remote-desktop lists from real reports; a pax-dns "media CDNs" option still to do.
* Developer ID signing + notarisation once there's an Apple Developer account.

## 0a. Ship v0.3 for real
* First `./scripts/build-dmg.sh` on a Mac: fix any SwiftUI compile errors (the screens were only
  parse-checked on Linux), click through Blocked sites against a local server.
* Deploy pax-dns as `dns.paxmobile.org`: two instances, HTTPS (Caddy), `--no-access-log`, health
  checks, the daily list loader, then set `PAX_DNS_BASE` in release builds.
* Notarise (Apple Developer Program, $99/yr) so the DMG opens without the Privacy & Security detour.

## 0. Hardware validation of Keep my data (before any public release)
* Run the whole Keep-my-data flow on real phones: iOS 17, 18, 26 and 27.0/27.1/27.2, Home-button
  and Face ID iPhones, an iPad, a phone with encrypted local backups, and strict mode. Record the
  results in the README the way attention awareness did.
* Confirm the iOS 27 live step accepts `SupervisorHostCertificates` (silent install), or make the
  manual Settings install the only path.
* Stream helper progress to the UI (today the app shows static on-phone steps while it waits).
* **Done in v0.8.6**: the helper is bundled inside Pax.app (its own universal2 Python with
  pymobiledevice3, backups and the seed restore through pymobiledevice3's Mobilebackup2), so users
  don't need `install-helper.sh`, a venv or Homebrew. Licence texts ship with it.
* Watch each iOS 28 beta. Keep my data stays refused there until it's tested.

## 1. pax-dns: from dev defaults to self-hosted
* **Done in v0.3**: per-user DoH paths (`/u/<token>/dns-query`), custom blocklist + exceptions with a
  72 h wait, a plain DNS front end, and a HaGeZi/OISD list loader (`pax-dns/scripts/load_lists.py`).
* Production upstream: an unfiltered resolver Pax runs (Unbound) instead of CleanBrowsing, with the
  HaGeZi and OISD restricted-content lists loaded daily. Add DoT.
* Per-user choice of category strictness (Family-like vs Core-like) once lists are self-hosted.
* **Blocking media on mixed sites** without blocking the site (the Family Filter blocks Reddit
  entirely today): keep reddit.com and x.com reachable,
  but return NXDOMAIN for their image and video CDNs:
  `i.redd.it`, `v.redd.it`, `preview.redd.it`, `pbs.twimg.com`, `video.twimg.com`
  (user-selectable, as it blanks all media on those sites).
* **Forced SafeSearch** with CNAME rewrites: `www.google.*` → `forcesafesearch.google.com`,
  `www.bing.com` → `strict.bing.com`, DuckDuckGo → `safe.duckduckgo.com`, YouTube →
  `restrict.youtube.com` / `restrictmoderate.youtube.com`.
* **Done in v0.5**: block DoH/VPN/proxy endpoints (HaGeZi "DoH/VPN/TOR/Proxy bypass" list, default in
  `load_lists.py`) plus Pax's cloud-PC and remote-desktop categories.
* Per-device tokens (so one lost device can be cut off without touching the others) and a
  "recently added" undo window for typos, if users ask for it.

## 2. Server-side profile generation and updates
* Move profile generation to the server (or have the server sign it), and pipe it straight to
  `cfgutil install-profile -` so the password never sits on the Mac's disk.
* Custom *site* blocks no longer need a profile update (v0.3: they live in pax-dns). App blocks and
  Apple web-filter URLs still do, because the supervision key is deleted on purpose.

## 3. Declarative device management readiness
* `com.apple.dnsSettings.managed` and `blockedAppBundleIDs` are marked deprecated in the iOS 27
  schema. Prototype a minimal, self-hostable MDM/DDM component (DNS settings and app-settings
  declarations) in case manual profiles stop being honoured.

## 4. Mac self-lock
* **Done in v0.4**: standard-user demotion with an escrowed hidden admin, the self-lock profile with
  browser and extension policies, pax-guard (hosts, pf, bypass apps), ad blocking.
* Next: run it on real Macs (Apple silicon and Intel, macOS 12–26; a real Monterey Mac is still to test, docs/MONTEREY.md) and record results; port pax-guard
  to Swift (no Command Line Tools dependency); check Chrome/Edge pre-release channels' policy domains
  and manage them instead of blocking; add Vivaldi once it documents a policy for its VPN; an "ads"
  category in pax-dns so iPhone gets the same ad blocking; consider a supervised/MDM path for Safari
  extension management.
* **Done in v0.8.7**: the Home ads switch works live on local escrow; Blocked apps (iPhone at set-up,
  Mac enforced by pax-guard by bundle ID and code signature).
* Next for Blocked apps: apply for Apple's Endpoint Security entitlement so pax-guard can refuse a blocked
  app's launch outright (today it is closed within about 2 seconds), and let a protected iPhone's app list
  change without a new set-up if a supported path ever allows it.

## 5. Product
* Optional donations (no payments in v0.1).
* Cross-platform desktop set-up (Windows and Linux via pymobiledevice3 / go-ios) behind the
  `DeviceService` protocol.
* Later: time limits and focus tools. *Protection first, not another timer.*
* Android (Device Owner DPC) as a separate repo.
