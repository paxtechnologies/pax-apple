# Pax for iPhone and iPad (App Store)

Work in progress on a branch. Not released, not submitted to Apple.

**Interim app:** `Guide/` is a small guide app with no entitlements (how to set up Pax Strict from
a Mac, plus a "Check you're protected" test) that can ship first under the same bundle id. See
[Guide/README.md](Guide/README.md).

Plug-and-play Pax: install from the App Store and turn it on with one tap, no Mac.
It uses Apple's Screen Time APIs with individual authorization:

- the system adult-website filter, plus your own sites (Managed Settings `webContent`),
- Pax can't be deleted while it's on (`denyAppRemoval`),
- apps and sites you choose are shielded with a calm screen,
- optional encrypted DNS through Pax's own filter (`dns.paxpeace.com`),
- an optional Screen Time passcode that Pax keeps until your turn-off wait ends.

**1.2 one-tap set-up** (branch `ios/onetap-v1.2`): Welcome ("Turn Pax on") → your email → the
6-digit code → Apple's Screen Time sheet (once) → Done. Every Pax account has a verified email
(server 0.8.31, [docs/ONETAP_ACCOUNTS.md](../docs/ONETAP_ACCOUNTS.md)), so a lost or replaced phone
never means a lost account: the same email and code sign in again. An email that already has an
account shows "Welcome back" (its wait, trusted person and devices) before the Screen Time sheet.
Quietly, in this order: the turn-off wait (only ever lengthened: 7 days, 30 on a child's device),
the release key escrowed on the Pax server, and only then the settings (fail closed: if the server
can't be reached nothing is switched on and the app offers "Try again"). "Setting up for a child?"
uses the same email and code, with the parent's email. Home then offers "Make Pax stronger", all
optional, in this order: Lock Screen Time (the passcode, added to this device's escrow with
`PUT /v1/devices/{id}/escrow`, recommended), someone you trust (with your first name for their
emails), encrypted DNS, apps to keep closed, the turn-off wait (longer is instant, shorter waits),
and setting Pax up from a Mac or Windows PC (paxpeace.com/setup).

Since 24 Oct 2026 Home is minimal: "Pax is on" and the turn-off wait, the Lock Screen Time nudge only
until it's done, and two actions, Blocked sites and Settings. Settings holds everything else as
one-line rows (Protection: Lock Screen Time, encrypted DNS, apps to keep closed, blocked apps, blocked
sites, YouTube Restricted Mode; Your account: someone you trust, turn-off wait, set up from a computer,
account; then Turn off Pax). YouTube Restricted Mode is on by default and lives in the account's DNS
filter; its switch appears only on a server that makes turning it off take the turn-off wait
(`GET /v1/categories` lists `youtube_restricted`), never for a child or a Mac set-up. Blocked apps
are named by bundle ID (`Application(bundleIdentifier:)` in `blockedApplications`), so an app that
isn't installed yet can be blocked; its websites can be added to your blocked sites too. Removing one
needs the server's blocked-apps list (`/v1/apps`) and takes the turn-off wait; without it they stay
blocked.

Turning it off works like on a Mac: you ask, your trusted person (if you have one) is emailed
first, the wait you chose runs on the Pax server, then everything is removed and the Screen Time
passcode is shown. The first hour after set-up has no wait. If anything fails, Pax stays on.

Honest limits (on paxpeace.com and with support; since 1.2 not shown in the app): a computer restore
or full erase removes it, and anyone can switch the DNS layer off in Settings (Pax notices and tells
your trusted person). For the strongest protection, set Pax up from a Mac: the Mac app sets up a
supervised iPhone or iPad over a cable.

**1.2 additions (23 Oct 2026):**

- *Child accounts* (server 0.8.32, [docs/CHILD_ACCOUNTS.md](../docs/CHILD_ACCOUNTS.md)): "Setting up for a
  child?" → the parent's email (`POST /v1/accounts/child/start`) → the code (`/child/verify`, with the
  child's optional first name and the device name) → Screen Time → Done. Always a new child account with
  the server's 30-day wait (no `PUT /me/wait`, no trial day, no "Welcome back"); the token is kept only if
  `kind == "child"`. Signing in again uses `/child/start` + `/child/signin` with this device's account id.
  A server without these routes answers a plain 404: the app says it needs a Pax update and never falls
  back to the parent's own account. 1.2 never calls `POST /v1/accounts` (CI checks).
- *Removing your own blocked sites* uses the server's rule (`POST /v1/blocklist/remove`, the same as Pax
  for Mac): the person you trust is emailed first (fail closed), the site stays blocked for the turn-off
  wait ("Removing, available in …", Cancel), and this device takes it off only once the server's list no
  longer has it and the server's clock is past the wait (`Shared/SiteRemoval.swift`). Adding stays instant.
- *Encrypted DNS steps*: an app can open only its own page in Settings, so "Show me how" lists the exact
  path from there (General › VPN & Device Management › DNS › Pax; iOS 18+ via ‹ Apps › ‹ Settings).
- *A device already set up from a Mac* (supervised, Pax's locked profile): after the email code the app
  checks for Pax's filter on the device (without its own DNS) and a Mac set-up on the account
  (`org.paxpeace.pax.ios.*` device record). Both: it joins that set-up ("Set up from a Mac") and only
  shows and adds to it: no Screen Time request, no device record, no DNS configuration, no wait sent.
  Pax's filter with no Mac set-up on the account: another account's, so nothing is set up
  (`Shared/StrictSync.swift`).
- No "Good to know" section; nothing in the app explains a way round the turn-off wait.

Account deletion is in the app (Account › Delete my account), using the server's
`DELETE /v1/accounts/me` (0.8.30); older servers get an emailed request to Pax support.

## Build

```
brew install xcodegen
cd pax-ios && xcodegen generate && open Pax.xcodeproj
```

Targets: `Pax` (app), `PaxShieldConfiguration`, `PaxShieldAction`, `PaxMonitor`
(Device Activity Monitor), `PaxTests`. Development signing works without Apple's approval;
App Store builds need the Family Controls (Distribution) entitlement for all four bundle IDs
(granted). Unit tests (`Tests/`) cover the policy logic and the app's wording.
CI builds for the simulator, unsigned: `.github/workflows/ios.yml`.
