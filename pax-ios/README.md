# Pax for iPhone and iPad (App Store)

Work in progress on a branch. Not released, not submitted to Apple.

**Interim app:** `Guide/` is a small guide app with no entitlements (how to set up Pax Strict from
a Mac, plus a "Check you're protected" test) that can ship first under the same bundle id. See
[Guide/README.md](Guide/README.md).

Plug-and-play Pax: install from the App Store, set up on the phone in about five minutes, no Mac.
It uses Apple's Screen Time APIs with individual authorization:

- the system adult-website filter, plus your own sites (Managed Settings `webContent`),
- Pax can't be deleted while it's on (`denyAppRemoval`),
- apps and sites you choose are shielded with a calm screen,
- optional encrypted DNS through Pax's own filter (`dns.paxpeace.com`),
- an optional Screen Time passcode that Pax keeps until your turn-off wait ends.

Set-up happens on the phone: who it's for (you, or your child's device), your email and the code
the Pax server sends, someone you trust (optional; they're only ever told, they never approve),
your turn-off wait (3 days to 1 year), Screen Time access (once), apps to keep closed, the Pax
Screen Time passcode (recommended), then encrypted DNS.

Turning it off works like on a Mac: you ask, your trusted person (if you have one) is emailed
first, the wait you chose runs on the Pax server, then everything is removed and the Screen Time
passcode is shown. The first hour after set-up has no wait. If anything fails, Pax stays on.

Honest limits: a computer restore or full erase removes it, and anyone can switch the DNS layer
off in Settings (Pax notices and tells your trusted person). For the strongest protection, set
Pax up from a Mac: the Mac app sets up a supervised iPhone or iPad over a cable.

Account deletion is in the app (Account › Delete my account). The server has no delete route yet,
so the app sends a deletion request by email to Pax support until it does.

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
