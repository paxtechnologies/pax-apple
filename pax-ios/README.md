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

Turning it off works like Pax Strict: you ask, your partner (if you have one) is emailed first, the
wait you chose runs on the Pax server, then everything is removed. The first hour after set-up has
no wait. If anything fails, Pax stays on.

Honest limits: a computer restore or full erase removes it, and iPhone lets anyone switch the DNS
layer off in Settings (Pax notices and tells your partner). The stronger option is **Pax Strict**:
the Mac app that sets up a supervised iPhone over USB.

## Build

```
brew install xcodegen
cd pax-ios && xcodegen generate && open Pax.xcodeproj
```

Targets: `Pax` (app), `PaxShieldConfiguration`, `PaxShieldAction`, `PaxMonitor`
(Device Activity Monitor), `PaxTests`. Development signing works without Apple's approval;
App Store builds need the Family Controls (Distribution) entitlement for all four bundle IDs.
CI builds for the simulator, unsigned: `.github/workflows/ios.yml`.
