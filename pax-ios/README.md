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

**1.2 one-tap set-up** (branch `ios/onetap-v1.2`): Welcome ("Turn Pax on") → Apple's Screen Time
sheet (once) → Done. Quietly, in this order: a private device account with no email, the turn-off
wait (7 days; 30 on a child's device), the release key escrowed on the Pax server, and only then
the settings (fail closed: if the server can't be reached nothing is switched on and the app offers
"Try again"). "Setting up for a child?" asks for the parent's email and a code first. Home then
offers "Make Pax stronger", all optional, in this order: Lock Screen Time (the passcode escrow,
recommended), someone you trust, encrypted DNS, apps to keep closed, the turn-off wait (longer is
instant, shorter waits), and setting Pax up from a computer. The private account needs a server
change ([SERVER_CHANGE.md](SERVER_CHANGE.md)); until it ships the app asks for an email and a code
after the Screen Time sheet.

Turning it off works like on a Mac: you ask, your trusted person (if you have one) is emailed
first, the wait you chose runs on the Pax server, then everything is removed and the Screen Time
passcode is shown. The first hour after set-up has no wait. If anything fails, Pax stays on.

Honest limits: a computer restore or full erase removes it, and anyone can switch the DNS layer
off in Settings (Pax notices and tells your trusted person). For the strongest protection, set
Pax up from a Mac: the Mac app sets up a supervised iPhone or iPad over a cable.

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
