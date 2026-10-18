# Home and Settings (v0.8.18; Settings v0.8.23; phone status v0.8.26)

Ruben, 2026-10-17: "simplify, simplify, simplify: 1, 2, 3, not option overwhelm", without removing any
functionality.

## Home (each device's page)

1. **Status**: one big calm line: "Protected", or "Pax turns off in 12 h 19 min · Cancel". During the trial
   day: "Trial day · turn off anytime until …" with a gentle countdown and "Start my wait now". At most one
   quiet line, "1 thing to know" / "2 things to know", that opens to the notices: the backup filter (only when
   Pax's own filter isn't answering), an update note, an older Chrome extension list, the latest security-setting
   change, or partner email still to set up.
2. **What's blocked**: Sites (count, opens the full list; one *Add*, then a field and *Block*) and Apps
   (count, opens the list with *Unblock…* / *Cancel*; one *Add* opens the picker). On an iPhone or iPad the
   apps are a count "chosen at set-up". One line: "Blocking is instant. Unblocking takes your turn-off wait."
3. **Turn off**: one button ("Start the turn-off wait", or "Turn Pax off" in the trial day), then "Turn Pax
   off on this Mac" when the wait is over. *In an emergency* (folded): emergency release, a support code,
   and (Mac) "I'm locked out of this Mac". On a Mac it opens with (v0.8.21): "Emergency release is self-serve.
   You give a reason, your trusted person is emailed, and Pax turns off after 24 hours instead of your full
   turn-off wait. You can use it once every 90 days." The hours follow the server's
   `PAX_EMERGENCY_COOLOFF_SECONDS` (sent as `emergency_cooloff_seconds` in device status; 24 hours when an
   older server or pax-guard doesn't send it). In the trial day there is no cooling-off, so it says Pax turns
   off "straight away, as it's your trial day". On an iPhone or iPad, *Device details* (folded) holds its details,
   Support ID and support-release switch.

## iPhone and iPad status from the server (v0.8.26)

The card for an iPhone or iPad shows what the Pax server says, not what this Mac remembers from set-up
(before 0.8.26 it kept saying "Protected" after Pax was turned off). PaxCore `PhoneStatus` maps the
server's device status, in this order:

| Server says | Card says |
| --- | --- |
| `released` (or `released_at`, or a request with status `revealed`): a finished turn-off wait with the password shown, an emergency or trial-day turn-off, or a support code | **Turned off** · "Pax is off on Ruben's iPhone." · "If Pax's settings are still on the iPhone, remove them there in Settings › General › VPN & Device Management." (plus the password while the server still offers it) |
| a removal request `pending` / `notifying` | the turn-off wait countdown, as before |
| `checking_in: false` (no Pax DNS traffic for 48 hours or more; phones on Pax's own filter only) | **Not checking in** · "It may have been reset or removed." · "Last seen Thu 15 Oct" |
| trial day / nothing else | Trial day / **Protected**, as before |
| the server answered but the phone isn't on the account | "Pax can't find this device on your account any more." |

* **Turned off** hides *What's blocked* and *Turn off* (turn-off, emergency and support controls). The card
  has a prominent **Remove from list** and **Set up again**. The confirm reads "This removes it from the list on
  this Mac." Removing also asks the server to forget the device (`POST /v1/devices/{id}/retire`), which the server
  allows only for a device whose password was already released. It never turns anything off, and it's logged.
  If the server can't be reached, the device still leaves this Mac's list.
* **Not checking in** keeps the Turn off card (Pax may still be on the phone). Its *Remove from list* is local
  only: "This removes it from the list on this Mac. If Pax is still on it, Pax stays on." All of an account's
  iPhones and iPads share one Pax DNS address, so the server can't tell them apart: a phone shows as not
  checking in only when none of the account's phones has used Pax DNS for 48 hours or more. The owner sees this
  on their own Mac. The partner isn't emailed.
* A protected phone keeps *Remove from this list* inside *Device details*, with its honest text: "This only
  tidies the list on this Mac. Pax stays on the device."
* **When it refreshes**: one request for all of the account's phones (`GET /v1/devices`) when the app opens,
  whenever it becomes active, when Home appears, and from a small **Refresh status** link on the Status card (at
  most once every 10 seconds, with a small spinner). There is no timer. Under the status: "Checked just now" or
  "Last checked 12 min ago". If Pax can't be reached, the last known state stays, with "· couldn't reach Pax just
  now" added, so an old "Protected" never looks fresh. Nothing fails open.
* The sidebar label under each phone follows the same states: Protected · Turn-off wait · Turned off · Not
  checking in · Setting up.

## Sidebar and Blocked Sites / Apps (v0.8.21)

* The sidebar lists the devices, then **Blocked Sites / Apps** and **Settings**. There is no *Home* row: the
  app opens on Home (when something is protected), and clicking a device opens its Home. Settings and
  Blocked Sites / Apps each start with a *‹ Home* link; the Pax logo and *Pax › Home* (⇧⌘H) also go Home.
  In a narrow window the header links are *Blocked Sites / Apps* and *Settings*.
* **Blocked Sites / Apps** starts with one calm line naming the device the sidebar has picked:
  "Blocking on Ruben's MacBook Air" (this Mac's name) or the iPhone's or iPad's name. Under it, how far the
  blocks reach (PaxCore `BlockedPage`):
  * "Sites: applies to all your devices." for the account's list, or this Mac's list while sync is on.
  * "Sites: applies to this Mac only. Turn on sync in Settings › Blocking to use them on all your devices."
    while this Mac keeps its own list with sync off.
  * "Sites: applies to all your iPhones and iPads. This Mac keeps its own list while sync is off." when a
    phone is picked and this Mac's sync is off.
  * "Apps: this Mac only." or "Apps: this iPhone only, chosen at set-up." Apps are always per device, and
    the page lists them under the sites (with *Add* and *Unblock…* on a Mac that keeps its own key).
* Settings has no device header: it is this Mac's settings plus app-wide ones, as before.

## Settings (sidebar › Settings, ⌘,) (v0.8.23)

Ruben, 2026-10-17: "settings looks a bit cluttered … only keep what is necessary … without affecting any core
functions." Each card is a short title and its current state; explanations and rare actions sit under a closed
**Details** disclosure. Nothing was removed: every switch, button and check is at most one click deeper.
Order (PaxCore `AppSettingsLayout.sections`):

* **Blocking** (this Mac): the switches Ads and trackers · Sync blocked sites across devices · YouTube
  Restricted Mode, with no line under each. *Details*: what each one does (incl. the sync state line) and
  "Pictures and video on X and Bluesky are always off" (no switch).
* **Turning Pax off**: Turn-off wait row · trial day line and "Start my wait now" (in the trial) · the
  *Allow verified support release* switch with its one state line. *Details*: what the wait applies to, what
  support release is, and its rule (off instant; on takes the turn-off wait, instant in the trial day).
* **Accountability partner email**: their email (or "Not set"), one state line ("Told before any turn-off
  wait starts.", "Changing to … on …", "Being removed on …", "N emails waiting to send. Pax keeps trying.") and
  one button, *Add…* / *Change…*. The sheet holds the rule, the partner and your own email, and under *How Pax
  sends the email* the Pax server / own email account choice with its fields. Rules unchanged (told first,
  fail closed; changing or removing them waits; pax-guard enforces both).
* **Updates**: "Version 0.8.26 · last checked …" and *Update now*; *About Pax* (folded) holds the auto-update
  line, wordmark, tagline, principles, licence and site link (About was its own card before).
* **Pax Max** (folded like Advanced, closed by default, just above it; off by default for everyone): the row
  shows *On* / *Off* / *Turning off* and "Blurs pictures and video in Firefox. Other browsers aren't covered
  yet." Opening it shows the explanation, the "isn't perfect" note, the rule and the switch (unchanged
  behaviour: on instant; off partner first, then 1 hour, cancellable). Pax Max is only installed in Firefox
  (Pax Image Blur); Chrome and Safari aren't covered.
* **Advanced** (folded, unchanged): this Mac's Support ID (copy), which filter is answering (and the backup's
  reason and time while it's on), filter lists, the **Extra family filter layer** switch (off by default; on
  is immediate, off waits like a removal), security notices, where this Mac keeps its key, Pax server, for
  testers.

### Security notices (v0.8.23)

* Shown as plain sentences ("The list of administrators on this Mac changed (17 Oct 2026, 12:43)."), never
  as log codes; an unknown kind gets a general sentence.
* pax-guard still writes every `dns:fallback_on` / `dns:fallback_off` to the tamper log. A backup episode
  shorter than 10 minutes (pax-guard starts on the backup after an update until its lists load and the
  self-check passes) isn't shown, in Settings or on Home. A longer one is one line: "Pax used its backup
  family filter for 25 minutes on 17 Oct (its own filter wasn't ready or didn't pass a self-check). You
  stayed protected." One still running is shown once it has lasted 10 minutes. pax-guard's status leaves
  brief pairs out of `tamper.recent` too (`_shown_tamper_events`).

## Set-up

* Turn-off wait step: the "first hour" line became the trial-day line, and verified support release is a
  ticked-by-default checkbox, "Allow verified support release (recommended)".
* Mac "Lock it in": the three "what Pax will block" lines are one line; the trial day replaces the first hour.
* Mac "Your Mac is ready": no longer asks again for the backup already confirmed on "Lock it in".
* The Mac (3 steps) and iPhone (4 steps: plug in, choose, wait, lock it in) flows keep every step protection
  depends on, so no step was merged away.
