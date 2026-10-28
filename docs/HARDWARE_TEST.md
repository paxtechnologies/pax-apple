# Hardware test checklist (v0.8.0)

Everything here was tested only with mocks and on Linux/macOS CI. These checks need a real Mac and a
real iPhone. Note the result (pass/fail + one line) next to each, and the macOS/iOS version.

Before you start: a Time Machine/Finder backup, the FileVault recovery key written down, and a second way
into the Mac (another Mac or iPhone for email). Have `guard/scripts/pax-uninstall-emergency.sh` handy
(README "Remove Pax by hand").

**macOS 12 Monterey:** support is new in v0.8.20 and not yet tried on a real Monterey Mac. Its own checklist is in [MONTEREY.md](MONTEREY.md).

## Mac (Apple silicon; Intel too if you have one)

1. **Install**: open `Pax-0.8.2.dmg` from the CI artifact, drag to Applications, right-click › Open
   (ad-hoc signed, not notarised). Setup: This Mac › choose blocks › 24 hours wait › Lock it in.
2. **Preflight**: wrong password is refused; a second admin is flagged; an MDM-enrolled Mac shows a warning,
   not a block.
3. **Local escrow**: after setup you are a Standard user; `paxadmin` exists; `sudo ls /Library/PaxGuard/escrow`
   is impossible from your account; Home shows "Protected" with no server configured.
4. **pax-guard**: `sudo launchctl print system/org.paxpeace.pax-guard` (as paxadmin) shows it running;
   `ls -l /var/run/pax-guard.sock` is `srw-rw-rw-`; Home's filter line says "Filtering through CleanBrowsing".
5. **DNS forwarder**: System Settings › Network › DNS shows `127.0.0.1` on Wi-Fi and Ethernet;
   `dig @127.0.0.1 restricted-check.paxpeace.com` → `0.0.0.0` (Pax's test name on the restricted list;
   `python3 common/pax_restricted.py --sample` prints a real restricted site too); `dig @127.0.0.1 ssstik.io` →
   `0.0.0.0` (media converters, v0.8.1); `dig @127.0.0.1 example.com` → a real address;
   `dig @1.1.1.1 example.com` times out (pf blocks plain DNS); a DoH browser setting doesn't bypass it.
   Turn Wi-Fi off/on and switch networks: DNS stays on 127.0.0.1.
6. **Failover**: block `doh.cleanbrowsing.org` at your router (or pf as paxadmin) → Home says AdGuard
   Family (backup), sites still filtered; block both → sites don't open (SERVFAIL), never unfiltered.
7. **Blocked sites**: add a site → blocked at once; ask to remove it → 24 h countdown; cancel works.
   v0.8.1: ask for an exception for a restricted site (`--sample`) or `ssstik.io` → refused at once with
   "This site is in a category Pax always blocks, so it can't be allowed." (PAX-DNS-010), no countdown,
   no partner email; an exception for a VPN-list site (e.g. nordvpn.com) still gets the countdown.
8. **Partner email**: set a relay or SMTP transport and a partner; ask for removal → partner gets the email
   *before* the countdown appears; with the network off the request shows "telling your partner"
   (PAX-ESCROW-010) and starts once it's back.
9. **Removal**: after the wait, Request a change › reveal gives paxadmin's password; it works in
   System Settings › Users; partner gets "password revealed".
10. **Clock**: set the date forward a week while waiting → the countdown doesn't jump.
11. **Recovery-key rotation** (FileVault on): the old personal recovery key no longer validates
    (`fdesetup validaterecovery` as paxadmin); the new one is released only after the wait.
12. **Updates**: once a v0.8.1 tag exists, Settings › Updates › Update now installs it without an admin
    prompt; Pax restarts and stays protected. A tampered `pax-update.json` is ignored.
13. **Design T5 (Recovery)**: shut down, hold the power button › Options. Does the Recovery user picker list
    your **Standard** account? Does its password get you into Recovery (Terminal, Disk Utility, Startup
    Security)? Does "Forgot all passwords?" accept the **old** recovery key after rotation (it should not)?
    Write down exactly what you see; this decides the next step of recovery-lock/DESIGN.md.
14. **Intel only**: the firmware password is set (`firmwarepasswd -check`), escrowed, and released after
    the wait.
15. **Emergency removal script** works from paxadmin and restores DNS settings.

### v0.8.6: no Command Line Tools on the Mac path

16. **Fresh Mac, no Command Line Tools**: on a Mac where `xcode-select -p` fails (or after
    `sudo rm -rf /Library/Developer/CommandLineTools` on a test Mac), install from the notarised DMG and run
    *Protect this Mac*. No "install developer tools" prompt appears at any point (set-up, escrow deposit,
    the first check, Home, Settings, Request a change, removal). As paxadmin:
    `sudo cat /Library/LaunchDaemons/org.paxpeace.pax-guard.plist` shows `/bin/sh
    /Library/PaxGuard/bin/pax-guard-launch.sh run`; `ps -axo pid,command | grep pax_guard` shows
    `/Library/PaxGuard/runtime/bin/python3.12 -I -B /Library/PaxGuard/bin/pax_guard.py run`;
    `sudo ls -l /Library/PaxGuard/runtime` is root:wheel and not group/other-writable;
    `codesign -dv /Library/PaxGuard/runtime/bin/python3.12` shows `TeamIdentifier=Z94GSK7JA8`;
    `ls /Library/PaxGuard/runtime/lib/python3.12/site-packages` is empty or missing (pax-guard's copy has
    no iPhone packages). `/Library/PaxGuard/runtime/bin/python3.12 -I -B /Library/PaxGuard/bin/pax_guard.py ask
    '{"cmd":"status"}'` shows `"runtime": {... "on_runtime": true ...}`.
17. **Partner email and updates over TLS on the runtime**: with SMTP or the relay set, a removal request
    still emails the partner first (the runtime trusts macOS's `/etc/ssl/cert.pem`); Home's filter line
    still says CleanBrowsing (DoH works).
18. **Tamper check**: as paxadmin, append a line to
    `/Library/PaxGuard/runtime/lib/python3.12/json/__init__.py`, then wait up to 10 minutes (or
    restart pax-guard): Home shows a tamper event `changed:runtime`, the log says it was rebuilt from
    Pax.app, and the file is back to normal. Repeat after moving `/Applications/Pax.app` away: the event
    says it couldn't be repaired, and `cat /Library/PaxGuard/state/runtime-starts` shows `3` (the launcher
    now uses `/usr/bin/python3` if the tools are there, else the runtime). Put Pax.app back.
19. **Upgrade from 0.8.5 without a gap**: on a Mac protected with 0.8.5 (pax-guard on `/usr/bin/python3`),
    let the forced update to 0.8.6 run (Settings › Updates › Update now). Keep a browser open and run
    `dig @127.0.0.1 restricted-check.paxpeace.com` in a loop: it never returns a real address (a few
    seconds of no answer during the restart are expected). Afterwards the plist uses the launcher and
    `ps` shows the runtime (step 16). `grep -E "switching pax-guard|stays on" /var/log/pax-guard.log`
    shows the switch. If the runtime ever fails its check, the log says "stays on /usr/bin/python3" and
    protection carries on there.
20. **Update mirror**: after the 0.8.6 tag, block `github.com` and `objects.githubusercontent.com` at the
    router (or with pf as paxadmin), then Update now on a 0.8.6 Mac when 0.8.7 is out: it installs from
    the jsDelivr parts. `/var/log/pax-guard.log` never mentions a 403.

### v0.8.6: YouTube Restricted Mode switch

21. **Default on**: `https://www.youtube.com/` shows the Restricted Mode banner in Safari, Chrome and
    Firefox; `dig @127.0.0.1 www.youtube.com` returns a CNAME to `restrict.youtube.com`.
22. **Off**: Home › This Mac › YouTube Restricted Mode off (0.8.12 only: under Safer social media ›
    Advanced). Within a few seconds (reload the page) the
    banner is gone in Safari and Firefox; `dig @127.0.0.1 www.youtube.com` returns ordinary Google
    addresses. On a Mac set up with 0.8.6, Chrome/Edge/Brave also drop it (an older Pax profile still
    pins `ForceYouTubeRestrict` in those three until Pax is set up again). Google and Bing still force
    SafeSearch (`dig @127.0.0.1 www.google.com` → `forcesafesearch.google.com`), a restricted site is
    still blocked, and no partner email is sent. The tamper list in the app shows
    `setting:youtube_restricted`.
23. **On again** is immediate too. Switch it off, then Update now (or reinstall the same version): it stays
    off. Block `doh.cleanbrowsing.org` while it's off: YouTube comes back *restricted* through AdGuard
    Family, never unfiltered.

### v0.8.10: other administrator accounts (a rented Mac's rmsvc)

Best on a fresh rented cloud Mac (Rent a Mac / SimpleMDM, which ships an `rmsvc` admin) or any Mac with a
second admin account. Before: Protect this Mac stopped with PAX-MAC-003 "There are other administrator
accounts (rmsvc)".

1. Protect this Mac as usual. After "Protect my Mac" the check screen lists **Also make these standard
   accounts: rmsvc** (ticked) with one button. On an MDM-enrolled Mac there's also an info line that the
   management server could still change accounts or undo Pax. No System Settings, no Terminal.
2. Untick it: the button stays disabled with a line saying why. Tick it again and continue.
3. When it finishes: `dseditgroup -o checkmember -m rmsvc admin` says "no …", the same for your account;
   paxadmin is the only admin. Pax's tamper log (Home › details) shows `accounts:made_standard` within a
   minute. `sudo plutil -p /Library/PaxGuard/config.json` lists `demoted_admins`.
4. Re-promote rmsvc as paxadmin (or via the provider): within about a minute pax-guard makes it standard
   again, logs `admin:made_standard_again` and shows a notification.
5. Failure path (optional): make the demotion fail (e.g. a name dseditgroup refuses). Set-up stops with
   PAX-MAC-003, says Pax undid every step, and every account is an admin again, yours included.
6. Remove Pax properly after the wait: rmsvc and your account are administrators again, paxadmin gone.
   The emergency uninstaller (`pax-uninstall-emergency.sh --user <you>`) also restores rmsvc.
7. Test mode still works as before: `defaults write org.paxmobile.pax pax.testing.allowExtraAdmins -bool
   true` leaves rmsvc an admin, with the test-mode warning.

### v0.8.33: install and update apps as the Standard user (docs/APP_INSTALLS.md)

On a protected Mac, logged in as the everyday (Standard) account. Watch `sudo tail -f /var/log/pax-guard.log`
from another admin session if you have one, else read `/Library/PaxGuard/state/installs.json` after the
turn-off wait.

1. **New app**: download a notarised .dmg (Firefox, VS Code, Rectangle). Settings › Updates › Install or
   update an app › drop the .dmg. "Copying… / Opening the disk image… / Checking the app… / Installing…",
   then "<App> <version> is installed in Applications." No password prompt. `ls -le@ /Applications/<App>.app`:
   owner root, group admin, not group/other-writable, no `com.apple.quarantine`. The app opens normally.
   The disk image isn't left mounted (`hdiutil info`), `/Library/PaxGuard/installs` is empty.
2. **Drop an .app** (from a mounted image in /Volumes, and from Downloads): same result.
3. **Update**: install an older notarised version of an app (e.g. from the developer's archive), then drop the
   newer one: "<App> is updated to <version>." The folder name is kept. With the app open: "Quit the app
   first." (PAX-MAC-026). Dropping the older one again: PAX-MAC-027.
4. **Different developer**: an app with the same bundle ID signed by another team (build one with your own
   Developer ID): PAX-MAC-022, the installed copy untouched.
5. **Refusals**: AnyDesk or TeamViewer .dmg → "Pax doesn't install remote-desktop tools: …" (PAX-MAC-021);
   Tailscale, Opera, a VPN app → PAX-MAC-021; an unsigned or ad-hoc app (e.g. one you built with `swift
   build`) → PAX-MAC-019; a Developer ID but un-notarised app → PAX-MAC-020; a Developer ID .pkg
   (Zoom, Office) → PAX-MAC-024; Pax.app or an Apple app → PAX-MAC-023. Nothing appears in /Applications.
6. **Apple package**: an Apple-signed .pkg (e.g. a Command Line Tools or ProVideo Formats .pkg from
   developer.apple.com, `pkgutil --check-signature` shows "signed Apple Software") installs.
7. **Two apps in one image** (any suite .dmg): Pax asks which; choosing one installs only that one.
8. **Licence .dmg** (one that shows an agreement when double-clicked): installs without hanging.
9. **Updates the apps downloaded**: in a Sparkle app (e.g. one with "Check for Updates…") and an Electron
   app (Slack, Discord) let the app download its update and cancel its administrator prompt. Open the
   sheet: does "Updates ready to install" list it? Install → updated. Note which apps leave an unpacked copy.
10. **Apple software updates**: Check for updates lists what `softwareupdate --list` shows. Install a Safari
   or security update: installs, no restart. A macOS point update on Apple silicon: note whether it installs
   or shows PAX-UPDATE-011 ("macOS wants an administrator"); either way the Mac doesn't restart by itself.
11. **Abuse**: from Terminal as the Standard user, `python3 /Library/PaxGuard/bin/pax_guard.py ask
   '{"cmd":"installs.start","path":"/System/Applications/Chess.app"}'`, a path with `..`, a symlink to an app,
   `/Volumes/Macintosh HD/...`: all PAX-MAC-018. Swap the .app in Downloads for another app while "Copying…"
   shows: the app that was copied is what's checked and installed.
12. Restart pax-guard mid-install (`sudo launchctl kickstart -k system/org.paxpeace.pax-guard` from an admin):
   no image left mounted, staging empty after it comes back, nothing half-installed in /Applications.
13. **Home card + notification**: with a Sparkle/Electron update downloaded (step 9), open Pax: Home shows
   "App update ready: <App> <version>" with **Update**, and one notification "<App> has an update ready.
   Pax can install it for you." (allow notifications when macOS asks). Click it with Pax quit: Pax opens on
   "Update <App>?". Quit and reopen Pax, wait 30 minutes: no second notification for the same version.
   After updating, the card goes.
14. **Open With / Dock / window**: right-click a .dmg in Downloads › Open With: Pax is listed but the .dmg
   still opens in DiskImageMounter by double-click (Pax isn't the default). Open With › Pax, a drop on the
   Dock icon, and a drop on Pax's window each show "Install <App>?" (or "Update <App>?" when it's in
   Applications) once, with one button, and no extra Pax window opens. Repeat with Pax quit first.

## iPhone / iPad

0. (v0.8.6) Use a Mac that has **never had the old helper**: no `~/Library/Application Support/Pax/venv`,
   no Homebrew `idevicebackup2`, ideally no Command Line Tools, and `PAX_PYTHON` / `PAX_IDEVICEBACKUP2`
   unset, so the bundled helper is what runs. Install Pax from the notarised DMG. No Terminal step should
   be needed anywhere below. Test once on Apple silicon and, if possible, once on an Intel Mac.
   Run the iOS 27 phone first and an iOS 17–26 phone second: the restore now goes through
   pymobiledevice3 instead of `idevicebackup2` (same options). Check photos, messages and the Apple
   Account are all still there afterwards. If the restore fails, repeat with
   `PAX_IDEVICEBACKUP2=/opt/homebrew/bin/idevicebackup2` on a developer Mac to tell an engine problem
   from a method problem.
1. Plug in, set up through the app (Keep my data); the phone shows as supervised (Settings › General ›
   About › "This iPhone is supervised").
2. Profile installs silently (or by one tap without the supervision certificate).
3. DNS: Settings › General › VPN & Device Management › Pax shows the DNS profile; it is **CleanBrowsing
   Family over DoH, direct** (there's no forwarder on iOS). A restricted site (`python3 common/pax_restricted.py --sample`) fails in Safari and in another
   app's web view; `redd.it`/`imgur.io` media don't load.
4. The profile can't be removed without the removal password.
5. Request a change in the Mac app for the iPhone: countdown, partner email, cancel; after the wait the
   password is shown and removes the profile.
6. Finder backup still works (unless Strict pairing was chosen).
7. (v0.8.6) **YouTube Restricted Mode on the iPhone** is chosen in "Choose what to block" (its own switch
   again since 0.8.13) and fixed in the
   iPhone's locked profile (the supervision key is deleted after set-up, so Pax can't change the profile
   later). With it on (default): YouTube in Safari and the YouTube app show Restricted Mode. Set up a
   second phone with it off: YouTube is unrestricted, but Google SafeSearch is still forced, Reddit and
   a restricted site still don't load (the rest still goes through CleanBrowsing Family). Settings ›
   General › VPN & Device Management › Pax › DNS shows the same CleanBrowsing Family server either way.

### v0.8.8: Pax's own DNS filter on the iPhone

Before you start: `dns.paxpeace.com` must have both A records (167.233.42.17 and 89.167.17.42) and
`https://dns.paxpeace.com/health` must answer `"ok": true`. An iPhone set up before 0.8.8 keeps
CleanBrowsing directly: remove Pax from it first (removal password after the wait), then set it up again.

1. Check the old set-up first (why custom sites didn't block): Settings › General › VPN & Device
   Management shows **Pax** under Configuration Profile and "This iPhone is supervised and managed by …"
   at the top of Settings. Tap the profile: it lists DNS, Restrictions and **Content Filter**. Screen
   Time › Content & Privacy Restrictions › App Store, Media, Web & Games › Web Content shows "Limit Adult
   Websites" and can't be changed (managed). If the profile or the Content Filter line is missing, or the
   phone isn't supervised, the web filter never applied.
2. Set up with 0.8.8, default options (don't open Advanced). Add two of your own sites in "Choose what to
   block". After set-up, Settings › General › VPN & Device Management › Pax › DNS shows
   `https://dns.paxpeace.com/u/…/dns-query`.
3. Your sites don't open in Safari, Chrome or another app's web view, including `m.` and other subdomains.
4. On the Mac, Blocked sites: add a new site. Within about 10 seconds it no longer opens on the phone
   (no new profile). Ask to remove it: the partner gets an email first, the countdown starts, and the site
   stays blocked until the wait ends.
5. X app and x.com: posts load, images and videos don't. Bluesky the same. A Reddit image link
   (`i.redd.it`) and an Imgur image don't load.
6. YouTube with Restricted Mode on (default) shows Restricted Mode. On the Mac (or with
   `PUT /v1/dns/settings {"youtube_restricted": false}`) turn it off: YouTube is unrestricted within
   about a minute, Google SafeSearch stays on.
7. Failover: ask us to stop one server (or block one IP on your router). Browsing keeps working through
   the other. Note how long the first page takes after the switch.
8. Advanced › "Use CleanBrowsing directly" on a second test phone: DNS shows CleanBrowsing Family, and a
   site added later on the Mac does **not** reach that phone (expected).

### v0.8.9: blocked sites sync, and the 24-hour wait

Needs a Mac protected with 0.8.9 (its own key) and an iPhone set up from that Mac with 0.8.8 or later
(Pax's filter). Note the times.

1. Home on the Mac shows **Sync blocked sites across devices** switched on, with "Sites you add here are
   blocked on your iPhone and iPad within seconds". (If it says it joins "as soon as one is set up", the
   Mac isn't linked yet: set up the iPhone from this Mac, or open Home again once online.)
2. On the Mac, Blocked sites: add a site. It stops opening on the Mac at once and on the iPhone within
   about 15 seconds, in Safari and in another app.
3. Add a site from the iPhone side (Blocked sites with the iPhone selected). It stops opening on the Mac
   within about 15 seconds.
4. Remove a site from the Mac: your partner gets an email first, the countdown shows the Mac's own wait
   (or the account's if longer). Cancel it from the iPhone side: the countdown disappears on the Mac too.
   Remove it again and let the wait end: it opens again on both, not before.
5. Turn Wi-Fi off on the Mac. Add a site: blocked on the Mac at once. Try to remove one: Pax says it
   can't reach your account and nothing changes. Turn Wi-Fi on: the added site reaches the iPhone.
6. Switch sync off: nothing opens that was blocked. Add a site on the Mac: it doesn't reach the iPhone.
   Switch sync on: the iPhone gets it; nothing is unblocked anywhere. The tamper log shows both switches.
7. Wait time: in an iPhone set-up, the wait step offers **24 hours**, 72 hours and 7 days; choosing 24
   hours works (0.8.8 failed with PAX-ESCROW-002). Shortening a wait later waits out the current one and
   emails the partner.
8. A second Mac (protected with its own key): start "Protect an iPhone or iPad" there with the same email.
   At the wait step press **Send code**; the 6-digit code that arrives joins the same account (v0.8.32: the
   same step as a new account, no extra screen), and the first Mac's sites appear on the second Mac within
   about 15 seconds.

### v0.8.32: every new account checks its email with a code (Mac)

Use a Mac with no Pax account yet (Settings › Advanced shows no account), a fresh address you can read, and
a second address that already has a Pax account.

1. **Protect this Mac** (server key) → wait step: one email field, the button reads **Send code**, and the line
   under the field says Pax emails a 6-digit code. Type a fresh address and press Send code: the email "Your
   Pax code" arrives within a minute; the step now shows "We emailed a 6-digit code to …" and a code field.
   Nothing else on the screen changed and no new screen opened.
2. Paste the whole email text into the code field: only the 6 digits stay. Type one digit wrong and press
   Return: "That code isn't right or has expired. Check the newest email from Pax, or send a new code." in
   the step (no error card), and nothing is made.
3. **Resend code** is greyed out with a countdown for 30 seconds, then sends a new code; the old code no
   longer works, the new one does. Pressing it 5 times in an hour greys it out with "Resend code in … min".
4. Enter the right code and press Continue: set-up goes on to Lock it in as before. Settings › Advanced (or
   `GET /v1/accounts/me` with the token) shows the account with `email_verified: true`.
5. Change the email field after a code was sent: the code field disappears and the button reads Send code
   again.
6. Repeat 1–4 for **Protect an iPhone or iPad** with the address that already has an account: the code joins
   that account (its blocked sites appear; the holder gets "a new device signed in").
7. A Mac protected **with its own key**, no account yet: Settings › Accountability partner email › Add… →
   relay through Pax's server, your email in "Your email" → Save sends a code and keeps the sheet open with
   the code field; Save again with the code saves and closes it. A test partner email arrives.
8. An already set-up Mac (account token saved): updating to 0.8.32 changes nothing; no email step appears.
9. Pax 0.8.31 (old DMG) against a 0.8.32 server: the wait step's Continue shows PAX-ESCROW-005 "Pax's server
   said no to that request"; *Copy details* contains "can't make new accounts any more … paxpeace.com".
   With an address that already has an account it still gets the old "already has a Pax account" code step.
   `curl -X POST …/v1/accounts -H 'Content-Type: application/json' -d '{"email":"new@example.com"}'`: 410
   `app_update_required`, PAX-ESCROW-020.

### v0.8.13: X and Bluesky pictures and video always off

1. **Choose what to block** (Mac, then the iPhone set-up): a plain *YouTube Restricted Mode* switch and the
   notice "Pictures and video on X and Bluesky are always off. Posts stay readable." No X or Bluesky switch
   anywhere, Advanced included. The Mac lock-in summary says "Hide pictures and video on X and Bluesky."
2. After set-up: `pbs.twimg.com` and `cdn.bsky.app` don't resolve; x.com and bsky.app posts load as text.
   Home › This Mac shows the YouTube switch (instant, as in step 22) and the same notice.
3. Update a Mac set up with 0.8.12 with X pictures allowed: after pax-guard updates, `pbs.twimg.com` no
   longer resolves and `/Library/PaxGuard/log` has the one "always blocked now" line.
4. `curl -X PUT …/v1/dns/settings -d '{"x_media": false}'` with an account token: 422
   `media_always_blocked`, `pax_code` PAX-DNS-016, no email to the partner.
5. An exception request for `pbs.twimg.com` is refused at once (PAX-DNS-010).

### v0.8.12: Pax Max after set-up (Mac, key on this Mac)

1. Set up with Pax Max **off**. Firefox › Add-ons lists Pax Image Blur 0.6.0 (installed by policy); pictures
   load normally. `/etc/hosts` has `127.80.77.0 pax-max-off.guard.paxpeace.com` inside the Pax block.
2. Settings › Pax Max (v0.8.23: folded; click the arrow): the explanation and the "isn't perfect" note show. Turn it on: a confirmation explains it
   first; after OK the line is gone from `/etc/hosts` at once and a new Firefox tab blurs pictures until checked.
3. Turn it off: the confirmation says it takes effect after 1 hour. With a trusted person set, they get the
   email first and the countdown shows 60 minutes; the tamper list shows `setting:pax_max_off_requested`.
   "I've changed my mind" cancels (`setting:pax_max_off_cancelled`); Pax Max stays on.
4. Start it again and wait the hour: the line returns to `/etc/hosts`, new tabs no longer blur, Settings says
   "Pax Max is off", the tamper list shows `setting:pax_max`.
5. Wi-Fi off, then try to turn it off: PAX-GUARD-014 and nothing starts. Partner relay unreachable (with a
   partner set): PAX-ESCROW-010 and the hour doesn't start until they're told.
6. Moving the Mac's clock forward an hour doesn't end the wait early (network time must agree).

### v0.8.14: one Settings, device details on the device's page

1. The top bar has no gear. The sidebar shows the devices, then *Blocked Sites / Apps* and **Settings**
   (v0.8.21: no *Home* row; clicking a device opens its Home, and Settings has a *‹ Home* link).
2. Click *This Mac*: its page shows the status card, Request a change, the This Mac switches (ads, sync,
   YouTube Restricted Mode, the X/Bluesky notice, Pax Max line) and Blocked apps.
3. Click an iPhone/iPad: its page shows the status card, Request a change, then **Details**: Status, iOS,
   Set up by, Filter, one row "Images and video on X and Bluesky: Always blocked", YouTube Restricted Mode,
   "Your blocked apps: N apps" (click to see the names, wrapped), the set-up note, *Set up again* and
   *Remove from this list*. Nothing is cut off at the window's narrowest width.
4. Click *Settings*: Blocking, Turning Pax off, Accountability partner email, Updates (About folded inside),
   a closed *Pax Max* and a closed *Advanced* (where this Mac keeps its key, the server address). No device is highlighted in the sidebar.
5. Pax › Settings… (⌘,) opens that same screen in the main window (and reopens the window if it was closed).
   No separate Settings window appears.
6. On a Mac set up before 0.8.4, Home › This Mac says Chrome is using the extension list from set-up and
   names Momentum; pax-guard's status (`{"cmd":"status"}`) has `browser_rules.outdated: true`.
   Nothing about the profile changes.

### v0.8.15: verified support release

Use a test device and a test support key only (never redeem on a device you rely on).

1. Set up a test Mac: the wait step shows **Allow verified support release**, on, with one line under it.
   Settings › Turning Pax off shows the switch on and (v0.8.27) the **Support ID** (Copy works).
2. On a Mac set up with 0.8.14, after the update to 0.8.15: the switch is **off** (v0.8.27: so no Support ID shows).
3. Turn the switch off: it says off straight away. Turn it on: the partner gets an email first and Details
   says when it turns on (after the wait).
4. With the switch on, issue a code for the test Mac's Support ID (`tools/pax-support-release.py issue …`)
   and paste it in Request a change › In an emergency › I have a support code. The partner email arrives,
   then the Mac shows "Your wait is over" with Remove Pax. Using the same code again gives PAX-ESCROW-016;
   a code for another Support ID gives PAX-ESCROW-014; with the partner's mail path broken, PAX-ESCROW-018
   and nothing is released.
5. iPhone/iPad: Device details shows the switch, and (v0.8.27, switch on) the Turn off card shows the Support ID; In an emergency takes a code and
   shows the removal password after the partner email.
6. The tamper log (`{"cmd":"tamper.list"}`) shows `support_release_setting`, `support_code_refused` and
   `support_release_used` entries; no entry contains a code.

### v0.8.23: calmer Settings

1. Settings shows, top to bottom: Blocking (three switches, no lines under them), Turning Pax off, Accountability
   partner email, Updates, then *Pax Max* and *Advanced* as rows with an arrow, both closed. Nothing is cut off at
   the narrowest window width, light and dark.
2. Each *Details* opens on click and shows the explanations that used to be under each switch (Blocking: ads,
   sync state, YouTube, X/Bluesky line; Turning Pax off: wait, support release and its rule).
3. Every switch still works as before: ads, sync, YouTube, support release (off instant; on waits, partner told),
   Start my wait now (trial day), Update now, the family layer (Advanced).
4. Pax Max row says *Off* on a new set-up (it's off by default; the set-up switch starts off) and "Blurs pictures
   and video in Firefox. Other browsers aren't covered yet." Opening it shows the switch; on/off behave as in
   v0.8.12 above, and while the hour runs the row says *Turning off*.
5. Accountability partner email: with no one set it says "Not set" and *Add…*; with someone set, their email,
   "Told before any turn-off wait starts." and *Change…*. *Change…* opens a sheet with the rule, both emails and
   (under *How Pax sends the email*) the Pax server / own email choice. Changing or removing them still shows
   "Changing to … on …" (after the turn-off wait), on the card and in the sheet. With the relay down after a
   removal request, the card says "1 email waiting to send. Pax keeps trying."
6. Updates: "Version 0.8.27 · last checked …" and *Update now*; *About Pax* opens to the wordmark, principles,
   licence and site link.
7. Security notices: after a pax-guard update (a short backup episode in `{"cmd":"tamper.list"}` as
   `dns:fallback_on` / `dns:fallback_off`), Settings › Advanced and Home show no notice for it. Stop the filter
   for 10+ minutes (block the upstream): one line "Pax used its backup family filter for N minutes on …". No
   notice shows a code like `dns:fallback` or `changed:admins`; adding an admin shows "The list of
   administrators on this Mac changed (…)".

### v0.8.26: iPhone/iPad status from the server

1. With a protected iPhone, its Status card says "Protected" and, under it, "Checked just now" with a small
   *Refresh status* link. Click it: a brief spinner, then "Checked just now". Clicking again within 10 seconds
   does nothing.
2. Turn Pax off on the iPhone (trial day, or a finished turn-off wait with the password shown, or a support
   code). Within a refresh (switch away from Pax and back, open Home, or *Refresh status*) the card says
   "Turned off" and "Pax is off on <name>.", the sidebar says "Turned off", and *What's blocked* and *Turn off*
   are gone. *Remove from list* (prominent) and *Set up again* are on the card. *Remove from list* asks
   "Remove <name> from the list?" / "This removes it from the list on this Mac." and the phone leaves the
   sidebar. A second Mac on the same account no longer lists it either (server: device retired).
3. Leave a phone on Pax DNS switched off (or in flight mode) for 3 UTC days: "Not checking in", "It may have
   been reset or removed.", "Last seen …". Switch it on and use it: "Protected" again after a refresh.
4. Disconnect the Mac from the network and refresh: the last state stays, with "Last checked … · couldn't
   reach Pax just now". No error card.

### v0.8.27: Support ID next to the turn-off controls

1. On a Mac set up with *Allow verified support release* ticked: Settings › **Turning Pax off** shows
   "Support ID: XXXX-XXXX-XXXX-XXXX" under the switch, with *Copy* (paste it somewhere: it matches) and
   "Share this with Pax support if you can't turn Pax off the usual way." Settings › Advanced no longer shows a
   Support ID.
2. Turn the switch off: the Support ID disappears straight away. Turn it on again: nothing shows during its
   turn-off wait; it appears once the switch is on.
3. A Mac set up before 0.8.15 (switch off, never migrated): no Support ID anywhere in Settings.
4. iPhone/iPad with the switch on: its Home **Turn off** card shows the same row under *In an emergency*;
   *Device details* has the switch but no Support ID. With the switch off: no Support ID on the card.
5. Turn the phone off (trial day, finished wait, or a support code): after a refresh the card is **Turned
   off** and no Support ID shows. Same on this Mac once its wait is over.
6. A support code issued for the shown ID still works as before (PAX-ESCROW-014 for another device's ID).

### v0.8.27: support code paste

1. Copy a full support code from an email (grouped in fives, with line breaks; also try it in lower case).
   Paste it into *In an emergency › I have a support code* on this Mac and on an iPhone's card: it appears at
   once, with no beachball or typing lag. *Use support code* becomes available straight away.
2. Click elsewhere: the field shows the code tidied (upper case, no spaces). Return or *Use support code*
   sends it; a code for another device still gives PAX-ESCROW-014.

### v0.8.27: Blocked Sites / Apps lists only devices Pax is on

1. With a protected iPhone picked, Blocked Sites / Apps says "Blocking on <iPhone>" and lists its apps.
2. Turn Pax off on that iPhone and remove the profile. After a refresh (switch away and back, open the page
   or Home, or *Refresh status*), the page no longer names the iPhone or lists its apps: it shows this Mac (if
   protected) or the next phone still protected.
3. With no device left (the only phone turned off, or removed from the list, and this Mac not protected), the
   page shows "No devices are protected right now" and no sites, apps or pending changes.
4. On this Mac: after its turn-off wait ends, and again after *Remove Pax from this Mac*, the page no longer
   shows "Blocking on <this Mac>" or this Mac's apps.

