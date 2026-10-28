# Pax-approved installs and updates (Mac, v0.8.33)

Status: released in 0.8.33 (28 Oct 2026).

On a protected Mac your everyday account is a **Standard** account and the only administrator,
`paxadmin`, is kept behind the turn-off wait. macOS asks for an administrator to put an app in
`/Applications` or to replace one there, so before 0.8.33 a Standard user couldn't install or update
ordinary apps. pax-guard, Pax's root service, now does it for apps it can check, and refuses the rest.
Nothing here loosens Pax: a Standard user could already *run* a signed app from Downloads; what changes
is only that a checked app can live in Applications and be kept up to date.

Where: **Settings › Updates › Install or update an app** (shown once this Mac is protected). Drop an
app or a disk image on the box, or press **Choose…**.

Simpler ways in (Ruben, 28 Oct 2026), all ending on the same one-button sheet ("Update <App>?" /
"Install <App>?") and the same pax-guard checks:
- **Home card + one notification.** Pax runs the "Updates ready to install" scan when it opens, when it
  becomes active (at most once a minute) and every 30 minutes while open. Each update an app already
  downloaded shows on Home as "App update ready: <App> <version>" with one **Update** button (at most
  three cards), and one macOS notification "<App> has an update ready. Pax can install it for you." is
  posted once per app and version (remembered in `pax.installs.notified`, last 200 pairs; never
  repeated). Clicking it opens Pax on that install; only a path still in the latest scan opens the sheet.
  Installing from the card is update-only (`update_only`), like the Settings list.
- **Open With › Pax** on a .dmg or an .app, a drop on Pax's Dock icon, or a drop anywhere on Pax's
  window. Pax.app declares `com.apple.disk-image-udif` and `com.apple.application-bundle` as a Viewer
  with `LSHandlerRank` Alternate, so it is never the default for these files. On a Mac Pax doesn't
  protect, the file is just shown in Finder.
Rules and wording: `mac-app/Sources/PaxCore/AppUpdatePrompts.swift` (tested in V0833Tests); app side
`mac-app/Sources/Pax/AppUpdatesModel.swift`.

Code: `guard/app_installs.py` (pax-guard side), `guard/app-install-deny.txt` (the extra deny list),
`mac-app/Sources/PaxCore/AppInstalls.swift` + `mac-app/Sources/Pax/Views/AppInstallViews.swift` (app
side; Home card, notification and Open With in `AppUpdatePrompts.swift` + `AppUpdatesModel.swift`), tests in `guard/tests/test_v0833_installs.py` and `mac-app/Tests/PaxCoreTests/V0833Tests.swift`.

## What pax-guard installs

| What | Rule |
|---|---|
| **Update to an app in /Applications** | Installed at once, no wait, when the new copy has the **same bundle ID** and the **same Apple Developer Team ID** as the installed one, passes `codesign --verify --deep --strict`, is a Developer ID chain to Apple Root CA, `spctl --assess --type execute` says `source=Notarized Developer ID`, isn't older, isn't blocked (below), and the app isn't running. The installed folder name is kept. |
| **New app** | The same signature and notarisation checks, then refused if it's a blocked kind of app. Otherwise copied to `/Applications/<name>.app`. Refused if another app already has that name. |
| **Updates the apps downloaded themselves** | Apps that update with Sparkle or Squirrel (Electron's ShipIt) unpack the new version in `~/Library/Caches` and then ask for an administrator. Pax lists a newer copy it finds there (only inside `org.sparkle-project.Sparkle` folders and `*.ShipIt` folders, at most 6 levels and 3,000 folders deep) under "Updates ready to install". Installing one is an ordinary request marked *update only*: every check above runs, and it must replace an installed app. Zipped or still-packed downloads aren't covered; drop the app or .dmg instead. Works only where the updater leaves an unpacked app; needs testing app by app on a real Mac. |
| **.pkg installer** | **Refused** and left behind the turn-off wait: a package runs its own scripts as root and could remove Pax. Exceptions: (v0.8.34) notarised Developer ID Installer packages from a short list of trusted developers that pass the content checks (see "v0.8.34" below), and packages Apple signed itself (`pkgutil --check-signature` says `signed Apple Software`, chain `Software Update` → `Apple Software Update Certification Authority` → `Apple Root CA`) that `spctl --assess --type install` accepts are installed with `installer -pkg … -target /`. Folder-style (non-flat) packages are refused. |
| **Apple software updates** | "Apple software updates" on the same screen runs `softwareupdate --list` and, for a label from that list, `softwareupdate --install <label> --agree-to-license`. **Never** `--restart`: Pax says "Restart your Mac when you're ready". On Apple silicon macOS asks a volume owner to approve macOS updates; when `softwareupdate` says so, Pax reports `PAX-UPDATE-011` and does **not** use the administrator password it holds (see "Left out"). Safari, XProtect and similar updates usually install fine. |

## Never touched

* **Pax itself** (bundle IDs `org.paxpeace.*` / `org.paxmobile.*`, Team ID `Z94GSK7JA8`, or a folder
  called `Pax.app`): Pax updates only through its own Ed25519-signed path (`docs/UPDATES.md`).
* **Apple's apps** (`com.apple.*`, or signed by Apple's *Software Signing*): they update through the
  App Store or Software Update.
* **/System and anything outside /Applications.** The target is always directly inside
  `/Applications`, never a sub-folder, never a link.
* **An app with a different Team ID** (or an unsigned installed copy) is never replaced.
* **Unsigned, ad-hoc, Apple Development-signed or un-notarised apps** are refused.

## Blocked kinds of app (refused as new installs *and* as updates)

Checked on the staged copy, in this order; the first match refuses with `PAX-MAC-021` and says which
kind it is:

1. **Your own Blocked apps** (`guard_config.app_matches`: bundle ID, sealed signing identifier + Team ID,
   or program name).
2. **pax-guard's existing lists** in `guard/guard_config.py`, reused as they are: `BYPASS_APPS` (VPNs,
   Tor, proxies, Cloudflare WARP, Psiphon…), `UNMANAGEABLE_BROWSERS` (Opera, Vivaldi, Arc, Orion,
   Firefox/Chrome pre-release channels…), `REMOTE_AI_APPS` (ChatGPT, Atlas, Manus) and `VM_APPS`. By
   bundle ID, then by app or folder name. Unlike the quarantine sweep, a managed browser's *name*
   doesn't excuse an app with another bundle ID.
3. **`guard/app-install-deny.txt`**, for kinds those lists don't cover: remote-desktop tools
   (AnyDesk, TeamViewer, Parsec, RustDesk, Splashtop, Jump Desktop, RealVNC, NoMachine, ScreenConnect,
   LogMeIn, Chrome Remote Desktop host, Microsoft Remote Desktop / Windows App, Screens, Moonlight…),
   rented-Mac and cloud-computer clients (DeskIn, Shadow, Amazon WorkSpaces, Citrix, Horizon…), mesh
   VPNs (Tailscale, ZeroTier, NetBird, Twingate, Hamachi) and proxy clients (Clash, V2Ray, Surge,
   Shadowsocks, Hiddify…). Rules are by bundle ID, bundle ID prefix, Team ID (only Tailscale's,
   `W5364U7YZB`, confirmed from a public source) and name. If the file is missing or has a line pax-guard
   doesn't understand, **every** install is refused (`PAX-MAC-028`, fail closed).
4. **Any other web browser**: an app whose Info.plist offers to open `http`/`https` links, unless it's
   one of the browsers the Pax profile manages (Chrome `com.google.Chrome`, Edge `com.microsoft.edgemac`,
   Brave `com.brave.Browser`, Chromium `org.chromium.Chromium`, Firefox `org.mozilla.firefox`). This also
   catches link-picker apps (Choosy, Velja…): stricter on purpose.

These apps can still be installed after the turn-off wait, with the Mac's administrator, as before.
Remote-desktop apps stay refused here even if you turned the "Block remote desktop" site category off.

## How a request is handled (security)

The socket (`/var/run/pax-guard.sock`) is `0666`, so every request is treated as untrusted.

1. **Who.** The asking process's uid comes from the socket (`LOCAL_PEERCRED`). Only uid 0 and local
   accounts (uid 501+ with a home under `/Users`) may install; the request may only name a file in
   *that* account's home or under `/Volumes`.
2. **The path.** Absolute, already simple (`os.path.normpath`), no `.` or `..`, at most 1,024
   characters, no NUL, `realpath(path) == path` (no link anywhere on the way, so `/Volumes/Macintosh
   HD` → `/` is refused), not itself a link, owned by the asker or world-readable, and an `.app`
   folder, `.dmg` file or flat `.pkg` file. A choice inside a disk image is a plain name, no `/`.
3. **Copy first, then check (no TOCTOU).** A fresh `mkdtemp` folder under
   `/Library/PaxGuard/installs` (root, `0700`; if `/Applications` were on another volume, under
   `/Applications/.pax-installing` instead, so the last step is always a same-volume rename).
   * `.dmg`/`.pkg`: copied with `O_NOFOLLOW` + `fstat` (must be a regular file, at most 20 GB).
   * `.dmg`: the *copy* is attached with `hdiutil attach -readonly -nobrowse -noautoopen -noautofsck
     -mountpoint <staging>/mnt` (`Y` is answered to an image's licence prompt, since the user chose to
     install from it). Top-level `.app` folders (not links) and packages are listed; more than one app
     and no choice → `PAX-MAC-025` with the names; the chosen app is copied out with
     `ditto --noacl`, and the image is always detached (`-force` if needed), also at pax-guard's next
     start for a job cut short.
   * `.app`: copied with `ditto --noacl`.
   Whatever the user does to their own file after this point changes nothing.
4. **The staged tree** is walked without following links: every link must be relative and stay inside
   the bundle (checked lexically and with `realpath`), no setuid/setgid files (they would become
   root's), no devices, pipes or sockets, at most 300,000 entries and 20 GB (`PAX-MAC-031`).
5. **Checks** (all on the staged copy): bundle ID readable; not Pax or Apple; `codesign --verify
   --deep --strict`; `codesign -dv --verbose=4`: Team ID set, leaf `Developer ID Application: … (TEAM)`,
   chain through `Developer ID Certification Authority` to `Apple Root CA`, signing identifier equal to
   the bundle ID; `spctl --assess --type execute -vv`: accepted, `source=Notarized Developer ID`, origin
   Team ID equal to the signature's; blocked kinds; then, for an update, the installed copy's Team ID,
   version and whether it's running.
6. **Install.** `xattr -dr com.apple.quarantine` (only now), `chown -h -R root:admin`, `chmod -R go-w`,
   `codesign --verify --deep --strict` and the tree walk once more on the root-owned copy, then a
   rename into `/Applications`. An update renames the old copy into the staging folder first and puts
   it back if the second rename fails. The staging folder (and the old copy) is then removed.
7. **One job at a time** (`PAX-MAC-029`), at most 6 requests a minute; the work runs in a background
   thread and the app polls `installs.status`.
8. **Logged.** Every install, update and refusal goes to `/var/log/pax-guard.log` and the last 200 to
   `/Library/PaxGuard/state/installs.json` (time, result, app name, bundle ID, Team ID, version, file
   name, code). Any unexpected error refuses with `PAX-MAC-028`; nothing outside the staging folder
   has changed by then.

Socket commands: `installs.start {path, choice?, update_only?}`, `installs.status`, `installs.updates`,
`system_updates.check`, `system_updates.status`, `system_updates.install {label}` (a label must be one
from the last list and match `^[A-Za-z0-9][A-Za-z0-9 ._()+:,-]{0,199}$`; it's passed as one argument,
never through a shell).

## Error codes

`PAX-MAC-018` couldn't open that file · `019` not signed by its developer · `020` not notarised ·
`021` a blocked kind of app · `022` a different developer · `023` Pax or Apple's apps · `024` installer
packages wait · `025` choose one app · `026` quit the app first · `027` older version · `028` couldn't
install, nothing changed · `029` already installing · `030` another app has that name · `031` packaged
in a way Pax can't check · `032` (v0.8.34) the installer would change something Pax protects · `033`
(v0.8.34) a change after installing: protection put back, trusted person told · `PAX-UPDATE-009` couldn't check Apple updates · `010` Apple update didn't
install · `011` macOS wants an administrator. Full wording in [ERROR_CODES.md](ERROR_CODES.md).

## Left out on purpose

* **Using paxadmin's password for macOS updates.** On Apple silicon `softwareupdate` needs a volume
  owner's password for macOS updates. pax-guard holds paxadmin's password, but using it for anything
  but the turn-off wait would be a new way to use the held secret; Pax reports `PAX-UPDATE-011` instead.
  Smaller Apple updates (Safari, security responses, XProtect) don't need it.
* **Third-party .pkg installers** from developers not on `guard/pkg-trusted-teams.txt`, even Developer
  ID signed and notarised: their pre/post-install scripts run as root and could remove or weaken Pax.
  They wait like turning Pax off. (v0.8.34 lets a short, vetted list through; see below.)
* **.zip downloads**: unpacking an untrusted archive as root adds risk for little gain (Safari unpacks
  zips into an app in Downloads anyway, which Pax can install).
* **Installing into ~/Applications or anywhere else**, and privileged helpers / system extensions an
  app asks for after it's installed: macOS still asks for an administrator for those.
* **Mac App Store apps**: the App Store installs those itself.

## Needs a real Mac

Everything here is tested against faked `codesign`, `spctl`, `pkgutil`, `hdiutil`, `ditto`,
`installer` and `softwareupdate` output. On real hardware (see HARDWARE_TEST.md), check: a notarised
.dmg app (e.g. Firefox, VS Code), an update of an installed app (same Team ID), an update with a
different Team ID, a remote-desktop app (refused), a Developer ID .pkg (refused) and an Apple .pkg,
a dmg with a licence prompt, a dmg with two apps, an app running while it's updated, a Sparkle app's
and an Electron app's downloaded update, `softwareupdate` on Intel and Apple silicon (Safari update
and a macOS point update, no restart), `/Library` and `/Applications` on the same volume (`st_dev`),
the exact `spctl` wording on macOS 12–26, and the new files' ownership (`root:admin`, not
group-writable) and that apps installed this way open normally for the Standard user.

## v0.8.34: pointing people at Pax, and trusted installer packages

Status: released in 0.8.34 (28 Oct 2026).

On a protected Mac, dragging an app from a disk image to Applications makes Finder ask "Finder wants
to copy <App>. Enter an administrator's name and password", and third-party updaters do the same.
People don't know Pax can install it. Two quiet pointers, both ending on the same one-button sheet and
the same pax-guard checks (rules in `mac-app/Sources/PaxCore/InstallHelpers.swift`, tested in
V0834Tests; AppKit side `mac-app/Sources/Pax/InstallHelpersModel.swift`). Both only while Pax is
running (since 0.8.34 Pax opens hidden at every login on a protected Mac; see "Pax opens at login"), only on a Mac Pax protects, and only for a Standard account (admin group membership via
`getgrouplist`; if macOS won't say, the helpers stay quiet).

* **A disk image with an app on it.** Pax watches `NSWorkspace.didMountNotification` (and looks at the
  disks already mounted when it opens). A disk counts only when it's `/Volumes/<name>` (not hidden),
  local, backed by a `.dmg` per `hdiutil info -plist`, and has no Time Machine markers; so USB disks,
  network volumes, Time Machine and system volumes are ignored. Pax's own disk image (any
  `org.paxpeace.*`/`org.paxmobile.*` app or `Pax.app`) and Apple's apps are ignored. One top-level app →
  "Install <App>?", or "Update <App>?" when the same bundle ID is in /Applications with an older version
  (same or newer installed: nothing). Several apps → the .dmg itself goes to pax-guard, which asks which
  one. Offered **once per disk + app + version** (volume UUID; remembered in `pax.installs.mounted`, last
  200), so dismissing it doesn't bring it back, even after relaunching Pax with the disk still mounted.
  Pax never opens over a sheet that's already showing.
* **A small panel beside macOS's administrator dialog.** Every 1.5 s Pax reads the on-screen window list
  (`CGWindowListCopyWindowInfo`: window number, owner name, owner pid, bounds, alpha; **no titles, no
  contents, no Screen Recording permission**). A dialog-sized window owned by `SecurityAgent` (by name,
  or, where macOS hides owner names without Screen Recording, by the pid's bundle ID
  `com.apple.SecurityAgent` / executable path) that appears when Finder or a third-party app was the
  last app in front shows a floating, non-activating panel beside it: **"Installing or updating an
  app?" / "Pax can do it for you."** with **Open Pax** and **Not now**. No mention of passwords. Pax
  never clicks, types into, moves or reads the dialog. At most once every 2 minutes and once per
  dialog; it closes by itself when the dialog goes. Apple's other apps (System Settings, Installer,
  Safari, Keychain Access) and Pax itself don't trigger it. **Open Pax** opens the sheet already
  waiting, else the disk image just offered, else an update an app already downloaded, else Settings ›
  Updates › Install or update an app.
  * Permission note: on macOS 10.15–15 the window list gives other apps' owner names and bounds without
    Screen Recording (only titles and sharing state are withheld). A developer report says macOS 26
    withholds owner names too; owner pid and bounds are still given, so Pax resolves the pid itself. Pax
    never asks for Screen Recording; if macOS gives neither, the panel simply never shows (needs a real
    Mac on 26 to confirm).

### Trusted installer packages without the wait (Ruben, 28 Oct 2026 12:20 GMT)

Reason given: make installing normal software simple for Standard users. A third-party `.pkg` is
installed straight away **only when all of these hold**; anything else still waits like turning Pax
off (`PAX-MAC-024`), exactly as in 0.8.33:

1. `pkgutil --check-signature`: status "signed by a developer certificate issued by Apple", chain
   exactly `Developer ID Installer: <name> (<TEAM>)` → `Developer ID Certification Authority` →
   `Apple Root CA`.
2. Notarised: pkgutil's "Notarization: trusted by the Apple notary service" or `xcrun stapler validate`,
   **and** `spctl --assess --type install` says accepted, `source=Notarized Developer ID`, same Team ID.
3. The Team ID is on [`guard/pkg-trusted-teams.txt`](../guard/pkg-trusted-teams.txt): Microsoft
   `UBF8T346G9`, Google `EQHXZ8M8AV`, Adobe `JQ525L2MZD`, Zoom `BJ4HAAB9B3`, each confirmed from the
   vendor's documentation or a real signed package (sources in the file). Pax's own team and any team
   on the deny list can never be listed; a missing or malformed list means no package skips the wait.
4. The staged copy is expanded inside the root-only staging folder (`pkgutil --expand-full`, plus
   `--payload-files`) and refused (`PAX-MAC-032`) if anything would land on Pax's or the system's paths
   (`/Library/PaxGuard`, Pax.app, Pax's launchd jobs, `/System`, `/etc`, `/var`, `/usr` except
   `/usr/local`, `/Library/Extensions`, `/Library/SystemExtensions`, profiles, `SystemConfiguration`,
   Security plug-ins, other accounts' homes, other disks), or it contains a kernel, system or driver
   extension, a `.mobileconfig`, a network extension (app-extension point or app entitlement), an app
   from another team, an app on the deny list / the user's Blocked apps / pax-guard's bypass lists, a
   link into a protected place, a setuid file, or scripts (or the Distribution) that use words only
   something reaching for Pax would (pfctl, `/etc/hosts`, DNS/proxy `networksetup`, `profiles`,
   `systemextensionsctl`, `kextload`, `dseditgroup`, the admin group, `paxadmin`, Gatekeeper/SIP/
   FileVault/firmware tools, Pax's names) or `allow-external-scripts`. A package description with a DTD
   or entities, or that can relocate itself outside /Applications, is refused too.
5. Before installing, pax-guard runs an enforcement cycle and takes a picture; `installer -pkg <staged>
   -target /` runs; then the **full self-check** (`PkgIntegrity.check`), whatever the installer said:
   pax-guard still loaded by launchd, its own files and install rules unchanged, the tamper snapshot
   unchanged (admins, paxadmin, volume owners, Secure Token, FileVault, recovery key, MDM, startup
   security), the Pax profile still installed, no change to configuration profiles or activated system
   extensions, a fresh enforcement cycle that finds nothing to put back (hosts, pf, DNS settings, blocked
   apps, VPNs), the DNS canary, and pax-guard's runtime.
6. **Any failure fails closed** (`PAX-MAC-033`): protection is re-applied (enforcement cycle, standard
   accounts), the tamper log gets `install:pkg_check_failed`, the user gets a notification and the
   trusted person an email (local escrow), and `state/pkg-fastpath.json` turns this fast path **off for
   good** on that Mac (setting Pax up again is the only way back). A check that can't run counts as
   failed.

Same one-button UI ("Install <App>?"), also from Open With › Pax (Pax is now an Alternate viewer for
`com.apple.installer-package-archive`, never the default). Tests: `guard/tests/test_v0834_pkg_installs.py`.

Honest limits: a package's root scripts still run before the check, so a hostile script from a trusted
team could do harm that the check only *detects* (and repairs where Pax can); the protection is the
short, verified team list, the content checks, and failing closed afterwards. A script could also stop
pax-guard itself: a marker (`state/pkg-inflight.json`) is written before the installer runs and
removed only by the check, so when launchd starts pax-guard again it finds the marker and fails closed. Word matching in scripts is a tripwire, not a proof.

Needs a real Mac (HARDWARE_TEST.md "v0.8.34"): the disk-image prompt on drag installs, the panel beside
Finder's "wants to copy" dialog on macOS 12–26 (owner name vs pid on 26), and real packages from each
listed team (Microsoft Office / Edge / Teams, Google Chrome, Adobe Acrobat Reader, Zoom), including
whether their scripts or contents trip a check, `pkgutil --expand-full` on macOS 12, and the post-install
check staying quiet after a clean install.

## Pax opens at login (v0.8.34)

Status: released in 0.8.34 (28 Oct 2026). Ruben approved 28 Oct 2026: the helpers above only work while
Pax is running, so on a Mac Pax protects it now starts at every login, quietly.

* pax-guard (root) keeps `/Library/LaunchAgents/org.paxpeace.pax-login.plist`, `root:wheel 0644`, written
  by itself (no quarantine attribute), checked every cycle (~30 s): `ProgramArguments` = `/usr/bin/open -g
  -j -F -a /Applications/Pax.app --args --pax-login`, `RunAtLoad` true, `LimitLoadToSessionType` Aqua (real
  login sessions for every account, never ssh), `ProcessType` Interactive, `AssociatedBundleIdentifiers`
  `org.paxmobile.pax` (so macOS 13+ Login Items shows "Pax"). **No `KeepAlive`**: if you quit Pax it stays
  quit until the next login (no relaunch loop).
* Hidden start: `-g` (don't bring forward), `-j` (launch hidden), `-F` (don't restore old windows); Pax
  also hides itself when it sees `--pax-login` (`PaxCore/LoginLaunch.swift`, `PaxAppDelegate`) unless a
  file was opened with it. It comes forward only when something needs you: a disk image install prompt,
  the admin-dialog panel's Open Pax, a notification you click, or the Dock icon.
* Nothing is loaded into the session that's already running when the agent is first written (no window
  popping up after an update); it starts from the next login.
* Tamper: missing, changed, not root-owned, group/other-writable or a link → rewritten, tamper log
  `changed:login_agent` (Security notices: "Pax's open-at-login item was removed or switched off, and Pax
  put it back"), log `PAX-GUARD-016`. `launchctl disable gui/<uid>/org.paxpeace.pax-login` (the logged-in
  user's own override) is checked every minute and undone as root. The first install is quiet.
* A trusted `.pkg` (above) can't write Pax's LaunchAgents (`PAX-MAC-032`), and a post-install check that
  finds the agent had to be put back fails closed (`PAX-MAC-033`).
* Unprotected Macs have no pax-guard, so no agent. Remove Pax (`pax_guard.py uninstall` and
  `pax-uninstall-emergency.sh`) deletes it. While the password is released (before removal) the agent
  stays but isn't re-checked.
* Tests: `guard/tests/test_v0834_login_agent.py`, `mac-app/Tests/PaxCoreTests/V0834LoginTests.swift`.
  Needs a real Mac: HARDWARE_TEST.md "v0.8.34" steps 10–14 (hidden start on macOS 12–26, the macOS 13+
  "Background Items Added" notice, whether a Standard user can switch it off in Login Items without an
  administrator, fast user switching).

## Pax opens for installs, even when it isn't running (v0.8.35)

Status: built on branch `mac-autolaunch-installs` (28 Oct 2026). Before this, the disk-image prompt and the
admin-dialog panel only worked while Pax was running. On a Mac Pax protects, for a **Standard** account only:

* **(a) A disk is mounted.** pax-guard keeps a second root-owned LaunchAgent,
  `/Library/LaunchAgents/org.paxpeace.pax-installs.plist` (`root:wheel 0644`, `StartOnMount` true, Aqua
  sessions, no RunAtLoad/KeepAlive). launchd runs it in the user's session on every mount; its `/bin/sh`
  script does nothing for administrators (gid 80) or when Pax is already running (a running Pax sees the
  mount itself, and `open` on a running app would bring its window up), and starts Pax with `open -g -j -a
  /Applications/Pax.app --args --pax-install-check` only when some `/Volumes/*/` has an app at its top level.
  Pax then checks the mounted volumes and shows "Install <App>?" only when one has an app to install or
  update (same rules and dedupe as 0.8.34); otherwise it stays out of sight: no window, no Dock icon
  (`NSApplication` accessory policy until something is shown; `PaxCore/InstallCheckLaunch.swift`).
  pax-guard keeps the file like the login agent (missing/changed/permissions → rewritten, tamper log
  `changed:installs_agent`, `PAX-GUARD-017`), undoes `launchctl disable` every minute, and loads it into the
  console session when it isn't there (first install, `launchctl bootout`), so mounts are noticed without
  logging out.
* **(b) macOS asks for an administrator.** pax-guard's install watch (every 2 s, `ps -axo pid,uid,comm`)
  notices a new macOS authorisation-dialog process (`SecurityAgent`) or an app's own updater in the console
  user's session (Sparkle `Autoupdate` / `Updater`, Squirrel `ShipIt`). If Pax isn't running for that user and
  the user isn't an administrator (`dseditgroup checkmember`; unknown counts as administrator), it runs
  `launchctl asuser <uid> /usr/bin/open -g -j -a /Applications/Pax.app --args --pax-install-check
  --pax-install-reason=auth|update`, at most once every 30 s and once per process (a dialog that's still up
  after you quit Pax doesn't bring it back). Processes already there at a new login or pax-guard start are
  the baseline. The existing floating panel then appears beside the dialog; because Pax wasn't running to see
  which app was in front, an `auth` launch treats an unknown front app as an install for one minute (a known
  non-install app such as System Settings still gets no panel). This covers Finder's drag to Applications:
  the panel's Open Pax goes to the mounted disk's "Install <App>?" sheet, or the Install or update an app
  sheet when there's no disk.
* **(c) An update is already downloaded.** Every ~10 minutes pax-guard runs the same scan as
  `installs.updates` on the console user's `~/Library/Caches` (Sparkle / ShipIt) and starts Pax hidden for
  an app+version it hasn't opened Pax for yet, so the "App update ready" card and notification appear.
* Nothing is loosened: pax-guard only ever starts Pax, which only offers installs pax-guard then checks.
  A trusted `.pkg` can't write Pax's LaunchAgents, and a post-install check that had to put the new agent
  back fails closed (`PAX-MAC-033`). Remove Pax and the emergency uninstaller delete the agent.
* Limits: a root daemon can't see windows, so (b) keys on the SecurityAgent process appearing, not on the
  dialog; if macOS reuses one SecurityAgent process for a second dialog while Pax isn't running, that second
  dialog doesn't start Pax. Apple's Installer.app (.pkg) dialogs aren't treated as installs by the panel
  (0.8.34 rule). StartOnMount throttling and the exact SecurityAgent process name/owner need checking on
  each macOS (HARDWARE_TEST v0.8.35 16–23).
* Tests: `guard/tests/test_v0835_autolaunch.py`, `mac-app/Tests/PaxCoreTests/V0835Tests.swift`.

## Same-team apps and Pax.app self-heal (v0.8.35)

* `PAX-MAC-023` ("Pax doesn't change this app") now protects only Pax itself: a Pax bundle ID or signing
  identifier (`org.paxpeace.` / `org.paxmobile.`), the name `Pax.app`, or an installed copy that is Pax.
  Pax's Team ID alone no longer makes an app untouchable: other apps from the same developer (Swoop,
  `com.swoopkey.swoop`) go through every normal check (codesign strict, Developer ID, notarisation,
  deny list and Blocked apps, same-team update rule) and install or update like anyone else's.
  Tests: `guard/tests/test_v0835_same_team_installs.py`.
* pax-guard checks `/Applications/Pax.app` every minute (exists, not a link, Pax's bundle ID) and fully every
  15 minutes (`codesign --verify --deep --strict`, Developer ID from Team Z94GSK7JA8; on Developer ID installs
  only). Missing or broken → restored from the signed update channel: the same `pax-update.json` (Ed25519,
  SHA-256 and size pinned), version never older than pax-guard; the app inside must have that version, Pax's
  bundle ID, pass codesign, be signed by Pax's team and pass Gatekeeper ("Notarized Developer ID"), then it's
  swapped in atomically (`renamex_np` RENAME_SWAP; a missing app is a single rename). A newer release goes
  through the normal update instead. Tamper log `changed:pax_app`, notification, `PAX-GUARD-018`; failures
  back off 5 min → 1 h. Skipped while an update or install is running and once the password is released.
  The updater also now pins Pax's Team ID when the installed app can't be read (before, a missing Pax.app
  meant no Team ID comparison). Tests: `guard/tests/test_v0835_pax_app_heal.py`.
