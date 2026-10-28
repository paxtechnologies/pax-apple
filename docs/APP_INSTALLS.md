# Pax-approved installs and updates (Mac, v0.8.33)

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
| **.pkg installer** | **Refused** and left behind the turn-off wait: a package runs its own scripts as root and could remove Pax. Exception: packages Apple signed itself (`pkgutil --check-signature` says `signed Apple Software`, chain `Software Update` → `Apple Software Update Certification Authority` → `Apple Root CA`) that `spctl --assess --type install` accepts are installed with `installer -pkg … -target /`. Folder-style (non-flat) packages are refused. |
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
in a way Pax can't check · `PAX-UPDATE-009` couldn't check Apple updates · `010` Apple update didn't
install · `011` macOS wants an administrator. Full wording in [ERROR_CODES.md](ERROR_CODES.md).

## Left out on purpose

* **Using paxadmin's password for macOS updates.** On Apple silicon `softwareupdate` needs a volume
  owner's password for macOS updates. pax-guard holds paxadmin's password, but using it for anything
  but the turn-off wait would be a new way to use the held secret; Pax reports `PAX-UPDATE-011` instead.
  Smaller Apple updates (Safari, security responses, XProtect) don't need it.
* **Third-party .pkg installers**, even Developer ID signed and notarised: their pre/post-install
  scripts run as root and could remove or weaken Pax. They wait like turning Pax off.
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
