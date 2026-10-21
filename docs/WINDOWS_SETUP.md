# Pax for iPhone set-up on Windows

Status: **branch `windows-setup` only. Not released, not signed, not tested on a real
Windows PC with an iPhone yet.**

The Windows version of the Mac app's iPhone/iPad "Keep my data" (no-erase) set-up, for
people without a Mac. It makes Pax hard to remove on an iPhone or iPad, from a Windows PC
over USB. It is **only** the phone set-up: it is not a Windows filter, and nothing here
protects the PC itself.

## 1. What carries over from the Mac, unchanged

| Part | Mac | Windows |
| --- | --- | --- |
| USB work (list, preflight, backup, seed restore, Trust, live configuration, status, profile install, profile list) | `device/pax_device.py` + `device/seed.py` on the Python bundled in Pax.app | **the same two files**, as `pax-helper.exe` (PyInstaller console program, started hidden). Same JSON protocol, same commands, same flags. |
| iOS method | 17–26 "restored" seed with system files + restart; 27 no-system seed + live `SetCloudConfiguration` in Setup; ≥28 refused | identical (it's the same `seed.py`) |
| pymobiledevice3 | 11.32.0, hash-pinned, `--no-deps` (`device/requirements-bundle.txt`) | same version, hash-pinned for win_amd64 (`windows/requirements-windows.txt`, made by `windows/lock_windows.py`, which reuses `device/lock_bundle.py`). Differences: no `ioregistry`; adds `pywin32` (pymobiledevice3's Windows layer imports `win32security`; Pax uses DPAPI) and `colorama`. |
| Profile | `profile/make_profile.py` run as a script | the same module, called in-process (`windows/pax_windows/profile_maker.py`); the test compares it with the CLI the Mac runs |
| Supervision identity | `/usr/bin/openssl` (cfgutil recipe) | same certificate (RSA 2048, self-signed, CN=Pax Supervision Identity, O=Pax, 3650 days, DER) made with `cryptography`; key overwritten and deleted after the install, on every path |
| Server | `EscrowClient.swift` etc. | `windows/pax_windows/escrow.py`: the same endpoints and bodies (`POST /v1/accounts`, sign-in code, `PUT .../wait`, `PUT .../partner`, `GET /v1/dns`, `PUT /v1/dns/settings`, `POST /v1/devices` with `support_release`, `trial`, `hardware_id`) |
| Safety order | `SetupCoordinator.swift` | `windows/pax_windows/flow.py`: account first; supervision read back before anything is escrowed; DNS filter health checked (PAX-DNS-012); **escrow before install**; key destroyed in `finally` |
| Choices | 1 day, 3 days (recommended), 7 days, Custom (server limits from `/v1/health`), trusted person optional, trial day, verified support release on, agreement "I'm 18 or over, and this iPhone/iPad is mine or my child's. I understand that turning Pax off takes my turn-off wait (…)." | the same, word for word (tests pin them) |
| Trial day hardware ID | `sha256("pax-hw-v1:" + id)`; without Apple Configurator the id is the UDID | the UDID, same formula, so a phone first set up from a Mac doesn't get a second trial day from Windows |

Requirements on the phone are the Mac's: **Find My off** (the phone refuses the restore
otherwise), a finished backup (Pax's own, or the person's from iCloud / Apple Devices /
iTunes), battery ≥ 50 % or charging. **The passcode stays on**: the phone asks for it after
the restart and for "Trust This Computer?". (The brief mentioned turning the passcode off;
the Mac flow doesn't, and nothing in the method needs it.)

## 2. Apple's driver on Windows

pymobiledevice3 talks to the phone through **Apple Mobile Device Service (AMDS)**, Apple's
usbmux on Windows, on `127.0.0.1:27015`. Pax can't ship it (it's Apple's). Two sources:

- **Apple Devices** (Microsoft Store, free, ID `9NP83LWLPZ9K`): Apple's current app for
  Windows 10/11. USB works; it doesn't find phones over Wi-Fi, which Pax doesn't need.
  **Recommended.**
- **iTunes** (classic installer, also provides AMDS).

Detection (`windows/pax_windows/driver.py`, as pymobiledevice3's own `win_util` does it):
the registry key `HKLM\SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service`
(ImagePath tells Store app from iTunes) plus a connect to port 27015. Missing → a calm
screen with "Open the Microsoft Store" (`ms-windows-store://pdp/?ProductId=9NP83LWLPZ9K`,
web fallback) and "Check again". Installed but not running → "restart, or open the Apple
Devices app once".

## 3. Trust (pairing)

Windows doesn't always raise "Trust This Computer?" by itself, so for an unpaired phone the
app sends **one** Pair request (`pax_device.py connect`) and then waits for "I tapped Trust"
before asking again. It never polls while the Trust dialog is up (a Pair sent while the
passcode is being typed cancels the dialog), exactly as on the Mac. The pair record is kept
by AMDS (and pymobiledevice3's own folder in the user profile).

## 4. iOS 17 and later

No tunnel is needed. Every service Pax uses (`mobilebackup2`, `com.apple.mobile.MCInstall`,
`diagnostics_relay`, `afc`, `notification_proxy`, `installation_proxy`, `springboard`) is a
classic **lockdown** service over usbmux, which pymobiledevice3 reaches as a normal user.
The RemoteXPC/RSD tunnel (admin rights, the wintun driver on Windows) is only for developer
services (DVT, Instruments, DDI), which Pax never uses. So: **no admin rights, no wintun,
no extra drivers** beyond Apple's AMDS. The installer is per-user (`PrivilegesRequired=lowest`).

## 5. UI

**tkinter** (in CPython, no extra runtime, small, robust under PyInstaller), styled in Pax's
brand v2: Mist background, white cards, Navy text and buttons, Dusk accents, the white
"pax" logo on a Navy step rail, Pax Inter / Pax Fraunces Soft loaded privately from the
Mac app's bundled OFL fonts (Segoe UI fallback). Content scrolls on small screens. Every
phone/server step runs on a worker thread.

Rejected: PySide6 (≈60–80 MB more, LGPL bundling care), pywebview (needs WebView2 runtime,
two languages to maintain). If the brand needs a richer look later, pywebview is the next
step; the flow code doesn't change.

Steps: 1 Plug in (driver check → find the phone → Trust) · 2 Get ready (Find My off,
passcode note, backup) · 3 Turn-off wait (1/3/7/Custom, email or 6-digit code, someone
you trust, trial day line, verified support release) · 4 Lock it in (agreement → preflight
→ seed restore → on-phone instructions while it restarts → Trust → supervision confirmed →
"Turn on protection" → escrow → install, or "one tap on your iPhone" if the silent install
falls back) · 5 Done (Find My back on; limits).

The **account step is pluggable** (`windows/pax_windows/account.py`): `EmailAccount` today;
an `AnonymousDeviceAccount` placeholder for the one-tap set-up with an anonymous device
account coming with the iOS app 1.2. Not built: the server has no such route yet.

## 6. Packaging

**PyInstaller onedir + Inno Setup** (recommended): `PaxSetup.exe` (window) and
`pax-helper.exe` (console helper) share one `_internal` folder; the Inno installer is
per-user, adds a Start-menu shortcut, no startup items, uninstalls cleanly. Onedir starts
fast and avoids the temp-folder unpacking that onefile builds do (which also trips
antivirus heuristics more often). MSIX was rejected for now: it must be signed to install
at all, and its container makes the helper's USB/AMDS access and per-user data paths
harder to reason about. CI builds both an installer and a zipped folder.

## 7. Code signing and SmartScreen

Unsigned, Windows shows "Windows protected your PC" (SmartScreen, "Unknown publisher") on
download/first run; people must click "More info › Run anyway", and some antivirus tools
are stricter with unsigned PyInstaller apps. Since 2024, **EV certificates no longer skip
SmartScreen**; OV, EV and Microsoft's cloud signing all build reputation over time
(learn.microsoft.com/windows/apps/package-and-deploy/code-signing-options, checked
21 Oct 2026).

| Option | Rough price (Oct 2026) | Notes |
| --- | --- | --- |
| **Azure Artifact Signing** (formerly Trusted Signing), Basic | **$9.99/month** (5,000 signatures) | Organisations in the UK are eligible; needs a paid Azure subscription and Microsoft's identity validation of the company; GitHub Action `azure/artifact-signing-action`. Short-lived certs, no hardware token. **Recommended.** |
| OV code-signing certificate | ≈ $99–$350/year (e.g. SSL.com $129/yr, Certum resellers ≈ $99/yr) | Key must be on a hardware token or a cloud HSM (extra cost); same SmartScreen behaviour |
| EV certificate | ≈ $300–$670/year | No SmartScreen advantage any more; only worth it for kernel drivers |

## 8. Decisions and purchases (maintainer)

1. **Signing**: set up Azure Artifact Signing (Basic, ~$9.99/month) for the company, or
   buy an OV certificate. Until then the app is unsigned and shows SmartScreen warnings.
2. **Apple driver dependency**: OK to ask people to install Apple's free "Apple Devices"
   app from the Microsoft Store first (Pax can't bundle it)?
3. **Turning Pax off from Windows**: this first version only sets up. Turning off later
   needs Pax on a Mac (same email) for now. Options: add a small "Turn off" screen to the
   Windows app (server already has everything), or a web page.
4. **Name** in the Start menu / installer: "Pax for iPhone set-up" (placeholder).
5. **Where it's offered**: website download page, and what the page says about the
   SmartScreen prompt while unsigned.

## 9. Honest limits

- A full restore of the phone from a computer (recovery/DFU mode) still removes Pax, as it
  removes everything. Same as the Mac.
- Unsigned until a signing option is set up: SmartScreen warnings.
- Not yet run on a real Windows PC with an iPhone. The USB code is the Mac's, but the
  Windows usbmux (AMDS) path, the Trust prompt behaviour and the restart/reconnect timing
  are untested on hardware.
- Advanced Mac options left out of this first version: "Strict" (no other computer can
  pair), CleanBrowsing directly, "Erase and set up fresh" (Clean mode needs Apple
  Configurator, which doesn't exist on Windows), the app picker, and the sites field.
- It doesn't protect the PC.

## 10. Build and test

```
pip install --no-deps --require-hashes --only-binary=:all: -r windows/requirements-windows.txt
pip install -r windows/requirements-dev.txt -r server/requirements-dev.txt pyinstaller pillow
python -m pytest windows/tests
python windows/make_icon.py
pyinstaller --noconfirm --distpath dist --workpath build/pyi windows/pax_setup.spec
dist\PaxSetup\pax-helper.exe selftest --expect-pymobiledevice3 11.32.0
ISCC /DSourceDir=%CD%\dist\PaxSetup /DOutDir=%CD%\dist windows\installer.iss
```

`python -m pax_windows --demo` (from `windows/`) walks the whole window with a canned phone
and an in-memory server. CI: `.github/workflows/windows-setup.yml` (windows-latest; runs
only for this branch or by hand; uploads the unsigned artifact `PaxSetup-windows-unsigned`).

## 11. Hardware test checklist (needs a Windows 10/11 PC + an iPhone)

1. Without Apple Devices installed: the driver screen appears; Store link opens.
2. With it: phone found; first-time Trust prompt appears after one Pair request.
3. "Back up with Pax" finishes and is verified (MobileBackup2 over AMDS).
4. iOS 17–26: seed restore → restart → reconnect → Trust → supervised → silent install.
5. iOS 27: restart into Setup → live configuration taken → "Restore Completed" → install.
6. Server shows the device with trial day, support release, turn-off wait; the trusted
   person's emails arrive.
7. Uninstall leaves nothing running; `%LOCALAPPDATA%\Pax` holds no key afterwards.
