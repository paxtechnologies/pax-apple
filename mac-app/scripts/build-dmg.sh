#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# Build Pax.app and Pax-<version>.dmg on a Mac with only the Xcode Command Line
# Tools (xcode-select --install). No Xcode, no Apple Developer account.
#
#   cd mac-app && ./scripts/build-dmg.sh
#   open dist/Pax-0.8.6.dmg
#
# Options (environment variables):
#   PAX_VERSION=0.8.6       version string (CFBundleShortVersionString, DMG name)
#   UNIVERSAL=1             build arm64 + x86_64 and lipo them (default: this Mac's arch;
#                           the GitHub workflow always builds universal)
#   SIGN_IDENTITY=-         "-" = ad-hoc (local testing only, the default). Releases (the
#                           Build DMG workflow): "Developer ID Application: <name> (<team ID>)"
#   NOTARY_PROFILE=         a `xcrun notarytool store-credentials` profile name (needs a
#                           Developer ID): notarises + staples Pax.app (so the update zip
#                           is notarised too), then the DMG
#   NOTARY_KEYCHAIN=        keychain holding that profile (CI uses a temporary keychain)
#   OUT_DIR=dist            where Pax.app and the DMG go
#   PAX_BUNDLE_ID=org.paxmobile.pax   (TODO: move to org.paxpeace.pax; the app's UserDefaults
#                           and Keychain items live under this ID, so changing it needs a migration)
#   BUNDLE_DEVICE_HELPER=1  bundle the iPhone helper runtime (default). 0 skips it for a quick
#                           local build: Keep my data then needs PAX_PYTHON (a developer venv).
#
# v0.8.6: Pax.app carries its own Python for the iPhone helper (Contents/Resources/device/
# python: python-build-standalone CPython, universal2, with pymobiledevice3), built by
# scripts/build-device-helper.sh from pinned, hash-checked downloads. Every Mach-O in it is
# signed with SIGN_IDENTITY (hardened runtime; the interpreter gets
# Resources/helper-python.entitlements) before the app itself, and the signed helper must
# pass `pax_device.py selftest` and `list` or the build fails. The app runs
# device/pax_device.py and, for iPhone profiles, profile/make_profile.py with it, so the
# iPhone set-up needs no Python, Command Line Tools or Homebrew on the user's Mac.
set -euo pipefail

die() { echo "build-dmg: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

[[ "$(uname -s)" == "Darwin" ]] || die "run this on macOS (it needs swift, codesign and hdiutil)"
for tool in swift codesign hdiutil plutil ditto; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found. Install the Command Line Tools: xcode-select --install"
done

VERSION="${PAX_VERSION:-0.8.32}"
BUNDLE_DEVICE_HELPER="${BUNDLE_DEVICE_HELPER:-1}"
UNIVERSAL="${UNIVERSAL:-0}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
NOTARY_PROFILE="${NOTARY_PROFILE:-}"
NOTARY_KEYCHAIN="${NOTARY_KEYCHAIN:-}"
if [[ -n "$NOTARY_PROFILE" && "$SIGN_IDENTITY" == "-" ]]; then
  die "notarisation needs SIGN_IDENTITY=\"Developer ID Application: …\""
fi
staple() {   # staple <path>: Apple's ticket CDN can lag or drop a connection, so retry
  local n
  for n in 1 2 3 4 5 6; do
    # stapler validate re-queries Apple's CDN and flakes the same way; staple
    # already checks the ticket, and CI runs spctl on the result.
    if xcrun stapler staple "$1"; then return 0; fi
    echo "   (stapling $(basename "$1") failed, attempt $n; retrying in $((n * 15))s)"
    sleep $((n * 15))
  done
  die "couldn't staple $(basename "$1")"
}
notarise() {   # notarise <file>: submit, wait, fail the build unless Apple accepts it
  local args=(--keychain-profile "$NOTARY_PROFILE")
  if [[ -n "$NOTARY_KEYCHAIN" ]]; then args+=(--keychain "$NOTARY_KEYCHAIN"); fi
  local out; out="$(xcrun notarytool submit "$1" "${args[@]}" --wait --timeout 30m 2>&1)" || true
  echo "$out"
  if ! grep -q "status: Accepted" <<<"$out"; then
    local id; id="$(sed -n 's/^ *id: \([0-9a-f-]*\).*/\1/p' <<<"$out" | head -n 1)"
    if [[ -n "$id" ]]; then xcrun notarytool log "$id" "${args[@]}" || true; fi
    die "Apple did not accept $(basename "$1") for notarisation"
  fi
}
helper_check() {   # helper_check <Pax.app>: the bundled helper starts, imports everything, lists devices
  local app="$1" py="$1/Contents/Resources/device/python/bin/python3.12" pin out
  pin="$(/usr/bin/python3 -I "$SCRIPT_DIR/helper_runtime.py" pin pymobiledevice3)"
  out="$("$py" -I -B "$app/Contents/Resources/device/pax_device.py" selftest --expect-pymobiledevice3 "$pin" | tail -n 1)"
  echo "   selftest: $out"
  grep -q '"ok": true' <<<"$out" || die "bundled helper selftest failed"
  out="$("$py" -I -B "$app/Contents/Resources/device/pax_device.py" list | tail -n 1)"
  echo "   list: $out"
  grep -q '"ok": true' <<<"$out" || die "bundled helper 'list' failed"
  # Running it must not have changed anything inside the sealed app.
  codesign --verify --strict "$app" || die "running the helper modified Pax.app"
}
BUNDLE_ID="${PAX_BUNDLE_ID:-org.paxmobile.pax}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAC_APP="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO="$(cd "$MAC_APP/.." && pwd)"
OUT_DIR="${OUT_DIR:-$MAC_APP/dist}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
APP="$OUT_DIR/Pax.app"
DMG="$OUT_DIR/Pax-$VERSION.dmg"
BUILD_NUMBER="$(git -C "$REPO" rev-list --count HEAD 2>/dev/null || date +%Y%m%d%H%M)"

step "Building Pax $VERSION (release)"
cd "$MAC_APP"
if [[ "$UNIVERSAL" == "1" ]]; then
  swift build -c release --triple arm64-apple-macosx12.0
  swift build -c release --triple x86_64-apple-macosx12.0
  BIN="$OUT_DIR/Pax-universal"
  lipo -create \
    "$(swift build -c release --triple arm64-apple-macosx12.0 --show-bin-path)/Pax" \
    "$(swift build -c release --triple x86_64-apple-macosx12.0 --show-bin-path)/Pax" \
    -output "$BIN"
else
  swift build -c release
  BIN="$(swift build -c release --show-bin-path)/Pax"
fi
[[ -x "$BIN" ]] || die "build produced no executable at $BIN"

step "Assembling Pax.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/profile" "$APP/Contents/Resources/device" \
  "$APP/Contents/Resources/guard" "$APP/Contents/Resources/lists" "$APP/Contents/Resources/extensions"
cp -X "$BIN" "$APP/Contents/MacOS/Pax"
chmod 755 "$APP/Contents/MacOS/Pax"

# v0.8.16 app icon (Pax Peace brand v2: a soft "p" on navy): mac-app/Resources/branding/
# pax-icon-navy-1024.png, rendered by render_icons.py into AppIcon.iconset + AppIcon.icns.
# iconutil (macOS) rebuilds the .icns from the iconset; the committed AppIcon.icns is the fallback.
ICON_KEY=""
ICONS="$MAC_APP/Resources"
if [[ -d "$ICONS/AppIcon.iconset" ]] && command -v iconutil >/dev/null \
   && iconutil -c icns "$ICONS/AppIcon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"; then
  ICON_KEY="AppIcon"
elif [[ -f "$ICONS/AppIcon.icns" ]]; then
  cp -X "$ICONS/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
  ICON_KEY="AppIcon"
elif [[ -f "$ICONS/AppIcon.png" ]] && command -v iconutil >/dev/null && command -v sips >/dev/null; then
  ICONSET="$(mktemp -d)/AppIcon.iconset"
  mkdir -p "$ICONSET"
  for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$ICONS/AppIcon.png" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
    sips -z $((size * 2)) $((size * 2)) "$ICONS/AppIcon.png" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
  ICON_KEY="AppIcon"
else
  echo "   (no app icon in mac-app/Resources: using the generic app icon)"
fi
echo "   app icon: ${ICON_KEY:-none}"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleDisplayName</key><string>Pax</string>
  <!-- TODO: bundle ID stays org.paxmobile.pax for now (defaults + Keychain migration). -->
  <key>CFBundleExecutable</key><string>Pax</string>
  <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>Pax</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${BUILD_NUMBER}</string>
  <key>CFBundleIconFile</key><string>${ICON_KEY}</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Pax Peace (paxpeace.com). GPL-3.0-only.</string>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSAllowsLocalNetworking</key><true/></dict>
</dict>
</plist>
PLIST
plutil -lint "$APP/Contents/Info.plist" >/dev/null
printf 'APPL????' > "$APP/Contents/PkgInfo"

# Helper scripts the app runs (found by ResourceLocator before the repo paths).
cp -X "$REPO/profile/make_profile.py" "$REPO/profile/bypass_apps.py" "$REPO/profile/fallback_denylist.py" \
   "$REPO/profile/mac_policies.py" "$REPO/profile/media_converters.py" "$REPO/common/pax_restricted.py" \
   "$REPO/profile/remote_ai_browsers.py" "$REPO/profile/app_blocks.py" "$APP/Contents/Resources/profile/"
# v0.4 "Protect this Mac": pax-guard (root LaunchDaemon) + its installer and uninstaller.
cp -X "$REPO/guard/pax_guard.py" "$REPO/guard/guard_config.py" "$REPO/guard/org.paxpeace.pax-guard.plist" \
   "$REPO/guard/scripts/pax-guard-install.sh" "$REPO/guard/scripts/pax-uninstall-emergency.sh" \
   "$REPO/guard/guard_runtime.py" "$REPO/guard/scripts/pax-guard-launch.sh" \
   "$APP/Contents/Resources/guard/"
chmod 755 "$APP/Contents/Resources/guard/pax-guard-install.sh" "$APP/Contents/Resources/guard/pax-uninstall-emergency.sh" \
  "$APP/Contents/Resources/guard/pax-guard-launch.sh"
# v0.8.0: local DNS forwarder, lists, local escrow, partner emails, updates,
# tamper log, recovery cheap wins, app socket, Ed25519 (all stdlib Python).
for mod in domain_matcher filter_lists dns_forwarder local_escrow local_blocklist list_sync partner guard_ipc \
           pax_update pax_signing ed25519 tamper recovery_guard support_code; do
  cp -X "$REPO/guard/$mod.py" "$APP/Contents/Resources/guard/"
done
# v0.8.1: the restricted-content rules, shared with the server and the profile.
cp -X "$REPO/common/pax_restricted.py" "$APP/Contents/Resources/guard/"
mkdir -p "$APP/Contents/Resources/guard/filters"
cp -X "$REPO"/guard/filters/* "$APP/Contents/Resources/guard/filters/"
/usr/bin/python3 -I "$APP/Contents/Resources/guard/pax_guard.py" selftest >/dev/null \
  || die "bundled pax-guard failed its self-test"
plutil -lint "$APP/Contents/Resources/guard/org.paxpeace.pax-guard.plist" >/dev/null
# v0.5: Pax's curated category lists (pax-guard's hosts block, the profile's
# URLBlocklist) and the Pax Image Blur Firefox add-on (installed by pax-guard to
# /Library/PaxGuard/extensions). A Mozilla-signed XPI (AMO unlisted) in
# extension/signed/pax-image-blur-signed.xpi wins over the unsigned build.
cp -X "$REPO/pax-dns/lists/cloud-pc-bypass.txt" "$REPO/pax-dns/lists/remote-desktop.txt" \
   "$REPO/pax-dns/lists/media-converters.txt" "$REPO/pax-dns/lists/media-converter-keywords.txt" \
   "$REPO/pax-dns/lists/remote-ai-browsers.txt" "$APP/Contents/Resources/lists/"
/usr/bin/python3 "$REPO/extension/build.py" >/dev/null || die "extension build failed"
cp -X "$REPO/extension/dist/pax-image-blur.xpi" "$APP/Contents/Resources/extensions/"
if [[ -f "$REPO/extension/signed/pax-image-blur-signed.xpi" ]]; then
  cp -X "$REPO/extension/signed/pax-image-blur-signed.xpi" "$APP/Contents/Resources/extensions/"
else
  echo "   (no extension/signed/pax-image-blur-signed.xpi: release Firefox won't install the unsigned add-on)"
fi
cp -X "$REPO/device/pax_device.py" "$REPO/device/seed.py" "$APP/Contents/Resources/device/"
# v0.8.6: the helper's own Python (no install-helper.sh, venv or Homebrew any more).
HELPER_PY="$APP/Contents/Resources/device/python/bin/python3.12"
if [[ "$BUNDLE_DEVICE_HELPER" == "1" ]]; then
  step "Bundling the iPhone helper runtime"
  HELPER_BUILD="$(mktemp -d)"
  "$SCRIPT_DIR/build-device-helper.sh" "$HELPER_BUILD"
  ditto "$HELPER_BUILD/python" "$APP/Contents/Resources/device/python"
  rm -rf "$HELPER_BUILD"
  [[ -x "$HELPER_PY" ]] || die "bundled helper runtime missing $HELPER_PY"
  # The iPhone profile generator runs on the bundled Python too (stdlib only).
  "$HELPER_PY" -I -B "$APP/Contents/Resources/profile/make_profile.py" --help >/dev/null \
    || die "make_profile.py doesn't run on the bundled Python"
else
  echo "   (BUNDLE_DEVICE_HELPER=0: no bundled helper; Keep my data needs PAX_PYTHON)"
fi
cp -X "$REPO/LICENSE" "$REPO/THIRD_PARTY_NOTICES.md" "$APP/Contents/Resources/"
# v0.8.16 brand: the bundled fonts (OFL; Theme.swift registers them at launch) and the
# logo images. Without them the app falls back to the system serif and a drawn wordmark.
mkdir -p "$APP/Contents/Resources/Fonts" "$APP/Contents/Resources/branding"
cp -X "$MAC_APP"/Resources/fonts/*.ttf "$MAC_APP/Resources/fonts/OFL.txt" "$APP/Contents/Resources/Fonts/"
cp -X "$MAC_APP"/Resources/branding/pax-peace-stacked-*.png "$MAC_APP"/Resources/branding/pax-navy.png \
  "$MAC_APP"/Resources/branding/pax-white.png "$APP/Contents/Resources/branding/"
# SwiftPM resource bundles, if any target ever gains resources.
for b in "$(dirname "$BIN")"/*.bundle; do
  if [[ -e "$b" ]]; then ditto "$b" "$APP/Contents/Resources/$(basename "$b")"; fi
done

step "Signing (${SIGN_IDENTITY/#-/ad-hoc})"
xattr -cr "$APP"   # stray Finder/quarantine attributes break codesign
if [[ -d "$APP/Contents/Resources/device/python" ]]; then
  # Inside out: every library and module, then the interpreter (with its entitlements),
  # then the app. Notarisation checks each Mach-O for a Developer ID signature, the
  # hardened runtime and a secure timestamp.
  HELPER_ROOT="$APP/Contents/Resources/device/python"
  ENTITLEMENTS="$MAC_APP/Resources/helper-python.entitlements"
  plutil -lint "$ENTITLEMENTS" >/dev/null
  EXECS="$(/usr/bin/python3 -I "$SCRIPT_DIR/helper_runtime.py" executables "$HELPER_ROOT" | tr '\0' '\n')"
  n=0
  while IFS= read -r -d '' f; do
    args=(--force)
    if grep -qxF "$f" <<<"$EXECS"; then args+=(--entitlements "$ENTITLEMENTS"); fi
    if [[ "$SIGN_IDENTITY" == "-" ]]; then
      codesign "${args[@]}" --sign - --timestamp=none "$f"
    else
      codesign "${args[@]}" --sign "$SIGN_IDENTITY" --options runtime --timestamp "$f"
    fi
    n=$((n + 1))
  done < <(/usr/bin/python3 -I "$SCRIPT_DIR/helper_runtime.py" list-macho "$HELPER_ROOT")
  echo "   signed $n Mach-O files in the helper runtime"
  [[ "$n" -gt 0 ]] || die "found no Mach-O files to sign in $HELPER_ROOT"
  # v0.8.6: the manifest pax-guard's own runtime copy is checked against (every file
  # but site-packages, hashed after signing). Inside Resources, so the app's signature
  # seals it. TEAM is the Developer ID team, "-" for an ad-hoc build (which then
  # can't give pax-guard a runtime: it falls back to /usr/bin/python3).
  TEAM="-"
  if [[ "$SIGN_IDENTITY" != "-" ]]; then
    TEAM="$(sed -n 's/.*(\([A-Z0-9]\{10\}\))$/\1/p' <<<"$SIGN_IDENTITY")"
    [[ -n "$TEAM" ]] || die "can't read the Team ID from the signing identity"
  fi
  /usr/bin/python3 -I "$SCRIPT_DIR/helper_runtime.py" guard-manifest "$HELPER_ROOT" --team "$TEAM" \
    --out "$APP/Contents/Resources/guard/runtime-manifest.json"
fi
if [[ "$SIGN_IDENTITY" == "-" ]]; then
  codesign --force --sign - --timestamp=none "$APP"
else
  # Developer ID: hardened runtime + secure timestamp, both required for notarisation.
  codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp "$APP"
fi
codesign --verify --strict --verbose=2 "$APP"
if [[ -x "$HELPER_PY" ]]; then
  step "Checking the signed iPhone helper"
  helper_check "$APP"
  # v0.8.6: pax-guard runs on the same interpreter (its own copy, stdlib only).
  "$HELPER_PY" -I -B "$APP/Contents/Resources/guard/pax_guard.py" selftest >/dev/null \
    || die "pax-guard's self-test fails on the bundled Python"
  codesign --verify --strict "$APP" || die "running pax-guard's self-test modified Pax.app"
fi
NOTARISED=0
if [[ -n "$NOTARY_PROFILE" ]]; then
  step "Notarising Pax.app"
  APPZIP="$(mktemp -d)/Pax-notarise.zip"
  ditto -c -k --sequesterRsrc --keepParent "$APP" "$APPZIP"
  notarise "$APPZIP"
  rm -rf "$(dirname "$APPZIP")"
  staple "$APP"
  NOTARISED=1
fi

step "Creating $(basename "$DMG")"
STAGE="$(mktemp -d)/Pax $VERSION"
mkdir -p "$STAGE"
ditto "$APP" "$STAGE/Pax.app"
ln -s /Applications "$STAGE/Applications"
# Volume icon: the app icon on the mounted DMG (needs SetFile from the Command Line Tools).
if [[ -f "$APP/Contents/Resources/AppIcon.icns" ]]; then
  cp -X "$APP/Contents/Resources/AppIcon.icns" "$STAGE/.VolumeIcon.icns"
  if command -v SetFile >/dev/null; then
    SetFile -a C "$STAGE" || echo "   (SetFile failed: DMG keeps the generic volume icon)"
  else
    echo "   (no SetFile: DMG keeps the generic volume icon)"
  fi
fi
if [[ "$NOTARISED" == "1" ]]; then
  OPEN_STEP="2. Open Pax from Applications. It is signed and notarised by Apple."
else
  OPEN_STEP="2. This build is not notarised by Apple yet. The first time, Control-click (or right-click)
   Pax in Applications and choose Open. On macOS 15 or later: try to open it once, then
   go to System Settings > Privacy & Security, scroll down and click \"Open Anyway\"."
fi
cat > "$STAGE/Read me first.txt" <<TXT
Pax $VERSION. Pax Peace: free, open source (GPL-3.0). paxpeace.com

1. Drag Pax into Applications.
$OPEN_STEP
3. Open Pax and choose "This Mac" or "iPhone or iPad". Pax walks you through the rest.
4. For an iPhone or iPad, just plug it in with a cable. Nothing else to install.
5. Pax uses its own server (https://api.paxpeace.com/). To run your own instead:
   Pax > Settings > Advanced (Cmd-,) sets the server address.
TXT
rm -f "$DMG"
hdiutil create -volname "Pax $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG" >/dev/null
hdiutil verify "$DMG" >/dev/null
if [[ "$SIGN_IDENTITY" != "-" ]]; then
  codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DMG"
fi
# v0.8.0: the zip pax-guard's updater downloads (Pax.app at the top level).
ZIP="$OUT_DIR/Pax-$VERSION.zip"
rm -f "$ZIP"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"
echo "   update zip: $ZIP"
if [[ -n "$NOTARY_PROFILE" ]]; then
  step "Notarising $(basename "$DMG")"
  notarise "$DMG"
  staple "$DMG"
  spctl --assess --type execute -v "$APP"
  spctl --assess --type open --context context:primary-signature -v "$DMG"
fi
if [[ -d "$APP/Contents/Resources/device/python" ]]; then
  echo "   iPhone helper runtime: $(du -sh "$APP/Contents/Resources/device/python" | cut -f1)"
fi
echo "   Pax.app: $(du -sh "$APP" | cut -f1); DMG: $(du -h "$DMG" | cut -f1)"
rm -rf "$(dirname "$STAGE")"
if [[ "$UNIVERSAL" == "1" ]]; then rm -f "$OUT_DIR/Pax-universal"; fi

step "Done"
echo "App: $APP"
echo "DMG: $DMG"
shasum -a 256 "$DMG"
