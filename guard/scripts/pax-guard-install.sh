#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
#
# Installs pax-guard as a root LaunchDaemon. Run as root (the Pax app runs it
# through an administrator prompt during "Protect this Mac"):
#
#   pax-guard-install.sh --src <Pax.app/Contents/Resources/guard> --config <config.json> \
#                        [--profile <Pax.mobileconfig>]
#
# Installs /Library/PaxGuard (root:wheel; config 0600 because it holds the
# read-only guard token) and /Library/LaunchDaemons/org.paxpeace.pax-guard.plist,
# runs one enforcement cycle and checks launchd has the daemon. Exits non-zero
# (and leaves nothing loaded) if anything fails, so the app can roll back.
#
# v0.5 also installs Pax's curated lists (bin/lists/*.txt: cloud PCs / remote
# browsers / proxies, remote desktop) and, if the app bundles it, the Pax Image
# Blur Firefox add-on at /Library/PaxGuard/extensions/pax-image-blur.xpi (world-
# readable: the Firefox policy installs it from that file:// path).
#
# v0.8.6: no Command Line Tools needed. pax-guard runs on its own copy of the
# signed CPython inside Pax.app, /Library/PaxGuard/runtime (root-owned, never
# executed from /Applications). The copy is made by guard/guard_runtime.py, which
# checks Pax.app and every Mach-O against Pax's Developer ID (Team ID Z94GSK7JA8)
# and every file against the app's sealed runtime-manifest.json, then runs
# pax-guard's self-test on it. The LaunchDaemon starts bin/pax-guard-launch.sh,
# which runs pax-guard on the copy (or on /usr/bin/python3 if the copy keeps
# failing and the Command Line Tools are there). A build that isn't Developer ID
# signed (a developer's own build) uses /usr/bin/python3 as before.
set -euo pipefail

LABEL="org.paxpeace.pax-guard"
DEST="/Library/PaxGuard"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SRC=""; CONFIG=""; PROFILE=""

die() { echo "pax-guard-install: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --src) SRC="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$(id -u)" == "0" ]] || die "must run as root"
[[ -f "$SRC/pax_guard.py" && -f "$SRC/guard_config.py" && -f "$SRC/${LABEL}.plist" ]] || die "PAX-GUARD-001: missing guard files in $SRC"
[[ -f "$CONFIG" ]] || die "PAX-GUARD-001: missing config $CONFIG"

TEAM_ID="Z94GSK7JA8"
REQ="=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"${TEAM_ID}\""
RES="$(cd "$SRC/.." && pwd)"                 # Pax.app/Contents/Resources (or the repo)
APP="$(cd "$RES/../.." && pwd)"              # Pax.app
BUNDLED_PY="$RES/device/python/bin/python3.12"
LAUNCHER="$SRC/pax-guard-launch.sh"
[[ -f "$LAUNCHER" ]] || LAUNCHER="$SRC/scripts/pax-guard-launch.sh"   # running from the repo
[[ -f "$LAUNCHER" ]] || die "PAX-GUARD-001: missing pax-guard-launch.sh"
[[ -f "$SRC/guard_runtime.py" ]] || die "PAX-GUARD-001: missing guard_runtime.py"
clt_python_ok() {
  /usr/bin/xcode-select -p >/dev/null 2>&1 && /usr/bin/python3 -I -c 'import ssl, json, plistlib' >/dev/null 2>&1
}
# The app's own interpreter may only run as root once it passes Pax's Developer ID check.
signed_runtime=0
if [[ -x "$BUNDLED_PY" ]] \
   && /usr/bin/codesign --verify --strict -R "$REQ" "$APP" >/dev/null 2>&1 \
   && /usr/bin/codesign --verify --strict -R "$REQ" "$BUNDLED_PY" >/dev/null 2>&1 \
   && /usr/bin/codesign --verify --strict -R "$REQ" "$RES/device/python/lib/libpython3.12.dylib" >/dev/null 2>&1; then
  signed_runtime=1
elif ! clt_python_ok; then
  die "PAX-GUARD-002: this copy of Pax has no Developer ID signed runtime (Team ID $TEAM_ID) and the Command Line Tools aren't installed"
fi

install -d -o root -g wheel -m 0755 "$DEST" "$DEST/bin"
install -d -o root -g wheel -m 0700 "$DEST/state" "$DEST/quarantine"
install -o root -g wheel -m 0644 "$SRC/pax_guard.py" "$SRC/guard_config.py" "$SRC/guard_runtime.py" "$DEST/bin/"
install -o root -g wheel -m 0755 "$LAUNCHER" "$DEST/bin/pax-guard-launch.sh"
# v0.8.0 modules: local DNS forwarder, lists, local escrow, partner emails,
# updates, tamper log, recovery cheap wins, app socket, Ed25519.
for mod in domain_matcher filter_lists dns_forwarder local_escrow local_blocklist list_sync partner guard_ipc \
           pax_update pax_signing ed25519 tamper recovery_guard support_code; do
  [[ -f "$SRC/$mod.py" ]] || die "PAX-GUARD-001: missing $mod.py"
  install -o root -g wheel -m 0644 "$SRC/$mod.py" "$DEST/bin/"
done
# v0.8.33 Pax-approved installs: the module and what it refuses (read next to itself);
# v0.8.34: the short list of developers whose notarised packages skip the wait.
for f in app_installs.py app-install-deny.txt pkg-trusted-teams.txt; do
  [[ -f "$SRC/$f" ]] || die "PAX-GUARD-001: missing $f"
  install -o root -g wheel -m 0644 "$SRC/$f" "$DEST/bin/"
done
# v0.8.1: the restricted-content rules (common/pax_restricted.py in the repo).
RESTRICTED="$SRC/pax_restricted.py"
[[ -f "$RESTRICTED" ]] || RESTRICTED="$SRC/../common/pax_restricted.py"   # running from the repo
[[ -f "$RESTRICTED" ]] || die "PAX-GUARD-001: missing pax_restricted.py"
install -o root -g wheel -m 0644 "$RESTRICTED" "$DEST/bin/pax_restricted.py"
# v0.8.0 bundled filter lists (the fallback that is always there).
[[ -f "$SRC/filters/filters.json" ]] || die "PAX-GUARD-001: missing bundled filter lists (filters/filters.json)"
install -d -o root -g wheel -m 0755 "$DEST/bin/filters"
for f in "$SRC"/filters/*; do [[ -f "$f" ]] && install -o root -g wheel -m 0644 "$f" "$DEST/bin/filters/"; done
install -d -o root -g wheel -m 0755 "$DEST/lists.d"
UNINSTALLER="$SRC/pax-uninstall-emergency.sh"
[[ -f "$UNINSTALLER" ]] || UNINSTALLER="$SRC/scripts/pax-uninstall-emergency.sh"   # running from the repo
[[ -f "$UNINSTALLER" ]] || die "PAX-GUARD-001: missing pax-uninstall-emergency.sh"
install -o root -g wheel -m 0755 "$UNINSTALLER" "$DEST/bin/pax-uninstall-emergency.sh"

# Curated category lists: next to the guard files (bundle: Resources/lists,
# repo: pax-dns/lists). Without them pax-guard can't block cloud PCs, remote
# desktop or (v0.8.1) media converters and remote AI browsers.
CURATED=(cloud-pc-bypass.txt remote-desktop.txt media-converters.txt media-converter-keywords.txt
         remote-ai-browsers.txt)
LISTS=""
for d in "$SRC/lists" "$SRC/../lists" "$SRC/../pax-dns/lists"; do
  ok=1
  for f in "${CURATED[@]}"; do [[ -f "$d/$f" ]] || ok=0; done
  if [[ $ok == 1 ]]; then LISTS="$d"; break; fi
done
[[ -n "$LISTS" ]] || die "PAX-GUARD-001: missing Pax lists (${CURATED[*]})"
install -d -o root -g wheel -m 0755 "$DEST/bin/lists"
for f in "${CURATED[@]}"; do install -o root -g wheel -m 0644 "$LISTS/$f" "$DEST/bin/lists/"; done

# Pax Image Blur for Firefox (optional: protection works without it). A signed
# build (AMO unlisted) is preferred; release Firefox refuses an unsigned one.
XPI=""
for f in "$SRC/../extensions/pax-image-blur-signed.xpi" "$SRC/../extensions/pax-image-blur.xpi" \
         "$SRC/../extension/dist/pax-image-blur-signed.xpi" "$SRC/../extension/dist/pax-image-blur.xpi"; do
  if [[ -f "$f" ]]; then XPI="$f"; break; fi
done
install -d -o root -g wheel -m 0755 "$DEST/extensions"
if [[ -n "$XPI" ]]; then
  install -o root -g wheel -m 0644 "$XPI" "$DEST/extensions/pax-image-blur.xpi"
else
  echo "pax-guard-install: no Pax Image Blur .xpi bundled; Firefox gets no image blur" >&2
fi
install -o root -g wheel -m 0600 "$CONFIG" "$DEST/config.json"
if [[ -n "$PROFILE" && -f "$PROFILE" ]]; then
  install -o root -g wheel -m 0644 "$PROFILE" "$DEST/Pax.mobileconfig"
fi
install -o root -g wheel -m 0644 "$SRC/${LABEL}.plist" "$PLIST"
/usr/bin/plutil -lint "$PLIST" >/dev/null || die "PAX-GUARD-001: bad launchd plist"
# A downloaded DMG marks every file com.apple.quarantine and `install` copies
# that xattr. launchd refuses a quarantined plist ("Bootstrap failed: 5",
# log: "Refusing to execute/trust quarantined program/file").
/usr/bin/xattr -dr com.apple.quarantine "$DEST" "$PLIST" 2>/dev/null || true
/usr/bin/xattr -c "$PLIST" 2>/dev/null || true

# v0.8.6: pax-guard's own runtime, checked file by file, then its self-test.
if [[ "$signed_runtime" == 1 ]]; then
  if out="$("$BUNDLED_PY" -I -B "$DEST/bin/guard_runtime.py" install --app "$APP" --base "$DEST")"; then
    echo "pax-guard-install: runtime $out"
    printf '0\n' > "$DEST/state/runtime-starts"; chmod 0600 "$DEST/state/runtime-starts"
  else
    echo "pax-guard-install: runtime not installed: $out" >&2
    rm -rf "$DEST/runtime" "$DEST/runtime.new"
    clt_python_ok || die "PAX-GUARD-002: Pax's runtime didn't verify and the Command Line Tools aren't installed"
    echo "pax-guard-install: using /usr/bin/python3 instead" >&2
  fi
fi

# One cycle now (hosts, pf, lists), so protection is on before the user is demoted.
/bin/sh "$DEST/bin/pax-guard-launch.sh" once || die "PAX-GUARD-004: first enforcement cycle failed"

# A leftover copy (an earlier attempt) is unloaded first. bootout returns before
# launchd has finished tearing it down, and bootstrapping too early, or while
# the label is still in the disabled list, fails with "5: Input/output error".
# So: enable first, wait for the old one to go, and retry before giving up.
/bin/launchctl enable "system/${LABEL}" >/dev/null 2>&1 || true
/bin/launchctl bootout "system/${LABEL}" >/dev/null 2>&1 || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
  /bin/launchctl print "system/${LABEL}" >/dev/null 2>&1 || break
  sleep 1
done
loaded=0
for attempt in 1 2 3; do
  if /bin/launchctl bootstrap system "$PLIST" 2>/tmp/pax-guard-bootstrap.err; then loaded=1; break; fi
  # Already running (an earlier attempt that bootout couldn't stop) counts as loaded.
  if /bin/launchctl print "system/${LABEL}" >/dev/null 2>&1; then loaded=1; break; fi
  echo "pax-guard-install: bootstrap attempt ${attempt} failed: $(cat /tmp/pax-guard-bootstrap.err)" >&2
  /bin/launchctl enable "system/${LABEL}" >/dev/null 2>&1 || true
  sleep 3
done
if [[ "$loaded" != 1 ]]; then
  # Older interface, which also clears a disabled override. It can exit 0
  # without loading anything, so check.
  /bin/launchctl load -w "$PLIST" >/dev/null 2>&1 || true
  /bin/launchctl print "system/${LABEL}" >/dev/null 2>&1 && loaded=1
fi
if [[ "$loaded" != 1 ]]; then
  /usr/bin/xattr -l "$PLIST" >&2 || true
  echo "pax-guard-install: diagnostics:" >&2
  /bin/launchctl print-disabled system 2>/dev/null | /usr/bin/grep -i pax >&2 || true
  /bin/ls -l "$PLIST" >&2 || true
  /usr/bin/sw_vers >&2 || true
  /usr/bin/profiles status -type enrollment >&2 2>&1 || true
  die "PAX-GUARD-003: launchctl bootstrap failed (see attempts above; quarantine or error 5)"
fi
sleep 2
/bin/launchctl print "system/${LABEL}" >/dev/null 2>&1 || die "PAX-GUARD-005: pax-guard is not loaded"
echo "pax-guard installed"
