#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
#
# Removes Pax from a self-locked Mac. Needs root, which on a protected Mac means
# the paxadmin password (released by the Pax server after your wait):
#
#   su paxadmin                      # type the released password
#   sudo /Library/PaxGuard/bin/pax-uninstall-emergency.sh --user <your-short-name>
#   exit
#   sudo sysadminctl -deleteUser paxadmin    # now as your re-promoted account
#
# Steps: make <user> an administrator again (first, so you are never left without
# one), stop pax-guard, make any other accounts Pax made standard administrators
# again (v0.8.10), remove pax-guard, remove the /etc/hosts block and the pf anchor,
# put quarantined apps back, remove the Pax profile(s). --delete-paxadmin also
# deletes the paxadmin account (not possible while you are logged in as it).
set -uo pipefail

LABEL="org.paxpeace.pax-guard"
DEST="/Library/PaxGuard"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
PREFIX="org.paxpeace.pax.macos-selflock."
USER_NAME=""; DELETE_ADMIN=0

say() { echo "pax-uninstall: $*"; }
die() { echo "pax-uninstall: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) USER_NAME="$2"; shift 2 ;;
    --delete-paxadmin) DELETE_ADMIN=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$(id -u)" == "0" ]] || die "run with sudo (as paxadmin or another administrator)"

# 1. Re-promote the everyday account first.
if [[ -n "$USER_NAME" ]]; then
  /usr/bin/dscl . -read "/Users/$USER_NAME" >/dev/null 2>&1 || die "no such user: $USER_NAME"
  /usr/sbin/dseditgroup -o edit -a "$USER_NAME" -t user admin
  if /usr/sbin/dseditgroup -o checkmember -m "$USER_NAME" admin | grep -q '^yes'; then
    say "$USER_NAME is an administrator again"
  else
    die "could not make $USER_NAME an administrator; nothing else was changed"
  fi
fi

# 2. Stop pax-guard, then undo what it did (hosts block, pf anchor, quarantine).
/bin/launchctl bootout "system/${LABEL}" >/dev/null 2>&1 || true

# 2a. v0.8.10: the other administrators Pax made standard at set-up become
# administrators again (only now that pax-guard, which keeps them standard, is stopped).
CONFIG="$DEST/config.json"
if [[ -f "$CONFIG" ]]; then
  i=0
  while other=$(/usr/bin/plutil -extract "demoted_admins.$i" raw -o - "$CONFIG" 2>/dev/null); do
    i=$((i + 1))
    [[ "$other" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { say "skipped an unexpected account name"; continue; }
    [[ "$other" == "paxadmin" || "$other" == "root" ]] && continue
    /usr/bin/dscl . -read "/Users/$other" >/dev/null 2>&1 || { say "$other no longer exists"; continue; }
    /usr/sbin/dseditgroup -o edit -a "$other" -t user admin
    if /usr/sbin/dseditgroup -o checkmember -m "$other" admin | grep -q '^yes'; then
      say "$other is an administrator again"
    else
      say "could not make $other an administrator again: Pax's administrator can do it in Users & Groups"
    fi
  done
fi
# v0.8.6: pax-guard's own runtime first (no Command Line Tools needed), else /usr/bin/python3.
GUARD_PY=""
if [[ -x "$DEST/runtime/bin/python3.12" ]]; then
  GUARD_PY="$DEST/runtime/bin/python3.12"
elif /usr/bin/xcode-select -p >/dev/null 2>&1 && /usr/bin/python3 -I -c 'import json' >/dev/null 2>&1; then
  GUARD_PY="/usr/bin/python3"
fi
python_done=0
if [[ -f "$DEST/bin/pax_guard.py" && -n "$GUARD_PY" ]]; then
  if "$GUARD_PY" -I -B "$DEST/bin/pax_guard.py" uninstall; then
    python_done=1
  else
    say "pax-guard uninstall step reported a problem; removing the block without it"
  fi
fi
if [[ "$python_done" != 1 ]]; then
  # Fallback without Python: strip the marked block from /etc/hosts.
  /usr/bin/sed -i '' '/^# BEGIN PAX (managed by pax-guard/,/^# END PAX$/d' /etc/hosts
  /sbin/pfctl -a com.apple/250.org.paxpeace.pax -F all >/dev/null 2>&1 || true
  # v0.8.0: DNS settings that point at Pax's forwarder go back to automatic.
  /usr/sbin/networksetup -listallnetworkservices 2>/dev/null | /usr/bin/tail -n +2 | while IFS= read -r svc; do
    svc="${svc#\*}"
    if /usr/sbin/networksetup -getdnsservers "$svc" 2>/dev/null | /usr/bin/grep -qx '127.0.0.1'; then
      /usr/sbin/networksetup -setdnsservers "$svc" Empty || true
    fi
  done
fi
/usr/bin/dscacheutil -flushcache; /usr/bin/killall -HUP mDNSResponder 2>/dev/null || true
rm -f "$PLIST"
# v0.8.34: Pax no longer opens at login (the LaunchAgent pax-guard kept).
rm -f "/Library/LaunchAgents/org.paxpeace.pax-login.plist"
say "pax-guard stopped and removed"

# 3. Remove the Pax profile(s).
IDS=$( { /usr/bin/profiles show -type configuration 2>/dev/null; /usr/bin/profiles -P 2>/dev/null; } \
       | grep -o "${PREFIX//./\\.}[0-9a-f-]*" | sort -u )
for id in $IDS; do
  if /usr/bin/profiles remove -identifier "$id" >/dev/null 2>&1 || /usr/bin/profiles -R -p "$id" >/dev/null 2>&1; then
    say "removed profile $id"
  else
    say "could not remove profile $id: remove it in System Settings > General > Device Management (macOS 12: System Preferences > Profiles)"
  fi
done

# 4. Remove the rest of /Library/PaxGuard (the quarantine is already restored).
if [[ -d "$DEST/quarantine" ]] && [[ -n "$(ls -A "$DEST/quarantine" 2>/dev/null)" ]]; then
  mkdir -p "/Users/Shared/Pax quarantine"
  mv "$DEST/quarantine/"* "/Users/Shared/Pax quarantine/" 2>/dev/null || true
  say "left-over quarantined apps moved to /Users/Shared/Pax quarantine"
fi
rm -rf "$DEST"

# 5. Optionally delete paxadmin.
if [[ "$DELETE_ADMIN" == "1" ]]; then
  if [[ "${SUDO_USER:-}" == "paxadmin" ]]; then
    say "you are logged in as paxadmin: run 'sudo sysadminctl -deleteUser paxadmin' from $USER_NAME"
  else
    /usr/sbin/sysadminctl -deleteUser paxadmin && say "paxadmin deleted"
  fi
fi
say "done. Pax is removed from this Mac."
