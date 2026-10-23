# SPDX-License-Identifier: GPL-3.0-only
"""Pax support error codes (v0.7.0): the one table every part of Pax uses.

Format: PAX-<AREA>-<NNN>. Codes are STABLE: never renumber or reuse one; retire a
code by marking it retired instead. Each code has
  * message: one calm, plain sentence the user sees (no jargon),
  * action:  one line on what to try,
  * cause:   the internal technical cause, for support and patches only.

The Mac app's catalog (mac-app/Sources/PaxCore/PaxError.swift) and
docs/ERROR_CODES.md are generated from this table by common/gen_error_codes.py,
and tests (common/tests, PaxCoreTests) check all three agree.
Used at runtime by pax-guard (log lines), make_profile.py (stderr) and the
escrow server (`pax_code` in JSON error bodies).
"""
from __future__ import annotations

import re
from typing import NamedTuple

CODE_RE = re.compile(r"^PAX-(APP|MAC|IOS|GUARD|DNS|ESCROW|PROFILE|NET|UPDATE)-\d{3}$")
AREAS = ("APP", "MAC", "IOS", "GUARD", "DNS", "ESCROW", "PROFILE", "NET", "UPDATE")


class PaxCode(NamedTuple):
    code: str
    message: str
    action: str
    cause: str


CODES: list[PaxCode] = [
    # ---------------------------------------------------------------- APP
    PaxCode("PAX-APP-000", "Something went wrong.",
            "Try again. If it keeps happening, copy the details and send them to us.",
            "An error Pax has no code for yet (unclassified Swift/Python error)."),
    PaxCode("PAX-APP-001", "Pax is missing some of its own files.",
            "Download Pax again from paxpeace.com and replace the copy in Applications.",
            "A bundled resource (profile/, guard/, lists/ or device/ in Pax.app/Contents/Resources) "
            "was not found by ResourceLocator."),
    # ---------------------------------------------------------------- MAC
    PaxCode("PAX-MAC-001", "That password didn't match this Mac account.",
            "Type the password you use to log in to this Mac, then try again.",
            "dscl -authonly failed for the current user in preflight (or MacLockdownError.wrongPassword)."),
    PaxCode("PAX-MAC-002", "This account can't make changes to the Mac.",
            "Log in with the Mac's main (administrator) account and open Pax again.",
            "The current user is not in the admin group, so Pax cannot create paxadmin."),
    PaxCode("PAX-MAC-003", "Another account on this Mac can undo Pax.",
            "Leave \"Also make these standard accounts\" on and try again. Pax undid every step.",
            "v0.8.10: other admin accounts are made standard at set-up with the user's OK (dseditgroup -d, "
            "verified; pax-guard keeps them standard; a proper removal makes them admins again). This code "
            "remains when the user turned that off, an admin appeared after the check, an account name "
            "can't be changed safely, or demoting/verifying one failed (rolled back). Testing only: "
            "defaults write org.paxmobile.pax pax.testing.allowExtraAdmins -bool true leaves them as "
            "admins with a warning."),
    PaxCode("PAX-MAC-004", "An old Pax administrator account is still on this Mac and couldn't be removed.",
            "In Terminal run: sudo sysadminctl -deleteUser paxadmin -adminUser <you> -adminPassword - then try again.",
            "v0.8.29: a leftover paxadmin (an earlier set-up, or a removal macOS only half finished) could be "
            "neither deleted (sysadminctl -deleteUser with the user's credentials, then dscl -delete, rechecked "
            "for directory lag) nor reused (sysadminctl -resetPasswordFor with the user's credentials, else "
            "dscl -passwd, proven with dscl -authonly, then made admin). Technical lists each command's exit "
            "status and output. Rolled back: the user stays admin, the leftover is left without admin rights. "
            "Before 0.8.29 this was the preflight block on an admin paxadmin, which now only warns."),
    PaxCode("PAX-MAC-005", "Pax couldn't create the key it keeps for you.",
            "Restart the Mac and try again. Nothing was changed.",
            "MacLockdownError.createAdminFailed: sysadminctl/dscl failed creating the hidden paxadmin."),
    PaxCode("PAX-MAC-006", "Pax couldn't finish the disk encryption step.",
            "Make sure FileVault isn't busy encrypting, restart, and try again. Nothing was changed.",
            "MacLockdownError.secureTokenFailed: sysadminctl -secureTokenOn for paxadmin failed."),
    PaxCode("PAX-MAC-007", "Pax checked its key and it didn't work, so it stopped.",
            "Try again. Nothing was locked.",
            "MacLockdownError.verifyAdminFailed: dscl -authonly paxadmin failed after creation."),
    PaxCode("PAX-MAC-008", "Pax couldn't switch your account to a standard account.",
            "Try again. Pax undid every step, so your Mac is as it was.",
            "MacLockdownError.demotionFailed: dseditgroup -d <user> admin failed."),
    PaxCode("PAX-MAC-009", "Your account still has full control, so Pax didn't lock anything.",
            "Try again. If it repeats, copy the details and send them to us.",
            "MacLockdownError.stillAdmin: the user was still in the admin group after demotion."),
    PaxCode("PAX-MAC-010", "Pax stopped part-way and put everything back.",
            "Try again. Your Mac is as it was before.",
            "MacLockdownError.rolledBack(step, why): a later step failed and rollback ran."),
    PaxCode("PAX-MAC-011", "Pax couldn't remove itself from this Mac.",
            "Try again, or follow \"Remove Pax by hand\" on paxpeace.com.",
            "MacLockdown.removePax failed (profile removal, guard uninstall or re-promotion)."),
    # v0.8.0: Recovery-mode cheap wins (recovery-lock/DESIGN.md)
    PaxCode("PAX-MAC-012", "Pax couldn't replace your disk encryption recovery key yet.",
            "Nothing to do: your old key still works and Pax tries again later.",
            "pax-guard: fdesetup changerecovery -personal failed (exit 38 = preflight refused, old key "
            "stays valid) or printed no key."),
    PaxCode("PAX-MAC-013", "Pax kept a new recovery key but couldn't check it.",
            "Contact us before restarting in Recovery. Pax kept the key behind your turn-off wait.",
            "pax-guard: the rotated PRK did not pass fdesetup validaterecovery; it stays escrowed (alarm)."),
    PaxCode("PAX-MAC-014", "Pax couldn't set the startup password on this Mac.",
            "Nothing to do: protection still works. Pax tries again later.",
            "pax-guard (Intel only): firmwarepasswd -setpasswd / -setmode command / -verify failed."),
    PaxCode("PAX-MAC-015", "This Mac is managed by an organisation.",
            "Pax still protects it, but leaves its recovery key and startup settings alone.",
            "profiles status -type enrollment shows an MDM enrollment (or test mode is on): MDM-related "
            "steps, PRK rotation and firmware password are skipped."),
    PaxCode("PAX-MAC-016", "This app can't be blocked.",
            "Pax never blocks itself, Apple's own apps or password managers. Choose another app.",
            "apps.add (v0.8.7) refused: guard_config.app_protected_reason (part of macOS, com.apple., "
            "Pax's bundle IDs or Team ID, a password manager by bundle ID or name)."),
    PaxCode("PAX-MAC-017", "Pax couldn't add that app.",
            "Choose an app from your Applications folder, then try again.",
            "apps.add/apps.unblock (v0.8.7): not an .app in /Applications or ~/Applications, no bundle "
            "ID in its Info.plist, not on the list, or the list is full (200 apps)."),
    # ---------------------------------------------------------------- IOS
    PaxCode("PAX-IOS-001", "Pax needs Apple Configurator for this.",
            "Install Apple Configurator from the Mac App Store, then choose Apple Configurator > "
            "Install Automation Tools.",
            "DeviceServiceError.toolMissing: cfgutil not found at /usr/local/bin/cfgutil."),
    PaxCode("PAX-IOS-002", "Your iPhone didn't respond the way Pax expected.",
            "Unplug the iPhone, plug it back in, unlock it, and try again.",
            "DeviceServiceError.commandFailed: a cfgutil command returned non-zero."),
    PaxCode("PAX-IOS-003", "Pax couldn't read your iPhone's details.",
            "Unplug and replug the iPhone, keep it unlocked, and try again.",
            "DeviceServiceError.unexpectedOutput: cfgutil/helper output could not be parsed."),
    PaxCode("PAX-IOS-004", "Pax can't see an iPhone or iPad.",
            "Plug it in with a cable, unlock it, and tap Trust if it asks.",
            "DeviceServiceError.noDevice: no device listed by cfgutil or the helper."),
    PaxCode("PAX-IOS-005", "Part of Pax that sets up iPhones is missing from this copy.",
            "Download Pax again from paxpeace.com, drag it to Applications, then try again.",
            "SetupError.helperMissing: device/pax_device.py or its bundled Python (Resources/device/python) "
            "not available."),
    PaxCode("PAX-IOS-006", "Your iPhone's version can't be set up without erasing.",
            "Choose \"Erase and set up fresh\" under Advanced, after backing up.",
            "Keep-my-data not supported for this iOS version (KeepDataPlan / SetupError.keepDataUnavailable "
            "/ DeviceServiceError.notSupported)."),
    PaxCode("PAX-IOS-007", "Your iPhone didn't confirm it's ready, so Pax didn't lock anything.",
            "Try again, or choose \"Erase and set up fresh\" under Advanced.",
            "SetupError.supervisionNotConfirmed: device did not report IsSupervised after set-up."),
    PaxCode("PAX-IOS-008", "Restoring your backup undid the set-up.",
            "Set up fresh again without restoring the backup, then use iCloud to bring your things back.",
            "SetupError.supervisionLost: restoring an unsupervised backup removed supervision."),
    PaxCode("PAX-IOS-009", "The backup didn't finish.",
            "Keep the iPhone plugged in and unlocked, make sure the Mac has free space, and try again.",
            "Helper backup_incomplete / MobileBackup2 backup failed."),
    PaxCode("PAX-IOS-010", "The helper stopped unexpectedly.",
            "Unplug and replug the iPhone, then try again.",
            "HelperFailure with another code (no_output, unexpected, error) from device/pax_device.py."),
    PaxCode("PAX-IOS-011", "Your iPhone isn't quite ready yet.",
            "Follow the checklist on screen (for example turn off Find My), then try again.",
            "KeepDataPreflight.blocking is non-empty (Find My on, low battery, not trusted, no backup)."),
    PaxCode("PAX-IOS-012", "Pax couldn't read the apps on your iPhone.",
            "Unlock the iPhone and keep it plugged in, then try again. You can also type an app's ID.",
            "pax_device.py apps (v0.8.7): installation_proxy Lookup failed (not paired, locked, "
            "disconnected)."),
    # ---------------------------------------------------------------- GUARD
    PaxCode("PAX-GUARD-001", "Pax's background protection files are missing.",
            "Download Pax again from paxpeace.com and replace the copy in Applications.",
            "pax-guard-install.sh: missing guard files, lists or uninstaller in the app bundle."),
    PaxCode("PAX-GUARD-002", "This copy of Pax is incomplete, so it can't protect this Mac.",
            "Download Pax again from paxpeace.com, replace the copy in Applications, then try again.",
            "pax-guard-install.sh (v0.8.6): Pax.app's runtime is missing or not Developer ID signed by Team "
            "Z94GSK7JA8 (or failed its check) and there is no /usr/bin/python3 (Command Line Tools) to fall "
            "back on; or the launcher found no Python."),
    PaxCode("PAX-GUARD-003", "macOS didn't let Pax's background protection start.",
            "Restart the Mac and try again. Pax undid every step.",
            "launchctl bootstrap failed (often \"Bootstrap failed: 5: Input/output error\": a quarantined "
            "plist, a label left in the disabled list, or bootout not finished)."),
    PaxCode("PAX-GUARD-004", "Pax's background protection couldn't run its first check.",
            "Try again. If it repeats, copy the details and send them to us.",
            "pax-guard-install.sh: `pax_guard.py once` (first enforcement cycle) failed."),
    PaxCode("PAX-GUARD-005", "Pax's background protection started, then stopped.",
            "Restart the Mac and try again.",
            "pax-guard-install.sh: launchctl print system/org.paxpeace.pax-guard failed after bootstrap."),
    PaxCode("PAX-GUARD-006", "Pax's background protection didn't install.",
            "Try again. Pax undid every step.",
            "MacLockdownError.guardInstallFailed without a more specific code."),
    PaxCode("PAX-GUARD-007", "Pax couldn't reach its server, so it's using your saved lists.",
            "Nothing to do: protection stays on. Check your internet connection if it lasts.",
            "pax-guard: GET /v1/guard/config failed; the cached remote.json is used (log only)."),
    PaxCode("PAX-GUARD-008", "One of Pax's built-in block lists is missing.",
            "Download Pax again and protect the Mac again, or contact us.",
            "pax-guard: curated list (cloud-pc-bypass / remote-desktop) not found in list dirs (log only)."),
    PaxCode("PAX-GUARD-009", "Pax couldn't load part of its network protection.",
            "Restart the Mac. If it repeats, copy the details and send them to us.",
            "pax-guard: pfctl refused the anchor (with the 'user root' rule it retries without it)."),
    PaxCode("PAX-GUARD-010", "Pax's safe on this Mac looks changed, so it won't open early.",
            "Contact us. Nothing is released until this is sorted.",
            "local_escrow: owner/mode/symlink/HMAC check failed on /Library/PaxGuard/escrow (tamper)."),
    PaxCode("PAX-GUARD-011", "Pax noticed a change to this Mac's security settings.",
            "Open Pax to see what changed. If it wasn't you, talk to someone you trust.",
            "tamper.py: a watched value changed (admins, volume owners, FileVault, recovery key, MDM, "
            "startup security, firmware, guard files) or the clock jumped."),
    PaxCode("PAX-GUARD-012", "Pax couldn't reach its background protection.",
            "Restart the Mac and open Pax again.",
            "The app socket /var/run/pax-guard.sock is missing, refused, or answered with an error."),
    PaxCode("PAX-GUARD-013", "Pax noticed a change to its own files on this Mac.",
            "Nothing to do if Pax says it repaired them. If not, download Pax again and keep it in "
            "Applications.",
            "guard_runtime (v0.8.6): /Library/PaxGuard/runtime differs from its manifest (changed, missing or "
            "extra file, wrong mode or signature); it is rebuilt from a verified /Applications/Pax.app, else "
            "marked as failing so the launcher stops using it. Logged to the tamper log."),
    PaxCode("PAX-GUARD-014", "Pax couldn't go online, so Pax Max stays on.",
            "Try again when you're online. Nothing has changed.",
            "v0.8.12 paxmax.off: no network time from the filtered upstreams in the last 15 minutes (offline), "
            "or no local forwarder; the hour never starts offline (fail closed)."),
    PaxCode("PAX-GUARD-015", "Pax Max can only be changed by setting Pax up again on this Mac.",
            "Set Pax up again with the current version to switch Pax Max in Settings.",
            "v0.8.12 paxmax.*: this Mac was set up before 0.8.12 (config has no pax_max_switchable), or "
            "keeps its key on a Pax server (server escrow)."),
    # ---------------------------------------------------------------- DNS
    PaxCode("PAX-DNS-001", "That filter address doesn't look right.",
            "Leave the filter setting on its default, or check the address under Advanced.",
            "PaxDNS.URLError: the pax-dns base URL is invalid or not https."),
    PaxCode("PAX-DNS-002", "Pax couldn't update its ad and tracker list.",
            "Nothing to do: the last good list stays on. It will try again later.",
            "pax-guard: ad/bypass list download failed or was too small; old copy kept (log only)."),
    PaxCode("PAX-DNS-003", "Pax's main filter didn't answer, so it's using the backup filter.",
            "Nothing to do: you're still protected.",
            "dns_forwarder: CleanBrowsing Family DoH failed or timed out; AdGuard Family DoH used (log only)."),
    PaxCode("PAX-DNS-004", "No filter is reachable, so websites won't open for now.",
            "Check your internet connection. Pax never lets lookups go around the filter.",
            "dns_forwarder: every DoH upstream failed; answers are SERVFAIL (never unfiltered DNS)."),
    PaxCode("PAX-DNS-005", "Pax didn't accept a list update.",
            "Nothing to do: the last good list stays on.",
            "filter_lists: update refused (signature, SHA-256, format, minimum size, mass deletion or older "
            "version); current copy kept."),
    PaxCode("PAX-DNS-006", "One of Pax's lists was damaged, so it's using the built-in copy.",
            "Nothing to do: protection stays on.",
            "filter_lists: an updated list failed its SHA-256 or would not load; previous/bundled used."),
    PaxCode("PAX-DNS-007", "An extra list you added was skipped.",
            "Check the list file and its settings in /Library/PaxGuard/lists.d.",
            "filter_lists: plugin descriptor/file not root-owned, bad format, SHA-256 or too few entries."),
    PaxCode("PAX-DNS-008", "Pax's filter on this Mac couldn't start.",
            "Restart the Mac. Websites stay blocked until it starts.",
            "dns_forwarder: binding 127.0.0.1:53 failed (another resolver running?)."),
    PaxCode("PAX-DNS-009", "That isn't a website address.",
            "Type a site such as example.com.",
            "local_blocklist.normalise rejected the input (not a domain / an IP address)."),
    PaxCode("PAX-DNS-010", "This site is in a category Pax always blocks, so it can't be allowed.",
            "Nothing to do: no wait was started. If you think it's a mistake, tell us which site.",
            "Exception refused (v0.8.1): the site or a parent is restricted content (pax_restricted name "
            "rule, top-level domain or hand list; pax-block, pax-nrd), a media converter, a remote AI "
            "browser (ChatGPT, Manus), blocked by "
            "CleanBrowsing Family (NXDOMAIN, 0.0.0.0 or block page), or the CleanBrowsing check failed "
            "(fail closed). Server: HTTP 422 restricted_site."),
    PaxCode("PAX-DNS-011", "YouTube Restricted Mode can't be changed on this Mac.",
            "Nothing to do: Restricted Mode stays on. Setting Pax up again with the current version adds "
            "the switch.",
            "settings.set (v0.8.6) on a Mac whose DNS doesn't go through pax-guard's forwarder "
            "(dns_mode 'profile'), where CleanBrowsing Family forces Restricted Mode."),
    PaxCode("PAX-DNS-012", "Pax's filter didn't answer, so this iPhone wasn't locked to it.",
            "Nothing changed on the phone. Try again shortly, or choose CleanBrowsing directly under Advanced.",
            "v0.8.8: GET <dns base>/health (default https://dns.paxpeace.com/health) failed or wasn't ok "
            "before the profile pointing at Pax's DoH filter was generated. A locked profile can't be "
            "changed later, so set-up stops instead of locking the phone to a filter that isn't there."),
    # v0.8.9: blocked-sites sync with the user's Pax account (guard/list_sync.py).
    PaxCode("PAX-DNS-013", "Pax couldn't reach your Pax account, so nothing changed.",
            "The site stays blocked. Try again when you're online.",
            "list_sync: POST /v1/sync/unblock (or a cancel) failed to connect; a removal never starts "
            "offline (fail closed). Additions are queued and sent later."),
    PaxCode("PAX-DNS-014", "Pax couldn't link this Mac's list to your account.",
            "Try again from Settings. If it repeats, copy the details and send them to us.",
            "sync.link refused: the server address isn't https (or localhost) or the sync token is malformed."),
    PaxCode("PAX-DNS-015", "Your Pax account doesn't know this Mac any more.",
            "Open Pax: it links this Mac again. Nothing was unblocked.",
            "The server answered 401 to this Mac's sync token (revoked, or the server's database was "
            "replaced). pax-guard keeps enforcing its own copy of the list."),
    # v0.8.13: pictures and video on X and Bluesky are always blocked (no switch).
    PaxCode("PAX-DNS-016", "Pictures and video on X and Bluesky are always off, so this can't be changed.",
            "Nothing to do: no wait was started and nobody was emailed. Posts stay readable.",
            "v0.8.13: PUT /v1/dns/settings (or a guard/config path) asked for x_media or bluesky_media false. "
            "Their media servers (guard_config.X_MEDIA_NAMES, BLUESKY_MEDIA_NAMES) are always blocked; the "
            "server refuses with HTTP 422 media_always_blocked before any request, wait or email."),
    # v0.8.18: Pax's own filter failed a check; the family filter answers meanwhile.
    PaxCode("PAX-DNS-017", "Pax's own filter failed its self-test, so a backup family filter is answering for now.",
            "Nothing to do: you stay protected, and Pax switches back by itself once the self-test passes.",
            "v0.8.18: dns_forwarder.Forwarder entered its fallback (lists missing, too small or failing their "
            "checks; the decision code threw or took over DECIDE_SLOW; or the canary self-test failed). Every "
            "lookup goes to the family-filter chain until Forwarder.canary passes; logged to the tamper log "
            "(dns:fallback_on / dns:fallback_off) and shown as filter_mode \"fallback\" in the DNS status."),
    # ---------------------------------------------------------------- ESCROW
    PaxCode("PAX-ESCROW-001", "Pax needs to sign you in again.",
            "Try again: Pax will set up your account afresh.",
            "Escrow API 401 unauthorized: the saved account token is unknown to this server."),
    PaxCode("PAX-ESCROW-002", "That turn-off wait isn't available.",
            "Choose a turn-off wait between 24 hours and 365 days, then try again.",
            "PUT /v1/accounts/me/wait refused: outside min_wait_seconds..max_wait_seconds. v0.8.9: "
            "24 h to 365 days on the server and on a Mac's own key alike (0.8.8 servers refused under "
            "3 days); the app offers only what the path in use allows."),
    PaxCode("PAX-ESCROW-003", "Pax couldn't save your key safely, so it changed nothing.",
            "Check your internet connection and try again.",
            "MacLockdownError.escrowFailed / POST /v1/devices failed before anything was locked."),
    PaxCode("PAX-ESCROW-004", "Pax's server is having trouble.",
            "Wait a few minutes and try again.",
            "Escrow API returned 5xx."),
    PaxCode("PAX-ESCROW-005", "Pax's server said no to that request.",
            "Try again. If it repeats, copy the details and send them to us.",
            "Escrow API returned another 4xx (bad_request, not_found, conflict, gone, limit_reached)."),
    PaxCode("PAX-ESCROW-006", "Too many tries in a short time.",
            "Wait a little and try again.",
            "Escrow API 429 rate_limited."),
    PaxCode("PAX-ESCROW-007", "That isn't possible until your turn-off wait is over.",
            "Check the timer on the home screen.",
            "Escrow API 425 too_early (reveal before unlock_at)."),
    PaxCode("PAX-ESCROW-008", "Pax couldn't store that in its safe.",
            "Try again. If it repeats, copy the details and send them to us.",
            "local_escrow: invalid deposit/request (unknown secret, already stored, bad reason)."),
    PaxCode("PAX-ESCROW-009", "This Mac keeps its key somewhere else.",
            "Check Settings > Advanced: this Mac uses either itself or a Pax server.",
            "App socket escrow./blocklist. request while the guard is in server mode, or nothing held yet. "
            "v0.8.7: settings.set adblock while the guard is in server mode (the server holds that setting)."),
    PaxCode("PAX-ESCROW-010", "Your partner hasn't been told yet, so your turn-off wait hasn't started.",
            "Nothing to do: Pax keeps trying and starts the wait once they're told.",
            "partner.py: partner email not delivered (relay/SMTP failed); action queued, countdown not "
            "started (fail closed). Server (v0.8.5): HTTP 503 partner_unreachable (email failed or the "
            "daily email limit was reached); nothing started."),
    PaxCode("PAX-ESCROW-011", "Pax can't email your partner with these settings.",
            "Check Settings > Accountability partner email.",
            "partner.py: invalid transport (relay URL/token, SMTP host/From) or partner address."),
    # v0.8.15: verified support release (guard/support_code.py; docs/PARTNER.md).
    PaxCode("PAX-ESCROW-012", "That support code isn't complete.",
            "Paste the whole code from Pax support, including the PAXS- at the start.",
            "v0.8.15 support_code.parse: not base32, wrong length (91 bytes) or unknown version. Server: "
            "400 support_code_malformed."),
    PaxCode("PAX-ESCROW-013", "That support code wasn't issued by Pax support.",
            "Check you copied it exactly. Only Pax support can issue these codes.",
            "v0.8.15 support_code.verify: the Ed25519 signature doesn't match a pinned support key "
            "(SUPPORT_PUBLIC_KEYS_HEX). Server: 403 support_code_unverified."),
    PaxCode("PAX-ESCROW-014", "That support code is for a different device.",
            "Check the Support ID under Turn off for this device matches the one you gave support.",
            "v0.8.15: the code's support ID isn't this device's (local escrow state.json support.id, or "
            "devices.support_id on the server). Server: 403 support_code_wrong_device."),
    PaxCode("PAX-ESCROW-015", "That support code has expired.",
            "Ask Pax support for a new code. Codes last at most 24 hours.",
            "v0.8.15: now (or network time) is at or past expires_at, issued_at is more than 5 minutes in the "
            "future, or the lifetime is over 24 h. Server: 410 support_code_expired."),
    PaxCode("PAX-ESCROW-016", "That support code has already been used.",
            "Each code works once. Ask Pax support if you still need help.",
            "v0.8.15: the nonce is in local escrow support.used_nonces or the server's support_nonces table "
            "(kept for good). Server: 409 support_code_used."),
    PaxCode("PAX-ESCROW-017", "Verified support release is off on this device.",
            "Nothing was released. Your usual turn-off wait still works from Request a change.",
            "v0.8.15: the device's \"Allow verified support release\" is off (devices set up before 0.8.15 "
            "start off; turning it on waits the full wait). Every code is refused. Server: 403 "
            "support_release_off."),
    PaxCode("PAX-ESCROW-018", "Your partner couldn't be told, so nothing was released.",
            "Check your internet connection and try the same code again shortly.",
            "v0.8.15: the partner email for a support release failed. Not queued (unlike PAX-ESCROW-010) and "
            "the nonce isn't used up; the code works again until it expires. Server: 503 "
            "support_partner_unreachable."),
    PaxCode("PAX-ESCROW-019", "Too many support code tries in a short time.",
            "Wait a little, then try again.",
            "v0.8.15: pax-guard allows 3 codes a minute; the server allows 10 refused codes an hour per "
            "device (429 support_rate_limited)."),
    # v0.8.32: verified-email accounts (docs/ONETAP_ACCOUNTS.md).
    PaxCode("PAX-ESCROW-020", "This version of Pax can't make new accounts any more.",
            "Download the latest Pax from paxpeace.com, then set up again. It checks your email with a 6-digit code.",
            "v0.8.32: POST /v1/accounts refuses new accounts (410 app_update_required); accounts are made only by "
            "POST /v1/accounts/email/start + /verify, so every email is verified. An address that already has an "
            "account still gets 409 sign_in. Seen by Pax for Mac 0.8.31 or older (shown there as PAX-ESCROW-005)."),
    # ---------------------------------------------------------------- PROFILE
    PaxCode("PAX-PROFILE-001", "Pax couldn't prepare your protection settings.",
            "Try again. If it repeats, copy the details and send them to us.",
            "make_profile.py exited non-zero (ProfileError or validation failure)."),
    PaxCode("PAX-PROFILE-002", "The Pax settings weren't approved on this Mac.",
            "Install \"Pax (this Mac)\" in System Settings > Device Management (macOS 12: System Preferences > Profiles), then retry.",
            "MacLockdownError.profileInstallFailed: the self-lock profile was not installed/approved."),
    PaxCode("PAX-PROFILE-003", "Pax couldn't find its settings on your iPhone.",
            "On the iPhone open Settings > Profile Downloaded > Install, then try again.",
            "SetupError.profileNotVerified: profile identifier not in the device's installed profiles."),
    PaxCode("PAX-PROFILE-004", "One of the apps you chose can't be blocked on the iPhone.",
            "Remove it from your list: Pax never blocks Apple's own apps or password managers.",
            "make_profile.py (v0.8.7): --block-app refused by profile/app_blocks.py (com.apple., a "
            "password manager, not a bundle ID) or more than 200 custom apps."),
    # ---------------------------------------------------------------- UPDATE (v0.8.0)
    PaxCode("PAX-UPDATE-001", "Pax couldn't check for updates.",
            "Nothing to do: it tries again later. Your version keeps protecting you.",
            "pax_update: no manifest URL answered (offline, or the release repo isn't public)."),
    PaxCode("PAX-UPDATE-002", "Pax ignored an update it couldn't trust.",
            "Nothing to do. If it repeats, tell us.",
            "pax_update/filter_lists: manifest unsigned, signature invalid for the pinned Ed25519 key, or "
            "malformed."),
    PaxCode("PAX-UPDATE-003", "Pax won't go back to an older version.",
            "Nothing to do.",
            "pax_update: manifest version <= installed, or older than one already seen (stale mirror)."),
    PaxCode("PAX-UPDATE-004", "An update download was damaged, so Pax didn't use it.",
            "Nothing to do: Pax tries again later.",
            "pax_update: zip size/SHA-256 doesn't match the signed manifest."),
    PaxCode("PAX-UPDATE-005", "An update didn't pass Pax's checks.",
            "Nothing to do: your version keeps running.",
            "pax_update: Info.plist version mismatch, missing guard, or the new pax-guard failed selftest."),
    PaxCode("PAX-UPDATE-006", "An update wasn't signed by the same developer.",
            "Nothing to do: Pax kept your version. Tell us if it repeats.",
            "pax_update: codesign --verify failed, or the Developer ID Team ID differs from the installed app."),
    PaxCode("PAX-UPDATE-007", "Pax put the previous version back.",
            "Nothing to do: you're protected by the version you had.",
            "pax_update: swap failed or the new pax-guard didn't confirm within 3 minutes; watchdog rolled back."),
    PaxCode("PAX-UPDATE-008", "Update servers asked Pax to slow down.",
            "Nothing to do: Pax waits and tries again.",
            "pax_update/filter_lists: HTTP 429 or 5xx; exponential back-off (1 h to 24 h, Retry-After honoured)."),
    # ---------------------------------------------------------------- NET
    PaxCode("PAX-NET-001", "Pax can't reach its server.",
            "Check your internet connection and try again.",
            "URLError cannotConnectToHost / cannotFindHost / timedOut / networkConnectionLost."),
    PaxCode("PAX-NET-002", "This Mac seems to be offline.",
            "Connect to the internet and try again.",
            "URLError notConnectedToInternet."),
    PaxCode("PAX-NET-003", "Pax couldn't make a secure connection to its server.",
            "Check the Mac's date and time, then try again.",
            "URLError secureConnectionFailed / serverCertificate* (TLS)."),
    PaxCode("PAX-NET-004", "That server address doesn't look right.",
            "Check the address in Settings > Advanced, or put the default back.",
            "ServerURLSetting.Problem: invalid URL, or http:// to a non-local host."),
]

BY_CODE: dict[str, PaxCode] = {c.code: c for c in CODES}


def get(code: str) -> PaxCode:
    return BY_CODE.get(code, BY_CODE["PAX-APP-000"])


def line(code: str, detail: str = "") -> str:
    """A log/stderr line: 'PAX-GUARD-003: <message> (<detail>)'. The Mac app
    finds the code in a failure message with CODE_IN_TEXT."""
    c = get(code)
    return f"{c.code}: {c.message}" + (f" ({detail})" if detail else "")


CODE_IN_TEXT = re.compile(r"PAX-(?:APP|MAC|IOS|GUARD|DNS|ESCROW|PROFILE|NET|UPDATE)-\d{3}")


# v0.8.15: the server's error names for verified support release (escrow.SUPPORT_ERRORS).
SUPPORT_ERRORS = {
    "support_code_malformed": "PAX-ESCROW-012",
    "support_code_unverified": "PAX-ESCROW-013",
    "support_code_wrong_device": "PAX-ESCROW-014",
    "support_code_expired": "PAX-ESCROW-015",
    "support_code_used": "PAX-ESCROW-016",
    "support_release_off": "PAX-ESCROW-017",
    "support_partner_unreachable": "PAX-ESCROW-018",
    "support_rate_limited": "PAX-ESCROW-019",
}


def escrow_code(status: int, error: str = "", message: str = "") -> str:
    """Code for an escrow-server error response (used by the server and mirrored
    by the Mac app's PaxError.classify)."""
    if error == "restricted_site":
        return "PAX-DNS-010"
    if error == "media_always_blocked":
        return "PAX-DNS-016"
    if error == "partner_unreachable":
        return "PAX-ESCROW-010"
    if error == "app_update_required":                # v0.8.32
        return "PAX-ESCROW-020"
    if error in SUPPORT_ERRORS:                       # v0.8.15 verified support release
        return SUPPORT_ERRORS[error]
    if status == 401:
        return "PAX-ESCROW-001"
    if status == 400 and "wait time" in message:
        return "PAX-ESCROW-002"
    if status == 429:
        return "PAX-ESCROW-006"
    if status == 425:
        return "PAX-ESCROW-007"
    if status >= 500:
        return "PAX-ESCROW-004"
    return "PAX-ESCROW-005"
