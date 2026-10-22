# Pax Peace (Apple), v0.8.31

**Less scrolling. More living.**

**Requirements:** a Mac with **macOS 12 Monterey or later**, Intel or Apple silicon (the iPhone
or iPad is set up from that Mac). Hardware testing on a real Monterey Mac is still pending; see
[docs/MONTEREY.md](docs/MONTEREY.md).

Pax (Latin for *peace*) is a free, open-source (GPL-3.0) content blocker for restricted content on
**iPhone and iPad**, set up from a Mac, and since v0.4 on **the Mac itself** ([Pax for Mac](#pax-for-mac)). It's built for people who choose this for themselves.
Turning it off is never impossible. It just takes a **turn-off wait** you picked in advance: if you
ever decide to switch Pax off, you ask first, then wait that long before it turns off, and you can
cancel any time during the wait. So the decision gets made by the calm version of you. (The same
wait applies before a blocked site or app is unblocked.)

*Decentralised. Open source. Free for everyone. Power at the local level.* (Pax Peace: [paxpeace.com](https://paxpeace.com))

Positioning: Pax does **restricted-content filtering** and nothing else. Time limits and focus tools
are on the [roadmap](ROADMAP.md). Pax is free. We may add an optional donation later, but there are
no payments in this code.

It needs no MDM server and no staff in the loop:

1. The **Mac app** supervises the iPhone over USB **without erasing it** ("Keep my data", iOS 17–27).
   If that isn't possible it falls back to erasing and supervising with Apple's `cfgutil` ("Clean").
2. It installs a **locked configuration profile**. The profile forces filtered encrypted DNS
   (CleanBrowsing **Family** filter by default), turns
   on Apple's built-in content filter, blocks VPN creation, DNS changes, iCloud Private Relay,
   Erase All Content and Settings, manual profile installs and known bypass apps. It also has a
   **removal password**.
3. That password is generated at random, sent straight to the **escrow server**, and never shown.
4. To remove Pax you start a removal request. The **turn-off wait** runs (default 3 days, choose
   24 hours to 365 days). When it ends you confirm, and the password is released. Your optional
   **accountability partner** is emailed. On a genuinely new set-up the **first 24 hours are a trial
   day** (v0.8.18): Pax can be turned off any time with no wait (the partner is still told first), and
   "Start my wait now" ends it early. Setting up again never restarts it (docs/TRIAL_DAY.md). A set-up
   without a trial day still gets the old **first hour** with no wait. There's a
   rate-limited **emergency release** with a short cooling-off and crisis-line auto-reply.
5. **Verified support release** (v0.8.15): in a genuine emergency that Pax support has checked, support
   can issue a one-time code that removes Pax from **one device** straight away. There is no universal
   code. Each device has **Allow verified support release** (on by default at set-up, off on devices set
   up before 0.8.15); with it off, every code is refused. See docs/SUPPORT_RELEASE.md.

The code is open source on purpose. Pax gets its security from the password the server holds and
the wait it enforces. Keeping the code secret adds nothing.

## Repository layout

```
device/       pax_device.py        USB helper for Keep my data (preflight, backup, seed restore,
                                   re-pair, live SetCloudConfiguration, verify, profile install)
              seed.py              pure logic: version gate, cloud configuration, seed backup,
                                   restore arguments, preflight verdict
              tests/               pytest (no iPhone needed)
profile/      make_profile.py      .mobileconfig generator (iOS/iPadOS, macOS DNS-only, Mac self-lock)
              mac_policies.py      v0.4 browser policies (Chrome, Edge, Brave, Chromium, Firefox)
              bypass_apps.py       default blocked bundle IDs (verified via iTunes Search API)
              refresh_bypass_apps.py  re-checks those bundle IDs before a release
              apple-schema/        Apple's MIT-licensed payload schemas, used by the tests
              tests/               pytest
server/       pax_server/          FastAPI + SQLite escrow service (+ blocklist API, DNS tokens,
                                   pax-dns change feed)
              tests/               pytest with a fake clock
pax-dns/      pax_dns/             per-user DoH resolver (FastAPI) + plain DNS (dnslib)
              scripts/load_lists.py  builds the category list from HaGeZi / OISD (+ bypass list, v0.5)
              lists/pax-additions.txt  Pax's own additions (reviewed, short)
              lists/cloud-pc-bypass.txt  v0.5 "bypass" category (always on; also used by pax-guard
                                   and the Mac profile)
              lists/remote-desktop.txt   v0.5 "remote desktop" category (on by default)
              tests/               pytest (no network: fake upstreams)
guard/        pax_guard.py         v0.4 root daemon for a self-locked Mac (hosts, pf, bypass apps)
              guard_config.py      pure rules: hosts block, pf anchor, app lists, ad list parsing
              org.paxpeace.pax-guard.plist  LaunchDaemon
              support_code.py      v0.8.15 verified support release codes (also used by the server)
              scripts/             pax-guard-install.sh, pax-uninstall-emergency.sh
              tests/               pytest (fake system; never touches the Mac)
tools/        pax-support-release.py  v0.8.15: issue (or check) a one-device support code
mac-app/      Package.swift        SwiftPM: PaxCore (Foundation logic) + Pax (SwiftUI app)
              Sources/PaxCore/     DeviceService protocol, cfgutil backend (Clean), Keep-my-data
                                   supervisor + helper client, escrow client, profile generator
                                   wrapper, setup coordinator
              Sources/Pax/         Theme.swift (brand), SetupModel, guided SwiftUI flow,
                                   Blocked sites screen, Keychain token store
              Sources/PaxCore/MacLockdown.swift  v0.4 Protect this Mac (order, verification, rollback)
              Sources/Pax/Views/ProtectMacView.swift  v0.4 screens
              Tests/PaxCoreTests/  XCTest: cfgutil arguments/parsing, Keep-my-data plan + helper calls,
                                   per-user DoH URL, blocklist models, Mac lockdown order + rollback
              scripts/             build-dmg.sh, build-device-helper.sh + helper_runtime.py (v0.8.6
                                   bundled helper), linux-xctest.sh, install-helper.sh (developers)
extension/    src/                 v0.5 Pax Image Blur (MV3): content script, classifier, options;
                                   TensorFlow.js bundle and model stored gzipped in <85 KB parts
              build.py             joins the parts; dist/chrome, Web Store zip, Firefox .xpi
              tests/               node --test (core logic; content script in jsdom)
.github/workflows/  ci.yml (tests, shellcheck), build-dmg.yml (universal DMG artifact + ci-logs)
```

## Architecture

```
 ┌──────────── Mac (Pax app) ─────────────┐        HTTPS        ┌──── Pax escrow server ────┐
 │ SwiftUI flow ─► SetupCoordinator        │ ──────────────────► │ FastAPI + SQLite          │
 │   │  KeepDataSupervisor ─► pax_device.py│  register account   │ AES-256-GCM password at   │
 │   │     (pymobiledevice3 on bundled Python)                   │                           │
 │   │  DeviceService ─► cfgutil (Clean)   │                     │                           │
 │   │  ProfileGenerator ─► make_profile.py│  set wait/partner   │ rest (key outside the DB) │
 │   └─ EscrowClient                       │  escrow password    │ timers, partner emails,   │
 └──────────────┬──────────────────────────┘  removal requests   │ emergency release         │
                │ USB: Keep my data: seed restore (+ live MCInstall on iOS 27), verify,
                │      install profile                             └───────────────────────────┘
                │      Clean: backup, erase, prepare --supervised, install-profile
                ▼
          iPhone / iPad: supervised + locked Pax profile ──DoH──► filtering resolver
```

**Filter lists update themselves.** Every night a GitHub Actions workflow in this repo rebuilds Pax's
lists, tests them (everyday sites, the Tranco top 10k, a held-out benchmark) and, only if every check
passes, publishes a signed *filter pack*. Macs and Pax's DoH servers check for one every 6 hours and run
their own checks and self-test before using it, keeping the last good lists otherwise. No person is in
that loop; see [`docs/FILTER_PACKS.md`](docs/FILTER_PACKS.md).

**Order of set-up matters.** The app first re-reads supervision from the phone and stops if it isn't
supervised (nothing escrowed, nothing locked). It escrows the password *before* it installs the locked
profile.
If the install then fails, the server just holds a password nobody needs. The other order could
leave a phone locked with no password anywhere.

## Set-up

### Server

```bash
cd server
pip install -r requirements-dev.txt
export PAX_SERVER_KEY=$(python3 -m pax_server.crypto --generate-key)   # keep this safe & backed up
export PAX_DB_PATH=/var/lib/pax/pax.sqlite3
uvicorn --factory pax_server.main:create_app --host 127.0.0.1 --port 8080
python3 -m pytest -q
```

Run it only behind HTTPS. Bearer tokens and released passwords travel in request and response bodies.
If you lose `PAX_SERVER_KEY`, every escrowed password is gone, and those users can only get out by
restoring their device in Finder (which erases it).

| Env var | Default | Meaning |
|---|---|---|
| `PAX_DEFAULT_WAIT_SECONDS` | 259200 (72 h) | wait for new accounts |
| `PAX_MIN_WAIT_SECONDS` / `PAX_MAX_WAIT_SECONDS` | 24 h / 365 d | allowed range (v0.8.9: the same as a Mac's own key; was 3 d) |
| `PAX_GRACE_SECONDS` | 1 h | no-wait window after a device is registered; a request made in it lapses when it ends |
| `PAX_TRIAL_SECONDS` | 24 h | v0.8.18 trial day for a genuinely new set-up (counted from the account's / hardware's first one); 0 turns it off |
| `PAX_REVEAL_WINDOW_SECONDS` | 7 d | how long after the wait ends you can still confirm; after that the request lapses |
| `PAX_EMERGENCY_COOLOFF_SECONDS` | 24 h | emergency release cooling-off |
| `PAX_EMERGENCY_MIN_INTERVAL_SECONDS` | 90 d | one emergency release per account per interval |
| `PAX_SIGNUP_PER_IP_HOUR` / `PAX_SIGNUP_PER_IP_DAY` | 5 / 20 | new-account attempts per client address (0 = no limit); `X-Forwarded-For` is used only from localhost |
| `PAX_MAIL_DAILY_CAP` | 90 | emails in any 24 hours, all kinds (-1 = no limit); keep it under your provider's daily quota |
| `PAX_ACCOUNT_MAIL_DAILY_CAP` | 60 | account-holder emails stop at this total, so the rest is kept for partner alerts |

A 24-hour wait is allowed everywhere since v0.8.9 (before, the server's minimum was 3 days). For quick
tests, `PAX_DEFAULT_WAIT_SECONDS=86400` starts new accounts at 24 hours (lowering an existing wait is a
decrease, which itself waits and tells the partner).

| `PAX_BLOCKLIST_DELAY` | `wait` | v0.8.9: the one removal rule's wait. `wait`: the user's own wait (the longer of the account's and a linked Mac's). `fixed`: `PAX_BLOCKLIST_DELAY_SECONDS` |
| `PAX_BLOCKLIST_DELAY_SECONDS` | 259200 (72 h) | with `PAX_BLOCKLIST_DELAY=fixed`: wait before a removal, an exception or a DNS token rotation takes effect |
| `PAX_BLOCKLIST_MAX_ENTRIES` / `PAX_ALLOWLIST_MAX_ENTRIES` | 2000 / 500 | list size caps |
| `PAX_BLOCKLIST_SWEEP_SECONDS` | 5 | how often due changes are applied and emailed (0 = only on access) |
| `PAX_DNS_BASE_URL` | `https://dns.paxmobile.org` | base of the per-user DoH URL handed out by `GET /v1/dns` |
| `PAX_INTERNAL_KEY` | (empty = off) | shared secret for pax-dns's `/internal/v1/dns/changes` feed |

API (all under `/v1`, Bearer token except the first three): `GET health`, `GET crisis-lines`,
`POST accounts` (limited per client address, v0.8.5), `GET accounts/me`, `PUT accounts/me/wait {wait_days|wait_hours}`,
`PUT accounts/me/partner {email|null}`, `POST devices`, `GET devices`, `GET devices/{id}`,
`POST devices/{id}/removal-request`, `POST devices/{id}/removal-request/cancel`,
`POST devices/{id}/removal-request/confirm {confirm:true}`, `POST devices/{id}/emergency {reason}`.
Verified support release (v0.8.15): `POST devices {support_release}` (the set-up choice; left out = off),
`PUT devices/{id}/support-release {allowed}` (off at once; on after the wait, partner told first),
`POST devices/{id}/support-release/redeem {code}` (partner emailed first, then the password is returned;
refusals are `support_*` errors, PAX-ESCROW-012 to 019). `GET devices/{id}` shows `support_id` and
`support_release`.
Device state (v0.8.26): `GET devices` / `GET devices/{id}` add `released` and, for iPhones and iPads,
`last_seen` (a UTC day) and `checking_in` (false after 48 hours or more with no Pax DNS traffic; null =
unknown). `POST devices/{id}/retire` forgets a device on the owner's list, only once its password was
released (409 otherwise, 404 for another account's device; logged; never turns anything off).
Delete account (v0.8.30, App Store guideline 5.1.1(v)): `DELETE accounts/me` with the account's (or any
signed-in) Bearer token. 204, no body: the account and every row on it (devices, turn-off requests, guard
and sync sign-ins, blocked sites and their requests, DNS addresses, sign-in codes, history, usage rows) are
deleted in one transaction, the token stops working at once, and the holder is emailed "Your Pax account
has been deleted" (best-effort; a failed email never undoes it; the trusted person isn't emailed). Fail
closed: 409 `devices_still_protected` (`count`, `devices: [{device_id, name, platform, reason, removal_request,
checking_in}]`, `reason` one of `pax_on` | `turn_off_wait` | `emergency_release` | `pending_request`) while
Pax still holds any device's key (including one that isn't checking in) or any removal request is open;
deleting never skips the wait or the trusted person's email. 401 without a valid token; 429 after 10 refused
tries in an hour. Kept by design: the hashed hardware code (`trial_hardware`, no second trial day) and used
support codes (`support_nonces`, a code works once); `mail_log`/`signup_attempts` hashes go within two days.
The DNS feed carries the account once with `"deleted": true` so both DNS servers drop it at their next
poll; that `dns_changes` row (random ID, sequence number, time) is pruned after an hour.
One-tap accounts (branch, for the iPhone app 1.2; not released yet). Every account has a verified email:
`POST accounts/email/start {email}` (no token; the same per-client sign-up limit as `POST accounts`) always
answers 202 `{sent: true}` and emails a 6-digit code (15 minutes, 5 tries, 5 codes an hour per address), new
address or not; `POST accounts/email/verify {email, code, label?}` answers 201 `{account_id, token, created:
true}` (a new account, made only now, email verified) or 200 `{account_id, token, created: false}` (a sign-in to
the address's existing account), 401 for a wrong, used or expired code (nothing made). There is no email-less
account. `GET accounts/me` adds `email_verified` and `display_name`. `PUT accounts/me/partner` takes an optional
`from_name` (one line, at most 40 characters, no control characters or links; 422 otherwise), and every email to
the trusted person names the holder by it, else by their email. `PUT devices/{id}/escrow {removal_password}`
(20-256 characters, owner's token) replaces the secret Pax holds for a device: 200 device status; 409
`conflict` with `reason` `released` | `retired` | `removal_request_open` | `emergency_open` while it can't; 404
`not_found` for another account's device; logged, never loosens anything. Storage: two added columns and a
hashes-only `signup_codes` table; `accounts.email` stays NOT NULL. Details, request/response JSON and a note on
Sign in with Apple: [docs/ONETAP_ACCOUNTS.md](docs/ONETAP_ACCOUNTS.md).
Blocklist (v0.3): `GET blocklist`, `POST blocklist {domain}` (instant), `POST blocklist/remove
{domain}` (202, waits), `POST allowlist {domain}` (202, waits), `POST allowlist/remove {domain}`
(instant), `POST blocklist/requests/{id}/cancel`, `GET dns` (your DoH URL; creates the token),
`POST dns/rotate` (202). Mac (v0.4): `POST devices` accepts `platform: "mac"` (the escrowed secret is
the paxadmin password), `PUT accounts/me/adblock {enabled}` (immediate both ways), `POST
devices/{id}/guard-token` (Mac devices only) and `GET guard/config` with `X-Pax-Guard-Token` (read-only:
effective blocklist, exceptions, ad blocking, released flag; it can't request, cancel or reveal).
Categories (v0.5): `GET categories`, `PUT categories/{bypass|remote_desktop} {enabled}` (on is
immediate; turning `remote_desktop` off answers 202 with a request that waits the blocklist delay and
is cancelled with `POST blocklist/requests/{id}/cancel`; `bypass` can't be turned off). `GET
guard/config` and the pax-dns feed carry `categories`. Internal: `GET /internal/v1/dns/changes?since=N` with
`X-Pax-Internal-Key` (404 without it).
v0.8.8: `GET|POST /u/{token}/dns-query` and `/v1/doh/u/{token}/dns-query` (DoH, RFC 8484; Pax's iPhone
filter, see docs/DNS.md), `GET|PUT dns/settings {youtube_restricted?}` (v0.8.13: `x_media` / `bluesky_media`
are always true; sending either as false is refused with 422 `media_always_blocked`, PAX-DNS-016) and
`GET /v1/replica/dns/changes?since=N` with `X-Pax-Replica-Key` (the second server's feed; 404 without a
known key). `PAX_ROLE=dns` runs a DoH-only server.
Email goes through a pluggable `EmailSender`: SMTP when `PAX_SMTP_HOST` is set (v0.8.0), otherwise a
logging stub. Emails never contain the password. Since v0.8.5 every email counts against the daily
budget above; partner alerts fail closed and account-holder emails are best-effort.

### pax-dns (per-user filtering resolver)

> v0.8.8: production iPhones use the DoH filter built into pax-server (`server/pax_server/doh.py`, the
> Mac's engine and lists). This stand-alone pax-dns stays for development and self-hosting.

```bash
cd pax-dns
pip install -r requirements-dev.txt
python3 -m pytest -q                       # no network needed
# Same host as the escrow server (reads its SQLite file read-only):
PAX_DNS_SOURCE=sqlite:////var/lib/pax/pax.sqlite3 \
  uvicorn --factory pax_dns.doh:create_app --host 127.0.0.1 --port 8053 --no-access-log
# Or another host, over the internal API (set the same PAX_INTERNAL_KEY on the server):
PAX_DNS_SOURCE=https://escrow.internal PAX_INTERNAL_KEY=... uvicorn --factory pax_dns.doh:create_app ...
# Plain DNS (UDP+TCP): one user's lists or category filtering only
python3 -m pax_dns.plain --address 0.0.0.0 --port 53 [--token TOKEN]
```

Put it behind HTTPS as `dns.paxmobile.org` (Caddy/nginx). Endpoints: `GET|POST /u/<token>/dns-query`
(RFC 8484: GET `?dns=` base64url without padding, POST `application/dns-message`; 400 for a bad
message, 415 for the wrong content type, 413 over 65,535 bytes; `Cache-Control: max-age` = the
smallest TTL), `GET|POST /dns-query` (no token: category filtering only; turn off with
`PAX_DNS_PUBLIC_ENDPOINT=0`) and `GET /health`.

**Resolution order** for every query, each entry matching the domain and all its subdomains:

1. **Your exceptions** (allow-list) → forwarded to the *allow upstream*, which must not
   category-filter (default CleanBrowsing **Security** Filter, malware only), so the exception works.
2. **Your blocklist** → blocked answer.
3. **Category list** (if `PAX_DNS_CATEGORY_FILE` is set) → blocked answer.
4. Everything else → the upstream (default CleanBrowsing **Family** Filter, which blocks restricted
   content, proxy/VPN and mixed sites itself and forces SafeSearch).

Exceptions beat your own blocks (as specified). An exception for `example.com` therefore also
unblocks a blocked `sub.example.com`; the server refuses an exception for a domain that's on your
blocklist, but not for its parent. A CNAME that points at a blocked name is blocked too. Unknown,
malformed or retired tokens still get steps 3–4 (filtered, never unfiltered). If the upstream fails
the answer is SERVFAIL, never an unfiltered fallback.

**Blocked answers**: `0.0.0.0` for A, `::` for AAAA, an empty answer (NODATA) for other types such as
HTTPS/SVCB, each with an SOA so resolvers cache the block for `PAX_DNS_BLOCK_TTL` (60 s). Set
`PAX_DNS_BLOCK_MODE=nxdomain` for NXDOMAIN instead. Forwarded answers have their TTL capped at
`PAX_DNS_MAX_TTL` (300 s), so a site you just blocked stops resolving on a phone that cached it within
5 minutes at most (new lookups: within the 2 s poll).

| Env var | Default | Meaning |
|---|---|---|
| `PAX_DNS_UPSTREAM` | CleanBrowsing Family DoH | `https://…` DoH or `udp://host[:port]` |
| `PAX_DNS_ALLOW_UPSTREAM` | CleanBrowsing Security DoH | where exceptions go (must not category-filter) |
| `PAX_DNS_CATEGORY_FILE` | (none) | merged list from `scripts/load_lists.py`; reloaded when it changes |
| `PAX_DNS_SOURCE` | (none) | `sqlite:////path/pax.sqlite3` or `https://escrow-server` |
| `PAX_INTERNAL_KEY` | | needed for the https source |
| `PAX_DNS_POLL_SECONDS` | 2 | how often lists are re-read |
| `PAX_DNS_BLOCK_MODE` / `PAX_DNS_BLOCK_TTL` / `PAX_DNS_MAX_TTL` | null / 60 / 300 | see above |
| `PAX_DNS_CACHE_SIZE` | 10000 | shared answer cache (per-user decisions are made before it) |

No query names are logged. Run uvicorn with `--no-access-log`: the URL path holds the user's token.

**CleanBrowsing is a development default only.** Its free tier is described as "for parents, not
organizations" and is throttled, and its paid app plans start at hundreds of dollars a month. A public
Pax service must self-host its category lists: set `PAX_DNS_UPSTREAM` to an unfiltered resolver you
run (e.g. Unbound) and load **HaGeZi** and **OISD** lists:

```bash
python3 scripts/load_lists.py --out /var/lib/pax/category.txt          # HaGeZi + OISD restricted lists
python3 scripts/load_lists.py --source hagezi-restricted --source oisd-restricted --source hagezi-doh-vpn \
    --out /var/lib/pax/category.txt                                     # + DoH/VPN/proxy bypass
```

Run it daily (cron or a systemd timer). It writes atomically and refuses to write a list that came
back suspiciously small (`--min-entries`, default 10,000), so a failed download never empties the
filter. Tests never download; they use a fake fetcher. Note that self-hosting drops CleanBrowsing's
forced SafeSearch and proxy blocking until the roadmap's SafeSearch rewrites land; add the HaGeZi
DoH/VPN list for the latter.

### Profile generator

```bash
cd profile
python3 make_profile.py --out pax.mobileconfig --escrow-out escrow.json \
    [--filter family|core | --resolver-url https://your-dns.example/dns-query] \
    [--block-app com.example.app] [--block-url badsite.example] [--no-default-app-blocks]
python3 make_profile.py --macos --out mac.mobileconfig --escrow-out mac-escrow.json   # Mac, DNS-only
python3 make_profile.py --self-lock --out this-mac.mobileconfig [--no-adblock]   # v0.4 Pax for Mac
python3 -m pytest -q
```

The password goes **only** to the escrow JSON (mode 0600). It is never printed. The profile file
contains it too, because that's how iOS checks it, so it's also written 0600. The Mac app deletes both
straight away and sends the profile to `cfgutil` over stdin.

`--filter family` (default) and `--filter core` pick the CleanBrowsing filter; `--resolver-url`
replaces it with any https DoH resolver (the two options are mutually exclusive).

**Per-user DNS (v0.3)**: `--user-token TOKEN` sets the DNS server to
`https://dns.paxmobile.org/u/TOKEN/dns-query` (change the base with `--dns-base` or `PAX_DNS_BASE`).
It works for the iOS profile and the macOS DNS-only profile (`--macos --user-token …`), and is
exclusive with `--filter`/`--resolver-url`. Because the profile only holds the address, your blocklist
can change any time without reinstalling it. The token is a secret: stdout shows it masked. The Mac
app gets it from `GET /v1/dns` and uses the same token for all your devices.

**Fallback deny-list**: with `--user-token` the iOS profile also carries a short built-in list of the
most-visited restricted sites (`profile/fallback_denylist.py`, 60 URLs) in Apple's web filter
`DenyListURLs`, after your own `--block-url` entries and within Apple's 500-entry cap. It backs up DNS
in Safari and web views. Turn it on for other profiles with `--fallback-denylist`, off with
`--no-fallback-denylist`. macOS has no built-in web filter, so the Mac profile stays DNS-only.

### Device helper (Keep my data)

**Users: nothing to install, no Terminal step.** Since v0.8.6 the helper ships inside Pax.app
(`Contents/Resources/device/`): `pax_device.py` plus its own Python
(`device/python/bin/python3.12`, CPython 3.12 from python-build-standalone, universal2) with
pymobiledevice3 and the packages it imports. The app runs it with `-I -B` (ignores the user's
Python settings, never writes into the signed app). Plug the iPhone in and Pax does the rest.

How it's built: `mac-app/scripts/build-device-helper.sh` (called by `build-dmg.sh`) downloads the
two CPython archives pinned by sha256 in `device/helper-runtime.json`, installs the wheels in
`device/requirements-bundle.txt` (`--no-deps --require-hashes`, one set per architecture), removes
what the helper never uses, merges arm64 and x86_64 with `lipo`, precompiles, and runs
`pax_device.py selftest`. `build-dmg.sh` then signs every Mach-O inside with the Developer ID
(hardened runtime, secure timestamp; the interpreter gets `mac-app/Resources/helper-python.entitlements`)
before signing and notarising the app.

For developers:

```bash
cd device && python3 -m pytest -q                   # pure-logic tests, no iPhone needed
python3 -m venv .venv && .venv/bin/pip install -r device/requirements.txt   # pymobiledevice3
.venv/bin/python device/pax_device.py selftest      # imports everything the helper uses
.venv/bin/python device/pax_device.py list          # JSON: connected iPhones
"/Applications/Pax.app/Contents/Resources/device/python/bin/python3.12" -I -B \
  "/Applications/Pax.app/Contents/Resources/device/pax_device.py" selftest   # the bundled one
```

The app looks for, in order: `PAX_PYTHON`, the bundled Python, the old developer venv in
`~/Library/Application Support/Pax/venv` (for `swift run` builds, which have no bundle), then
`/usr/bin/python3`. `PAX_DEVICE_HELPER` overrides the
script path. `PAX_IDEVICEBACKUP2=/path/to/idevicebackup2` is an optional advanced override that makes
backup and the seed restore run libimobiledevice's `idevicebackup2` with the v0.8.5 flags; Pax never
looks for it otherwise. After changing a pin, run `python3 device/lock_bundle.py` to refresh the hashes.

### Mac app

Building it yourself needs macOS 13+ and Xcode 15+ (or the Command Line Tools); the build targets
macOS 12, so the app runs on **macOS 12 Monterey or later**. Using it needs neither: **Keep my data** runs on the helper bundled in Pax.app, so there is no Terminal step (a
`swift run` build has no bundle: set `PAX_PYTHON` to a developer venv, see above). **Clean set-up**
also needs **Apple Configurator** from the Mac App Store, with *Apple Configurator › Install
Automation Tools…* run (that puts `cfgutil` in `/usr/local/bin`).

```bash
cd mac-app
swift build
PAX_SERVER_URL=https://your-pax-server/ PAX_PROFILE_SCRIPT=../profile/make_profile.py \
  PAX_DEVICE_HELPER=../device/pax_device.py swift run Pax
PAX_DNS_BASE=https://dns.paxmobile.org swift run Pax   # v0.3: per-user DNS in new profiles
PAX_DEMO=1 swift run Pax      # walk through the UI with a mock iPhone on iOS 27.2
swift test                    # PaxCore unit tests
```

The guided flow goes: welcome → consent (18+, my own device, I understand the turn-off wait) → account
email → back-up reminder (backup, Find My **off**) → connect and detect the iPhone → turn-off wait and
optional partner → set-up method and filter → prepare (Keep my data: checks, backup, restore,
on-phone steps, confirmed; or Clean: back up, erase, supervise) → confirm supervision, generate
profile, escrow password, install and verify → done (turn Find My back on).

**Home and Settings** (v0.8.18, "1, 2, 3, not option overwhelm"; docs/HOME_AND_SETTINGS.md): Home is
three cards: **1 Status** (one big line, "Protected" or "Pax turns off in 12 h 19 min · Cancel", the
trial-day countdown, and at most one "1 thing to know" line that opens to notices), **2 What's blocked**
(sites and apps, a count and one *Add* each) and **3 Turn off** (one button, *In an emergency* inside;
on a Mac it reads "Emergency release is self-serve. You give a reason, your trusted person is emailed, and
Pax turns off after 24 hours instead of your full turn-off wait. You can use it once every 90 days.", with
the hours taken from `PAX_EMERGENCY_COOLOFF_SECONDS` and "straight away" in the trial day).
This Mac's switches and details are in **Settings** (v0.8.23: each card is a title and its state, with
explanations under *Details*): *Blocking* (ads and trackers, sync, YouTube Restricted Mode; the X/Bluesky
line under Details), *Turning Pax off* (turn-off wait, trial day, verified support release, and its Support ID while that is on),
*Accountability
partner email* (their email, one state line and *Change…*; the form is in a sheet), *Updates* (version, last
check, *Update now*; *About Pax* folded inside), *Pax Max* (folded, off by default: "Blurs pictures and video
in Firefox. Other browsers aren't covered yet.") and *Advanced* (filter and its backup state, the
*Extra family filter layer* switch, security notices, where the key is kept, server). Security
notices are plain sentences; a backup-filter episode shorter than 10 minutes (as when pax-guard restarts
after an update) stays in the tamper log but isn't shown.

**Blocked Sites / Apps** (v0.3; renamed in v0.8.21): once you have an account on this Mac (the token is
kept in the Keychain) or this Mac keeps its own key, the sidebar shows *Blocked Sites / Apps* (also
*Pax › Blocked Sites / Apps*, ⇧⌘B, and a card on Home). Since v0.8.21 the page starts with a calm line
saying which device it's about ("Blocking on Ruben's MacBook Air", or the selected iPhone's or iPad's
name) and how far blocks reach ("Sites: applies to all your devices." while sync is on or for the
account's list; "Sites: applies to this Mac only." while this Mac's sync is off; "Apps: this Mac only." /
"Apps: this iPhone only, chosen at set-up."), and it lists that device's apps under the sites. The sidebar
has no *Home* row any more (v0.8.21): the app opens on Home, and a device row, the Pax logo, the *‹ Home*
link on Settings and on this page, or *Pax › Home* (⇧⌘H) goes back to it. v0.7.0 adds
*Import list…* for pasted lists and .txt/.csv files.
Type a site and press *Block now*; it's added at once. *Remove* asks for confirmation, then shows the
removal under *Waiting* with a live 72-hour countdown and *Cancel*. Exceptions to the Family Filter
work the same way.

Branding (brand v2, v0.8.16) lives in `Sources/Pax/Theme.swift`: Mist `#F7F9FB` background, Navy
`#1E2A38` text and primary pill buttons, Dusk blue `#6E8BA8` accents (selection, status dots, links,
eyebrows), Haze `#C9D4DF` borders and subtle fills, White cards, Slate `#3B4654` body text, and a muted
red only for errors. A very subtle sky wash sits behind the window (dusk-blue tint `#DCE5EE` at the top,
Mist, faint peach `#F6EDE6` at the bottom) under white rounded cards (radius 18) with soft shadows.
Headings use Fraunces Soft (opsz 72, wght 420, SOFT 100), body and UI use Inter, and Playfair Display
Italic is the one accent word on the welcome screen. They're bundled as static, renamed OFL instances in
`mac-app/Resources/fonts` (licence: `OFL.txt` there), copied to `Pax.app/Contents/Resources/Fonts` by
`build-dmg.sh` and registered at launch; without them the app falls back to New York and SF Pro. The
stacked logo ("pax" with an italic "peace" tucked beside the lower p) and the app icon are in
`mac-app/Resources/branding` (`render_icons.py` rebuilds `AppIcon.iconset`/`AppIcon.icns`).
Dark mode keeps the same layout on deep navy `#121A24` with Mist text.

**Set-up modes**

* **Keep my data (default, iOS 17–27).** Supervises the phone in place. Apps, photos, messages and
  the Apple Account stay. Pax restores a tiny backup that holds one file,
  `CloudConfigurationDetails.plist` in `SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles`
  (`Library/ConfigurationProfiles/`), with `IsSupervised = true` and the Pax supervision certificate.

  | iOS on the iPhone | What Pax does |
  |---|---|
  | 17–26 | Restores the seed **with** system files, skipping apps, without a reboot (what `idevicebackup2 restore --system --skip-apps --no-reboot` did; the seed also marks Setup Assistant done), restarts the phone, re-pairs, verifies `IsSupervised`. |
  | 27.x | Apple's deployment guide says iOS 27 backups no longer carry supervision status, so the restored plist alone does nothing. Pax restores the seed **without** system files, skipping apps, removing items not in the seed, and lets the phone reboot (what `restore --skip-apps --remove --reboot` did; system files lost photos and signed out the Apple Account on iOS 27 in testing). The phone reboots into Setup. Pax re-pairs and, while the phone is still in Setup, sends `SetCloudConfiguration` to the lockdown service `com.apple.mobile.MCInstall` (retried every 2 s for up to 90 s), then reads it back with `GetCloudConfiguration`. |
  | 28 or later | **Refused.** Untested; Apple may change this again. Pax offers Clean set-up. |
  | older than 17, or unreadable | Refused, Clean set-up offered. |

  Both the app and the helper apply this gate, and the helper re-reads the version right before it
  writes to the phone.

  **Restore options (v0.8.6).** Up to v0.8.5 the restore ran libimobiledevice's `idevicebackup2`.
  Since v0.8.6 the helper sends the MobileBackup2 `Restore` request itself, through pymobiledevice3's
  Mobilebackup2 service (its DeviceLink, sync lock and message loop), with exactly the options
  `idevicebackup2` put in that request for the old flags (read from `tools/idevicebackup2.c`):

  | `idevicebackup2` flag | Restore option / host action | iOS 17–26 | iOS 27 |
  |---|---|---|---|
  | `--system` | `RestoreSystemFiles` (always sent) | `true` | `false` |
  | `--no-reboot` / `--reboot` | `RestoreShouldReboot` | `false` | **not sent** (the phone's default: reboot) |
  | no `--copy` | `RestoreDontCopyBackup` | `true` | `true` |
  | no `--settings` | `RestorePreserveSettings` | `true` | `true` |
  | `--remove` | `RemoveItemsNotRestored` (always sent) | `false` | `true` |
  | `--skip-apps` | host doesn't write `/iTunesRestore/RestoreApplications.plist` | skipped | skipped |
  | no `--password` | `Password` | not sent | not sent |

  `SourceIdentifier` and `TargetIdentifier` are both the phone's UDID, and like `idevicebackup2` the
  helper refuses a seed whose `Status.plist` doesn't say `finished`. pymobiledevice3's high-level
  `restore()` always sends `RestoreShouldReboot`, so Pax doesn't call it: on iOS 27 the key is left out,
  as it was in the tested runs. The mapping lives in `device/seed.py` (`restore_options`) and is pinned
  by tests. A developer can still run the real `idevicebackup2` with `PAX_IDEVICEBACKUP2`.

  **Preflight** (blocks the start until it passes): this Mac is trusted (paired); **Find My is off**
  (read over lockdown, `com.apple.fmip` › `IsAssociated`; if it can't be read the user confirms);
  **a backup exists and finished** (Pax makes a full MobileBackup2 backup with pymobiledevice3 into
  `~/Library/Application Support/Pax/Backups` and checks `Status.plist` says *finished*, or the user
  confirms a Finder/iCloud backup made today); **battery** at least 50 %, or at least 20 % while
  charging (`com.apple.mobile.battery`). It warns if the phone is already supervised or local backup
  encryption is on.

  **On the iPhone** (the app shows these while it waits): do nothing while the restore runs; it
  restarts by itself. "Press home to upgrade": press Home (or swipe up). Enter the passcode. If asked,
  tap **Trust** and enter the passcode. On iOS 27, if it shows **Restore Completed**, stay there and
  **don't tap Continue** until Pax says it's supervised; then tap Continue and finish the few setup
  screens (the Apple Account may ask for its password once). At the end, **turn Find My back on**.

  Re-pairing: the restore resets the phone's pairing, so Pax reconnects one attempt at a time. While
  the phone is missing or locked it retries every 2 s. Once a Trust prompt is showing it sends **no
  further Pair requests** until the user clicks "I tapped Trust" (a Pair sent while the passcode is
  being typed cancels the prompt).

  If the live step fails, "Try again" re-sends only the configuration (no second restore). If
  supervision can't be confirmed, Pax stops with nothing escrowed and nothing locked, and offers Clean.

  *Strict* (opt-in, untested): sets `AllowPairing = false`, so no other computer can pair with the
  phone afterwards. That also blocks using the same no-erase restore to unsupervise it, but Finder
  backups to any computer stop working.

* **Clean (fallback).** The official Apple Configurator path: `cfgutil backup` → `cfgutil erase`
  → (Hello screen) → `cfgutil prepare --supervised --name … --host-cert …` → verify
  `get isSupervised`. You then **set up fresh and sign back into iCloud**. The local backup stays on
  the Mac as a safety net. Restoring that backup afterwards is an experimental opt-in that usually
  removes supervision (Apple: a backup of an unsupervised device "can be restored only to an
  unsupervised device"; iOS 27 doesn't restore supervision from backups). The app checks
  `isSupervised` afterwards and stops if it was lost.

**Supervision identity.** The app creates one with `/usr/bin/openssl` (the recipe from the cfgutil
man page). In Keep my data its certificate goes into the phone's `SupervisorHostCertificates`, so the
profile installs **silently** (MCInstall `Escalate` + `InstallProfileSilent`). Then Pax **deletes the
private key**, as in v0.1. Anyone holding that key can manage the phone silently, which would give the
user a way around their own lock. attention awareness registers no supervisor certificate at all: its
profile arrives as a download and the user taps Install in Settings. That shows the key isn't needed
once set-up is done, so there's no reason to keep it. Pax uses the same manual install as its
fallback: if the phone won't take the certificate or the silent install fails, the profile is sent as
a download and the app asks the user to install it in Settings, then checks it's there. The catch is
unchanged: changing your blocks later means a removal (with the wait) and running set-up again.

## Build and open the DMG

We can't build macOS binaries in this repo's Linux tooling, so the DMG is built on a Mac or by GitHub.

**On your Mac** (building needs macOS 13+ with only the Command Line Tools, no Xcode or Apple account; the app it builds runs on macOS 12+):

```bash
xcode-select --install            # once, if `swift --version` doesn't work
cd pax-apple/mac-app
./scripts/build-dmg.sh            # UNIVERSAL=1 for Intel + Apple silicon
open dist/Pax-0.5.dmg             # drag Pax to Applications
```

The script runs `swift build -c release`, assembles `dist/Pax.app` (Info.plist, the icon if
`mac-app/Resources/AppIcon.icns` or a 1024 px `AppIcon.png` exists, and `make_profile.py`,
`pax_device.py` (since v0.8.6 with its own Python) and, since v0.4, `profile/mac_policies.py` and the `guard/`
files in `Contents/Resources`; v0.5 adds `Resources/lists` and `Resources/extensions/pax-image-blur.xpi`,
built by `extension/build.py`), signs it with the identity in `SIGN_IDENTITY` (hardened runtime and a
secure timestamp; see [Signing and notarisation](#signing-and-notarisation)), and makes
`dist/Pax-<version>.dmg` with `hdiutil` (Pax.app, an Applications shortcut and a read-me). Since
v0.8.6 it also bundles the iPhone helper's Python (`build-device-helper.sh`; downloads about 50 MB of
pinned archives and wheels the first time, `BUNDLE_DEVICE_HELPER=0` skips it) and signs every binary in
it before the app. Without
`SIGN_IDENTITY` a local build is signed ad hoc, which is only meant for testing on your own Mac.

**From GitHub**: every push (or *Actions › Build DMG › Run workflow*) runs
`.github/workflows/build-dmg.yml` on a macOS runner, builds a **universal** app (it checks `lipo -archs`
shows both arm64 and x86_64), signs it with the project's **Developer ID Application** certificate, has Apple
notarise it, staples the ticket, and attaches `Pax-<version>-universal-dmg` to the run. Whatever happens, the
last step force-pushes `build.log` and `status.txt` to the orphan **`ci-logs`** branch, so a failed build
can be read without opening Actions. The workflow first runs `find .. -name "*.sh" -exec chmod +x {} +`,
because pushing with the GitHub contents API drops exec bits (`ci.yml` does the same). GitHub
downloads it as a `.zip`; double-click to get the DMG.

**Opening it.** Pax is signed with a Developer ID and notarised by Apple, so a
downloaded DMG opens with the normal first-launch prompt and no Gatekeeper workaround. You can check
the signature with `spctl -a -vv /Applications/Pax.app` (it reports *Notarized Developer ID*).

**iPhone set-up needs no Terminal step.** Since v0.8.6 the device helper is inside Pax.app with its own
Python, so "Keep my data" works straight after plugging the iPhone in, with nothing to install (no
Python, Command Line Tools or Homebrew). The workflow checks that the signed helper runs from the app,
the DMG and the update zip. Clean set-up still needs Apple Configurator's `cfgutil`.

## Pax for Mac

"Protect this Mac" makes restricted sites effectively unreachable on the Mac you run Pax on, with the same
unlock model as the iPhone: an escrowed password, your turn-off wait, partner emails, the first-hour
grace period and the emergency release.

### What it does

1. **Preflight**: checks your password (`dscl . -authonly`), that you are an administrator and the
   *only* one (another admin would be a way around the wait, so Pax refuses), and reads FileVault's
   state. An old `paxadmin` from an earlier set-up only gets a warning (v0.8.29; see step 2). It asks you to save the FileVault recovery key outside
   the Mac and to have a backup.
2. **Creates `paxadmin`**, a hidden administrator with a random 32-character password generated on the
   Mac (`sysadminctl -addUser … -admin`, then `IsHidden 1`). A leftover `paxadmin` is deleted first
   (`sysadminctl -deleteUser` with your credentials, then `dscl . -delete`, rechecked for directory
   lag). v0.8.29: if macOS won't delete it, Pax reuses it: a new random password
   (`sysadminctl -resetPasswordFor` with your credentials, else `dscl . -passwd`), proven with
   `dscl . -authonly`, then made an administrator and hidden. If neither works, Pax stops with
   `PAX-MAC-004` and each command's result in Copy details.
3. **Gives it a SecureToken** (`sysadminctl -secureTokenOn`), so FileVault, updates and Recovery keep
   working. With FileVault on, a missing token stops everything.
4. **Verifies the password works** (`dscl . -authonly paxadmin …`). Nothing is escrowed or locked
   before this passes.
5. **Escrows it** (`POST /v1/devices`, platform `mac`), reads the device back, and gets a read-only
   guard token for pax-guard.
6. **Installs the profile.** macOS no longer installs profiles from the command line, so Pax opens it
   and System Settings; you click Install (General › Device Management, or Privacy & Security ›
   Profiles on older macOS). Pax checks it's really installed.
7. **Installs pax-guard** (`/Library/PaxGuard`, LaunchDaemon `org.paxpeace.pax-guard`) and runs one
   enforcement pass.
8. **Only then demotes you** (`dseditgroup -o edit -d <you> -t user admin`) and checks you're no longer
   in `admin`.

If any step fails, Pax undoes the finished steps newest first (re-promoting you with paxadmin if the
demotion already happened, then removing pax-guard and the profile, then deleting paxadmin, or, if
macOS keeps it, leaving it hidden with no admin rights and a forgotten password) and tells you where it
stopped. **Remove Pax** re-promotes you, checks you really are an administrator, removes pax-guard and
the profile, then deletes paxadmin with every route in one root shell (v0.8.29: before, a lone
`sysadminctl -deleteUser` could take paxadmin out of the admin group without deleting it). If macOS
still keeps it, Pax takes away its admin rights and says so; setting Pax up again reuses it. Root steps run through `osascript` (`do shell script … user name … password …
with administrator privileges`), with the script on stdin so your password isn't in any process's
arguments. The paxadmin password is never written to disk or logged.

**Profile** (`make_profile.py --self-lock`, System scope, no removal password: once you're Standard,
removing a System profile needs an administrator, and Apple's schema says a manually installed profile
with `PayloadRemovalDisallowed` and no removal password "requires admin auth"):

| Area | Setting |
|---|---|
| DNS | `com.apple.dnsSettings.managed`, DoH to CleanBrowsing Family (or your pax-dns URL with `PAX_DNS_BASE`) |
| iCloud Private Relay | `allowCloudPrivateRelay = false` (macOS 12+) |
| Chrome, Edge, Brave, Chromium | `DnsOverHttpsMode off`, `BuiltInDnsClientEnabled false` (use the macOS resolver, so the DNS profile and `/etc/hosts` apply), `ProxySettings {ProxyMode: direct}`, `ForceGoogleSafeSearch`, `ForceYouTubeRestrict 2`, `URLBlocklist` (`chrome://flags`, `chrome://net-internals`, `chrome://net-export`, `edge://…`), Edge `ForceBingSafeSearch 2`, Brave `TorDisabled` and `BraveVPNDisabled` |
| Extensions (Chromium) | `ExtensionInstallBlocklist ["*"]` (also disables already-installed extensions not allowed), `ExtensionInstallAllowlist` = the six password managers (v0.7.0; Edge gets their Edge Add-ons and Chrome Web Store IDs), `ExtensionAllowedTypes ["extension"]`, `ExtensionDeveloperModeSettings 1` (no developer mode, so no "Load unpacked"), `BlockExternalExtensions`, `ExtensionSettings` with `"*"` blocked and `blocked_permissions ["proxy", "vpnProvider"]` on every allowed extension |
| Firefox | `EnterprisePoliciesEnabled`, `DNSOverHTTPS {Enabled: false, Locked: true}`, `Proxy {Mode: none, Locked: true}`, `BlockAboutConfig`, `ExtensionSettings` with `"*"` blocked and the six password managers `"allowed"` (v0.7.0; Pax Image Blur force-installed only with Pax Max) |
| Ad blocking (default on) | System-wide only: HaGeZi Multi LIGHT in `/etc/hosts` via pax-guard (v0.6.1 dropped the uBlock extensions) |

Allowed extensions (v0.7.0, project decision: password managers only, nothing force-installed): 1Password,
Bitwarden, LastPass, Dashlane, Proton Pass and iCloud Passwords. Every Chrome Web Store, Edge Add-ons
and Firefox (AMO) ID was checked on the official store on 2026-10-15; the IDs and their source URLs
are in the `profile/mac_policies.py` docstring. Momentum (Chrome Web Store and Edge Add-ons) is allowed
again from v0.8.4; Video Speed Controller stays commented out. Key
names were checked against Chromium's policy definitions (`ProxyMode` is deprecated, so Pax uses
`ProxySettings`), Microsoft's Edge policy reference, Brave's Group Policy page and Mozilla's
policy-templates. Incognito, InPrivate, private windows and guest mode are **left on** on purpose:
the DNS filter, the hosts block and the locks still apply in them.

**pax-guard** (Python 3 from the Command Line Tools, standard library only, root, `KeepAlive`): every
30 s, and within 5 s of a network change:

* `/etc/hosts`: a marked block (`# BEGIN PAX` … `# END PAX`), rewritten only when it changes, your
  own lines left alone. Order: your synced blocklist (+ `www.`), DoH resolver names (built-in + HaGeZi's
  "Encrypted DNS servers" list, plus Firefox's `use-application-dns.net` canary and Private Relay's
  `mask.icloud.com` / `mask-h2.icloud.com` opt-out), then ads. CleanBrowsing's and your Pax server's
  host names are never blocked. Capped at 175,000 names.
* **Ads**: HaGeZi Multi LIGHT, legacy hosts build (GPL-3.0, about 147,000 names on 2026-10-14; HaGeZi
  says it "shouldn't cause any real restrictions"), downloaded at install and daily, rejected if it
  comes back under 10,000 names (the old copy is kept). An allow-list (`ADS_ALLOWLIST` in
  `guard/guard_config.py`, plus your Pax exceptions) is never blocked. Ad blocking off removes only the
  ad names.
* **pf** (anchor `com.apple/250.org.paxpeace.pax`, so `/etc/pf.conf` is never edited): blocks TCP/UDP
  853 everywhere; ports 53 and 443 to a curated list of public resolvers (Cloudflare, Google, Quad9,
  OpenDNS, AdGuard, NextDNS, ControlD, dns0 and others); port 53 to HaGeZi's ~1,400 DoH server IPs (not
  443, because some are shared cloud addresses); WireGuard 51820, OpenVPN 1194, IKE 500/4500, L2TP 1701,
  PPTP 1723. CleanBrowsing's addresses (and whatever your resolver's host name resolves to) are passed
  first, and so is plain DNS to whatever servers the current network hands out (even if that's
  1.1.1.1), because macOS needs them to reach the DoH server. Outbound only; normal browsing isn't
  touched.
* **Bypass apps**: VPN clients, Tor, and browsers Pax can't manage are killed and moved to
  `/Library/PaxGuard/quarantine` (root only), from `/Applications`, `~/Applications`, `~/Downloads` and
  `~/Desktop`, and any running copy anywhere (even from a mounted DMG) is killed. Matched by bundle ID
  (App Store IDs checked via Apple's lookup API) and by app name. Removing Pax puts them back.
  Connected VPN services (`scutil --nc list`) are disconnected.
* **Profile check**: if the Pax profile disappears, pax-guard logs it and shows a notification (hourly
  at most); hosts and pf protection carry on.
* After the password is released, pax-guard stops re-applying anything until Remove Pax runs.

**Browsers** (managed, blocked, or neither):

| Browser | How Pax handles it |
|---|---|
| Chrome, Edge, Brave, Chromium | managed by the profile (policy domains `com.google.Chrome`, `com.microsoft.Edge`, `com.brave.Browser`, `org.chromium.Chromium`) |
| Firefox | managed by the profile (`org.mozilla.firefox`) |
| Safari | not manageable by a profile you install yourself (Apple's Safari extension management is declarative device management for **supervised** Macs only); covered by DNS, `/etc/hosts`, Private Relay off and pax-guard. Safari web extensions have no proxy API |
| Opera, Opera GX/Air (built-in VPN), Vivaldi (built-in Proton VPN with no documented policy to disable it), Arc, Orion, SigmaOS, Zen, LibreWolf, Waterfox, Floorp, Epic, Yandex, Aloha, DuckDuckGo, Thorium, Tor Browser, Mullvad Browser, Chrome/Edge Beta/Dev/Canary, Brave Beta/Nightly, Firefox Developer Edition/Nightly | blocked: killed and quarantined by pax-guard |

### Test it on your Mac today (step by step)

Moved to [docs/MANUAL_TESTING.md](docs/MANUAL_TESTING.md).

### Remove Pax by hand (emergency)

With the released paxadmin password (or, on this local test, `server/scripts/local_reveal.py`), in
Terminal as yourself:

```bash
su paxadmin                                     # type the paxadmin password
sudo /Library/PaxGuard/bin/pax-uninstall-emergency.sh --user alex
exit
sudo sysadminctl -deleteUser paxadmin -adminUser "$USER" -adminPassword -   # you're an admin again
```

The script re-promotes you **first**, then stops pax-guard, removes the hosts block and the pf anchor,
puts quarantined apps back, removes the Pax profile(s) (or tells you to remove it in System Settings
if macOS refuses) and deletes `/Library/PaxGuard`.

**Local test break-glass**: while the server runs on this Mac with your key, you can always get the
password without the wait: `PAX_SERVER_KEY="$(cat ~/.pax-test-key)" python3
~/pax-apple/server/scripts/local_reveal.py --db ~/pax-test.sqlite3` (lists devices) then add
`--device <id>`. That's also why a local server is for testing only (see Known gaps).

**If the server, its database or the key is lost** (and you never revealed the password): start the
Mac in Recovery (Apple silicon: shut down, hold the power button until "Loading startup options",
choose Options). When asked for an administrator password, choose **Forgot all passwords?** and use
the **FileVault recovery key** (or your Apple Account, if you linked it) to reset `paxadmin`'s password.
Restart, log in as paxadmin, and run the emergency script above. Without FileVault, Recovery's Terminal
`resetpassword` does the same. This is why you saved the recovery key in step 0.

### Known gaps (honest)

* **Recovery mode is a way out.** Anyone with the FileVault recovery key (or the Apple Account linked
  to FileVault) can reset paxadmin's password from Recovery. Apple silicon Macs have no firmware
  password, so you can't lock Recovery. If you want this to hold against yourself, give the recovery
  key to your accountability partner rather than keeping it.
* **Erasing the Mac** (Recovery › Erase, or *Erase All Content and Settings*, which asks for an admin)
  removes Pax along with everything else. Target disk / share disk mode lets another Mac read the disk
  if FileVault is off.
* **A local test server isn't escrow.** With the server, database and `PAX_SERVER_KEY` on this Mac,
  you can read the password at any time. Real protection needs the server elsewhere.
* **Private browsing is allowed** (your choice). It's still filtered by DNS, hosts and the locks.
* **Safari and its extensions aren't managed** (needs a supervised Mac). Safari is still covered by
  DNS, hosts, Private Relay off and pax-guard.
* **Another user account**: you can't create one as a Standard user. The Guest account, if you turn
  it on, gets the same system-wide DNS, hosts and pf (but not paxadmin's rights).
* **Phone hotspot / other networks**: still filtered (the DNS profile and hosts are system-wide). A
  network that blocks DoH to CleanBrowsing leaves you with no DNS, never unfiltered DNS.
* **VPNs on unusual ports** (e.g. WireGuard on 443) and **web proxies** aren't caught by pf (v0.5 blocks
  the best-known proxies and HaGeZi's bypass list by name). pax-guard
  disconnects VPN services macOS knows about and quarantines known VPN apps; CleanBrowsing Family
  blocks many proxy and VPN domains; new or renamed apps can slip through until the lists catch up.
* **A hard-coded DoH server not on the lists** could still resolve around the filter for that app.
* **The paxadmin password passes through your Mac during set-up** (`sysadminctl` takes passwords as
  arguments for the moment it runs, visible to `ps`). You're an admin at that point anyway, so this
  only matters if you set out to copy it; the same applies to the iPhone flow.
* **pax-guard's runtime damaged and Pax.app gone**: it can't repair itself; the launcher falls back to
  `/usr/bin/python3` if present, else sites stop opening (never unfiltered).
* **Macs set up before 0.8.6** keep `ForceYouTubeRestrict` in Chrome/Edge/Brave until set up again.
* **`/etc/hosts` is large** with ad blocking on (~150,000 lines, ~6 MB). It's within what macOS
  handles, but if lookups ever feel slow, turn ad blocking off and tell us.
* **Removing the profile from the command line** isn't guaranteed on every macOS version; the uninstall
  script then tells you to remove it in System Settings (you're an admin again by then).
* **Untested on hardware**: none of this has run on a real Mac yet (v0.4 was written and unit-tested on
  Linux; the SwiftUI screens are parse-checked only). In particular, check on your Mac that Chrome shows
  the policies, that `/etc/hosts` is honoured while the DNS profile is active, and that pf loads the
  anchor. `pax-dns` doesn't have an "ads" category yet; ads are blocked on the Mac only.

## Pax Image Blur

A browser extension in `extension/` (GPL-3.0-only) that blurs restricted pictures and video frames on any
web page.

* **Blur first, then check.** `content.css` is injected at `document_start`, so every `<img>` and
  `<video>` is blurred before the page paints. As pictures come near the viewport the content script
  hands them to the extension's classifier: a **MobileNetV2** image model (Infinite Red, 224×224, MIT) on
  **TensorFlow.js** (WebGL, CPU fallback; Apache-2.0), both bundled. It runs in an offscreen document
  in Chrome and in the background page in Firefox. **No picture, frame or URL leaves the browser**;
  the extension has no server and sends nothing anywhere.
* **Switching it off (v0.8.12).** On a Mac set up with 0.8.12 (key on this Mac) the add-on is always installed
  in Firefox and asks the background (Firefox's `dns` API, at most every 20 s) whether Pax Max is off. It stops
  and leaves the page alone only when `pax-max-off.guard.paxpeace.com` answers exactly `127.80.77.0`, which
  pax-guard writes into its `/etc/hosts` block after the hour to turn Pax Max off. No answer, an error or any
  other address keeps it blurring. Chrome has no such API, so there it always blurs (and isn't installed yet).
* **Verdicts** (`extension/src/core.js`, deliberately cautious): *locked* if Restricted ≥ 0.5,
  RestrictedDrawn ≥ 0.6 or the two together ≥ 0.6; *veiled* if Borderline ≥ 0.5 or Restricted +
  RestrictedDrawn + Borderline ≥ 0.5; otherwise *safe*. (The model's classes go by neutral names in the
  code.) Safe pictures are un-blurred. **Veiled** ones, and anything Pax couldn't check (a cross-origin video
  the page won't let anyone read, a decode error), stay blurred until you **click** them (the click
  doesn't follow the link). **Locked pictures stay blurred with no way to reveal them**, and a video whose frame
  turns out restricted is re-blurred, paused and locked even if you'd revealed it. Videos are sampled
  about every 1.2 s while playing. Images under 48 px (icons) are left alone.
* **Allowlist** (toolbar button or the extension's options): on a listed site (and its subdomains)
  pictures aren't pre-blurred, but anything classified as restricted is still hidden. It's a local list
  with no wait, so it's for sites where the blur flash gets in the way (a photo editor, maps), not a
  way to switch the filter off.
* **Known gaps**: CSS background images, pictures drawn into `<canvas>`, and SVG aren't checked;
  Chrome-family browsers don't run any extension in Incognito unless you allow it on
  `chrome://extensions` (there's no policy to force it; Firefox's policy can, and Pax sets
  `private_browsing: true`); the model is about 90 % accurate (the model authors' own figure), so expect some
  false blurs and some misses; the first page after the browser starts waits a second or two for the
  model to load.

### Installing it on a protected Mac: what actually works

Researched 2026-10-14 against the policy texts and Chromium's source:

| Browser | Off-store force-install on an **unmanaged** Mac (profile installed by hand) | What Pax does |
|---|---|---|
| Chrome, Brave, Chromium | **No.** Chrome's `ExtensionInstallForcelist`: "On macOS instances, apps and extensions from outside the Chrome Web Store can only be force installed if the instance is managed via MDM, joined to a domain via MCX or enrolled in Chrome Enterprise Core." Chromium's `base/enterprise_util_mac.mm` decides "managed" from `profiles status -type enrollment` (MDM enrollment), which a hand-installed profile isn't. So a CRX served by pax-guard on localhost, or a `file://` update URL, is refused, and Pax's `ExtensionDeveloperModeSettings` lock rules out "Load unpacked". | **Chrome Web Store, unlisted** listing (only people with the link can find it, and policy force-install by ID works on any Mac). The listing isn't published yet, so its ID is empty: `BLUR_CHROME_WEBSTORE_ID = ""` in `profile/mac_policies.py`, or `PAX_BLUR_CHROME_ID` / `make_profile.py --blur-chrome-id` without editing code. Until then Chrome-family browsers get no blur (DNS, hosts and the other policies still apply). |
| Edge | **No**, same rule ("managed via MDM, or joined to a domain via MCX"). | Its own Edge Add-ons ID if one exists (`BLUR_EDGE_ADDONS_ID` / `PAX_BLUR_EDGE_ID`), otherwise the Chrome Web Store ID with the Web Store update URL. Whether Edge accepts a Web Store ID by policy on an unmanaged Mac is **unverified**. |
| Firefox | **Yes.** `ExtensionSettings` `install_url` may be a `file:///` URL. But release and beta Firefox only install add-ons **signed by Mozilla**; unsigned ones work only in Developer Edition, Nightly and ESR (which Pax quarantines or doesn't manage). | Force-installed from `file:///Library/PaxGuard/extensions/pax-image-blur.xpi`, which `pax-guard-install.sh` copies from the app, with `private_browsing: true` (Firefox 136+). Sign it once through AMO as **unlisted** (below) and the same file path keeps working. |

Not chosen: enrolling Chrome in **Chrome Enterprise Core** (free) would allow off-store installs, but
every Pax user's browser would be enrolled in an organisation someone runs, which is the opposite of
self-hosted. A real MDM is roadmap §3.

**Publish the unlisted Chrome Web Store item (not done yet).** Register a Chrome Web Store
developer account (one-time US$5 fee), run `python3 extension/build.py`, upload
`extension/dist/pax-image-blur-chrome.zip`, set *Visibility: Unlisted*, fill in the privacy form
("no data collected": the classifier is local) and submit. When it's approved, put the 32-letter item
ID in `BLUR_CHROME_WEBSTORE_ID` (or export `PAX_BLUR_CHROME_ID` before building/running Pax) and
regenerate the profile. Optionally do the same on Partner Center for Edge Add-ons.

**Sign the Firefox add-on (AMO unlisted, free).** Create an addons.mozilla.org account, create API
credentials (*Developer Hub › Manage API Keys*), then:

```bash
cd extension && python3 build.py
npx web-ext sign --channel=unlisted --source-dir dist/firefox \
  --api-key "$AMO_JWT_ISSUER" --api-secret "$AMO_JWT_SECRET" --artifacts-dir signed
mv signed/*.xpi signed/pax-image-blur-signed.xpi
```

`build-dmg.sh` bundles `extension/signed/pax-image-blur-signed.xpi` when it exists (the unsigned build
otherwise) and pax-guard installs it as `/Library/PaxGuard/extensions/pax-image-blur.xpi`. Unlisted
versions are checked automatically and usually signed within minutes; bump `version` in both
`extension/src/manifest.*.json` for each upload. The signed file is ~2.4 MB, so keep it out of the
contents-API upload and build the DMG locally, or sign in CI with the two keys as secrets.

**Try it before protecting the Mac.** `python3 extension/build.py`, then Chrome › `chrome://extensions`
› Developer mode › *Load unpacked* › `extension/dist/chrome`, or Firefox › `about:debugging` › *This
Firefox* › *Load Temporary Add-on* › `extension/dist/firefox/manifest.json`. (Once the Mac is
protected, developer mode is blocked by policy on purpose.) Tests: `cd extension && npm install &&
npm test` (core logic always; the content script in jsdom when jsdom is installed).

**Repository size.** The TensorFlow.js bundle (1.6 MB) and the model (2.6 MB weights, 118 KB
topology) are stored gzipped in parts under 85 KB (`extension/src/**/*.gz.part-NNN`) so no file in the
repo is over ~90 KB; `build.py` joins them and checks `src/SHA256SUMS`. `scripts/update-vendor.sh`
rebuilds them (Node, pinned versions in `package.json`).

## Cloud PCs and remote desktop

A remote computer or remote browser shows you pages Pax never sees, so v0.5 blocks the services that
provide them, in two categories (the lists are `pax-dns/lists/*.txt`; every name was checked to resolve
on 2026-10-14):

| Category | What | Default | Turning it off |
|---|---|---|---|
| **bypass** | Consumer cloud PCs (SensePC, Shadow, Paperspace, Mighty, Neverinstall, Vagon, airgpu, Maximum Settings, Apporto, V2 Cloud), browser isolation and in-browser browsers (Browserling, Hyperbeam, RollApp, Puffin, Turbo.net, Browserbase, Browserless, Steel, SquareX…), cross-browser testing clouds (BrowserStack, LambdaTest, Sauce Labs, TestingBot), WebVM, and the best-known web proxies (CroxyProxy, BlockAway, ProxySite, Hidester, KProxy…) | on | **never** (an exception for one site still works, after its 72 h wait) |
| **remote desktop** | Chrome Remote Desktop, AnyDesk, TeamViewer, Parsec, RustDesk's public servers, Splashtop, Windows 365, Azure Virtual Desktop, Quick Assist, Amazon WorkSpaces and WorkSpaces Secure Browser, RealVNC, LogMeIn/GoToMyPC, Zoho Assist, Supremo, DWService, NoMachine, Jump Desktop, ScreenConnect, Remote Utilities, HopToDesk, Getscreen.me, Iperius, Ammyy, UltraViewer, remote.it | **on** | Blocked sites › *Block remote desktop* off: waits the blocklist delay (72 h), shows a countdown with Cancel, emails your partner. Back on is instant. |

Enterprise virtual desktops (Windows 365, AVD, Amazon WorkSpaces) are in *remote desktop*, not
*bypass*, because people use them for work; that's the one deliberate move from the brief.

Where it's enforced:

* **pax-dns**: both lists are built-in categories (`PAX_DNS_BYPASS_FILE`, `PAX_DNS_REMOTE_DESKTOP_FILE`,
  default the shipped files, reloaded when they change); each entry blocks the domain and every
  subdomain; the per-user switch arrives in the change feed. `scripts/load_lists.py` now adds HaGeZi's
  DoH/VPN/Tor/Proxy bypass list by default and drops any entry that would cover Pax's own resolver
  names (HaGeZi lists `cleanbrowsing.org`).
* **pax-guard** (Mac): each entry and `www.` go into `/etc/hosts`, plus the listed fixed host names
  (TeamViewer's masters, Parsec's API hosts…), plus HaGeZi's bypass list (apex names only), ahead of
  the ad list (cap raised to 200,000 names). While *remote desktop* is on, pf also blocks outbound TCP
  3389, 5900, 5938, 7070, 4000 and 21115–21119 and UDP 3389, 4000, 21116 (RDP, VNC/Screen Sharing,
  TeamViewer, AnyDesk, NoMachine, RustDesk), which catches connections typed as an IP address.
* **Browsers**: the *bypass* list is also in Chrome/Edge/Brave `URLBlocklist` and Firefox
  `WebsiteFilter` (remote desktop isn't, because the profile can't change when you switch it off).

Limits: `/etc/hosts` only matches exact names, so on the Mac relays on unlisted subdomains (AnyDesk,
TeamViewer routers) are caught only by pax-dns (when the Mac's DNS profile points at your pax-dns) or
the ports; self-hosted RustDesk, Moonlight/Sunshine or RDP on a non-standard port can't be blocked by
name; Parsec's UDP range is shared with other software and is left alone; and Google Translate's page
proxy (`translate.goog`) can't be blocked without breaking Translate.

## Virtual machines

A virtual machine is a second computer with its own DNS and browsers and none of Pax's policies, so
pax-guard treats VM apps like VPN clients: killed and moved to `/Library/PaxGuard/quarantine`, put back
when Pax is removed. Listed in `guard/guard_config.py` (`VM_APPS`): UTM (`com.utmapp.UTM`, App Store ID
checked), Parallels Desktop (`com.parallels.desktop.appstore` checked, and the direct download),
VMware Fusion, VirtualBox, virtualOS (`com.github.yep.ios.virtualOS`, checked), VirtualBuddy, Tart
(including Homebrew's `tart.app`), Veertu/Anka and QEMU front-ends (QEMU, QtEMU, AQEMU, Qemu Manager).
Any process whose executable is `qemu-system-*` is killed wherever it lives. That also stops Lima,
Colima or Podman machines that use the QEMU backend; Docker Desktop and OrbStack (Apple's
Virtualization framework) aren't touched. Quit your VMs before protecting the Mac.

## Share a build with a tester

What someone else needs to run your DMG on their Mac:

1. **The DMG** from *Actions › Build DMG* (universal, so Apple silicon or Intel, macOS 12 Monterey or later).
2. **Nothing for Gatekeeper.** Builds from the workflow are signed with a Developer ID
   and notarised, so Pax opens like any downloaded app.
3. **A Pax server.** By default the app uses Pax's own server, `https://api.paxpeace.com/`, so
   there's nothing to set up. To self-host instead, run `server/` on their own Mac (Set-up › Server)
   or host one: any Linux box or PaaS with Python 3.12, `PAX_SERVER_KEY` set and backed up, behind
   HTTPS (Caddy is the easiest). Then in Pax: **Settings** (in the sidebar, or Pax › Settings… ⌘,) › Advanced › type
   `https://your-server/` (or `http://127.0.0.1:8080/` for one on this Mac) › *Test* › *Save* › quit
   and reopen Pax.
   Plain `http://` is accepted only for this Mac and private networks (`192.168.x.x`, `10.x`,
   `*.local`), because the escrowed password travels in the request. The address can't be changed while
   that Mac is protected (its password and pax-guard's token live on the current server). Each server
   keeps its own sign-in in the Keychain. `PAX_SERVER_URL` still overrides the setting for developers.
4. For *Protect this Mac*: nothing (v0.8.6). An unsigned build of your own still needs the Command
   Line Tools for pax-guard.
5. For an iPhone or iPad (*Keep my data*): nothing. The helper is bundled (v0.8.6), no Terminal step.

### Signing and notarisation

Pax is signed with a **Developer ID Application** certificate and notarised by Apple. The Build DMG
workflow does it on every push when the signing secrets are present:

1. It imports the Developer ID certificate (`MACOS_CERT_P12`, `MACOS_CERT_PASSWORD`) into a temporary
   keychain and stores notary credentials there (`APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`).
2. `build-dmg.sh` signs the app with the hardened runtime and a secure timestamp, submits it with
   `notarytool --wait`, staples it, then signs, notarises and staples the DMG and runs `spctl`.
3. *Check the bundle* verifies the signature (`codesign --verify --deep --strict`) and that the app is
   universal.

The secrets live only in the repository's Actions settings; nothing secret is in the repo. On a tag
`v*` the workflow also signs the update manifest (Ed25519, `PAX_UPDATE_SIGNING_KEY`) and publishes the
release ([docs/UPDATES.md](docs/UPDATES.md)).

To sign a build on your own Mac with your own certificate:
`SIGN_IDENTITY="Developer ID Application: <name> (<team ID>)" NOTARY_PROFILE=<notarytool profile> UNIVERSAL=1 ./scripts/build-dmg.sh`.
Without `SIGN_IDENTITY` the script signs ad hoc, which is fine for testing on that Mac only.

## Testing on a cloud Mac or a Mac with another admin (v0.5.1)

Rented cloud Macs (and work Macs) often have a hidden admin account that belongs to the provider, such as `rmsvc`. Pax normally refuses to set up there, because that account could undo Pax without the wait. Don't delete it: you could lose access to the machine. To test every other feature, turn on test mode before you click Check:

```bash
defaults write org.paxmobile.pax pax.testing.allowExtraAdmins -bool true
# back to normal:
defaults delete org.paxmobile.pax pax.testing.allowExtraAdmins
```

Pax then shows a warning instead of an error and goes ahead. Filtering, ad blocking, bypass and VM blocking all behave normally. Only the wait is meaningless, because the other admin can remove Pax.

Pax's remote-desktop block is outbound only (pf `block drop out`), so your incoming VNC or Screen Sharing session to the cloud Mac keeps working. If the provider connects with its own agent app, check that the agent isn't on the remote-desktop list before you turn that category on.

## Test v0.5 on your Mac (step by step)

Moved to [docs/MANUAL_TESTING.md](docs/MANUAL_TESTING.md).

## How removal works

| Action | Effect |
|---|---|
| Request removal | Starts your current turn-off wait (none in the trial day or, without one, the first hour). Your partner is emailed first: if that email can't be sent, nothing starts (`PAX-ESCROW-010`). You get a copy when the daily email budget allows. |
| Cancel | Ends the request. Your partner is emailed. |
| Confirm (after the timer) | You must send `confirm: true`. The password is released and the device is marked released. Your partner is emailed. Asking again within the reveal window returns the same password. |
| Don't confirm within 7 days | The request lapses, and a new one starts the full wait again. |
| Don't confirm a grace-period request within the first hour | It lapses when the hour ends (v0.8.5); a new request takes the full wait. |
| Trial day (v0.8.18) | New set-ups only: 24 h in which a removal or emergency needs no wait (partner still emailed first) and turning on verified support release is instant. A request made in it lapses when the day ends. |
| Start my wait now (v0.8.18) | Ends the trial day at once; a no-wait request made in it lapses. Instant, no email (it's stricter). |
| Lengthen the turn-off wait | Takes effect immediately. |
| Shorten the turn-off wait | Takes effect only after your *current* wait has passed. Your partner is emailed. Requests already open keep the wait they started with. |
| Add first partner | Takes effect immediately (more accountability is never delayed). |
| Change or remove partner | Takes effect after the current wait. The current partner is emailed and keeps getting notifications until then. |
| Emergency release | Needs a reason. It's logged, unlocks after 24 h (configurable), and you can use it once every 90 days. The auto-reply includes Samaritans **116 123** (UK & Ireland) and **988** (US). Your partner is emailed. |
| Verified support code (v0.8.15) | Only when Pax support has checked a genuine emergency. The code names one device (its Support ID), works once and expires within 24 hours. The device must have **Allow verified support release** on. Your partner is emailed first; if that fails, nothing is released (`PAX-ESCROW-018`). Then the password is released at once. |
| Allow verified support release: off | Takes effect immediately. Every code is refused (`PAX-ESCROW-017`). |
| Allow verified support release: on | Takes effect after your current wait (instantly during the trial day). Your partner is emailed first (`PAX-ESCROW-010` if they can't be). |

Nothing needs a human at Pax to approve it. Removing the profile itself happens on the phone:
Settings › General › VPN & Device Management › Pax › Remove Profile, then enter the password.

## Ads and trackers (v0.8.7)

*Ads and trackers* (HaGeZi Multi LIGHT in `/etc/hosts`) is chosen at set-up and can be switched on Home.

* **Mac, own key (default):** the switch goes to pax-guard (`settings.set {"adblock": bool}`), which keeps it
  in `/Library/PaxGuard/state/settings.json` and rewrites `/etc/hosts` straight away. Both directions are
  immediate, with no wait and no partner email, and each change is a `setting:adblock` line in the tamper
  log. Turning it on with no list downloaded yet fetches one in the background.
* **Mac, key on a Pax server:** the switch is the server's account setting; pax-guard reads it within a
  minute and fetches a fresh ad list on the next check if the one it has is old.
* **iPhone/iPad:** no ad blocking yet.
* **Restricted content never depends on it.** The ad list contains some restricted names (adult ad
  servers). Those go into `/etc/hosts` with the restricted categories, ahead of everything you can switch
  off, and stay there with ads off; exceptions and the ad allow-list never free them. The forwarder's own
  lists and CleanBrowsing Family are untouched by the switch.

## Blocked apps (v0.8.7)

**iPhone and iPad (set-up only).** In *Choose what to block*, the *Apps* card opens a list of the
plugged-in phone's own apps (read with the bundled helper: `pax_device.py apps --udid U [--icons-dir D]`),
with search and a field for an app ID such as `com.example.app`. The apps go into the profile's
`blockedAppBundleIDs` with Pax's own list. Because the supervision key is deleted after set-up, the list
can only change by setting the phone up again, and the app says so. Up to 200 of your own; apps Pax
already blocks don't count.

**Mac.** Click *This Mac* in the sidebar › *Blocked apps* › *Add app…* lists Applications and ~/Applications.
pax-guard reads the app itself (as root): bundle ID, and the identifier and Team ID sealed in its code
signature. A watcher looks at running programs every 2 seconds; a blocked app is closed and its bundle is
moved into pax-guard's root-only quarantine wherever it ran from. That catches a renamed app, a copy in
another folder, and a copy whose Info.plist was edited. *Unblock…* is a loosening: it waits like
unblocking a site (your wait, partner emailed first, nothing starts if they can't be told), can be
cancelled, and puts the app back where it was when the wait ends.

Never blocked, on either platform: Pax, Apple's own apps (`com.apple.*`, /System, Apple-signed), and
password managers (1Password, Bitwarden, LastPass, Dashlane, Proton Pass, KeePass apps, Strongbox, Enpass,
Keeper, NordPass, RoboForm).

Why close-and-quarantine rather than something stronger: Apple's Endpoint Security framework can refuse a
launch outright, but it needs an Apple-granted entitlement, a system extension and Full Disk Access; the
profile's legacy app restrictions block by path (renaming defeats them) and couldn't change after set-up.
Known limits: a blocked app can run for up to about 2 seconds before it is closed, and a copy re-signed under
a new identifier with its program renamed isn't recognised. Blocked apps need the Mac to keep its own key.

## Blocked sites (synced blocklist)

One list per Pax account, on top of Pax's own lists and the Family Filter. iPhones and iPads set up with
Pax's filter (0.8.8+) read it through `dns.paxpeace.com`; a Mac on its own key keeps a synced copy in
pax-guard (v0.8.9, on by default; see [docs/SYNC.md](docs/SYNC.md)).

| Action | Effect |
|---|---|
| Add a site (any device) | **Immediate** on that device; on the others within seconds (Mac: about 15 s). Covers every subdomain. Also drops an exception for that exact domain and cancels a pending removal of it. |
| Remove a site | A **request**: your partner is emailed first (if that fails, nothing starts), then the site stays blocked for the wait (by default your own wait; `PAX_BLOCKLIST_DELAY`), shown with a countdown, cancellable from any device. |
| Ask for an exception | A request with the same wait, cancellable, partner emailed. Refused for restricted sites (PAX-DNS-010). Exceptions stay per device on a Mac with its own key. |
| Remove an exception | Immediate. |
| Rotate your DNS token (if it leaked) | New token at once; the old one keeps working for the wait. Partner emailed. |
| Sync off (Mac) | Immediate, logged. Nothing is unblocked; the Mac's copy and the account's list go their own way. On again merges them (union). |

Domains are normalised before they're stored: scheme, path, port and user info are stripped, `*.` is
dropped (subdomains are always included), the name is lower-cased and converted to IDNA/punycode
(`bücher.de` → `xn--bcher-kva.de`). IP addresses, wildcards elsewhere, single labels, TLDs and common
public suffixes (`co.uk`, `github.io`, …) are refused. Up to 2,000 blocked sites and 500 exceptions per
account.

## Profile contents and supervision

Every key below was checked against Apple's schema repo (github.com/apple/device-management, branch
`release`, commit `09f249a`, 2026-09-17). The test-suite re-checks every key and type the generator
emits against the vendored YAML.

| Payload / key | Value | Needs supervision (iOS)? |
|---|---|---|
| Top-level `PayloadRemovalDisallowed` | true | **Yes** |
| `com.apple.profileRemovalPassword` › `RemovalPassword` | random, ~148 bits | **Yes** (payload is supervised-only on iOS; not on macOS) |
| `com.apple.dnsSettings.managed` › `DNSSettings` (`DNSProtocol` HTTPS, `ServerURL`) | CleanBrowsing Family Filter DoH (default; Core or custom optional) | No (iOS 14+) |
| `com.apple.dnsSettings.managed` › `ProhibitDisablement` | true | **Yes** |
| `com.apple.applicationaccess` › `allowEraseContentAndSettings` | false | **Yes** |
| `com.apple.applicationaccess` › `allowVPNCreation` | false | **Yes** (on iOS 18+ also blocks unmanaged apps creating VPN configs) |
| `com.apple.applicationaccess` › `allowCloudPrivateRelay` | false | **Yes** (iOS 15+) |
| `com.apple.applicationaccess` › `allowUIConfigurationProfileInstallation` | false | **Yes** |
| `com.apple.applicationaccess` › `blockedAppBundleIDs` | bypass apps + remote AI apps (ChatGPT, Manus; v0.8.1) + custom | **Yes** (iOS 15+, marked deprecated in 27) |
| `com.apple.applicationaccess` › `blacklistedAppBundleIDs` | same list | **Yes** (iOS 9.3–14, deprecated 15; emitted for older devices) |
| `com.apple.webcontent-filter` › `FilterType` BuiltIn, `AutoFilterEnabled` true, `DenyListURLs` | Apple's automatic filter + custom sites + media converters + remote AI browsers + fallback list with `--user-token` (≤500) | No on iOS 16+ only with `ContentFilterUUID`, which Pax deliberately leaves out because it would limit the filter to managed apps |

iCloud Private Relay is turned off with **`allowCloudPrivateRelay`** in the restrictions payload.
There's no separate payload for it.

DNS resolver (default since v0.2): **CleanBrowsing Family Filter**,
`https://doh.cleanbrowsing.org/doh/family-filter/` (checked on cleanbrowsing.org/filters on
2026-10-12). It blocks restricted content, proxy/VPN domains and mixed-content sites such as Reddit
(fully blocked), and forces SafeSearch on Google, Bing and YouTube. `--filter core` uses CleanBrowsing's
narrower filter (its address is kept encoded in `common/pax_restricted.py`), which leaves Reddit and VPN/proxy domains reachable. `--resolver-url`
uses a self-hosted Pax DNS or any https DoH resolver instead, and `--user-token` uses your own
pax-dns path (v0.3).

## What is untested (v0.3)

* **The DMG has not been built on a Mac.** `build-dmg.sh` passes shellcheck and the workflow passes
  actionlint, but neither has run on macOS. The SwiftUI screens (including Blocked sites) were only
  parse-checked on Linux; `BlocklistModel` and all of PaxCore were type-checked and the PaxCore XCTests
  run there. Expect small compile fixes on the first `swift build`.
* **pax-dns has not run on a real iPhone or behind a real HTTPS proxy.** Its RFC 8484 handling is unit
  tested against the RFC's own example message, and one live smoke test against CleanBrowsing worked
  (example.com resolved; a blocked restricted site and reddit.com came back NXDOMAIN).
* Whether iOS accepts a `ServerURL` with a path segment per user (it should: the DoH URL is opaque to
  iOS) and how quickly iOS's own DNS cache honours the 60 s block TTL.

## What is untested on hardware (v0.8.6 helper)

* **The bundled helper has not touched an iPhone.** CI proves it starts, imports everything and lists
  devices from the signed, notarised app on Apple silicon and (through Rosetta) Intel, but no real
  restore has run through it.
* **The restore engine changed.** The options are the same as `idevicebackup2`'s, key for key, but
  the transport is now pymobiledevice3's DeviceLink. The first hardware test should cover iOS 27 *and*
  an iOS 17–26 phone, with the same checks as before (data, photos and Apple Account kept). If the
  restore misbehaves, the same test can be repeated with `PAX_IDEVICEBACKUP2` pointing at a Homebrew
  `idevicebackup2` to tell a transport problem from a method problem.
* **The safety backup** is now pymobiledevice3's MobileBackup2 backup, not `idevicebackup2 backup
  --full`. Check it finishes on a full phone and on one with encrypted backups (the phone asks for its
  passcode).

## What is untested on hardware (v0.2)

No iPhone or Mac was available while building v0.2. Unit tests cover the logic (version gate, cloud
configuration, seed bytes, restore arguments, preflight, helper calls, profile filter) but not a real
phone. Before release, test on real devices:

* **The whole Keep-my-data path in Pax**: the helper, the seed it writes, re-pairing, the live
  `SetCloudConfiguration` and verification. The *method* was tested by attention awareness on **one
  iPhone SE (2nd gen) on iOS 27.2** (data, photos and Apple Account kept). Pax's implementation is
  independent and has not run on a phone.
* **iOS 17–26 path in Pax.** attention awareness reports supervising iPhones on iOS 26 this way (an
  iPhone SE on 26.6.2, then the owner's iPhone in a retest). Versions down to 17 are untested.
* **Other iPhone models, iOS 27.0.x/27.1, and iPads.**
* **Registering the Pax certificate (`SupervisorHostCertificates`) through the iOS 27 live step.**
  attention awareness's tested dictionary had no supervisor certificate. Pax adds one for silent
  install. If the phone keeps rejecting it for half of the 90-second retry window, Pax falls back to
  the tested shape (no certificate).
  It then installs the profile manually through Settings.
* **Silent install with pymobiledevice3** (`Escalate` + `InstallProfileSilent`) on a phone supervised
  this way.
* `--remove` (removes items the seed doesn't contain) is what kept data on iOS 27.2 in testing.
  It sounds alarming and is only safe because the seed restores one domain. Never change the seed's
  contents without retesting.
* Strict mode (`AllowPairing = false`), the pairing behaviour after the restart, and encrypted-backup
  phones.
* Clean mode's cfgutil JSON shapes (as in v0.1).

**iOS 28 risk.** Apple already closed one no-erase route in iOS 27, and the profile payloads Pax
uses are deprecated in the iOS 27 schema. Expect iOS 28 to break Keep my data, the payloads or both.
Pax refuses Keep my data on iOS 28+ until someone tests it. Clean set-up and the profile still work
until Apple stops honouring manual profiles. Plan for a small DDM/MDM component (roadmap §3).

## Limitations (please read)

* **A Mac keeps the browser rules from the version it was set up with** (v0.8.14 finding). The Pax
  profile is a device profile, and macOS lets only an administrator install or replace one; the
  administrator password is kept behind your wait, so pax-guard can't refresh the profile, and neither
  can you without the wait. Updates change everything else, not the profile. The only effect today: an
  extension allowed after your set-up (Momentum since 0.8.4) shows as "blocked by your administrator" in
  Chrome. pax-guard notices this (status `browser_rules`) and Home says so; nothing is weaker. It updates
  the next time Pax is set up.

* **Apple can change supervision.** Everything depends on Apple Configurator supervision and on
  profile payloads Apple controls. In the iOS 27 schema, `com.apple.dnsSettings.managed` and
  `blockedAppBundleIDs` are marked **deprecated** in favour of declarative device management, which
  needs an MDM server. They still work today, but they could stop working in a future release. Pax
  would then need a small DDM/MDM component. See the roadmap.
* **The no-erase trick works both ways.** With Find My off and a trusted computer, the same kind of
  restore can be used to *un*supervise a phone (attention awareness tested exactly this in their
  debug build). That would make the removal password unenforceable. Find My must be off for it
  (which needs the Apple Account password), and strict mode blocks it by refusing new computer
  pairings. It's a real way around Pax for a determined user, like the recovery restore below.
* **A Finder/recovery restore always wins.** Blocking Erase All Content and Settings only covers the
  on-device menu. Anyone with a computer can put the phone in recovery mode and restore it. That
  wipes it and removes Pax (and their data). Every supervision-based tool has the same limitation.
* **DNS filtering has limits.** It blocks domains, not individual images. It can't see inside apps
  that use their own DNS, hard-coded IPs or tunnelled traffic (in-app browsers mostly use system
  DNS). It also can't filter content on mixed sites like Reddit or X while those stay reachable (see
  roadmap). Apple's built-in filter only covers WebKit (Safari and in-app web views), and sometimes
  blocks harmless pages.
* **The free CleanBrowsing tier** is described as being "for parents, not organizations" and is
  throttled. A public Pax service should self-host DNS or arrange a paid plan.
* **During set-up the password passes through the user's own Mac** (in memory, plus temp files that
  are deleted at once). Someone set on keeping a copy could do it with a debugger. Server-side
  profile generation (roadmap) narrows this. The same is true of any tool that installs the profile
  from the user's machine.
* **The macOS DNS-only profile is weak** (the one made with `--macos` for the set-up Mac): an admin can
  remove it. Pax for Mac (v0.4) fixes that with standard-user demotion; its own limits are listed in
  [Pax for Mac › Known gaps](#known-gaps-honest).
* **cfgutil details not yet tested on hardware** (Clean mode): the exact JSON shape of `cfgutil list` and
  `get configurationProfiles`, and whether newer Configurator builds renamed any `prepare --skip-*`
  flags. Check with `cfgutil help prepare` before release.
* **No email verification yet.** Accounts are email plus bearer token. Production needs magic-link
  verification. (The Mac app now keeps the token in the Keychain.)
* **Synced blocks depend on pax-dns being up.** iOS has no fallback DoH server: if
  `dns.paxmobile.org` is down, the phone can't resolve anything. Run at least two instances behind a
  load balancer before switching users to it. The built-in fallback deny-list only covers Safari and
  web views.
* **Per-user DNS identifies the user to the DNS server.** pax-dns logs no queries by default, but
  whoever runs it could. Self-hosters control this; a public Pax service needs a clear policy.
* **The token is visible to anyone who can read the profile** (Settings shows the DNS server URL).
  With it someone could probe which domains you block. It can't change your list. Rotate it if needed.

## Usage numbers (v0.8.24)

Pax's server keeps totals only: accounts, devices, how many were active each day, which version
Macs run, and how many DNS lookups were answered. Per device it keeps just its kind, the last day it
was active and its Pax version; never an IP address, a time of day, a name or a site. Only the
operator can read them (`/v1/stats` with a key; 404 for everyone else). Details:
[docs/USAGE_STATS.md](docs/USAGE_STATS.md).

## Licence

GPL-3.0-only (see `LICENSE`). `profile/apple-schema/` is Apple's MIT-licensed schema data (see its
`LICENSE.txt`). Credits for the Keep-my-data method and the ported MIT code, plus the runtime
dependencies' licences, are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
