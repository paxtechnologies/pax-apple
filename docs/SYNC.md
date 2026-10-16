# Blocked sites across devices (v0.8.9)

One blocked-sites list per Pax account, shared by the Mac and every iPhone and iPad, **on by default**,
with one switch to keep the lists separate.

## Where the list lives

| Device | Reads the list | Adds | Removes |
|---|---|---|---|
| iPhone / iPad (Pax's filter, 0.8.8+) | `dns.paxpeace.com` asks the account list on every query | instant | the one removal rule |
| Mac on the Pax server (server escrow) | pax-guard reads `/v1/guard/config` every cycle | instant | the one removal rule |
| Mac with its own key (local escrow, the default) | pax-guard keeps a copy and syncs it (`guard/list_sync.py`) | instant here, pushed at once | the one removal rule, on the server |

The second DNS server (`pax-dns2`, `PAX_ROLE=dns`) replicates the account lists from the primary's change
feed as before; a site the Mac pushes is in that feed like any other.

## Linking the Mac and the iPhone(s) to one account

* **Common case, no extra step.** The Pax app on a Mac holds one account sign-in per server (Keychain). It
  is made the first time an iPhone or iPad is set up from that Mac (or when partner emails go through Pax's
  server). Whenever the app has a sign-in and this Mac's pax-guard (own key) is protected, sync is on and
  not yet linked, it asks the server for a **sync token** (`POST /v1/sync/links`) and hands it to
  pax-guard over the local socket (`sync.link`). Union on link: the Mac's sites go to the account and the
  account's come to the Mac.
* **Same email on another Mac.** Registering an email that already has an account answers 409 with
  `sign_in: true`. The app then sends a one-time code to that email (`POST /v1/accounts/signin/start`,
  same answer for any address) and, with the code, gets its own sign-in to that account
  (`POST /v1/accounts/signin`; 6 digits, 15 minutes, 5 tries, 5 codes an hour). The account holder is
  emailed when a device signs in.
* A **sync token** (`pxs_…`, stored hashed) can only read the account's blocked sites, add to them, ask
  to remove one and cancel. It can't reveal a password, change the wait or the partner, or touch
  exceptions. pax-guard keeps it in `/Library/PaxGuard/state/sync.json` (root, 0600) and never logs or
  returns it.

## Rules

* **Adding** a site anywhere is instant on that device. A Mac pushes within a second or two of the add
  and pulls every 15 seconds (`SYNC_INTERVAL`); Pax's filter applies account changes at once.
* **Removing** a site from the synced list goes through **one rule** wherever it's asked for: the
  partner is emailed first (the account's partner and any partner a linked Mac reports); if that email
  can't be sent nothing starts (HTTP 503, PAX-ESCROW-010). Then the wait, cancellable from any device.
* **The wait is one server setting**, `PAX_BLOCKLIST_DELAY`:
  * `wait` (**default**, the Mac's existing behaviour): the user's own wait. With a Mac linked, the
    longest of the account's wait and the linked Macs' waits (each Mac reports its own), within 24 h to
    365 days.
  * `fixed`: `PAX_BLOCKLIST_DELAY_SECONDS` (72 h), the server's rule before 0.8.9.
  The same delay applies to the server's other loosenings (exceptions, category switches,
  DNS token rotation), so there is one number.
* **Fail closed.** A site leaves a Mac's copy only when the server reports the removal *took effect*
  (`removed`, after the wait), since sync was last switched on, and the site wasn't added on the Mac again
  since. A site that's just missing from the server's answer (new account, database restored, outage) is
  pushed back. Offline: the Mac enforces its last list plus local additions, queues the additions, and
  refuses to start a removal (PAX-DNS-013).
* **Switch off** (Home › Sync blocked sites across devices): immediate, written to the tamper log, no
  partner email (it can't unblock anything). Each device keeps its current list and they diverge.
  **Switch on**: union merge, no removals; removals that took effect while it was off don't reach the Mac.
* **Restricted sites** can't be allowed (PAX-DNS-010), with or without sync. Exceptions stay per device
  on a Mac with its own key.

## Wait times (v0.8.9)

One range everywhere: **24 hours to 365 days** (server `min_wait_seconds`/`max_wait_seconds`,
`guard/local_escrow.py` `MIN_WAIT`/`MAX_WAIT`; a test checks they agree). `/v1/health` reports
`wait_limits`, and the app's wait picker only offers values the path in use accepts (an older server
without `wait_limits` is treated as 3 days minimum). A shorter wait still waits out the current one and
emails the partner first.

## API

| Call | Auth | |
|---|---|---|
| `POST /v1/sync/links` `{device_name}` | account | 201 `{link_id, sync_token, account_email}` |
| `GET /v1/sync/links` | account | linked Macs |
| `POST /v1/sync` `{add[], since, wait_seconds, partner_email}` | `X-Pax-Sync-Token` | adds (instant); returns `blocked`, `pending`, `removed`, `delay_seconds` |
| `POST /v1/sync/unblock` `{domain}` | sync token | 202, the one removal rule |
| `POST /v1/sync/requests/{id}/cancel` | sync token | cancel a waiting removal |
| `POST /v1/accounts/signin/start` `{email}` | none (rate-limited) | 202 always |
| `POST /v1/accounts/signin` `{email, code, label}` | none | `{account_id, token}` |

pax-guard socket: `sync.get`, `sync.set {enabled}`, `sync.link {server_url, token, account_email}`,
`sync.now`. `blocklist.unblock` and `blocklist.cancel` go to the account while sync is on and linked.

## Known limits

* A removal requested on a Mac **before** 0.8.9 (local wait) still ends on that Mac, but if sync is on
  the account still has the site and it comes back to the Mac; ask again so it goes through the account.
* A Mac protected with its own key and never used to set up an iPhone, with no partner relay, has no
  account sign-in: its list stays its own until one exists (Home says so).
* Not yet tried on hardware: docs/HARDWARE_TEST.md, "v0.8.9".
