# Private accounts and escrow replace (server, for iPhone app 1.2)

Status: on branch `server/private-accounts`, not released. It will ship as part of a later server release.
The iPhone app 1.2 works against older servers too: it spots a missing route from FastAPI's plain
`404 {"detail": "Not Found"}` (no Pax `error` code) and falls back by itself. Pax's own 404s always carry
`{"error": "not_found", "message": ..., "pax_code": ...}`.

## Why

One-tap set-up on the iPhone (Apple's Screen Time sheet, then Done) needs an account to escrow the release
key with **before** anything is switched on (server escrow first, fail closed), but it must not ask for an
email. Later, the Screen Time passcode is added from Home, so the escrowed secret needs replacing in place.

## API

### `POST /v1/accounts/device`: a private account

No token. Shares the per-client-address sign-up limit with `POST /v1/accounts` and
`POST /v1/accounts/signin/start` (5 an hour, 20 a day by default; one bucket for all three).

```
POST /v1/accounts/device        {"label": "iPhone app"}      (body optional; label ≤ 100 chars)
201  {"account_id": "<32 hex>", "token": "pax_…", "private": true}
429  {"error": "rate_limited", "message": "too many new accounts from your network …", "pax_code": "PAX-ESCROW-006"}
422  FastAPI validation error (label over 100 characters)
```

* The account has **no email** (`accounts.email` is NULL). No welcome email, no code, and nothing is ever
  mailed to its holder: every holder copy goes through `_mail()`, which sends nothing without an address.
* The token is the device's secret. The app keeps it in that device's Keychain only. There is no sign-in
  by email for a private account, so losing the token loses the account (the turn-off wait still never
  releases anything without the token). See "Later" below for adding an email.
* Default wait as for any account (72 h); the app raises it straight away with `PUT /v1/accounts/me/wait`.
* The label is stored only in the `account_registered` event (`"private: iPhone app"`), and only when it
  is one clean line of at most 40 characters.

`GET /v1/accounts/me` now returns, for every account:

```
"email": null | "<address>",      null for a private account
"private": true | false,          true when the account has no email
"display_name": null | "<name>",  the from_name given with the trusted person (below)
```

Everything else works the same for a private account: devices, escrow, the turn-off wait, the grace hour
and trial day, emergency release, verified support release, `/v1/dns`, blocklist and categories,
`/v1/notify`, sync links (`account_email` is `null`), and `DELETE /v1/accounts/me` (409 while protected; on
success 204 and **no confirmation email**, as there is no address).

### `PUT /v1/accounts/me/partner {email, from_name?}`

`from_name` (new, optional) is the holder's first name for their trusted person's emails, stored as
`accounts.display_name`.

* Left out or `null`: unchanged. An empty string (after stripping): cleared.
* Stripped; one line; at most 40 characters; no control or format characters (newlines, tabs, NUL,
  bidi overrides), no line/paragraph separators or other non-space whitespace, no links (`://`, `www.`).
  Anything else is refused with 422 before anything changes.
* Saved before the email the same call sends, so the "you are now a trusted person" email already uses it.
* Logged as `display_name_set` / `display_name_cleared` (the name itself isn't logged).
* The trusted-person rules are unchanged: adding is instant; changing or removing waits the turn-off wait
  and tells the current person first (fail closed). "You cannot be your own accountability partner" is
  only checked when the account has an email.

### How emails name the holder: `who(acct)`

Every email to a trusted person that names the holder uses `Escrow.who(acct)`:
`display_name` → email → **"Someone using Pax"** ("someone using Pax" mid-sentence). Used by: partner added
(now and after a change applies), partner change requested, wait decrease requested, removal requested and
cancelled, password released, emergency release requested, verified support release turned on / requested /
used, blocked-site change requested / cancelled / applied. No email can say "None".

An email account that gives a `from_name` is named by it too (the spec's order).

### `PUT /v1/devices/{id}/escrow {removal_password}`: replace a device's secret

Account token of the device's owner.

```
PUT /v1/devices/{id}/escrow      {"removal_password": "paxios1.…"}      (20–256 characters)
200  device status (the same object as GET /v1/devices/{id})
401  {"error": "unauthorized", …, "pax_code": "PAX-ESCROW-001"}
404  {"error": "not_found", "message": "device not found", "pax_code": "PAX-ESCROW-005"}   (no such device / another account's)
409  {"error": "conflict", "message": …, "reason": "released" | "retired" | "removal_request_open" | "emergency_open" | "changed",
      "removal_request": {…} (with the two *_open reasons), "pax_code": "PAX-ESCROW-005"}
422  FastAPI validation error (missing, shorter than 20 or longer than 256 characters)
```

* Re-encrypted with the server key and `aad = device_id`, like registration (a ciphertext can't be moved to
  another device row).
* Refused while any removal request is open (including a grace-hour or trial-day one, and an emergency
  release), so a request in flight always reveals the secret it was made for. Cancel it first.
* Never loosens anything: the secret is only ever revealed when a finished wait, an emergency release or a
  verified support code releases it. It sends no email.
* Logged: `escrow_replaced` (device id, no detail) or `escrow_replace_refused` (the reason). The secret is
  never logged.
* Any platform the account owns; only the iPhone app uses it today. Replacing a secret with one that doesn't
  match the device can only make that device harder to turn off, never easier.

## Storage and migration

`accounts.email` was `TEXT NOT NULL UNIQUE`. It is now `TEXT UNIQUE` (SQLite allows any number of NULLs
under UNIQUE, so real addresses stay unique). A new `display_name TEXT` column holds `from_name`. Whether an
account is private is not stored separately: it is `email IS NULL`, so it can never disagree with the data.

SQLite can't drop NOT NULL in place, so `Database._email_nullable()` (server/pax_server/db.py) rebuilds the
table once, with SQLite's documented procedure:

1. Skip when the email column already allows NULL (new databases, and every start after the first).
2. Take the stored `CREATE TABLE accounts` text and change only `email TEXT NOT NULL UNIQUE` to
   `email TEXT UNIQUE`; refuse to start (RuntimeError, nothing changed) if the table has any other shape.
   Every other column, default and the column order stay exactly as they were.
3. `PRAGMA foreign_keys=OFF` (needed for the rebuild), then one `BEGIN IMMEDIATE` transaction: create
   `accounts_v0831_rebuild`, copy every row by column name, check the row counts, drop the old table,
   rename the new one to `accounts`, re-create any index or trigger, and run `PRAGMA foreign_key_check`
   (no new broken reference allowed). Any failure rolls everything back and the server doesn't start, so
   it never runs on a half-migrated table; the self-update's pre-update backup is there too.
4. `PRAGMA foreign_keys=ON` again. Account ids don't change, so every `REFERENCES accounts(id)` still
   points at the same rows.

pax-dns's read-only `SqliteSource` sees the old or the new table, never neither (WAL). The DoH-only second
server (dns2, `PAX_ROLE=dns`) has no database and gets accounts only through the replica feed, which never
carried an email; nothing changes there.

Rolling back to 0.8.30 after the rebuild works (its `CREATE TABLE IF NOT EXISTS` leaves the table alone),
but 0.8.30 would print "None" for a private account's holder in partner emails. Private accounts only exist
once this release is out, so roll back only before the 1.2 app is in use.

Why not a placeholder address (`device-<id>@invalid`) plus a `private` flag: every place that reads
`acct["email"]` (welcome, sign-in lookup, delete confirmation, notify-relay copies, sync `account_email`,
the own-partner check, the API) would see a fake address that looks real and would have to remember the
flag, and each one it forgot would quietly use the mail budget or show the fake address to the user. NULL
makes a forgotten check fail visibly and lets `_mail()`'s existing "no address, no email" rule cover every
holder copy. The cost is a one-time rebuild of a small table, done in one transaction with checks and tests.

## Tests

`server/tests/test_v0831_private_accounts.py`: create plus the shared rate limit; `me()` with null email;
partner with `from_name` and every email using `who()` (no "None" anywhere); `from_name` validation; escrow
replace OK, bound to the device, refused while a request or emergency is open or the device is released or
retired; deleting a private account (204, no email); the DNS feed, replica and pax-dns `SqliteSource` with a
private account; sync link and `/v1/notify`; the migration on databases shaped like v0.1 and v0.8.30 with
data in every table (rows, uniqueness, foreign keys, defaults, an open reader, idempotency, refusal of an
unexpected shape, rollback when a step fails, an old orphan row).

## Later (design only, not built)

Adding an email to a private account, so it can sign in on another device:

* `POST /v1/accounts/me/email/start {email}` (account token; counted against the same per-client sign-up
  limit): 409 `{"error": "conflict", "sign_in": true}` when that email already has an account; otherwise a
  one-time code to that address, made, stored (hashed), expired and rate-limited like today's sign-in codes
  (`signin_codes`), email kind `email_verify`.
* `POST /v1/accounts/me/email/verify {email, code}`: sets `accounts.email` (UNIQUE catches a race; 409),
  logs `email_added`, emails "This address is now on your Pax account". `private` becomes false and the
  holder now gets their own copies. Removing the email again isn't offered (it would make "sign in
  elsewhere" disappear without a wait); changing it can reuse the same two steps.
* The trusted person isn't told (it doesn't loosen anything), and `display_name` stays.
* Sign in with Apple could fill that email: it needs the Sign in with Apple capability on
  `org.paxpeace.pax` and server-side identity-token checks (Apple's keys, audience, nonce); a private relay
  address is a real address for this purpose.
