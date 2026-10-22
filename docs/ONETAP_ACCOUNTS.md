# One-tap accounts: verified email, first name, escrow replace (server, for iPhone app 1.2)

Status: on branch `server/private-accounts`, not released. It will ship as part of a later server release.

## The rule: every account has a verified email

An account's sign-in token lives in the device's Keychain. If that were the only way in, a lost, wiped or
replaced phone would mean a lost account: no sign-in on the new phone, and support could not restore it.
So every Pax account has an email, and every account the iPhone app makes has proved that email with a
one-time code before it exists. There is no email-less ("private") account and no `POST /v1/accounts/device`.
`accounts.email` stays `TEXT NOT NULL UNIQUE`.

The iPhone app 1.2 keeps one-tap set-up quick: Welcome → email → 6-digit code → Apple's Screen Time sheet →
Done. The account (and the escrowed release key) still exists **before** anything is switched on (server
escrow first, fail closed).

## iPhone app 1.2: the calls, in order

### 1. `POST /v1/accounts/email/start`: send a code

No token. Shares the per-client-address sign-up limit with `POST /v1/accounts` and
`POST /v1/accounts/signin/start` (5 an hour, 20 a day by default; one bucket for all three).

```
POST /v1/accounts/email/start      {"email": "sam@example.com"}
202  {"sent": true}
422  FastAPI validation error (not an email address)
429  {"error": "rate_limited", "message": "too many new accounts from your network …" | "too many codes; try again in an hour",
      "pax_code": "PAX-ESCROW-006"}
```

* Always the same 202 whether or not the address already has an account, so it can't be used to find out
  who uses Pax.
* New address: a 6-digit code ("Your Pax code", kind `signup_code`). Nothing is stored but hashes
  (`signup_codes`: a hash of the address, a hash of the code, times, tries); **no account is made yet**.
* Address that already has an account: today's sign-in code ("Your Pax sign-in code", kind `signin_code`,
  in `signin_codes`), exactly as `POST /v1/accounts/signin/start`.
* Codes: 15 minutes, only the newest one works, 5 tries each, 5 codes an hour per address.
* If the email can't go out (the server's daily email budget is spent), the answer is still 202 and no code
  arrives: no code, no account. The app shows "Didn't get it? Send again" (a new `start`).

### 2. `POST /v1/accounts/email/verify`: get the token

No token. Same fields as `POST /v1/accounts/signin`.

```
POST /v1/accounts/email/verify     {"email": "sam@example.com", "code": "123456", "label": "iPhone app"}
                                   (label optional, ≤ 100 chars: names the sign-in)
201  {"account_id": "<32 hex>", "token": "pax_…", "created": true}     a new account; its email is verified
200  {"account_id": "<32 hex>", "token": "pax_…", "created": false}    signed in to the existing account
401  {"error": "unauthorized", "message": "that code isn't right or has expired", "pax_code": "PAX-ESCROW-001"}
422  FastAPI validation error (code shorter than 4 or longer than 12 characters, label over 100)
```

* 401 for a wrong, used, expired or locked-out code. Nothing is made (fail closed).
* `created: true`: the account is new, with the default turn-off wait (72 h) and `email_verified: true`. No
  welcome email (the code email was enough). Logged `account_registered` ("email verified").
* `created: false`: the address already had an account (made on a Mac, an earlier iPhone, or a moment ago).
  The app gets a new sign-in to **that** account (`account_tokens`, as `POST /v1/accounts/signin`), the holder
  is emailed "a new device signed in", and the account's existing wait, trusted person, devices and blocked
  sites all apply. The app should read `GET /v1/accounts/me` and show what is already set rather than assume
  a fresh account (for example, it can't shorten an existing wait without waiting).
* The token goes in this device's Keychain (`AfterFirstUnlockThisDeviceOnly`). If it is ever lost, the same
  two calls on any device sign in again: the account is never lost with the phone.

### 3. After the token (unchanged routes)

```
PUT  /v1/accounts/me/wait          {"wait_days": 7}                       raise the wait (instant)
POST /v1/devices                   {name, platform: "ios", profile_identifier, removal_password, support_release}
                                   201 {"device_id": …}                    escrow first, then ManagedSettings
GET  /v1/accounts/me               {…, "email": "sam@example.com", "email_verified": true, "display_name": null | "Sam"}
```

### `PUT /v1/accounts/me/partner {email, from_name?}`

`from_name` (new, optional) is the holder's first name for their trusted person's emails, stored as
`accounts.display_name`.

```
PUT /v1/accounts/me/partner        {"email": "friend@example.org", "from_name": "Sam"}
200  account status (as GET /v1/accounts/me, with "display_name": "Sam")
422  from_name not one clean line of at most 40 characters
```

* Left out or `null`: unchanged. An empty string (after stripping): cleared.
* Stripped; one line; at most 40 characters; no control or format characters (newlines, tabs, NUL, bidi
  overrides), no line/paragraph separators or other non-space whitespace, no links (`://`, `www.`).
  Anything else is refused with 422 before anything changes.
* Saved before the email the same call sends, so the "you are now a trusted person" email already uses it.
* Logged as `display_name_set` / `display_name_cleared` (the name itself isn't logged).
* The trusted-person rules are unchanged: adding is instant; changing or removing waits the turn-off wait
  and tells the current person first (fail closed); you can't be your own trusted person.

### How emails name the holder: `who(acct)`

Every email to a trusted person that names the holder uses `Escrow.who(acct)`: `display_name` → email.
(A last "Someone using Pax" fallback is kept only as a defence for a row without an email, which the schema
no longer allows; no email can say "None".) Used by: partner added (now and after a change applies), partner
change requested, wait decrease requested, removal requested and cancelled, password released, emergency
release requested, verified support release turned on / requested / used, blocked-site change requested /
cancelled / applied.

### `PUT /v1/devices/{id}/escrow {removal_password}`: replace a device's secret

Account token of the device's owner. Used by Home › Lock Screen Time to add the Screen Time passcode after
set-up, instead of a second device record.

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
* Logged: `escrow_replaced` (device id, no detail) or `escrow_replace_refused` (the reason). Never the secret.

### Older servers

The app can tell a server without these routes from FastAPI's plain `404 {"detail": "Not Found"}` (no Pax
`error` code); Pax's own 404s always carry `{"error": "not_found", "message": …, "pax_code": …}`. On a
0.8.30 server the app should make the account with `POST /v1/accounts {email}` and, when that answers 409
`sign_in: true`, sign in with `POST /v1/accounts/signin/start` + `POST /v1/accounts/signin`; without the
escrow route it can fall back to a second device record for the passcode.

## The Mac app (unchanged)

`POST /v1/accounts {email}` (201 `{account_id, token}`, welcome email; 409 `sign_in: true` if the address has
an account), `POST /v1/accounts/signin/start` and `POST /v1/accounts/signin` work exactly as before. An
account made by `POST /v1/accounts` has an email but hasn't proved it (`email_verified: false`) until a
code to it is used once (any sign-in by code sets `email_verified_at`). Moving the Mac app to
`/v1/accounts/email/*` and then retiring unverified creation is a follow-up for a Mac release.

## Storage

* `accounts.email` stays `TEXT NOT NULL UNIQUE`. No table rebuild.
* Two plain `ALTER TABLE accounts ADD COLUMN`s at start-up: `display_name TEXT` (the `from_name`) and
  `email_verified_at INTEGER` (when a code to the email last worked; `GET /v1/accounts/me` shows it as
  `email_verified`). Rolling back to 0.8.30 leaves them unused.
* New table `signup_codes(id, email_hash, code_hash, created_at, expires_at, attempts, used_at)`: codes for
  addresses with no account yet. Hashes only, never an account id; rows are deleted a day after they expire
  (on the next `start`). Account deletion doesn't touch it, like `signup_attempts` and `mail_log`.

## Later (design note only, not built): Sign in with Apple

It could replace typing an email and a code with one Apple sheet.

* For: faster on iPhone; Apple has already verified the address; no code email (no mail budget, no spam
  folder).
* Against: "Hide My Email" gives a private-relay address (`…@privaterelay.appleid.com`). It is a real,
  working address for codes and support, but the person may not recognise it, and support can only find the
  account by it; mail to it must come from a sending domain registered with Apple, or it bounces.
* Work needed: the Sign in with Apple capability on `org.paxpeace.pax`; server-side identity-token checks
  (Apple's public keys fetched and cached, issuer, audience = the app's bundle id, expiry, nonce); storing
  Apple's stable `sub` so a later sign-in finds the account even if the relay address changes; registering
  `paxpeace.com` as a sending domain with Apple; and the Mac app would still need the email path.
* It would make an account with a verified email (Apple's), so it fits the rule above.

## Tests

`server/tests/test_v0831_onetap_accounts.py`: new account by code (hashes only, no account before the code,
`email_verified`, no welcome); existing account signs in with the same two calls; the same answer for known
and unknown addresses; wrong / used / expired / other-address codes and the 5-try lock (nothing made); only
the newest code works; 5 codes an hour per address; the shared per-IP limit (also behind the proxy); a code
sent before someone else made the account, and the UNIQUE-email race (both sign in instead); a spent mail
budget makes no account; expired codes pruned; validation; the Mac routes unchanged; no
`POST /v1/accounts/device` and `email` still NOT NULL; upgrading a v0.8.30-shaped database only adds two
columns and a table (no rebuild, idempotent); `who()`, `from_name` in every trusted-person email and its
validation; escrow replace (OK, bound to the device, refused while open / released / retired / grace hour);
deleting a code-made account still emails its confirmation.
