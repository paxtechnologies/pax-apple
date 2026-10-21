# Server change for Pax iOS 1.2 "one-tap set-up"

Status: proposed (2026-10-21). Not on any server yet. The 1.2 app works against today's server
(0.8.29/0.8.30) and switches to these routes by itself once they exist (it detects a missing route
from FastAPI's plain `404 {"detail": "Not Found"}`, which has no Pax `error` code).

## Why

1.2 turns Pax on with one tap: Apple's Screen Time sheet, then Done. The app needs an account to
escrow the release key with **before** it switches anything on (server-escrow-first, fail closed),
but it must not ask for an email. Today `accounts.email` is `NOT NULL UNIQUE`, `POST /v1/accounts`
needs an `EmailStr`, and there is no way to replace a device's escrowed secret later (the Screen
Time passcode is now added from Home, after set-up).

## 1. Private device account (required for one tap)

`POST /v1/accounts/device` (no auth; same per-IP limit as `POST /v1/accounts`)

```json
{"label": "iPhone app"}            →  201 {"account_id": "…", "token": "…", "private": true}
```

- Creates an account with **no email**. Minimal storage options (server team's choice):
  (a) make `accounts.email` nullable (SQLite table rebuild; UNIQUE allows many NULLs), or
  (b) keep the column and store a placeholder such as `device-<account_id>@invalid` plus a new
  `private INTEGER NOT NULL DEFAULT 0` column; `_mail()` must never send to a private account's
  placeholder.
- The token is the device secret: the app keeps it in this device's Keychain only
  (`AfterFirstUnlockThisDeviceOnly`). No welcome email, no code.
- Default wait as today (72 h); the app immediately raises it to 7 days with `PUT /v1/accounts/me/wait`.
- `GET /v1/accounts/me` returns `"email": null` (the 1.2 app decodes email as optional) and may add `"private": true`.
- Everything else unchanged: devices, escrow, turn-off wait, grace hour, DNS (`GET /v1/dns`),
  blocklist, `/v1/notify`, `DELETE /v1/accounts/me` (409 while protected).
- Every email that names the account holder (`f"{acct['email']} asked to …"`, partner_added,
  removal_requested, wait_decrease_requested, partner_change_requested, support release) must use
  a helper `who(acct)` = `display_name` → email → "Someone using Pax", so a private account never
  prints `None`. The holder's own copy (`_mail(acct["email"], …)`) is skipped for private accounts
  (already true: `_mail` returns False for a falsy address).

## 2. Trusted person for a private account (required for the trusted-person card)

`PUT /v1/accounts/me/partner` accepts an optional `from_name` (≤ 40 chars, one line) stored as
`accounts.display_name` and used by `who(acct)`. Today's server ignores the extra field (Pydantic
default), so the 1.2 app already sends it. Rules unchanged: adding is instant; changing/removing
waits the turn-off wait and tells the current person first; "cannot be your own partner" only
applies when the account has an email.

## 3. Replace a device's escrowed secret (recommended)

`PUT /v1/devices/{id}/escrow` (account auth)

```json
{"removal_password": "paxios1.…"}   →  200 device status
```

- Same validation as registration (20–256 chars), re-encrypted with `aad=device_id`.
- Refused with 409 if the device is released/retired or a removal request / emergency release is open.
- Never loosens anything: the secret only matters when a finished wait reveals it. Log
  `escrow_replaced`; optional non-required note to the trusted person.
- Used by Home › Lock Screen Time to add the Screen Time passcode after one-tap set-up.

Without it, the 1.2 app registers a **second device record** ("<device> · Screen Time passcode",
`profile_identifier org.paxpeace.pax.appstore.passcode.<uuid>`) holding the passcode, and turning
off asks for and releases both records (two "removal requested" emails; the account deletion list
shows two rows). It works, but the route is cleaner.

## 4. Later (optional, not needed for 1.2)

- `POST /v1/accounts/me/email/start` + `/verify` (code) to add an email to a private account so it
  can sign in on another device; 409 when that email already has an account.
- Sign in with Apple to fill that email (needs the Sign in with Apple capability on
  org.paxpeace.pax and server-side identity-token checks).

## What depends on what (app 1.2 build 5)

| App feature | Today's server | After this change |
|---|---|---|
| One tap: Welcome → Screen Time → Done | Asks for an email + code after the Screen Time sheet (5 screens) | 3 screens, no email |
| Escrow before ManagedSettings | Yes | Yes |
| Lock Screen Time from Home | Second device record | Replaces the escrow in place |
| Someone you trust | Works (account has an email) | Works; emails say the first name given |
| Child path (parent email + code) | Works | Works |
| Account deletion | Works (0.8.30) | Works |
