# Child accounts, verified by a parent (server 0.8.32)

Status: released in Pax server 0.8.32 (27 Oct 2026). For the iPhone app 1.2 "my child"
set-up. Pax for Mac doesn't offer child set-up in 0.8.32.

## Why

Many children have no email address, and a parent wants to be told, not the child. So a child's device gets its
**own, separate** Pax account whose email is the **parent's**, proved by a 6-digit code sent to the parent.
The parent's own Pax account (if they have one) is never looked at or changed, and still signs in with the same
email as before. One parent address can look after several child accounts and its own.

A child account still satisfies "every account has a verified email": the parent's address was proved by the code
when the account was made (`email_verified_at` is set then).

## Storage (plain column adds, no table rebuild)

* `accounts.kind TEXT NOT NULL DEFAULT 'adult'` (`'adult' | 'child'`), `accounts.parent_email TEXT` (child only,
  lower-cased), `accounts.label TEXT` (child only, e.g. "Sam's iPhone (child)"), index `idx_accounts_parent`.
* `accounts.email` stays `TEXT NOT NULL UNIQUE`. A child row stores a unique placeholder that can never receive
  mail and never leaves the server: `child.<account_id>@accounts.paxpeace.invalid` (`.invalid` is reserved,
  RFC 2606; the API's email validator also refuses it). Every lookup by email (`/email/*`, `/signin/*`,
  `POST /v1/accounts`) therefore only ever finds adult accounts.
* `signup_codes.purpose TEXT NOT NULL DEFAULT 'signup'` (`'signup' | 'child'`). A child code and a sign-up code
  never stand in for each other. Hashes only, as before.
* `display_name` = the child's first name when given (used in the trusted person's emails).
* Rolling back to 0.8.31 leaves the columns unused, but child rows would then send their mail to the
  `.invalid` placeholder (dropped). **Don't roll back once child accounts exist.**

## The calls

New routes, so a 0.8.31 server answers FastAPI's plain `404 {"detail": "Not Found"}` and an app can never land on
the parent's own account by mistake (0.8.31 ignores unknown fields on `/email/verify`).

### `POST /v1/accounts/child/start` `{"email": "parent@example.com"}`

202 `{"sent": true}`, always. No token. Shares the per-client-address sign-up limit with `/email/start`,
`/signin/start` and `POST /v1/accounts`; 5 child codes an hour per parent address (counted apart from the
parent's own codes); 15 minutes; newest code only; 5 tries. The email, to the parent:

> **Your Pax code to set up your child's device**
> Your Pax code is 123456. It works for 15 minutes. Use it on your child's iPhone or iPad to set Pax up there.
> It makes a separate Pax account for that device, which you look after: Pax emails you here about it. Your own
> Pax account (if you have one) doesn't change. If you didn't ask for it, you can ignore this email: nothing is
> made without the code.

### `POST /v1/accounts/child/verify`

```
{"email": "parent@example.com", "code": "123456", "label": "iPhone app",
 "child_name": "Sam", "device_name": "iPhone"}          # child_name, device_name optional, <= 40 chars
```

* **201** `{"account_id", "token", "created": true, "kind": "child", "label": "Sam's iPhone (child)",
  "wait_seconds": 2592000}`. Always a NEW child account, made only now, with the child wait (30 days) set in the
  same transaction: no `PUT /me/wait` needed. No "a new device signed in" email to the parent's own account.
  `label` is "<name>'s <device> (child)", else "<device> (child)", else "Child's device (child)".
* **401** `unauthorized` (PAX-ESCROW-001): wrong, used or expired code, nothing made.
* **429** `child_limit` (PAX-ESCROW-022): the address already looks after 5 child accounts
  (`PAX_CHILD_ACCOUNTS_PER_EMAIL`). Nothing made; the code isn't used up.
* After it's made (best-effort), to the parent: "Pax is set up on Sam's iPhone (child). Turning it off waits 30d,
  and Pax emails you here first. To change anything, use Pax on that device."

### `POST /v1/accounts/child/signin` `{"email", "code", "account_id", "label"?}`

For "Sign in to Pax again" on a child's device that lost its saved sign-in. The code comes from `/child/start`.
200 `{"account_id", "token", "created": false, "kind": "child", "label"}`; the parent is emailed "<label> signed in to
Pax again". 401 for a wrong code **and** for an `account_id` that isn't a child of that parent address (no hint
which). 422 for a malformed `account_id` (32 lower-case hex).

After the token, every other route works as for any account (`/me`, `/devices`, escrow, turn-off, blocked sites,
`DELETE /me`).

## Rules on a child account (all enforced by the server)

* **Turn-off wait at least 30 days** (`PAX_CHILD_WAIT_SECONDS`). `PUT /v1/accounts/me/wait` below it: **403**
  `child_wait_fixed` (PAX-ESCROW-021), nothing changes. Longer is allowed at once; coming back down (never below
  30 days) follows the usual rule (it waits out the current wait, and the parent is told).
* **No trial day**: `POST /v1/devices` with `trial: true` gets none (`trial: null`). The first hour after a device
  is registered (the grace hour, for set-up mistakes) still applies, as for every device; the parent is emailed first.
* **All its mail goes to the parent**: codes, set-up, sign-in, turn-off requests and cancellations, wait and
  trusted-person changes, emergency release, verified support release, relay copies, and the deletion
  confirmation. For anything that loosens Pax (turn-off request, wait decrease, trusted-person change,
  emergency release, support release) the parent is emailed **first and fail closed**, like a trusted person:
  if it can't be sent, the request answers 503 `partner_unreachable` (PAX-ESCROW-010) and nothing starts.
  The parent gets the third-person wording ("Sam asked to …"), subject prefixed "[Pax, <label>]".
* **Emergency release** (24 h, once every 90 days) is kept as a safety valve; the parent is emailed first.
* **Trusted person**: optional, as for adults; the parent's own address is refused (400, "the parent already gets
  every email about this account").
* **Deletion**: `DELETE /v1/accounts/me` with the child's token, same rules (409 `devices_still_protected` while
  protected); the confirmation goes to the parent. Deleting the parent's own account never touches child accounts,
  and the reverse.
* `GET /v1/accounts/me` on a child: `"email"` = the parent's address, `"kind": "child"`, `"label"`,
  `"parent_email"`, `"email_verified": true`. Adults get `"kind": "adult"` and nulls.
* The placeholder address never appears in any response or email (tests check every email).

## Support and data requests

To find every account an address holds or looks after:
`SELECT id, kind, label FROM accounts WHERE email = :e OR parent_email = :e;`

## Not in 0.8.32

* A "Your family" view for the parent (list or remove their children's accounts from the parent's phone).
* Child set-up in Pax for Mac (the Mac app makes adult accounts only).

## Tests

`server/tests/test_v0832_child_accounts.py`: made only with the parent's code (hashes only, nothing before the
code, `email_verified`, 30-day wait, parent emails); labels; the parent's own account untouched and still signing in;
several children then the limit (and the setting); child and sign-up codes kept apart; wrong / used / expired codes,
the 5-try lock, 5 codes an hour, the shared per-IP bucket; validation and the unreachable placeholder; the wait floor
(and its setting); no trial day; parent told first and fail closed (turn-off, emergency); trusted person rules and
`who()`; child sign-in only into that parent's child; deletion both ways; the 0.8.31 → 0.8.32 migration.
