# Server for iPhone app 1.2 (done)

The server side shipped in Pax server 0.8.31 (live on api.paxpeace.com since 22 Oct 2026). The
contract is [docs/ONETAP_ACCOUNTS.md](../docs/ONETAP_ACCOUNTS.md) on `main`.

What the app uses:

- `POST /v1/accounts/email/start {email}` → 202 (always the same answer); 422; 429 `PAX-ESCROW-006`.
- `POST /v1/accounts/email/verify {email, code, label}` → 201 `created: true` (new account) or
  200 `created: false` (the account this email already has: the app reads `GET /v1/accounts/me` and
  `GET /v1/devices` and shows what's set, and never shortens the wait); 401 `PAX-ESCROW-001`.
- `GET /v1/accounts/me` with `email_verified` and `display_name`.
- `PUT /v1/accounts/me/partner {email, from_name?}`.
- `PUT /v1/devices/{id}/escrow {removal_password}` → 200 | 409 `reason` | 404 (Home › Lock Screen Time).
- Unchanged: `PUT /v1/accounts/me/wait`, `POST /v1/devices`, the turn-off routes.

The earlier design here (an email-less "private device account", `POST /v1/accounts/device`) was
dropped on 22 Oct 2026: every Pax account has a verified email. The app has no fallback for older
servers.
