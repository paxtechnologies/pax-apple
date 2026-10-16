# Accountability partner (v0.8.0)

## What the partner is: a witness, nothing more

The partner is **witness-only**. They are told, by email, whenever something would weaken Pax; they can't
approve, veto, delay or speed up anything, and no endpoint or socket command takes their answer. That is
The project's decision: Pax stays fully automatic and the person stays in charge of their own device, while
someone they trust sees what happens. The wait, not the partner, is the protection.

The partner is told about:

* a removal request (Mac or iPhone) and its cancellation;
* the password/keys being released after the wait (`password_revealed`);
* an emergency release request;
* a shorter wait being chosen (longer waits apply at once, without email);
* the partner being changed or removed (that change itself waits the current wait);
* blocked-site changes: an unblock or exception request, its cancellation, and when it applies.

Emails never contain a password or key.

## Fail closed

When a partner is set, anything that would notify them must be **delivered (or queued and retried) before
its wait starts**. Until the email has gone out the request shows "telling your partner" with no countdown,
and the app shows `PAX-ESCROW-010`; pax-guard retries after 1, 5, 15, 30, 60 minutes, then hourly. A reveal
needs its email delivered first. Cancelling (which makes Pax stricter) never waits on email; its message is
queued. With no partner set nothing is sent and everything stays on the Mac.

## How the email gets there

On a Mac with **local escrow** (the v0.8.0 default) pax-guard sends the emails itself
(`guard/partner.py`) through one of two transports, set in Settings › Accountability partner email:

| Transport | Settings | Where secrets live |
|---|---|---|
| **relay** (default, v0.8.5) | The app's server (Pax's own, `https://api.paxpeace.com/`, unless Settings › Advanced names another) with this Mac's account on it, created the first time with your email; or your own `server/` URL and your account token there. pax-guard calls `POST /v1/notify`; the server mails through its own SMTP (`PAX_SMTP_*`) and only relays (the Mac's key stays on the Mac). | Token in `/Library/PaxGuard/escrow/notify.json` (root 0600, integrity-checked) |
| **smtp** | Your own mail account: host, port, STARTTLS or SSL, username, password, From address. | Password only in `notify.json`, never shown again in the app |

iPhones and iPads (and Macs on the server escrow mode) use the Pax server, which emails the partner
directly (`server/pax_server/escrow.py`).

**On the server, partner alerts fail closed too (v0.8.5).** The partner's email is sent *before* the
action it announces; if it can't be sent (an SMTP error or the daily email budget), the action doesn't
start and the answer is HTTP 503 `partner_unreachable` (`PAX-ESCROW-010`). `/v1/notify` answers the same
way, and pax-guard keeps the action queued and retries. Emails to the account holder are best-effort and
stop first when the budget runs low (`PAX_MAIL_DAILY_CAP`, default 90 a day; `PAX_ACCOUNT_MAIL_DAILY_CAP`,
default 60). Cancellations never wait on email.

## Production provider: Resend SMTP

Pax's own server sends through **Resend** from `paxpeace.com` (domain verified with SPF/DKIM/DMARC; the
`mail.paxpeace.com` subdomain was added in October 2026, see Sender address below).
Settings for the server:

```sh
PAX_SMTP_HOST=smtp.resend.com
PAX_SMTP_PORT=587            # STARTTLS (some hosts block 465); or 465 with PAX_SMTP_SECURITY=ssl
PAX_SMTP_SECURITY=starttls
PAX_SMTP_USER=resend         # literally "resend"
PAX_SMTP_PASSWORD=<Resend API key>
PAX_SMTP_FROM="Pax <hello@paxpeace.com>"   # v0.8.0 setting; this value means "Pax's default sender"
# v0.8.10 (optional):
PAX_MAIL_FROM="Pax <noreply@mail.paxpeace.com>"   # wins over PAX_SMTP_FROM when set
PAX_MAIL_REPLY_TO=hello@paxpeace.com             # default when sending as a paxpeace.com address
```

### Sender address (v0.8.10)

Automated mail is moving to the **mail.paxpeace.com** subdomain, so a complaint or bounce spike can't hurt
`paxpeace.com` itself. The server picks its From in this order (`server/pax_server/notify.py`,
`resolve_sender`):

1. `PAX_MAIL_FROM`, when set.
2. `PAX_SMTP_FROM` set to Pax's own `hello@paxpeace.com` means **Pax's default**, which is the constant
   `PAX_DEFAULT_MAIL_FROM` in the release the server runs. Since 0.8.11 that is
   `Pax <noreply@mail.paxpeace.com>` (0.8.10: `Pax <hello@paxpeace.com>`).
3. Any other `PAX_SMTP_FROM`, else `PAX_SMTP_USER` (self-hosting, unchanged).

Reply-To is `PAX_MAIL_REPLY_TO`, else `hello@paxpeace.com` whenever the sender is a paxpeace.com address
other than hello@ itself. `/v1/health` shows `mail_from_domain` (the domain only).

**Switching to the subdomain, no ssh:** once Resend has verified `mail.paxpeace.com` **and** the server's
Resend key may send from it, a release sets `PAX_DEFAULT_MAIL_FROM = PAX_SUBDOMAIN_FROM`. Servers move to it
when they self-update to that signed release (within about 30 minutes); `/v1/health` then reports
`"mail_from_domain": "mail.paxpeace.com"`. **Safety net:** if Resend refuses a `*.paxpeace.com` subdomain
sender (SMTP sender refused or a data error, e.g. not verified or the key isn't allowed that domain), the
same message is sent once more from `hello@paxpeace.com`, so partner emails, and the unlocks and changes
that wait on them, never stall on the switch. Any other failure is raised as before (fail closed).

The same values work for a user who wants pax-guard to send through Resend directly (transport `smtp`),
with their own API key. Keep the API key out of the repo; on the server it belongs in the environment or a
secrets manager.

## Checking it

* `guard/tests/test_v08_partner.py`: fail closed, retries, reveal gating, partner change waits, SMTP password
  root-only, relay/SMTP requests.
* `guard/tests/test_e2e_mac.py` and `server/tests/test_e2e_iphone.py`: the full flows with mocked mail,
  including that no approve/veto route exists.
