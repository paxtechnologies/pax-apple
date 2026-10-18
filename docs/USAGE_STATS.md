# Usage numbers (v0.8.24)

Pax's server keeps a few totals so the people running it can see whether Pax is being used:
how many accounts and devices there are, how many were active, which version Macs run, and how
many DNS lookups were answered. Only totals. Nothing here can tell anyone who you are, what you
looked up, or where you were.

## What is kept

* **One small row per device**: its kind (Mac, iPhone or iPad), the last day (UTC) it was active,
  and, for Macs on 0.8.24 or later, the Pax version it reported. No time of day, no IP address, no
  site, no name. A device that isn't seen for 35 days drops out of this table (since 0.8.26, except
  an iPhone or iPad Pax is still on, so its owner can still see when it was last seen).
* **One row of counts per day**: accounts, new accounts, devices, active devices, accounts using
  Pax DNS, and DNS lookups answered that day. Numbers only.
* DNS lookups are counted, never recorded: the count says how many, not what.

Accounts, devices and sign-in details were already on the server for Pax to work. The counts are
made from those, and from the rows above.

## What "active" means

A device is active on a day (midnight to midnight UTC) when that day:

* **a Mac** synced its blocked sites with its account or fetched its settings (pax-guard does this
  regularly while the Mac is on and online), or was set up;
* **an iPhone or iPad** had a lookup answered through its account's Pax DNS address on either
  Pax server, or was set up. An account's iPhones and iPads share one DNS address, so the server
  can't tell them apart: when it's used, each of that account's iPhones and iPads counts.

A Mac that keeps its key to itself and has "Sync blocked sites across devices" turned off never
talks to the server, so it isn't counted at all.

Because only the last active day is kept, "today or yesterday" covers at least the last 24 hours
and at most 48.

## Who can see them

`GET /v1/stats` answers only with the operator's key (`?key=…`, the `X-Pax-Stats-Key` header, or
`Authorization: Bearer …`) and returns 404 to everyone else, as if it didn't exist. The server only
holds a SHA-256 hash of the key (in `server/pax_server/stats.py`, or `PAX_STATS_KEY_SHA256` for a
self-hosted server). The access-log line for `/v1/stats` is dropped, so the key isn't written to logs.

* JSON by default; a plain page when a browser asks for HTML (or `&format=html`).
* `&days=30` (default 30, up to 400) adds the daily rows. Today's row says `"complete": false`.
* Days before 0.8.24 are rebuilt from sign-up and set-up dates, so they show totals with no activity.

The primary (`api.paxpeace.com`) has the full numbers. The second DNS server keeps none of its own:
every five minutes it tells the primary which account DNS addresses were used (as the same hashes the
primary already sends it) and how many lookups it answered. Its own `/v1/stats` shows only its
lookup count.

## Last seen, for the owner (v0.8.26)

The same last day is shown to the account's owner on their own Mac (in `GET /v1/devices`, signed in
to the account): `last_seen` ("2026-10-15", a UTC day, never a time) and `checking_in` for each iPhone
and iPad. `checking_in` is false when that day is 3 or more UTC days back (48 hours or more with no
Pax DNS traffic), and null when Pax can't tell (the account's DNS address hasn't been used since this
was kept, or the device is a Mac or already turned off). The Mac then says "Not checking in. It may
have been reset or removed." Nothing new is stored for this, and nobody else (not the partner, not
`/v1/stats`) sees it. Removing a turned-off device from the list (`POST /v1/devices/{id}/retire`)
deletes its row.

## Self-hosting

Set `PAX_STATS_KEY_SHA256` to the SHA-256 (hex) of a long random key of your own, e.g.
`python3 -c "import secrets; print(secrets.token_urlsafe(48))"`, then
`printf %s "$KEY" | sha256sum`. Without it, only the hash shipped in the code works.
