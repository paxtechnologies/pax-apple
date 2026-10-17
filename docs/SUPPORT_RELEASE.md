# Verified support release (v0.8.15)

Sometimes a real emergency can't wait for the wait timer, and the usual emergency release (a 24-hour
cooling-off, once every 90 days) isn't enough. When Pax support has checked that the emergency is genuine,
support can issue a **one-time code** that removes Pax from **one device** straight away.

There is **no universal code**. Every code:

* names one device, by its **Support ID** (device page › Details › Support ID, with a copy button);
* works **once** (its random nonce is recorded on the device and on the server, for good);
* expires within **24 hours**;
* is signed with the **support key**, an Ed25519 key separate from the update signing key;
* is refused by any device whose owner turned **Allow verified support release** off.

## What the person sees

* **Set-up** (Mac and iPhone/iPad, on the turn-off wait step): a checkbox, **ticked by default**, "Allow
  verified support release (recommended)", with one line under it: "If you ever face a genuine emergency, Pax
  support can check it and give you a one-time code that removes Pax from this device only. Your trusted
  person is told first." Unticking it sets the device up with the switch off (v0.8.18; it was a switch).
* **Afterwards** (v0.8.18): this Mac's switch is in **Settings › Turning Pax off** and its Support ID in
  **Settings › Advanced**; an iPhone's or iPad's are under **Turn off › Device details** on its page.
  * Turning it **off** takes effect straight away.
  * Turning it **on** goes through the normal change path: it takes effect after the current wait, and the
    partner is emailed first (fail closed, `PAX-ESCROW-010`), just like shortening the wait. It loosens
    protection, so it never skips the wait, **except during the trial day** (v0.8.18, docs/TRIAL_DAY.md):
    Pax can be turned off with no wait then anyway, so turning this on is instant too, still with the
    partner emailed first (no email, no change; nothing is queued).
* **Home › Turn off › In an emergency › I have a support code**: paste or type the code (`PAXS-…`; case,
  spaces and dashes don't matter) and choose **Use support code**.

Devices set up **before 0.8.15 start with the switch off**, because they never agreed to it. No migration
turns it on (pax-guard's state.json and the server's `devices.support_release` both default to off); the
owner can turn it on through the full wait.

## What happens when a code is used

1. The switch is checked: off → refused (`PAX-ESCROW-017`).
2. The signature, the device, the expiry (device clock, and network time on a Mac when known) and the
   nonce are checked (`PAX-ESCROW-012` to `016`).
3. The partner is emailed **first**. The email is never queued: if it can't be sent, nothing is released
   (`PAX-ESCROW-018`) and the same code can be tried again until it expires.
4. Only then is the device released, exactly as confirming a finished removal request does: on a Mac,
   pax-guard reveals the paxadmin password and keys and Pax can remove itself; on an iPhone or iPad the
   server returns the removal password to the owner's app.

Every refusal and every use is written to the Mac's tamper log (`support_code_refused`,
`support_release_used`, `support_release_setting`) or the server's `events` table. Tries are limited (3 a
minute on a Mac, 10 refused codes an hour per device on the server, `PAX-ESCROW-019`).

Where the switch lives: the Mac's own escrow keeps its copy in pax-guard (`/Library/PaxGuard/escrow/`), and
the server can't change it. iPhones and iPads keep theirs on the server, changed only by the owner's
account.

## Issuing a code (support only)

The private key lives offline with support, never in this repo. To issue a code after checking an
emergency, with the Support ID the person read from their device:

```
python3 tools/pax-support-release.py issue ABCD-EFGH-IJKL-MNOP --key /path/to/PAX_SUPPORT_SIGNING_KEY.txt
```

It prints the code (and, on stderr, the device, expiry and key ID). `--hours` shortens the lifetime (at
most 24). `verify <code> <support-id>` checks a code offline. `keygen --out PATH` makes a new key (file mode
0600; only the public key is printed); pin it in `guard/support_code.py` (`SUPPORT_PUBLIC_KEYS_HEX`) and
ship a release before issuing with it.

## Code format

```
payload   = version (1) | support ID (10 bytes) | nonce (8 bytes) | issued_at (u32) | expires_at (u32)
signature = Ed25519(support key, "pax-support-release/v1\0" + payload)
code      = "PAXS-" + base32(payload + signature), in groups of five (146 letters and digits)
```

The Support ID is 10 random bytes, shown as four groups of four base32 characters. It isn't a secret:
knowing it doesn't let anyone issue a code.
