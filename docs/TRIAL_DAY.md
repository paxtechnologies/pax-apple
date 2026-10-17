# Trial day (v0.8.18)

So people can try Pax fully before committing, a **genuinely new set-up** starts with a **trial day**: for
the first 24 hours Pax can be turned off at any time with **no turn-off wait**. After 24 hours the chosen
turn-off wait (default 3 days, 24 hours to 365 days) applies by itself. Home shows a gentle countdown:
"Trial day · turn off anytime until Sat 18 Oct 12:43", "23 h 10 min left · Start my wait now".

## Rules

* **Only a genuinely new set-up.** The app asks for a trial day; whoever holds the key decides.
  * **Mac, own key (pax-guard):** the first set-up on a Mac writes `/private/var/db/PaxPeace/trial.json`
    (root, 0700 folder, 0600 file) with its start time. Removing Pax leaves it there (the uninstallers only
    remove `/Library/PaxGuard`). Every later set-up, and a re-set-up after an unfinished one, reads it, so it
    only ever gets **what is left of the first day**. Macs set up before 0.8.18 are given the marker at
    pax-guard's first heartbeat, dated to their install time, so they never get a trial. A marker that
    can't be read counts as "trial used" (fail closed). An administrator could delete it; on a protected Mac
    only Pax's own administrator account exists.
  * **iPhone, iPad, or a Mac on the server path (Pax server):** the app sends `trial: true` and a hashed
    hardware ID (`hex SHA-256("pax-hw-v1:" + ECID)` for a phone, the Mac's IOPlatformUUID for a Mac). The
    server counts the day from the **earliest** of: the account's first trial start, the account's first
    device (accounts from before 0.8.18 have long had theirs), and that hardware's first trial start
    (`trial_hardware`, SHA-256 again, kept for good). So a re-set-up, a new account on the same phone or a
    reinstall gets only what is left of the first day. Without a hardware ID (an older app or a crafted
    client) there is no trial. Devices registered before 0.8.18 never have one. `PAX_TRIAL_SECONDS=0` turns
    trial days off on a server.
* **The partner is still told.** Turning Pax off in the trial day emails the accountability partner first,
  fail closed as always (`PAX-ESCROW-010`): no email, no release. Revealing the key emails them too.
* **Emergency release** in the trial day has no cooling-off (as in the old first hour).
* **A request made in the trial day lapses when the day ends**, like a first-hour request (v0.8.5): it can't
  become a standing unlock.
* **"Start my wait now"** ends the trial day at once (it's stricter, so no email). A no-wait request made in
  it lapses; a new one takes the full wait. Logged (`trial_ended_early`).
* **Verified support release:** turning it on is instant during the trial day (partner emailed first, nothing
  queued). After the trial it waits the full turn-off wait. Turning it off is always instant.
* Unchanged in the trial day: unblocking a site or app, shortening the wait and changing the partner still
  take the turn-off wait (a partner change must never let a turn-off go unannounced).
* A set-up **without** a trial day still gets the old **first hour** with no wait.

## API

* pax-guard socket: `escrow.end_trial`; `escrow.status` → `trial: {active, until, ended_at, started_at}` or null.
  Set-up: `local_escrow.py deposit … --trial on` (the receipt adds `trial_until`).
* Server: `POST /v1/devices` takes `trial` and `hardware_id`; `GET /v1/devices/{id}` → `trial: {active, until,
  ended_at}` or null; `POST /v1/devices/{id}/trial/end`. `grace_until` / `in_grace_period` now describe the
  whole no-wait window (trial day or first hour), so older apps keep working.

## History

The first-hour grace replaced a week-long grace in v0.8.4 (a week let people relapse). The trial day is
Ruben's 2026-10-17 request: a single day, only once per Mac/phone/account, ended early by the user at will.
