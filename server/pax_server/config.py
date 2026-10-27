# SPDX-License-Identifier: GPL-3.0-only
"""Server settings, read from environment variables (PAX_*)."""
from __future__ import annotations

import os
from dataclasses import dataclass

HOUR = 3600
DAY = 24 * HOUR


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


@dataclass(frozen=True)
class Settings:
    # Path to the SQLite database file.
    db_path: str = "pax.sqlite3"
    # 32-byte AES-256-GCM key, urlsafe-base64 encoded. Generate with:
    #   python3 -m pax_server.crypto --generate-key
    server_key_b64: str = ""

    # Wait time limits (seconds). Default 72 h; the user may choose 24 hours to 365
    # days. v0.8.9: one minimum everywhere, 24 hours, the same as a Mac's own key
    # (guard/local_escrow.py MIN_WAIT/MAX_WAIT; a test checks they agree). Before
    # 0.8.9 the server's minimum was 3 days, so the app's "24 hours" was refused.
    default_wait_seconds: int = 72 * HOUR
    min_wait_seconds: int = 24 * HOUR
    max_wait_seconds: int = 365 * DAY
    # v0.8.32 child accounts (docs/CHILD_ACCOUNTS.md): the turn-off wait a child
    # account is made with, and the shortest it can ever be set to; and how many
    # child accounts one parent address can look after.
    child_wait_seconds: int = 30 * DAY
    child_accounts_per_parent: int = 5

    # First N seconds after a device is registered: removal needs no wait.
    # A grace-period request lapses when this hour ends (v0.8.5), even if unconfirmed.
    grace_seconds: int = 3600  # first hour only
    # v0.8.18 trial day: a genuinely new set-up (the app asks for it and sends a
    # hashed hardware ID) can be turned off with no wait for this long, counted from
    # the account's / the hardware's FIRST trial start, so it never restarts.
    # 0 turns trial days off.
    trial_seconds: int = 24 * HOUR

    # Once a removal request's timer expires, the user has this long to confirm
    # and reveal; after that the request lapses and must be made again. Stops a
    # "just in case" request from becoming a standing unlock.
    reveal_window_seconds: int = 7 * DAY

    # Emergency release: short cooling-off, rate-limited.
    emergency_cooloff_seconds: int = 24 * HOUR
    emergency_min_interval_seconds: int = 90 * DAY

    # Custom blocklist (v0.3). Adding a site is immediate. Removing one, adding an
    # allow-list exception, or rotating the DNS token waits this long and can be
    # cancelled meanwhile; the partner is told.
    blocklist_delay_seconds: int = 72 * HOUR
    # v0.8.9: ONE removal rule for the synced list, wherever the removal is asked
    # for (iPhone, this Mac or another Mac). PAX_BLOCKLIST_DELAY picks the wait:
    #   "wait"  (default) the user's own wait, as a Mac on local escrow always did:
    #           the account's wait, or a linked Mac's longer wait (strictest wins);
    #   "fixed" blocklist_delay_seconds (PAX_BLOCKLIST_DELAY_SECONDS, 72 h), the
    #           server's rule before 0.8.9.
    blocklist_delay: str = "wait"
    blocklist_max_entries: int = 2000
    allowlist_max_entries: int = 500
    # How often the server applies changes whose wait has ended (0 = only on API
    # access / pax-dns polls).
    blocklist_sweep_seconds: int = 5
    # Base of the per-user DoH URL handed to the Mac app: <base>/u/<token>/dns-query.
    # v0.8.8: Pax's own DoH filter, served by pax-server on every Pax server.
    dns_base_url: str = "https://dns.paxpeace.com"
    # Shared secret for pax-dns's internal API (/internal/v1/...). Empty = disabled.
    internal_api_key: str = ""
    # v0.8.1: exception requests are checked against this filtering resolver
    # (DoH); a site it blocks, or a failed lookup, is refused (PAX-DNS-010).
    restricted_probe_url: str = "https://doh.cleanbrowsing.org/doh/family-filter/"

    # v0.8.5 abuse limits (pax_server/limits.py). New accounts per client IP
    # (X-Forwarded-For is trusted only from localhost, i.e. Caddy); 0 = no limit.
    signup_per_ip_hour: int = 5
    signup_per_ip_day: int = 20
    # Outbound email in any 24 hours, kept under the provider's quota (Resend's
    # free tier: 100 a day). Account-holder emails stop at the lower cap, so the
    # rest is kept for partner alerts, which fail closed. -1 = no limit.
    mail_daily_cap: int = 90
    account_mail_daily_cap: int = 60

    # v0.8.8 DoH filter (pax_server/doh.py). role "all": accounts, escrow and DoH
    # (the primary). role "dns": DoH only, lists pulled from the primary's replica
    # feed with a copy on disk (a second server; it never writes account state).
    role: str = "all"
    doh_enabled: bool = False          # Settings(): off (tests); from_env: on
    doh_state_dir: str = ""            # default: <db dir>/dns
    doh_rate_per_ip: float = 25.0      # queries per second, sustained
    doh_burst_per_ip: float = 400.0    # (per-IP: queries with no or an unknown token)
    # v0.8.25: queries with a known account token are limited per token (all of
    # the account's devices), then by a loose per-IP ceiling so many phones behind
    # one carrier-NAT address aren't throttled. 0 = that limit off.
    doh_rate_per_token: float = 25.0
    doh_burst_per_token: float = 400.0
    doh_ip_ceiling_rate: float = 2000.0
    doh_ip_ceiling_burst: float = 4000.0
    doh_max_inflight: int = 48         # worker threads answering at once
    replica_primary_url: str = "https://api.paxpeace.com"
    replica_key: str = ""              # role "dns": the shared key (secret)
    # role "all": SHA-256 of keys allowed to read the replica feed. The hashes of
    # Pax's own second server ship in the code (replica.py); more via env.
    replica_key_sha256: tuple = ()
    # v0.8.24 /v1/stats (pax_server/stats.py): SHA-256 of extra keys allowed to read
    # the aggregate usage numbers (the operator's own hash ships in stats.py).
    stats_key_sha256: tuple = ()
    # v0.8.8 primary only: add the DoH site to the local Caddy (caddy_sync.py).
    caddy_sync: bool = False
    # v0.8.17 role "dns" only: put the ACME challenge forwarder (to the primary)
    # at the front of the local Caddy's port-80 server (caddy_sync.py, mode "dns").
    # Separate from PAX_CADDY_SYNC, which the second server's env sets to 0.
    caddy_acme_forward: bool = False
    caddy_admin_url: str = "http://127.0.0.1:2019"
    dns_host: str = "dns.paxpeace.com"
    api_host: str = "api.paxpeace.com"

    def resolved_doh_state_dir(self) -> str:
        if self.doh_state_dir:
            return self.doh_state_dir
        import os.path
        return os.path.join(os.path.dirname(os.path.abspath(self.db_path)), "dns")

    @classmethod
    def from_env(cls) -> "Settings":
        d = cls()
        role = os.environ.get("PAX_ROLE", d.role).strip().lower() or "all"
        if role not in ("all", "dns"):
            raise ValueError("PAX_ROLE must be 'all' or 'dns'")
        delay = os.environ.get("PAX_BLOCKLIST_DELAY", d.blocklist_delay).strip().lower() or d.blocklist_delay
        if delay not in ("wait", "fixed"):
            raise ValueError("PAX_BLOCKLIST_DELAY must be 'wait' or 'fixed'")
        return cls(
            role=role,
            doh_enabled=os.environ.get("PAX_DOH", "1").strip().lower() not in ("0", "false", "off", "no"),
            doh_state_dir=os.environ.get("PAX_DOH_STATE_DIR", ""),
            doh_rate_per_ip=float(os.environ.get("PAX_DOH_RATE_PER_IP", d.doh_rate_per_ip)),
            doh_burst_per_ip=float(os.environ.get("PAX_DOH_BURST_PER_IP", d.doh_burst_per_ip)),
            doh_rate_per_token=float(os.environ.get("PAX_DOH_RATE_PER_TOKEN", d.doh_rate_per_token)),
            doh_burst_per_token=float(os.environ.get("PAX_DOH_BURST_PER_TOKEN", d.doh_burst_per_token)),
            doh_ip_ceiling_rate=float(os.environ.get("PAX_DOH_IP_CEILING_RATE", d.doh_ip_ceiling_rate)),
            doh_ip_ceiling_burst=float(os.environ.get("PAX_DOH_IP_CEILING_BURST", d.doh_ip_ceiling_burst)),
            doh_max_inflight=_env_int("PAX_DOH_MAX_INFLIGHT", d.doh_max_inflight),
            replica_primary_url=os.environ.get("PAX_REPLICA_PRIMARY_URL", d.replica_primary_url),
            replica_key=os.environ.get("PAX_REPLICA_KEY", ""),
            replica_key_sha256=tuple(h.strip().lower() for h in
                                     os.environ.get("PAX_REPLICA_KEY_SHA256", "").split(",") if h.strip()),
            stats_key_sha256=tuple(h.strip().lower() for h in
                                   os.environ.get("PAX_STATS_KEY_SHA256", "").split(",") if h.strip()),
            # On by default for a real primary (role all), off in tests (Settings()).
            caddy_sync=(role == "all" and os.environ.get("PAX_CADDY_SYNC", "1").strip() not in ("0", "false", "off")),
            caddy_acme_forward=(role == "dns" and os.environ.get("PAX_CADDY_ACME_FORWARD", "1").strip()
                                not in ("0", "false", "off")),
            caddy_admin_url=os.environ.get("PAX_CADDY_ADMIN_URL", d.caddy_admin_url),
            dns_host=os.environ.get("PAX_DNS_HOST", d.dns_host),
            api_host=os.environ.get("PAX_API_HOST", d.api_host),
            db_path=os.environ.get("PAX_DB_PATH", d.db_path),
            server_key_b64=os.environ.get("PAX_SERVER_KEY", ""),
            default_wait_seconds=_env_int("PAX_DEFAULT_WAIT_SECONDS", d.default_wait_seconds),
            min_wait_seconds=_env_int("PAX_MIN_WAIT_SECONDS", d.min_wait_seconds),
            max_wait_seconds=_env_int("PAX_MAX_WAIT_SECONDS", d.max_wait_seconds),
            child_wait_seconds=_env_int("PAX_CHILD_WAIT_SECONDS", d.child_wait_seconds),
            child_accounts_per_parent=_env_int("PAX_CHILD_ACCOUNTS_PER_EMAIL", d.child_accounts_per_parent),
            grace_seconds=_env_int("PAX_GRACE_SECONDS", d.grace_seconds),
            trial_seconds=_env_int("PAX_TRIAL_SECONDS", d.trial_seconds),
            reveal_window_seconds=_env_int("PAX_REVEAL_WINDOW_SECONDS", d.reveal_window_seconds),
            emergency_cooloff_seconds=_env_int(
                "PAX_EMERGENCY_COOLOFF_SECONDS", d.emergency_cooloff_seconds
            ),
            emergency_min_interval_seconds=_env_int(
                "PAX_EMERGENCY_MIN_INTERVAL_SECONDS", d.emergency_min_interval_seconds
            ),
            blocklist_delay_seconds=_env_int(
                "PAX_BLOCKLIST_DELAY_SECONDS", d.blocklist_delay_seconds),
            blocklist_delay=delay,
            blocklist_max_entries=_env_int("PAX_BLOCKLIST_MAX_ENTRIES", d.blocklist_max_entries),
            allowlist_max_entries=_env_int("PAX_ALLOWLIST_MAX_ENTRIES", d.allowlist_max_entries),
            blocklist_sweep_seconds=_env_int(
                "PAX_BLOCKLIST_SWEEP_SECONDS", d.blocklist_sweep_seconds),
            dns_base_url=os.environ.get("PAX_DNS_BASE_URL", d.dns_base_url),
            internal_api_key=os.environ.get("PAX_INTERNAL_KEY", ""),
            restricted_probe_url=os.environ.get("PAX_RESTRICTED_PROBE_URL", d.restricted_probe_url),
            signup_per_ip_hour=_env_int("PAX_SIGNUP_PER_IP_HOUR", d.signup_per_ip_hour),
            signup_per_ip_day=_env_int("PAX_SIGNUP_PER_IP_DAY", d.signup_per_ip_day),
            mail_daily_cap=_env_int("PAX_MAIL_DAILY_CAP", d.mail_daily_cap),
            account_mail_daily_cap=_env_int("PAX_ACCOUNT_MAIL_DAILY_CAP", d.account_mail_daily_cap),
        )
