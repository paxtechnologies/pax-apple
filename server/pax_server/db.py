# SPDX-License-Identifier: GPL-3.0-only
"""SQLite storage. All timestamps are integer Unix seconds (UTC)."""
from __future__ import annotations

import logging
import re
import sqlite3
import threading

log = logging.getLogger("pax.db")

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id                     TEXT PRIMARY KEY,
    email                  TEXT UNIQUE,  -- v0.8.31: NULL = a private (device-only) account
    token_hash             TEXT NOT NULL,
    created_at             INTEGER NOT NULL,
    wait_seconds           INTEGER NOT NULL,
    pending_wait_seconds   INTEGER,
    pending_wait_effective INTEGER,
    partner_email          TEXT,
    pending_partner_email  TEXT,      -- '' means "remove partner"
    pending_partner_effective INTEGER,
    last_emergency_at      INTEGER,
    adblock                INTEGER NOT NULL DEFAULT 1,  -- v0.4: Mac ad/tracker blocking
    block_remote_desktop   INTEGER NOT NULL DEFAULT 1,  -- v0.5: remote-desktop category
    trial_started_at       INTEGER,                     -- v0.8.18: when this account's trial day began
    display_name           TEXT                         -- v0.8.31: first name for the trusted person's emails
);

CREATE TABLE IF NOT EXISTS devices (
    id                 TEXT PRIMARY KEY,
    account_id         TEXT NOT NULL REFERENCES accounts(id),
    name               TEXT NOT NULL,
    platform           TEXT NOT NULL,
    profile_identifier TEXT NOT NULL,
    password_ct        BLOB NOT NULL,
    installed_at       INTEGER NOT NULL,
    released_at        INTEGER,
    support_id         TEXT,                        -- v0.8.15: shown in the app (Details › Support ID)
    support_release    INTEGER NOT NULL DEFAULT 0,  -- v0.8.15: "Allow verified support release"
    support_pending_on INTEGER,                     -- v0.8.15: when a requested "on" takes effect
    trial_until        INTEGER,                     -- v0.8.18: end of the trial day (NULL: none)
    trial_ended_at     INTEGER,                     -- v0.8.18: "Start my wait now"
    retired_at         INTEGER                      -- v0.8.26: removed from the owner's list (released only)
);

CREATE TABLE IF NOT EXISTS removal_requests (
    id           TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL REFERENCES devices(id),
    kind         TEXT NOT NULL,            -- 'standard' | 'grace' | 'trial' | 'emergency' | 'support'
    status       TEXT NOT NULL,            -- 'pending' | 'cancelled' | 'revealed' | 'lapsed'
    reason       TEXT,
    created_at   INTEGER NOT NULL,
    unlock_at    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    closed_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_rr_device ON removal_requests(device_id, status);

-- v0.3: custom blocklist / allow-list, synced to every device through pax-dns.
CREATE TABLE IF NOT EXISTS blocklist_entries (
    account_id  TEXT NOT NULL REFERENCES accounts(id),
    list        TEXT NOT NULL,            -- 'block' | 'allow'
    domain      TEXT NOT NULL,            -- normalised ASCII (IDNA) domain
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, list, domain)
);

CREATE TABLE IF NOT EXISTS blocklist_requests (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(id),
    action       TEXT NOT NULL,           -- 'unblock' | 'allow' | 'rotate_token'
                                          -- | 'remote_desktop_off' (v0.5)
    domain       TEXT,                    -- NULL for rotate_token / remote_desktop_off
    status       TEXT NOT NULL,           -- 'pending' | 'applied' | 'cancelled'
    created_at   INTEGER NOT NULL,
    effective_at INTEGER NOT NULL,
    closed_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_blr_due ON blocklist_requests(status, effective_at);
CREATE INDEX IF NOT EXISTS idx_blr_acct ON blocklist_requests(account_id, status);

-- Per-user DoH tokens. pax-dns looks tokens up by SHA-256 hash; the ciphertext
-- (AES-GCM, server key) lets the owner fetch their URL again for a new device.
CREATE TABLE IF NOT EXISTS dns_tokens (
    token_hash  TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id),
    token_ct    BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    retire_at   INTEGER                   -- NULL = current token
);
CREATE INDEX IF NOT EXISTS idx_dns_tokens_acct ON dns_tokens(account_id);

-- Change feed for pax-dns: one row per account whose effective lists changed.
CREATE TABLE IF NOT EXISTS dns_changes (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  TEXT NOT NULL,
    at          INTEGER NOT NULL
);

-- v0.4: read-only tokens for pax-guard on a self-locked Mac. A guard token can
-- only read that account's effective lists and the device's status; it cannot
-- start a removal, change the wait or reveal anything.
CREATE TABLE IF NOT EXISTS guard_tokens (
    token_hash  TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL REFERENCES devices(id),
    created_at  INTEGER NOT NULL
);

-- v0.8.5: abuse limits (pax_server/limits.py). Hashes only, pruned after 2 days.
CREATE TABLE IF NOT EXISTS signup_attempts (
    ip_hash     TEXT NOT NULL,
    at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_signup_ip ON signup_attempts(ip_hash, at);

CREATE TABLE IF NOT EXISTS mail_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    tier        TEXT NOT NULL,            -- 'account' | 'partner'
    to_hash     TEXT NOT NULL,
    status      TEXT NOT NULL             -- 'sending' | 'sent' | 'failed' | 'dropped'
);
CREATE INDEX IF NOT EXISTS idx_mail_at ON mail_log(at);
CREATE INDEX IF NOT EXISTS idx_mail_to ON mail_log(to_hash, kind, at);

-- v0.8.9: blocked-sites sync. A Mac on local escrow (pax-guard holds its own key)
-- links to the account with a sync token: it may read the account's blocked
-- sites, add to them, and request (or cancel) a removal through the same wait
-- and partner email as any other device. It can't reveal anything or change
-- the wait. wait_seconds / partner_email are what that Mac reports, so a
-- removal waits at least as long as the Mac's own wait and its partner is told.
CREATE TABLE IF NOT EXISTS sync_links (
    id            TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts(id),
    token_hash    TEXT NOT NULL UNIQUE,
    device_name   TEXT NOT NULL,
    platform      TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_seen     INTEGER,
    wait_seconds  INTEGER,
    partner_email TEXT,
    revoked_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sync_links_acct ON sync_links(account_id);

-- v0.8.9: more sign-ins for one account (a second Mac signing in with the
-- account's email and a one-time code). Hashes only.
CREATE TABLE IF NOT EXISTS account_tokens (
    token_hash  TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id),
    created_at  INTEGER NOT NULL,
    label       TEXT
);
CREATE TABLE IF NOT EXISTS signin_codes (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id),
    code_hash   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    used_at     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_signin_acct ON signin_codes(account_id, created_at);

-- v0.8.15: verified support release. Every nonce ever redeemed, kept for good, so
-- a code works once whatever any clock says.
CREATE TABLE IF NOT EXISTS support_nonces (
    nonce       TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    used_at     INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    key_id      TEXT
);

-- v0.8.18: hardware that has had a trial day (SHA-256 of the app's hashed ID), kept
-- for good so a new account on the same phone or Mac never gets a second one.
CREATE TABLE IF NOT EXISTS trial_hardware (
    hw_hash     TEXT PRIMARY KEY,
    first_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  TEXT NOT NULL,
    device_id   TEXT,
    at          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    detail      TEXT
);
"""


class Database:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            if path != ":memory:":
                # WAL lets pax-dns read the effective lists while the server writes.
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        """Add columns introduced after a database was created (v0.4+)."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(accounts)")}
        if "adblock" not in cols:
            self._conn.execute(
                "ALTER TABLE accounts ADD COLUMN adblock INTEGER NOT NULL DEFAULT 1")
        if "block_remote_desktop" not in cols:
            self._conn.execute(
                "ALTER TABLE accounts ADD COLUMN block_remote_desktop INTEGER NOT NULL DEFAULT 1")
        # v0.8.18: the extra family-filter layer (Advanced). Off by default: Pax's own
        # filter decides, then a malware-only resolver answers.
        if "dns_family_layer" not in cols:
            self._conn.execute(
                "ALTER TABLE accounts ADD COLUMN dns_family_layer INTEGER NOT NULL DEFAULT 0")
        # v0.8.8: Pax DNS settings for iPhones/iPads on Pax's own filter.
        for col in ("dns_x_media", "dns_bluesky_media", "dns_youtube_restricted"):
            if col not in cols:
                self._conn.execute(f"ALTER TABLE accounts ADD COLUMN {col} INTEGER NOT NULL DEFAULT 1")
        # v0.8.15: verified support release. A device registered before 0.8.15 never
        # agreed to it, so the column arrives OFF (DEFAULT 0) and nothing here turns it
        # on; its support ID is made the first time the device is read.
        dcols = {r[1] for r in self._conn.execute("PRAGMA table_info(devices)")}
        if "support_id" not in dcols:
            self._conn.execute("ALTER TABLE devices ADD COLUMN support_id TEXT")
        if "support_release" not in dcols:
            self._conn.execute("ALTER TABLE devices ADD COLUMN support_release INTEGER NOT NULL DEFAULT 0")
        if "support_pending_on" not in dcols:
            self._conn.execute("ALTER TABLE devices ADD COLUMN support_pending_on INTEGER")
        # v0.8.18 trial day. Existing devices and accounts arrive with none (NULL):
        # they set up before trial days existed, so they never get one.
        for col in ("trial_until", "trial_ended_at"):
            if col not in dcols:
                self._conn.execute(f"ALTER TABLE devices ADD COLUMN {col} INTEGER")
        # v0.8.26: a released device the owner removed from their list. Only ever set on
        # a device whose password was already released; it never turns anything off.
        if "retired_at" not in dcols:
            self._conn.execute("ALTER TABLE devices ADD COLUMN retired_at INTEGER")
        if "trial_started_at" not in cols:
            self._conn.execute("ALTER TABLE accounts ADD COLUMN trial_started_at INTEGER")
        # v0.8.31: the name a private account gives for its trusted person's emails.
        if "display_name" not in cols:
            self._conn.execute("ALTER TABLE accounts ADD COLUMN display_name TEXT")
        # v0.8.31: private (device-only) accounts have no email.
        self._email_nullable()
        # v0.8.13 (project decision): pictures and video on X and Bluesky are always
        # blocked. Force every account back on and close any waiting request to turn
        # them off. Runs at every start; a no-op once done.
        self._conn.execute("UPDATE accounts SET dns_x_media=1, dns_bluesky_media=1 "
                           "WHERE dns_x_media != 1 OR dns_bluesky_media != 1")
        self._conn.execute("UPDATE blocklist_requests SET status='refused', closed_at=CAST(strftime('%s','now') AS INTEGER) "
                           "WHERE status='pending' AND action IN ('x_media_off', 'bluesky_media_off')")

    # v0.8.31: the column definition the rebuild below replaces, as every database
    # since v0.1 has it (SQLite keeps the CREATE TABLE text it was given).
    _EMAIL_NOT_NULL = re.compile(r"\bemail(\s+)TEXT\s+NOT\s+NULL\s+UNIQUE\b", re.IGNORECASE)
    _CREATE_ACCOUNTS = re.compile(r"^\s*CREATE\s+TABLE\s+(?:\"accounts\"|accounts)\s*\(", re.IGNORECASE)

    def _email_nullable(self) -> None:
        """v0.8.31: make accounts.email nullable (a private account has none), with
        SQLite's documented table-rebuild procedure, once. Idempotent: does nothing
        when the column already allows NULL (new databases, or after the first run).

        * One BEGIN IMMEDIATE transaction: a crash or any failed check rolls it all
          back and the old table stays exactly as it was (the server then refuses to
          start, rather than run on a half-migrated table).
        * The new table is the stored CREATE TABLE text with only `NOT NULL` taken off
          the email column, so every other column, default, the UNIQUE constraint on
          email (SQLite allows many NULLs under UNIQUE) and the column order stay.
        * Rows are copied by column name and counted; ids are unchanged, so every
          REFERENCES accounts(id) in the other tables still points at the same rows.
          foreign_keys is off only for the rebuild (as SQLite requires) and
          PRAGMA foreign_key_check must find no new broken reference before COMMIT.
        * Readers (pax-dns's read-only SqliteSource) see the old or the new table,
          never neither (WAL). The DoH-only second server (role "dns") has no
          database, so this never runs there.
        """
        info = self._conn.execute("PRAGMA table_info(accounts)").fetchall()
        email = [r for r in info if r[1] == "email"]
        if not email or not email[0][3]:          # notnull flag
            return
        sql = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='accounts'").fetchone()[0]
        new_sql, n = self._EMAIL_NOT_NULL.subn(r"email\1TEXT UNIQUE", sql, count=1)
        new_sql, m = self._CREATE_ACCOUNTS.subn("CREATE TABLE accounts_v0831_rebuild (", new_sql, count=1)
        if n != 1 or m != 1:
            raise RuntimeError("accounts table has an unexpected shape; email NOT NULL not removed")
        cols = ", ".join('"%s"' % r[1] for r in info)
        extra = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE tbl_name='accounts' AND type IN ('index','trigger') "
            "AND sql IS NOT NULL").fetchall()
        self._conn.execute("PRAGMA foreign_keys=OFF")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                before = self._conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
                # Rows that already break a foreign key (none expected) don't stop the
                # rebuild; only a new break does.
                bad_before = {tuple(r) for r in self._conn.execute("PRAGMA foreign_key_check")}
                self._conn.execute("DROP TABLE IF EXISTS accounts_v0831_rebuild")
                self._conn.execute(new_sql)
                self._conn.execute(f"INSERT INTO accounts_v0831_rebuild ({cols}) SELECT {cols} FROM accounts")
                after = self._conn.execute("SELECT COUNT(*) FROM accounts_v0831_rebuild").fetchone()[0]
                if after != before:
                    raise RuntimeError(f"accounts rebuild copied {after} of {before} rows")
                self._conn.execute("DROP TABLE accounts")
                self._conn.execute("ALTER TABLE accounts_v0831_rebuild RENAME TO accounts")
                for (x,) in extra:
                    self._conn.execute(x)
                bad = {tuple(r) for r in self._conn.execute("PRAGMA foreign_key_check")} - bad_before
                if bad:
                    raise RuntimeError(f"foreign key check failed after the accounts rebuild ({len(bad)} rows)")
                if bad_before:
                    log.warning("accounts rebuild: %d row(s) already broke a foreign key before it", len(bad_before))
                if self._conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] != before:
                    raise RuntimeError("accounts row count changed in the rebuild")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")
        finally:
            self._conn.execute("PRAGMA foreign_keys=ON")
        log.info("accounts.email now allows NULL (private accounts); %d account(s) kept", before)

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def one(self, sql: str, params: tuple = ()):
        return self.execute(sql, params).fetchone()

    def all(self, sql: str, params: tuple = ()):
        return self.execute(sql, params).fetchall()

    def transaction(self):
        return _Tx(self)

    def close(self) -> None:
        self._conn.close()


class _Tx:
    def __init__(self, db: Database):
        self.db = db

    def __enter__(self):
        self.db._lock.acquire()
        self.db._conn.execute("BEGIN IMMEDIATE")
        return self.db

    def __exit__(self, exc_type, exc, tb):
        try:
            self.db._conn.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self.db._lock.release()
        return False
