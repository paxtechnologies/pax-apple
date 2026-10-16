# SPDX-License-Identifier: GPL-3.0-only
"""Accountability-partner emails for a Mac on local escrow (v0.8.0).

Until v0.7 the Pax server emailed the partner about every removal request,
cancellation, reveal, emergency, wait decrease, partner change and blocklist
change (server/pax_server/escrow.py `_notify`). With the secrets now held by
pax-guard, pax-guard sends those emails itself, through one of two pluggable
transports:

  relay  the optional Pax server or your own (server/: POST /v1/notify, account
         token), which mails through its own SMTP (PAX_SMTP_* settings);
  smtp   your own mail account (host, port, STARTTLS or SSL, user, password);
         the password lives only in /Library/PaxGuard/escrow/notify.json
         (root 0600, integrity-checked like the escrow).

The rule (fail closed): when a partner is set, anything that would notify them
must be delivered, or queued and retried, BEFORE its wait starts. Until the
partner email has gone out there is no countdown (the request shows as
"telling your partner"), and the app shows PAX-ESCROW-010. A reveal needs its
email delivered first. Cancelling (which makes Pax stricter) never waits on
email; its message is queued. With no partner set, nothing is sent and
everything stays on the Mac.
"""
from __future__ import annotations

import json
import re
import secrets
import smtplib
import ssl
import time
import urllib.request
from email.message import EmailMessage

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,63}$")
RETRY_SECONDS = (60, 300, 900, 1800, 3600)   # then hourly


class NotifyError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def valid_email(addr: str | None) -> bool:
    return bool(addr) and bool(EMAIL_RE.match(addr.strip()))


def validate_transport(t: dict | None) -> dict | None:
    if not t:
        return None
    kind = t.get("kind")
    if kind == "relay":
        url = str(t.get("url", ""))
        host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        local = host in ("127.0.0.1", "localhost", "::1") or host.startswith(("10.", "192.168."))
        if not (url.startswith("https://") or (url.startswith("http://") and local)):
            raise NotifyError("PAX-ESCROW-011", "the notify server must use https:// (http only on this Mac/LAN)")
        if not t.get("token"):
            raise NotifyError("PAX-ESCROW-011", "the notify server needs your account token")
        return {"kind": "relay", "url": url.rstrip("/") + "/", "token": str(t["token"])}
    if kind == "smtp":
        if not t.get("host") or t.get("security", "starttls") not in ("starttls", "ssl"):
            raise NotifyError("PAX-ESCROW-011", "SMTP needs a host and starttls or ssl")
        port = int(t.get("port") or (465 if t.get("security") == "ssl" else 587))
        sender = t.get("from") or t.get("username")
        if not valid_email(sender):
            raise NotifyError("PAX-ESCROW-011", "SMTP needs a From address")
        return {"kind": "smtp", "host": str(t["host"]), "port": port, "security": t.get("security", "starttls"),
                "username": str(t.get("username", "")), "password": str(t.get("password", "")),
                "from": sender}
    raise NotifyError("PAX-ESCROW-011", "unknown notification transport")


def send_relay(t: dict, msg: dict, partner: str | None, timeout: int = 20, opener=None) -> None:
    body = json.dumps({"kind": msg["kind"], "subject": msg["subject"], "body": msg["user_body"],
                       "partner_email": partner, "partner_body": msg["partner_body"]}).encode()
    req = urllib.request.Request(t["url"] + "v1/notify", data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {t['token']}"})
    with (opener or urllib.request.urlopen)(req, timeout=timeout) as r:  # noqa: S310
        if r.status not in (200, 201, 202):
            raise OSError(f"HTTP {r.status}")


def send_smtp(t: dict, msg: dict, partner: str | None, owner: str | None, timeout: int = 20,
              smtp_factory=None) -> None:
    ctx = ssl.create_default_context()
    factory = smtp_factory or (smtplib.SMTP_SSL if t["security"] == "ssl" else smtplib.SMTP)
    kwargs = {"timeout": timeout}
    if t["security"] == "ssl" and smtp_factory is None:
        kwargs["context"] = ctx
    with factory(t["host"], t["port"], **kwargs) as server:
        if t["security"] == "starttls":
            server.starttls(context=ctx)
        if t.get("username"):
            server.login(t["username"], t.get("password", ""))
        for to, subject, text in ([(partner, f"[Pax partner] {msg['subject']}", msg["partner_body"])]
                                  if partner else []) + ([(owner, msg["subject"], msg["user_body"])] if owner else []):
            m = EmailMessage()
            m["From"], m["To"], m["Subject"] = t["from"], to, subject
            m["X-Pax-Event"] = msg["kind"]
            m.set_content(text)
            server.send_message(m)


class PartnerNotifier:
    """Owns the partner setting, the transport and the outbox. `store` gives
    integrity-checked root-only load/save (LocalEscrow's)."""

    def __init__(self, store_load, store_save, clock=time.time, log=print, senders=None):
        self._load = store_load
        self._save = store_save
        self.clock = clock
        self.log = log
        self.senders = senders or {"relay": send_relay, "smtp": send_smtp}

    # -------------------------------------------------------------- config
    def config(self) -> dict:
        cfg = self._load("notify.json", None) or {}
        cfg.setdefault("partner", None)
        cfg.setdefault("pending_partner", None)
        cfg.setdefault("owner_email", None)
        cfg.setdefault("transport", None)
        cfg.setdefault("outbox", [])
        return cfg

    def partner(self) -> str | None:
        return self.config().get("partner")

    def public_view(self) -> dict:
        c = self.config()
        t = c.get("transport") or {}
        return {"partner": c["partner"], "pending_partner": c["pending_partner"], "owner_email": c["owner_email"],
                "transport": ({"kind": t.get("kind"), "url": t.get("url"), "host": t.get("host"),
                               "from": t.get("from")} if t else None),
                "queued": [{"id": m["id"], "kind": m["kind"], "attempts": m["attempts"], "gate": m.get("gate"),
                            "last_error": m.get("last_error", "")} for m in c["outbox"]]}

    def set_transport(self, transport: dict | None, owner_email: str | None = None) -> dict:
        c = self.config()
        if transport is not None:
            new = validate_transport(transport)
            old = c.get("transport") or {}
            if new and new["kind"] == "smtp" and not new["password"] and old.get("kind") == "smtp":
                new["password"] = old.get("password", "")          # keep the stored password
            c["transport"] = new
        if owner_email is not None:
            if owner_email and not valid_email(owner_email):
                raise NotifyError("PAX-ESCROW-011", "that isn't an email address")
            c["owner_email"] = owner_email or None
        self._save("notify.json", c)
        return self.public_view()

    def set_partner_now(self, email: str | None) -> None:
        c = self.config()
        c["partner"] = email
        c["pending_partner"] = None
        self._save("notify.json", c)

    def set_pending_partner(self, pending: dict | None) -> None:
        c = self.config()
        c["pending_partner"] = pending
        self._save("notify.json", c)

    # ---------------------------------------------------------------- send
    def _deliver(self, msg: dict, partner: str | None) -> None:
        c = self.config()
        t = c.get("transport")
        if not t:
            raise NotifyError("PAX-ESCROW-010", "no way to email your partner is set up (Settings › Accountability partner email)")
        if t["kind"] == "relay":
            self.senders["relay"](t, msg, partner)
        else:
            self.senders["smtp"](t, msg, partner, c.get("owner_email"))

    def notify(self, kind: str, subject: str, user_body: str, partner_body: str | None = None,
               gate: dict | None = None, to: str | None = None) -> bool:
        """Send now; on failure queue it (with `gate`, the action waiting on it)
        and return False. With no partner (and no `to` given) nothing is sent."""
        partner = to or self.partner()
        if not partner:
            return True
        msg = {"id": secrets.token_hex(6), "kind": kind, "subject": subject, "user_body": user_body,
               "partner_body": partner_body or user_body, "to": partner, "gate": gate,
               "created_at": int(self.clock()), "attempts": 0, "next_at": 0}
        try:
            self._deliver(msg, partner)
            return True
        except Exception as exc:  # noqa: BLE001 - queue and retry
            msg["attempts"] = 1
            msg["last_error"] = (getattr(exc, "message", None) or type(exc).__name__)[:160]
            msg["next_at"] = int(self.clock()) + RETRY_SECONDS[0]
            c = self.config()
            c["outbox"].append(msg)
            self._save("notify.json", c)
            self.log(f"PAX-ESCROW-010 partner email '{kind}' not sent ({msg['last_error']}); queued")
            return False

    def flush(self) -> list[dict]:
        """Retry what's due. Returns the gates of the messages delivered now."""
        c = self.config()
        now = int(self.clock())
        delivered, keep = [], []
        for msg in c["outbox"]:
            if now < msg.get("next_at", 0):
                keep.append(msg)
                continue
            try:
                self._deliver(msg, msg.get("to"))
                delivered.append(msg.get("gate") or {})
            except Exception as exc:  # noqa: BLE001
                msg["attempts"] += 1
                msg["last_error"] = (getattr(exc, "message", None) or type(exc).__name__)[:160]
                msg["next_at"] = now + RETRY_SECONDS[min(msg["attempts"] - 1, len(RETRY_SECONDS) - 1)]
                keep.append(msg)
        if c["outbox"]:
            c["outbox"] = keep
            self._save("notify.json", c)
        return [g for g in delivered if g]

    def drop_gate(self, gate: dict) -> None:
        """A cancelled action no longer waits on its email (the email is dropped
        too: it would announce something that won't happen)."""
        c = self.config()
        c["outbox"] = [m for m in c["outbox"] if m.get("gate") != gate]
        self._save("notify.json", c)
