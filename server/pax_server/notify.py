# SPDX-License-Identifier: GPL-3.0-only
"""Pluggable email sending. v0.1 ships a logging stub and an in-memory sender
for tests. Swap in SMTP / a transactional provider by implementing EmailSender.

Never put a removal password in an email: it is only ever returned over the
authenticated API after the wait has elapsed.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

log = logging.getLogger("pax.notify")

CRISIS_LINES = [
    {"region": "UK & Ireland", "name": "Samaritans", "contact": "116 123 (free, 24/7)",
     "url": "https://www.samaritans.org"},
    {"region": "US", "name": "988 Suicide & Crisis Lifeline", "contact": "Call or text 988",
     "url": "https://988lifeline.org"},
    {"region": "Anywhere", "name": "Emergency services",
     "contact": "999 / 112 (UK & EU), 911 (US) if you are in immediate danger", "url": None},
]


def crisis_text() -> str:
    lines = ["If you are struggling or thinking about harming yourself, please reach out now:"]
    for c in CRISIS_LINES:
        lines.append(f"  - {c['name']} ({c['region']}): {c['contact']}")
    return "\n".join(lines)


@dataclass
class Email:
    to: str
    subject: str
    body: str
    kind: str  # machine-readable event type, e.g. "removal_requested"


class EmailSender(Protocol):
    def send(self, email: Email) -> None: ...


class LoggingEmailSender:
    """Default stub: logs recipient + subject only (never the body)."""

    def send(self, email: Email) -> None:
        log.info("email[%s] to=%s subject=%r", email.kind, email.to, email.subject)


# v0.8.10: Pax's own sender addresses. Automated mail moves to the mail.
# subdomain to protect paxpeace.com's reputation. v0.8.11: mail.paxpeace.com is
# verified in Resend, so the default is the subdomain sender; servers pick it up
# when they self-update. A refused subdomain sender still falls back to hello@.
PAX_LEGACY_FROM = "Pax <hello@paxpeace.com>"
PAX_SUBDOMAIN_FROM = "Pax <noreply@mail.paxpeace.com>"
PAX_DEFAULT_MAIL_FROM = PAX_SUBDOMAIN_FROM
PAX_REPLY_TO = "hello@paxpeace.com"


def _addr(value: str) -> str:
    from email.utils import parseaddr
    return parseaddr(value or "")[1].lower()


def resolve_sender(env) -> tuple[str, str]:
    """(From, Reply-To) for the server's mail.
      PAX_MAIL_FROM          wins when set (any address you've verified).
      PAX_SMTP_FROM          the v0.8.0 setting; Pax's own production value
                             (hello@paxpeace.com) means "Pax's default".
      neither                PAX_SMTP_USER, as before (self-hosting).
    Reply-To: PAX_MAIL_REPLY_TO, else hello@paxpeace.com when sending as Pax."""
    explicit = (env.get("PAX_MAIL_FROM") or "").strip()
    legacy = (env.get("PAX_SMTP_FROM") or "").strip()
    if explicit:
        sender = explicit
    elif legacy and _addr(legacy) == _addr(PAX_LEGACY_FROM):
        sender = PAX_DEFAULT_MAIL_FROM
    else:
        sender = legacy or env.get("PAX_SMTP_USER", "")
    reply_to = (env.get("PAX_MAIL_REPLY_TO") or "").strip()
    if not reply_to and _addr(sender).endswith("paxpeace.com") and _addr(sender) != _addr(PAX_REPLY_TO):
        reply_to = PAX_REPLY_TO
    return sender, reply_to


class SmtpEmailSender:
    """v0.8.0: real delivery through an SMTP server you choose (self-hosting).
    Configured from the environment by `from_env()`:
      PAX_SMTP_HOST, PAX_SMTP_PORT (587), PAX_SMTP_SECURITY (starttls | ssl),
      PAX_SMTP_USER, PAX_SMTP_PASSWORD, PAX_SMTP_FROM; v0.8.10: PAX_MAIL_FROM,
      PAX_MAIL_REPLY_TO (see resolve_sender).
    Certificates are always verified. Raises on failure (callers decide).
    v0.8.10: if the server refuses a Pax subdomain sender (not verified yet), the
    message is sent once more from hello@paxpeace.com, so unlocks never wait on it."""

    def __init__(self, host: str, port: int = 587, security: str = "starttls", username: str = "",
                 password: str = "", sender: str = "", timeout: int = 20, reply_to: str = ""):
        if security not in ("starttls", "ssl"):
            raise ValueError("security must be starttls or ssl")
        self.host, self.port, self.security = host, port, security
        self.username, self.password = username, password
        self.sender = sender or username
        self.reply_to = reply_to
        self.timeout = timeout

    @classmethod
    def from_env(cls, env=None) -> "SmtpEmailSender | None":
        import os
        env = os.environ if env is None else env
        host = env.get("PAX_SMTP_HOST")
        if not host:
            return None
        sender, reply_to = resolve_sender(env)
        return cls(host, int(env.get("PAX_SMTP_PORT", "587")), env.get("PAX_SMTP_SECURITY", "starttls"),
                   env.get("PAX_SMTP_USER", ""), env.get("PAX_SMTP_PASSWORD", ""), sender,
                   reply_to=reply_to)

    @property
    def from_domain(self) -> str:
        return _addr(self.sender).rpartition("@")[2]

    def send(self, email: Email) -> None:
        import smtplib
        try:
            self._send(email, self.sender)
        except (smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as exc:
            # Only a Pax subdomain sender falls back, and only to the verified address.
            if not _addr(self.sender).endswith(".paxpeace.com"):
                raise
            log.warning("email[%s] sender %s refused (%s); sending from %s", email.kind,
                        _addr(self.sender), getattr(exc, "smtp_code", "?"), _addr(PAX_LEGACY_FROM))
            self._send(email, PAX_LEGACY_FROM)

    def _send(self, email: Email, sender: str) -> None:
        import smtplib
        import ssl
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = sender, email.to, email.subject
        if self.reply_to and _addr(self.reply_to) != _addr(sender):
            msg["Reply-To"] = self.reply_to
        msg["X-Pax-Event"] = email.kind
        msg.set_content(email.body)
        ctx = ssl.create_default_context()
        if self.security == "ssl":
            server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        with server:
            if self.security == "starttls":
                server.starttls(context=ctx)
            if self.username:
                server.login(self.username, self.password)
            server.send_message(msg)
        log.info("email[%s] sent to=%s", email.kind, email.to)


class MemoryEmailSender:
    def __init__(self) -> None:
        self.outbox: list[Email] = []

    def send(self, email: Email) -> None:
        self.outbox.append(email)

    def kinds_to(self, address: str) -> list[str]:
        return [e.kind for e in self.outbox if e.to == address]
