# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.10: configurable sender (PAX_MAIL_FROM), Reply-To, Pax's default sender
that a later release can flip to mail.paxpeace.com, and the fallback to the
verified hello@ address so a refused subdomain sender never blocks an unlock."""
import smtplib

import pytest

from pax_server import notify
from pax_server.notify import Email, SmtpEmailSender, resolve_sender

BASE = {"PAX_SMTP_HOST": "smtp.resend.com", "PAX_SMTP_USER": "resend", "PAX_SMTP_PASSWORD": "re_x"}


def test_production_env_uses_subdomain_default_with_reply_to_hello():
    # v0.8.11: the default is the verified mail.paxpeace.com sender.
    s = SmtpEmailSender.from_env({**BASE, "PAX_SMTP_FROM": "Pax <hello@paxpeace.com>"})
    assert s.sender == "Pax <noreply@mail.paxpeace.com>" == notify.PAX_DEFAULT_MAIL_FROM
    assert notify.PAX_DEFAULT_MAIL_FROM == notify.PAX_SUBDOMAIN_FROM
    assert s.reply_to == "hello@paxpeace.com"
    assert s.from_domain == "mail.paxpeace.com"


def test_legacy_hello_sender_adds_no_reply_to_loop(monkeypatch):
    monkeypatch.setattr(notify, "PAX_DEFAULT_MAIL_FROM", notify.PAX_LEGACY_FROM)
    s = SmtpEmailSender.from_env({**BASE, "PAX_SMTP_FROM": "Pax <hello@paxpeace.com>"})
    assert s.sender == "Pax <hello@paxpeace.com>"
    assert s.reply_to == ""            # Reply-To would equal From
    assert s.from_domain == "paxpeace.com"


def test_pax_mail_from_wins_with_reply_to_hello():
    sender, reply = resolve_sender({**BASE, "PAX_SMTP_FROM": "Pax <hello@paxpeace.com>",
                                    "PAX_MAIL_FROM": "Pax <noreply@mail.paxpeace.com>"})
    assert sender == "Pax <noreply@mail.paxpeace.com>" and reply == "hello@paxpeace.com"


def test_flipping_the_default_moves_production_without_env_changes(monkeypatch):
    monkeypatch.setattr(notify, "PAX_DEFAULT_MAIL_FROM", notify.PAX_SUBDOMAIN_FROM)
    s = SmtpEmailSender.from_env({**BASE, "PAX_SMTP_FROM": "Pax <hello@paxpeace.com>"})
    assert s.sender == "Pax <noreply@mail.paxpeace.com>" and s.reply_to == "hello@paxpeace.com"
    assert s.from_domain == "mail.paxpeace.com"


def test_self_hosting_unchanged():
    assert resolve_sender({"PAX_SMTP_USER": "pax@example.org"}) == ("pax@example.org", "")
    assert resolve_sender({"PAX_SMTP_FROM": "Me <me@example.org>"}) == ("Me <me@example.org>", "")
    assert resolve_sender({"PAX_SMTP_FROM": "Me <me@example.org>", "PAX_MAIL_REPLY_TO": "r@example.org"}) \
        == ("Me <me@example.org>", "r@example.org")


class FakeSMTP:
    sent: list = []
    refuse: set = set()

    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self, context=None): pass
    def login(self, u, p): pass

    def send_message(self, msg):
        if msg["From"] in FakeSMTP.refuse:
            raise smtplib.SMTPSenderRefused(550, b"domain not verified", msg["From"])
        FakeSMTP.sent.append(msg)


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.sent, FakeSMTP.refuse = [], set()
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    return FakeSMTP


def test_headers_on_the_wire(smtp):
    s = SmtpEmailSender.from_env({**BASE, "PAX_MAIL_FROM": "Pax <noreply@mail.paxpeace.com>"})
    s.send(Email("a@example.org", "Hi", "Body", "test"))
    (m,) = smtp.sent
    assert m["From"] == "Pax <noreply@mail.paxpeace.com>" and m["Reply-To"] == "hello@paxpeace.com"
    assert m["X-Pax-Event"] == "test"


def test_refused_subdomain_sender_falls_back_to_hello(smtp):
    smtp.refuse = {"Pax <noreply@mail.paxpeace.com>"}
    s = SmtpEmailSender.from_env({**BASE, "PAX_MAIL_FROM": "Pax <noreply@mail.paxpeace.com>"})
    s.send(Email("a@example.org", "Unlock", "Body", "removal_ready"))
    (m,) = smtp.sent
    assert m["From"] == "Pax <hello@paxpeace.com>" and m["Reply-To"] is None


def test_default_sender_refused_falls_back_to_hello(smtp):
    # v0.8.11: Pax's production env now sends from the subdomain by default.
    smtp.refuse = {"Pax <noreply@mail.paxpeace.com>"}
    SmtpEmailSender.from_env({**BASE, "PAX_SMTP_FROM": "Pax <hello@paxpeace.com>"}).send(
        Email("a@example.org", "Unlock", "Body", "removal_ready"))
    (m,) = smtp.sent
    assert m["From"] == "Pax <hello@paxpeace.com>" and m["Reply-To"] is None


def test_refused_other_sender_still_raises(smtp):
    smtp.refuse = {"Pax <noreply@mail.paxpeace.com>", "Pax <hello@paxpeace.com>", "Me <me@example.org>"}
    for env in ({**BASE, "PAX_SMTP_FROM": "Pax <hello@paxpeace.com>"}, {**BASE, "PAX_MAIL_FROM": "Pax <hello@paxpeace.com>"},
                {**BASE, "PAX_MAIL_FROM": "Me <me@example.org>"}):
        with pytest.raises(smtplib.SMTPSenderRefused):
            SmtpEmailSender.from_env(env).send(Email("a@example.org", "s", "b", "k"))
    assert smtp.sent == []


def test_health_reports_only_the_sending_domain(tmp_path):
    from fastapi.testclient import TestClient
    from pax_server.config import Settings
    from pax_server.crypto import generate_key_b64
    from pax_server.main import create_app
    from pax_server.notify import MemoryEmailSender
    s = Settings(db_path=str(tmp_path / "h.db"), server_key_b64=generate_key_b64())
    smtp_sender = SmtpEmailSender.from_env({**BASE, "PAX_SMTP_FROM": "Pax <hello@paxpeace.com>"})
    h = TestClient(create_app(s, sender=smtp_sender)).get("/v1/health").json()
    assert h["mail_from_domain"] == "mail.paxpeace.com" and "noreply@" not in str(h) and "hello@" not in str(h)
    s2 = Settings(db_path=str(tmp_path / "h2.db"), server_key_b64=generate_key_b64())
    assert "mail_from_domain" not in TestClient(create_app(s2, sender=MemoryEmailSender())).get("/v1/health").json()
