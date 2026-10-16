# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0: POST /v1/notify relay (partner emails for a Mac on local escrow),
SMTP sender from the environment, and the iPhone path's own partner emails
unchanged."""
from test_escrow_api import env, make_account, make_device, past_grace  # noqa: F401
from pax_server.notify import SmtpEmailSender


def test_relay_sends_to_account_and_partner(env):  # noqa: F811
    h = make_account(env, "me@example.com")
    r = env.client.post("/v1/notify", headers=h, json={
        "kind": "removal_requested", "subject": "Removal requested for this Mac", "body": "You asked.",
        "partner_email": "friend@example.org", "partner_body": "Your partner asked."})
    assert r.status_code == 202, r.text
    assert r.json() == {"relayed": True, "to_partner": True}
    assert env.mail.kinds_to("friend@example.org") == ["removal_requested"]
    sent = [e for e in env.mail.outbox if e.to == "friend@example.org"][0]
    assert sent.subject.startswith("[Pax partner]") and sent.body == "Your partner asked."
    assert "removal_requested" in env.mail.kinds_to("me@example.com")


def test_relay_needs_auth_and_valid_input(env):  # noqa: F811
    assert env.client.post("/v1/notify", json={"kind": "x", "subject": "s", "body": "b"}).status_code == 401
    h = make_account(env)
    r = env.client.post("/v1/notify", headers=h, json={"kind": "Bad Kind", "subject": "s", "body": "b"})
    assert r.status_code == 422
    r = env.client.post("/v1/notify", headers=h, json={"kind": "x", "subject": "s", "body": "b",
                                                       "partner_email": "nope"})
    assert r.status_code == 400


def test_relay_is_rate_limited(env):  # noqa: F811
    h = make_account(env)
    for _ in range(50):
        assert env.client.post("/v1/notify", headers=h, json={"kind": "k", "subject": "s",
                                                              "body": "b"}).status_code == 202
    r = env.client.post("/v1/notify", headers=h, json={"kind": "k", "subject": "s", "body": "b"})
    assert r.status_code == 429
    env.clock.advance(86401)
    assert env.client.post("/v1/notify", headers=h, json={"kind": "k", "subject": "s",
                                                          "body": "b"}).status_code == 202


def test_iphone_partner_emails_unchanged(env):  # noqa: F811
    h = make_account(env, "me@example.com")
    env.client.put("/v1/accounts/me/partner", headers=h, json={"email": "friend@example.org"})
    dev = make_device(env, h)
    past_grace(env)
    env.client.post(f"/v1/devices/{dev}/removal-request", headers=h)
    env.client.post(f"/v1/devices/{dev}/removal-request/cancel", headers=h)
    kinds = env.mail.kinds_to("friend@example.org")
    assert kinds == ["partner_added", "removal_requested", "removal_cancelled"]


def test_smtp_sender_from_env():
    assert SmtpEmailSender.from_env({}) is None
    s = SmtpEmailSender.from_env({"PAX_SMTP_HOST": "smtp.example.org", "PAX_SMTP_USER": "pax@example.org",
                                  "PAX_SMTP_PASSWORD": "x"})
    assert s.host == "smtp.example.org" and s.port == 587 and s.security == "starttls" and s.sender == "pax@example.org"
