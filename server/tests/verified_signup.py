# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.32 test helper: POST /v1/accounts no longer makes accounts, so tests make
them the only way there is: an emailed 6-digit code (POST /v1/accounts/email/start,
then /verify). Returns the /verify response (201 new account, 200 sign-in to an
existing one) or the /start response when that one failed (e.g. 429)."""
import re


def verified_signup(client, email, headers=None, label="test"):
    esc = client.app.state.escrow
    sender = esc.sender
    had_own = "send" in vars(sender)
    orig = sender.send
    sent = []

    def grab(m):
        sent.append(m)
        return orig(m)

    sender.send = grab
    try:
        r = client.post("/v1/accounts/email/start", json={"email": email}, headers=headers or {})
    finally:
        if had_own:
            sender.send = orig
        else:
            del sender.send
    if r.status_code != 202:
        return r
    mails = [m for m in sent if m.kind in ("signup_code", "signin_code")]
    assert mails, f"no code email went to {email!r} (mail budget?)"
    code = re.search(r"\b(\d{6})\b", mails[-1].body).group(1)
    return client.post("/v1/accounts/email/verify", json={"email": email, "code": code, "label": label})
