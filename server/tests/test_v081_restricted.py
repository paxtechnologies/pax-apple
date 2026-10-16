# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.1 (iPhone/iPad path): no exception for a site Pax always blocks. The
request is refused (422 restricted_site, PAX-DNS-010) with no wait and no email."""
import pax_restricted

from test_blocklist_api import HOUR, effective, env  # noqa: F401  (fixture)

MESSAGE = "This site is in a category Pax always blocks, so it can't be allowed."


def _ask(env, domain):
    return env.client.post("/v1/allowlist", headers=env.h, json={"domain": domain})


def _refused(r):
    body = r.json()
    return (r.status_code == 422 and body["error"] == "restricted_site"
            and body["pax_code"] == "PAX-DNS-010" and body["message"] == MESSAGE)


def test_restricted_sites_are_refused_without_wait_or_email(env):
    env.client.put("/v1/accounts/me/partner", headers=env.h, json={"email": "friend@example.com"})
    tld = sorted(pax_restricted.restricted_tlds())[0]
    kw = pax_restricted.keywords()[0]
    for domain in (pax_restricted.samples()[0],           # name rule
                   "www." + pax_restricted.samples()[0],   # a parent counts
                   "reddit.com",                           # hand list
                   f"site.{tld}",                          # whole top-level domain
                   f"{kw}-site.com",                       # name rule
                   "ssstik.io", "www.y2mate.com",          # media converters
                   "my-twittervideo.com",                  # media-converter name rule
                   "blocked-upstream.com",                 # CleanBrowsing blocks it
                   "down-upstream.com"):                   # CleanBrowsing can't be asked: fail closed
        r = _ask(env, domain)
        assert _refused(r), (domain, r.text)
    view = env.client.get("/v1/blocklist", headers=env.h).json()
    assert view["pending"] == [] and view["allowed"] == []
    assert "blocklist_allow_requested" not in env.mail.kinds_to("friend@example.com")


def test_benign_site_still_allowed_after_the_wait(env):
    assert _ask(env, "ads-tracker-example.com").status_code == 202
    env.clock.advance(72 * HOUR)
    assert effective(env)[1] == ["ads-tracker-example.com"]


def test_effective_list_and_sweep_never_carry_a_restricted_site(env):
    acct = env.app.state.escrow.authenticate(env.h["Authorization"][7:])
    db = env.app.state.blocklist.db
    # As if an older server had stored one, or a request was made before v0.8.1.
    db.execute("INSERT INTO blocklist_entries(account_id, list, domain, created_at) VALUES (?,?,?,?)",
               (acct["id"], "allow", "ssstik.io", 0))
    assert effective(env)[1] == []
    assert _ask(env, "fine-site.com").status_code == 202
    db.execute("UPDATE blocklist_requests SET domain='reddit.com' WHERE domain='fine-site.com'")
    env.clock.advance(72 * HOUR)
    env.app.state.blocklist.apply_due()
    rows = db.all("SELECT status FROM blocklist_requests WHERE domain='reddit.com'")
    assert [r["status"] for r in rows] == ["refused"]
    assert effective(env)[1] == []
