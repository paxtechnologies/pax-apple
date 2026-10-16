# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.7: the "Ads and trackers" switch on Home works live.

Up to 0.8.6 pax-guard on local escrow only read the set-up choice
(config adblock_default), so the switch on Home did nothing. Now it follows the
YouTube Restricted Mode model: state/settings.json (kept across updates and
restarts), the tamper log, both directions at once with no wait and no partner
email (ads are a convenience filter, not restricted-content protection).

Switching ads off must never weaken restricted-content blocking: the ad list
(HaGeZi Light) also carries restricted names (adult ad servers), so those stay
in /etc/hosts at restricted priority whether ads are on or off, and nothing a
user can free (exceptions, the ad allow-list) frees them."""
import json
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
sys.path.append(str(HERE.parents[1] / "common"))
import filter_lists as fl  # noqa: E402
import guard_config as gc  # noqa: E402
import pax_guard as pg  # noqa: E402
import pax_restricted as pr  # noqa: E402
from domain_matcher import SmallSuffixSet  # noqa: E402
from test_guard import ad_list, make_guard, remote  # noqa: E402
from test_v08_guard import local_guard  # noqa: E402

# A restricted name built from Pax's own restricted top-level domains (kept
# encoded in pax_restricted.py), so no such word is spelled out here.
TLD = sorted(pr.restricted_tlds())[0]
RESTRICTED_AD = f"track.example.{TLD}"


def ads_with_restricted(n=12_000, extra=()):
    body = "\n".join(f"0.0.0.0 t{i}.ads.example" for i in range(n))
    more = "\n".join(f"0.0.0.0 {d}" for d in (RESTRICTED_AD,) + tuple(extra))
    return ("# HaGeZi\n" + body + "\n" + more + "\n").encode()


def hosts(s):
    return s.files[gc.HOSTS_PATH]


def join_bg(g, name):
    t = g._bg.get(name)
    if t is not None:
        t.join(10)


def tamper(g, kind="setting:adblock"):
    return [e for e in g.tamper_log.entries() if e["kind"] == kind]


# ------------------------------------------------------------ local escrow
def test_local_switch_off_and_on_is_immediate_logged_and_survives(tmp_path):
    g, s = local_guard(tmp_path)
    s.urls[gc.ADS_LIST_URL] = ads_with_restricted()
    g.cycle()
    assert "0.0.0.0 t5.ads.example" in hosts(s)
    assert g.settings_view()["adblock"] is True and g.settings_view()["adblock_local"] is True

    r = g.handle_request({"cmd": "settings.set", "adblock": False}, 501)
    assert r["ok"] and r["settings"]["adblock"] is False
    # Straight away, without waiting for the next cycle.
    assert "t5.ads.example" not in hosts(s)
    assert "0.0.0.0 dns.google" in hosts(s)                      # DoH names untouched
    assert f"0.0.0.0 {RESTRICTED_AD}\n" in hosts(s)               # restricted ad name stays
    assert tamper(g)[-1]["detail"] == {"from": True, "to": False, "uid": 501}
    assert g.tamper_log.verify()[0]
    # No wait and nothing sent: no request, nothing queued for a partner.
    assert not g.blocklist.view().get("requests")
    # The next cycle agrees (the loop doesn't put them back).
    g.cycle()
    assert "t5.ads.example" not in hosts(s)

    # Restart or update: a new Guard reads it back from state/.
    state = tmp_path / "PaxGuard" / "state"
    g2 = pg.Guard(g.cfg, s, state_dir=state, quarantine_dir=tmp_path / "q")
    assert g2.local_adblock is False and g2.adblock is False
    assert json.loads(s.read(str(state / "settings.json")))["adblock"] is False
    g2.cycle()
    assert "t5.ads.example" not in hosts(s)

    r = g2.handle_request({"cmd": "settings.set", "adblock": True}, 501)
    assert r["settings"]["adblock"] is True
    assert "0.0.0.0 t5.ads.example" in hosts(s)                  # the kept copy, at once
    assert tamper(g2)[-1]["detail"] == {"from": False, "to": True, "uid": 501}
    assert g2.status_summary()["settings"]["adblock"] is True


def test_youtube_and_ads_are_kept_side_by_side(tmp_path):
    g, s = local_guard(tmp_path)
    g.handle_request({"cmd": "settings.set", "youtube_restricted": False}, 501)
    g.handle_request({"cmd": "settings.set", "adblock": False}, 501)
    st = json.loads(s.read(str(tmp_path / "PaxGuard" / "state" / "settings.json")))
    assert st["youtube_restricted"] is False and st["adblock"] is False
    g.handle_request({"cmd": "settings.set", "adblock": True}, 501)
    assert g.youtube_restricted is False and g.local_adblock is True


def test_set_up_choice_is_the_default_until_the_switch_is_used(tmp_path):
    g, s = local_guard(tmp_path, adblock_default=False)
    s.urls[gc.ADS_LIST_URL] = ads_with_restricted()
    g.cycle()
    assert g.local_adblock is False and "t5.ads.example" not in hosts(s)
    assert g.local_remote()["adblock"] is False
    assert not g._load_json("ads.json", [])                      # nothing downloaded while off


def test_switching_on_after_set_up_with_ads_off_fetches_the_list(tmp_path):
    g, s = local_guard(tmp_path, adblock_default=False)
    s.urls[gc.ADS_LIST_URL] = ads_with_restricted()
    g.cycle()
    r = g.handle_request({"cmd": "settings.set", "adblock": True}, 501)
    assert r["ok"] and r["settings"]["adblock"] is True          # the app isn't held up
    join_bg(g, "ads")
    assert "0.0.0.0 t5.ads.example" in hosts(s)
    assert g._load_json("lists-meta.json", {})["ads_fetched_at"] == s.t


def test_switching_on_with_the_lists_offline_blocks_nothing_less(tmp_path):
    g, s = local_guard(tmp_path, adblock_default=False)
    g.cycle()
    before = hosts(s)
    s.fail_fetch = True
    r = g.handle_request({"cmd": "settings.set", "adblock": True}, 501)
    join_bg(g, "ads")
    assert r["ok"] and hosts(s) == before                        # nothing removed; ads come later
    s.fail_fetch = False
    s.urls[gc.ADS_LIST_URL] = ad_list()
    s.t += gc.ADS_RETRY_SECONDS
    g.cycle()
    assert "0.0.0.0 t5.ads.example" in hosts(s)


def test_bad_values_and_server_escrow_change_nothing(tmp_path):
    g, s = local_guard(tmp_path)
    for bad in ("no", 0, None, "false"):
        r = g.handle_request({"cmd": "settings.set", "adblock": bad}, 501)
        assert r["ok"] is False and r["code"] == "PAX-GUARD-012"
    assert g.local_adblock is True and tamper(g) == []

    # A request with a refused part changes nothing at all.
    p, _ = local_guard(tmp_path / "p", dns_mode="profile")
    r = p.handle_request({"cmd": "settings.set", "adblock": False, "youtube_restricted": False}, 501)
    assert r["code"] == "PAX-DNS-011" and p.local_adblock is True
    # On a Mac whose DNS doesn't go through the forwarder, the ads switch still works (it's /etc/hosts).
    r = p.handle_request({"cmd": "settings.set", "adblock": False}, 501)
    assert r["ok"] and p.local_adblock is False

    srv, ss = make_guard(tmp_path / "srv")
    ss.urls["https://pax.example.org/v1/guard/config"] = remote()
    srv.cycle()
    r = srv.handle_request({"cmd": "settings.set", "adblock": False}, 501)
    assert r["ok"] is False and r["code"] == "PAX-ESCROW-009"
    assert srv.adblock is True and srv.settings_view()["adblock_local"] is False
    assert srv.settings_view()["adblock"] is True


def test_settings_set_runs_on_the_socket_thread_safely(tmp_path):
    g, s = local_guard(tmp_path)
    s.urls[gc.ADS_LIST_URL] = ads_with_restricted()
    g.cycle()
    errors = []

    def flip(v):
        try:
            for _ in range(5):
                g.handle_request({"cmd": "settings.set", "adblock": v}, 501)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    ts = [threading.Thread(target=flip, args=(v,)) for v in (True, False)]
    for t in ts:
        t.start()
    g.cycle()
    for t in ts:
        t.join()
    assert not errors
    g.handle_request({"cmd": "settings.set", "adblock": False}, 501)
    assert "t5.ads.example" not in hosts(s) and RESTRICTED_AD in hosts(s)


# ----------------------------------------------- restricted names in the ads
def test_restricted_ad_names_are_never_freed(tmp_path):
    g, s = local_guard(tmp_path)
    converter = g.restricted_sites()[0]
    sub = f"ads.{converter}"
    s.urls[gc.ADS_LIST_URL] = ads_with_restricted(extra=(sub,))
    g.cycle()
    assert set(g.restricted_ad_names()) == {RESTRICTED_AD, sub}
    g.handle_request({"cmd": "settings.set", "adblock": False}, 501)
    h = hosts(s)
    assert f"0.0.0.0 {RESTRICTED_AD}\n" in h and f"0.0.0.0 {sub}\n" in h

    # Neither an exception nor the ad allow-list frees them, ads on or off.
    out = gc.hosts_domains([], ads=[RESTRICTED_AD], allowlist=[f"example.{TLD}"],
                           exceptions=[f"example.{TLD}"], restricted_exact=[RESTRICTED_AD])
    assert RESTRICTED_AD in out
    out = gc.hosts_domains([], ads=None, exceptions=[f"example.{TLD}"], restricted_exact=[RESTRICTED_AD])
    assert RESTRICTED_AD in out


def test_restricted_ad_names_go_in_ahead_of_ads_under_the_cap():
    ads = [f"a{i}.ads.example" for i in range(500)] + ["late.example.org"]
    out = gc.hosts_domains([], ads=ads, max_entries=200, restricted_exact=["late.example.org"])
    assert "late.example.org" in out and len(out) == 200
    assert "a499.ads.example" not in out                         # ads are what the cap squeezes
    # Exact names only: no www. twin (unlike curated categories).
    assert "www.late.example.org" not in gc.hosts_domains([], restricted_exact=["late.example.org"])


class FakeForwarder:
    def __init__(self, filters):
        self.filters = filters

    def set_policy(self, policy):
        pass

    def pinned_ips(self):
        return []


def test_forwarder_restricted_lists_count_and_are_cached(tmp_path):
    g, s = local_guard(tmp_path)
    s.urls[gc.ADS_LIST_URL] = ads_with_restricted(extra=("adserver.listed.example",))
    g.refresh_lists(force=True)
    # Lists not loaded yet: only the static checks.
    assert g.restricted_ad_names() == [RESTRICTED_AD]
    fs = fl.FilterSet([], SmallSuffixSet([]), {}, restricted=[SmallSuffixSet(["listed.example"])],
                      info={"version": "2026.1016.1"})
    g.forwarder = FakeForwarder(fs)
    # The daemon works it out in the background; the last answer stands meanwhile.
    assert g.restricted_ad_names() == [RESTRICTED_AD]
    join_bg(g, "ads-restricted")
    assert set(g.restricted_ad_names()) == {RESTRICTED_AD, "adserver.listed.example"}
    # Cached: same ad list, same lists, no new work.
    calls = []
    g._compute_restricted_ads = lambda *a: calls.append(a) or []
    g.restricted_ad_names()
    assert calls == [] and "ads-restricted" in g._bg
    # A name the forwarder's allow-list frees is left to the ad switch, as in the forwarder.
    fs2 = fl.FilterSet([], SmallSuffixSet(["adserver.listed.example"]), {},
                       restricted=[SmallSuffixSet(["listed.example"])], info={"version": "2"})
    del g._compute_restricted_ads
    g.forwarder = FakeForwarder(fs2)
    g.restricted_ad_names()
    join_bg(g, "ads-restricted")
    assert g.restricted_ad_names() == [RESTRICTED_AD]


def test_restart_keeps_the_full_answer_until_lists_load(tmp_path):
    g, s = local_guard(tmp_path)
    s.urls[gc.ADS_LIST_URL] = ads_with_restricted(extra=("adserver.listed.example",))
    g.refresh_lists(force=True)
    fs = fl.FilterSet([], SmallSuffixSet([]), {}, restricted=[SmallSuffixSet(["listed.example"])],
                      info={"version": "1"})
    g.forwarder = FakeForwarder(fs)
    g.restricted_ad_names()
    join_bg(g, "ads-restricted")
    # A restarted daemon whose lists haven't loaded yet.
    g2 = pg.Guard(g.cfg, s, state_dir=tmp_path / "PaxGuard" / "state", quarantine_dir=tmp_path / "q")
    g2.forwarder = FakeForwarder(None)
    g2.restricted_ad_names()
    join_bg(g2, "ads-restricted")
    assert set(g2.restricted_ad_names()) == {RESTRICTED_AD, "adserver.listed.example"}


# ------------------------------------------------------ server escrow (Mac)
def test_server_switch_on_fetches_a_list_at_once(tmp_path):
    """Up to 0.8.6 a Mac on server escrow that had ads off got no ad list for up
    to a day after switching on (the one daily clock was reset while off)."""
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote(adblock=False)
    s.urls[gc.ADS_LIST_URL] = ad_list()
    g.cycle()
    assert "t5.ads.example" not in hosts(s)
    s.urls["https://pax.example.org/v1/guard/config"] = remote(adblock=True)
    s.t += 60
    g.cycle()
    assert "0.0.0.0 t5.ads.example" in hosts(s)


def test_stale_list_is_refreshed_when_switched_back_on(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote()
    s.urls[gc.ADS_LIST_URL] = ad_list()
    g.cycle()
    s.urls["https://pax.example.org/v1/guard/config"] = remote(adblock=False)
    s.t += 3 * 24 * 3600
    g.cycle()
    s.urls[gc.ADS_LIST_URL] = ad_list(13_000)
    s.urls["https://pax.example.org/v1/guard/config"] = remote(adblock=True)
    s.t += 60
    g.cycle()
    assert "0.0.0.0 t12500.ads.example" in hosts(s)


def test_failed_ad_download_is_retried_hourly_not_every_cycle(tmp_path):
    g, s = make_guard(tmp_path)
    s.urls["https://pax.example.org/v1/guard/config"] = remote()
    g.cycle()                                    # ad list unreachable
    fetched = []
    orig = s.fetch

    def counting(url, headers=None, timeout=20):
        fetched.append(url)
        return orig(url, headers, timeout)
    s.fetch = counting
    s.t += 30
    g.cycle()
    assert gc.ADS_LIST_URL not in fetched
    s.t += gc.ADS_RETRY_SECONDS
    s.urls[gc.ADS_LIST_URL] = ad_list()
    g.cycle()
    assert gc.ADS_LIST_URL in fetched and "0.0.0.0 t5.ads.example" in hosts(s)


def test_a_0_8_6_state_folder_upgrades_cleanly(tmp_path):
    """0.8.6 left lists-meta.json with only fetched_at and settings.json with only
    YouTube: ads follow the set-up choice and the ad list is fetched once."""
    g, s = local_guard(tmp_path)
    state = tmp_path / "PaxGuard" / "state"
    g._save_json("lists-meta.json", {"fetched_at": s.t})
    g._save_json("ads.json", [f"old{i}.ads.example" for i in range(10)])
    g._save_json("settings.json", {"youtube_restricted": False, "changed_at": s.t})
    s.urls[gc.ADS_LIST_URL] = ad_list()
    g.cycle()
    assert g.local_adblock is True and g.youtube_restricted is False
    assert "0.0.0.0 t5.ads.example" in hosts(s)
    assert "ads_fetched_at" in json.loads(s.read(str(state / "lists-meta.json")))


def test_ipc_doc_lists_the_switch():
    import guard_ipc
    assert "adblock" in guard_ipc.__doc__
