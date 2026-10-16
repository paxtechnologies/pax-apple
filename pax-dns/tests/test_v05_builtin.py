# SPDX-License-Identifier: GPL-3.0-only
"""v0.5: built-in categories (bypass always on, remote desktop switchable after
the wait), the curated list files, and the bypass list seeded from HaGeZi."""
import asyncio
import re
import sys
from pathlib import Path

from dnslib import QTYPE, DNSRecord

from conftest import TOKEN, FakeUpstream, feed

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import load_lists  # noqa: E402

from pax_dns import sources  # noqa: E402
from pax_dns.config import DNSSettings  # noqa: E402
from pax_dns.lists import BUILTIN_FILES, CategoryList, load_builtin, parse_line  # noqa: E402
from pax_dns.policy import Action, Store, UserLists, decide  # noqa: E402
from pax_dns.resolver import Resolver  # noqa: E402
from pax_dns.sources import Syncer  # noqa: E402

BUILTIN = load_builtin({k: str(v) for k, v in BUILTIN_FILES.items()})


def test_list_files_are_clean():
    for name, path in BUILTIN_FILES.items():
        if name == "media_converter_rule":
            continue
        seen = set()
        for n, raw in enumerate(path.read_text().splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            assert " " not in line and "\t" not in line, f"{path.name}:{n} inline text: {raw!r}"
            assert parse_line(line) == line, f"{path.name}:{n} not a clean domain: {raw!r}"
            assert line not in seen, f"{path.name}:{n} duplicate {line}"
            seen.add(line)
        # remote_ai_browsers is a short hand list (ChatGPT, Manus).
        assert len(seen) >= (8 if name == "remote_ai_browsers" else 40), name
    # the two lists don't overlap (each domain belongs to one category)
    a = set(BUILTIN["bypass"].domains)
    b = set(BUILTIN["remote_desktop"].domains)
    assert not a & b


def test_lists_cover_what_the_maintainer_asked_for():
    must = {
        "bypass": ["sensepc.com", "shadow.tech", "paperspace.com", "mightyapp.com", "browserling.com",
                   "hyperbeam.com", "rollapp.com", "neverinstall.com", "croxyproxy.com"],
        "remote_desktop": ["remotedesktop.google.com", "anydesk.com", "teamviewer.com", "parsec.app",
                           "rustdesk.com", "splashtop.com", "amazonworkspaces.com",
                           "windows365.microsoft.com"],
    }
    for cat, names in must.items():
        for n in names:
            assert BUILTIN[cat].match(n) == n, (cat, n)
            assert BUILTIN[cat].match("relay-1.x." + n), (cat, n)   # subdomains too


def test_builtin_categories_and_user_switch():
    on = UserLists()
    off = UserLists(categories_off=frozenset({"remote_desktop"}))
    sneaky = UserLists(categories_off=frozenset({"bypass"}))   # bypass can't be switched off
    d = decide("app.sensepc.com", on, None, BUILTIN)
    assert d.action is Action.BLOCK_CATEGORY and d.category == "bypass"
    assert decide("app.sensepc.com", sneaky, None, BUILTIN).action is Action.BLOCK_CATEGORY
    d = decide("remotedesktop.google.com", on, None, BUILTIN)
    assert d.action is Action.BLOCK_CATEGORY and d.category == "remote_desktop"
    assert decide("remotedesktop.google.com", off, None, BUILTIN).action is Action.FORWARD
    # unknown token: everything on
    assert decide("anydesk.com", None, None, BUILTIN).action is Action.BLOCK_CATEGORY
    # a user exception (which itself waited 72 h) still wins, as for every category
    allow = UserLists(allow=frozenset({"browserstack.com"}))
    assert decide("live.browserstack.com", allow, None, BUILTIN).action is Action.ALLOW


def test_store_reads_categories_from_feed():
    s = Store()
    f = feed()
    f["accounts"][0]["categories"] = {"remote_desktop": False}
    s.apply(f)
    assert s.lookup(TOKEN).categories_off == {"remote_desktop"}
    s.apply(feed())                       # older server: no "categories" = on
    assert s.lookup(TOKEN).categories_off == frozenset()


def _resolver(categories_off=()):
    store = Store()
    f = feed()
    f["accounts"][0]["categories"] = {c: False for c in categories_off}
    store.apply(f)
    syncer = Syncer(store, None, CategoryList(), builtin=dict(BUILTIN))
    up = FakeUpstream()
    return Resolver(DNSSettings(), store, syncer, upstream=up, allow_upstream=FakeUpstream()), up


def _ask(r, name, token=TOKEN):
    q = DNSRecord.question(name, "A")
    res = asyncio.run(r.resolve(bytes(q.pack()), token))
    return res.decision, str(res.reply.rr[0].rdata) if res.reply.rr else None


def test_resolver_blocks_builtin_and_cname_into_it():
    r, up = _resolver()
    d, ip = _ask(r, "www.shadow.tech")
    assert d.action is Action.BLOCK_CATEGORY and ip == "0.0.0.0" and not up.seen
    up.cnames["innocent.example"] = "relay.anydesk.com"
    d, ip = _ask(r, "innocent.example")
    assert d.category == "remote_desktop" and ip == "0.0.0.0"
    r2, _ = _resolver(categories_off=["remote_desktop"])
    d, ip = _ask(r2, "anydesk.com")
    assert d.action is Action.FORWARD and ip != "0.0.0.0"


def test_settings_default_to_shipped_lists(monkeypatch):
    s = DNSSettings.from_env()
    assert Path(s.bypass_file).exists() and Path(s.remote_desktop_file).exists()
    monkeypatch.setenv("PAX_DNS_REMOTE_DESKTOP_FILE", "")
    assert load_builtin(DNSSettings.from_env().builtin_paths()).keys() == {
        "bypass", "media_converters", "media_converter_rule", "remote_ai_browsers"}


def test_remote_desktop_sql_matches_server():
    sys.path.insert(0, str(ROOT.parent / "server"))
    from pax_server import blocklist as server_blocklist

    def norm(sql):
        return re.sub(r"\s+", " ", sql).strip()
    assert norm(sources.REMOTE_DESKTOP_SQL) == norm(server_blocklist.REMOTE_DESKTOP_SQL)


def test_loader_seeds_bypass_from_hagezi_and_spares_pax_names():
    assert "hagezi-doh-vpn" in load_lists.DEFAULT_SOURCES
    got = load_lists.drop_protected({"cleanbrowsing.org", "doh.cleanbrowsing.org", "paxmobile.org",
                                     "dns.paxmobile.org", "croxyproxy.com", "org"})
    assert got == {"croxyproxy.com", "org"}
