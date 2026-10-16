# SPDX-License-Identifier: GPL-3.0-only
"""List parsing and the HaGeZi/OISD loader. No downloads: the fetcher is faked."""
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import load_lists  # noqa: E402

from pax_dns.lists import CategoryList, compact, parse_line, parse_lines  # noqa: E402

HAGEZI_SAMPLE = """# Title: HaGeZi's restricted-content list
# Syntax: Domains (without subdomains)
blocked-one.example
blocked-two.example
""".splitlines()
OISD_SAMPLE = """# Title: oisd restricted-content list
# Syntax: Domains (wildcards) without *.
blocked-two.example
blocked-three.example
""".splitlines()


@pytest.mark.parametrize("line,expected", [
    ("example.com", "example.com"),
    ("*.Example.com", "example.com"),
    ("0.0.0.0 ads.example.com", "ads.example.com"),
    ("127.0.0.1\tads.example.com # comment", "ads.example.com"),
    ("||tracker.example^", "tracker.example"),
    ("||tracker.example^$important", "tracker.example"),
    ("||tracker.example^$third-party", None),
    ("@@||good.example^", None),
    ("||example.com/path^", None),
    ("# comment", None), ("! adblock comment", None), ("[Adblock Plus 2.0]", None), ("", None),
    ("0.0.0.0 localhost", None), ("localhost", None), ("com", None), ("co.uk", None),
    ("1.2.3.4", None), ("bücher.de", "xn--bcher-kva.de"), ("two words here", None),
])
def test_parse_line(line, expected):
    assert parse_line(line) == expected


def test_compact_drops_covered_subdomains():
    assert compact({"example.com", "a.example.com", "b.c.example.com", "other.org"}) == \
        {"example.com", "other.org"}


def test_category_list_match_and_reload(tmp_path):
    f = tmp_path / "cat.txt"
    f.write_text("restricted.example\n")
    cl = CategoryList.load(str(f))
    assert cl.match("www.restricted.example") == "restricted.example" and cl.match("example.org") is None
    assert cl.reload_if_changed() is cl
    time.sleep(0.01)
    f.write_text("restricted.example\nnew.example\n")
    os.utime(f, (time.time() + 5, time.time() + 5))
    cl2 = cl.reload_if_changed()
    assert cl2 is not cl and len(cl2) == 2
    f.unlink()
    assert cl2.reload_if_changed() is cl2  # file gone: keep the last good list


def fake_fetcher(url):
    return {load_lists.SOURCES["hagezi-restricted"]: HAGEZI_SAMPLE,
            load_lists.SOURCES["oisd-restricted"]: OISD_SAMPLE}[url]


def test_loader_merges_and_dedupes(tmp_path):
    extra = tmp_path / "extra.txt"
    extra.write_text("0.0.0.0 sub.blocked-one.example\nmine.example\n")
    domains, counts = load_lists.build(["hagezi-restricted", "oisd-restricted"], [extra], min_entries=1,
                                       fetcher=fake_fetcher, additions=None)
    assert domains == {"blocked-one.example", "blocked-two.example", "blocked-three.example",
                       "mine.example"}
    assert counts["hagezi-restricted"] == 2 and counts["oisd-restricted"] == 2


def test_loader_refuses_tiny_download(tmp_path):
    with pytest.raises(SystemExit):
        load_lists.build(["hagezi-restricted"], [], min_entries=1000, fetcher=fake_fetcher,
                         additions=None)


def test_loader_writes_atomically_and_cli_offline(tmp_path):
    src = tmp_path / "saved.txt"
    src.write_text("\n".join(HAGEZI_SAMPLE))
    out = tmp_path / "out" / "category.txt"
    assert load_lists.main(["--no-download", "--from-file", str(src), "--out", str(out)]) == 0
    assert parse_lines(out.read_text().splitlines()) >= {"blocked-one.example", "blocked-two.example"}
    assert not [p for p in out.parent.iterdir() if p.name.endswith(".tmp")]
    assert CategoryList.load(str(out)).match("x.blocked-one.example")


def test_default_sources_are_the_documented_urls():
    assert load_lists.SOURCES["hagezi-restricted"].startswith(
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/")
    assert load_lists.SOURCES["oisd-restricted"].startswith("https://") and "oisd.nl" in load_lists.SOURCES["oisd-restricted"]
