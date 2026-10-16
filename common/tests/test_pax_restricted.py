# SPDX-License-Identifier: GPL-3.0-only
"""common/pax_restricted.py (v0.8.1): the encoded data, the edge rules, the
static checks, the CleanBrowsing probe (mocked) and the CLI. Restricted names
are read from the module at run time, never written here."""
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent
REPO = COMMON.parent
sys.path.insert(0, str(COMMON))

import pax_restricted as pr  # noqa: E402

LISTS = REPO / "pax-dns" / "lists"


# ------------------------------------------------------------------ the data
def test_data_has_every_section():
    d = pr.data()
    for key in ("keywords", "keyword_allow_words", "tlds", "hand_list", "ios_fallback_sites",
                "samples", "sources"):
        assert d[key], key
    assert all(t and "." not in t for t in pr.restricted_tlds())
    assert len(pr.ios_fallback_sites()) == len(set(pr.ios_fallback_sites()))
    assert "restricted-check.paxpeace.com" in pr.hand_list()


def test_encode_decode_round_trip():
    d = {"keywords": ["alpha"], "tlds": ["zz"], "nested": {"a": [1, 2]}}
    blob = pr.encode_blob(d)
    assert pr.decode_blob(blob) == d
    assert all(len(line) <= 76 for line in blob.splitlines())
    assert pr.decode_blob(pr._DATA) == pr.data()


def test_the_source_reads_calmly():
    """The words the rules match never appear in plain text in the module."""
    src = (COMMON / "pax_restricted.py").read_text().lower()
    body = src.split('_data = """', 1)[0] + src.split('"""', 3)[-1]
    for w in pr.keywords() + pr.hand_list()[:5]:
        if len(w) >= 4 and w != "restricted-check.paxpeace.com":
            assert w.lower() not in body, "plain-text rule word in pax_restricted.py"


# ------------------------------------------------------------------ the rules
def test_suffixes():
    assert pr.suffixes("www.A.example.com.") == ["www.a.example.com", "a.example.com", "example.com", "com"]


def test_edge_rule_matches_at_label_edges_only():
    r = pr.EdgeRule(["foo"], labels="first")
    for hit in ("foo.example", "foobar.example", "barfoo.example", "x-foo-y.example", "2foo.example"):
        assert r.match(hit), hit
    for miss in ("xfooy.example", "www.foo.example", "xn--foo.example"):
        assert not r.match(miss), miss
    assert pr.EdgeRule(["foo"], labels="all").match("www.foo.example")
    assert not pr.EdgeRule(["foo"], labels="all").match("example.foo")   # never the last label


def test_edge_rule_allow_words_and_exact():
    r = pr.EdgeRule(["foo"], allow_words=["foods"], labels="first")
    assert r.match("foo.example") and not r.match("foods.example")
    e = pr.EdgeRule([], exact=["bar"], labels="all")
    assert e.match("bar.example") and e.match("a.bar.example") and not e.match("barn.example")


def test_empty_rule_matches_nothing():
    assert not pr.EdgeRule([]).match("anything.example")


def test_parse_rule_and_domain_files():
    r = pr.parse_rule_file("# comment\n\nfoo\n=bar\n")
    assert r.labels == "all" and r.match("x.foo-y.example") and r.match("bar.example")
    assert not r.match("barn.example")
    text = "# head\nExample.com.\nsub.example.org  # note\nnot a domain\nsingle\n\n"
    assert pr.parse_domain_file(text) == ["example.com", "sub.example.org"]


# ----------------------------------------------------------------- checking
def test_builtin_static_checks():
    chk = pr.RestrictedCheck()
    tld = sorted(pr.restricted_tlds())[0]
    assert chk.reason(f"a.b.{tld}") == "tld"
    assert chk.reason("restricted-check.paxpeace.com") == "hand-list"
    assert chk.reason("www.restricted-check.paxpeace.com") == "hand-list"      # parents count
    assert chk.reason(f"{pr.keywords()[0]}-site.example") == "name-rule"
    assert chk.reason(f"www.{pr.keywords()[0]}-site.example") == "name-rule"
    assert chk(pr.samples()[0])     # the first sample is caught statically (the others need pax-block)
    for ok in ("bbc.co.uk", "gov.uk", "openai.com", "paxpeace.com", "", "."):
        assert not chk(ok), ok


def test_extra_sets_and_rules():
    class M:
        def match(self, name):
            return name.endswith(".matched.example")
    chk = pr.RestrictedCheck(sets=[{"blocked.example"}, M()], rules=[pr.parse_rule_file("=zap")],
                             use_builtin=False)
    assert chk.reason("www.blocked.example") == "list"
    assert chk.reason("a.matched.example") == "list"
    assert chk.reason("zap.example") == "rule"
    assert not chk("restricted-check.paxpeace.com")                 # built-ins off
    assert not chk("fine.example")


def test_remote_ai_and_converter_lists_plug_in():
    ai = set(pr.parse_domain_file((LISTS / "remote-ai-browsers.txt").read_text()))
    conv = set(pr.parse_domain_file((LISTS / "media-converters.txt").read_text()))
    rule = pr.parse_rule_file((LISTS / "media-converter-keywords.txt").read_text())
    chk = pr.RestrictedCheck(sets=[conv | ai], rules=[rule])
    for d in ("chatgpt.com", "www.chatgpt.com", "ios.chat.openai.com", "files.oaiusercontent.com",
              "manus.im", "en.savefrom.net"):
        assert chk(d), d
    for d in ("openai.com", "platform.openai.com", "api.openai.com"):
        assert not chk(d), d


# ------------------------------------------------------- the upstream check
def test_query_and_answer_round_trip():
    q = pr.build_query("Example.com", pr.QTYPE_A, qid=0x1234)
    assert q[:2] == b"\x12\x34" and q.endswith(struct.pack("!HH", 1, 1))
    rcode, addrs = pr.answer_addresses(pr.fake_lookup(address="203.0.113.7")(q))
    assert rcode == 0 and addrs == ["203.0.113.7"]
    with pytest.raises(ValueError):
        pr.answer_addresses(b"\x00")


def test_upstream_blocked_outcomes():
    lookup = pr.fake_lookup(blocked=["blocked.example"], failing=["down.example"])
    assert pr.upstream_blocked("open.example", lookup) == (False, "open")
    assert pr.upstream_blocked("www.blocked.example", lookup) == (True, "nxdomain")
    assert pr.upstream_blocked("down.example", lookup)[0] is True                  # fail closed
    assert pr.upstream_blocked("x.example", pr.fake_lookup(address="0.0.0.0")) == (True, "block address")
    assert pr.upstream_blocked("x.example", pr.fake_lookup(address="146.112.61.104"))[0] is True

    def servfail(wire):
        return wire[:2] + struct.pack("!HHHHH", 0x8182, 1, 0, 0, 0) + wire[12:]
    assert pr.upstream_blocked("x.example", servfail) == (True, "rcode 2")
    assert pr.upstream_blocked("x.example", lambda w: b"junk")[0] is True


def test_check_exception():
    lookup = pr.fake_lookup(blocked=["blocked.example"])
    pr.check_exception("fine.example", lookup=lookup)
    pr.check_exception("fine.example")                                       # static only
    for d in ("restricted-check.paxpeace.com", "blocked.example"):
        with pytest.raises(pr.RestrictedSite) as e:
            pr.check_exception(d, lookup=lookup)
        assert e.value.code == "PAX-DNS-010" == pr.RESTRICTED_CODE
        assert str(e.value) == e.value.message == pr.RESTRICTED_MESSAGE
        assert e.value.domain == d and e.value.reason                      # reason stays internal


def test_message_matches_the_error_catalog():
    import pax_errors as pe
    code = next(c for c in pe.CODES if c.code == pr.RESTRICTED_CODE)
    assert code.message == pr.RESTRICTED_MESSAGE


# ------------------------------------------------------------------- the CLI
def run(*args):
    return subprocess.run([sys.executable, str(COMMON / "pax_restricted.py"), *args],
                          capture_output=True, text=True)


def test_cli():
    r = run("--sample")
    assert r.returncode == 0 and r.stdout.splitlines()[-1] == "restricted-check.paxpeace.com"
    r = run("--dump")
    assert r.returncode == 0 and json.loads(r.stdout) == pr.data()
    key = sorted(pr.data()["sources"])[0]
    assert run("--source", key).stdout.strip() == pr.source(key)
    assert run().returncode == 2


def test_cli_encode(tmp_path):
    f = tmp_path / "d.json"
    f.write_text(json.dumps({"keywords": ["alpha"]}))
    r = run("--encode", str(f))
    assert r.returncode == 0 and pr.decode_blob(r.stdout) == {"keywords": ["alpha"]}
