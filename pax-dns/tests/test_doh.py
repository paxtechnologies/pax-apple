# SPDX-License-Identifier: GPL-3.0-only
"""RFC 8484 handling and wire-format answers, with fake upstreams (no network)."""
import base64

import pytest
from conftest import TOKEN
from dnslib import EDNS0, QTYPE, RCODE, DNSRecord
from fastapi.testclient import TestClient

from pax_dns.config import DNSSettings
from pax_dns.doh import b64url_decode, b64url_encode, create_app
from pax_dns.resolver import BadQuery, parse_query

CT = "application/dns-message"


def q(name, qtype="A", qid=0, edns=False):
    rec = DNSRecord.question(name, qtype)
    rec.header.id = qid
    if edns:
        rec.add_ar(EDNS0(udp_len=4096))
    return rec


def client(resolver, **kw):
    return TestClient(create_app(DNSSettings(**kw), resolver=resolver, start_sync=False))


@pytest.fixture
def setup(make_resolver):
    r, up, allow_up = make_resolver(block=["bad.example"], allow=["restricted.example", "news.example"],
                                    category=["restricted.example", "blocked-example.test"])
    return client(r), r, up, allow_up


def get(c, rec, token=TOKEN):
    path = f"/u/{token}/dns-query" if token else "/dns-query"
    return c.get(path, params={"dns": b64url_encode(bytes(rec.pack()))}, headers={"Accept": CT})


def post(c, rec, token=TOKEN, ctype=CT):
    path = f"/u/{token}/dns-query" if token else "/dns-query"
    return c.post(path, content=bytes(rec.pack()), headers={"Content-Type": ctype, "Accept": CT})


def answer(resp):
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == CT
    return DNSRecord.parse(resp.content)


def test_rfc8484_example_query_decodes():
    # The GET example from RFC 8484 section 4.1.1 (www.example.com A, ID 0).
    wire = b64url_decode("AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
    rec = parse_query(wire)
    assert str(rec.q.qname) == "www.example.com." and rec.q.qtype == QTYPE.A
    assert rec.header.id == 0


def test_b64url_rules():
    assert b64url_decode(b64url_encode(b"\xff\xfe\x00")) == b"\xff\xfe\x00"
    assert b64url_decode(b64url_encode(b"abcd") + "==") == b"abcd"  # tolerate padding
    for bad in ["", "a+b/", "!!!!"]:
        with pytest.raises(BadQuery):
            b64url_decode(bad)


def test_get_and_post_custom_block_null_answers(setup):
    c, *_ = setup
    for send in (get, post):
        a = answer(send(c, q("www.bad.example", "A", qid=4242)))
        assert a.header.id == 4242 and a.header.qr and a.header.rcode == RCODE.NOERROR
        assert [str(rr.rdata) for rr in a.rr] == ["0.0.0.0"]
    a = answer(get(c, q("bad.example", "AAAA")))
    assert [str(rr.rdata) for rr in a.rr] == ["::"]
    # Other types (HTTPS/SVCB, MX, TXT): NODATA with an SOA for negative caching.
    a = answer(get(c, q("bad.example", "HTTPS")))
    assert a.rr == [] and a.header.rcode == RCODE.NOERROR and a.auth[0].rtype == QTYPE.SOA


def test_nxdomain_mode(make_resolver):
    r, *_ = make_resolver(block=["bad.example"], block_mode="nxdomain")
    a = answer(get(client(r), q("bad.example")))
    assert a.header.rcode == RCODE.NXDOMAIN and a.rr == [] and a.auth[0].rtype == QTYPE.SOA


def test_cache_control_uses_min_ttl(setup):
    c, *_ = setup
    r = get(c, q("bad.example"))
    assert r.headers["cache-control"] == "max-age=60"
    r = get(c, q("ok.example"))
    assert r.headers["cache-control"] == "max-age=300"  # 3600 capped by max_ttl


def test_forward_uses_id_zero_and_restores_id(setup):
    c, r, up, _ = setup
    a = answer(post(c, q("ok.example", qid=777)))
    assert a.header.id == 777 and str(a.rr[0].rdata) == "93.184.216.34"
    assert up.seen[-1].header.id == 0
    assert a.rr[0].ttl == 300


def test_category_block_beats_user_allow(setup):
    c, r, up, allow_up = setup
    # blocked-example.test: category-blocked for everyone
    assert str(answer(get(c, q("x.blocked-example.test"))).rr[0].rdata) == "0.0.0.0"
    # v0.8.1: restricted.example is in the category list; this user's exception
    # for it changes nothing.
    assert str(answer(get(c, q("restricted.example"))).rr[0].rdata) == "0.0.0.0"
    assert not any(str(x.q.qname) == "restricted.example." for x in allow_up.seen)
    # An exception for a site outside the category goes to the allow upstream.
    a = answer(get(c, q("news.example")))
    assert str(a.rr[0].rdata) == "10.9.9.9"
    assert allow_up.seen and str(allow_up.seen[-1].q.qname) == "news.example."
    # Without the token (or with an unknown one) the category stays blocked.
    assert str(answer(get(c, q("restricted.example"), token=None)).rr[0].rdata) == "0.0.0.0"
    assert str(answer(get(c, q("restricted.example"), token="u" * 30)).rr[0].rdata) == "0.0.0.0"


def test_allow_upstream_defaults_to_the_filtered_upstream():
    from pax_dns.config import CLEANBROWSING_FAMILY_DOH
    assert DNSSettings().allow_upstream == CLEANBROWSING_FAMILY_DOH == DNSSettings().upstream


def test_unknown_token_is_still_filtered_not_open(setup):
    c, *_ = setup
    # custom block doesn't apply, but the request is still answered through the
    # filtering upstream (never an error, never unfiltered)
    a = answer(get(c, q("bad.example"), token="z" * 40))
    assert str(a.rr[0].rdata) == "93.184.216.34"


def test_cname_to_blocked_name_is_blocked(setup):
    c, r, up, _ = setup
    up.cnames["innocent.example"] = "cdn.bad.example"
    a = answer(get(c, q("innocent.example")))
    assert [str(x.rdata) for x in a.rr] == ["0.0.0.0"]


def test_upstream_failure_is_servfail(setup):
    c, r, up, _ = setup
    up.fail = True
    a = answer(get(c, q("down.example")))
    assert a.header.rcode == RCODE.SERVFAIL and a.rr == []


def test_cache_serves_repeat_queries(setup):
    c, r, up, _ = setup
    answer(get(c, q("cached.example", qid=1)))
    n = len(up.seen)
    a = answer(get(c, q("cached.example", qid=2)))
    assert len(up.seen) == n and a.header.id == 2


def test_edns_echoed(setup):
    c, *_ = setup
    a = answer(get(c, q("bad.example", edns=True)))
    assert any(rr.rtype == QTYPE.OPT for rr in a.ar)


def test_http_errors(setup):
    c, *_ = setup
    assert c.get(f"/u/{TOKEN}/dns-query").status_code == 400                  # no dns param
    assert c.get(f"/u/{TOKEN}/dns-query", params={"dns": "a+b/"}).status_code == 400
    assert c.get(f"/u/{TOKEN}/dns-query",
                 params={"dns": b64url_encode(b"\x00" * 5)}).status_code == 400  # too short
    assert post(c, q("a.example"), ctype="application/json").status_code == 415
    big = c.post(f"/u/{TOKEN}/dns-query", content=b"\x00" * 70000, headers={"Content-Type": CT})
    assert big.status_code == 413
    # a response (QR=1) is not a query
    resp = q("a.example").reply()
    assert c.post(f"/u/{TOKEN}/dns-query", content=bytes(resp.pack()),
                  headers={"Content-Type": CT}).status_code == 400
    # two questions
    two = q("a.example")
    two.add_question(q("b.example").q)
    assert c.post(f"/u/{TOKEN}/dns-query", content=bytes(two.pack()),
                  headers={"Content-Type": CT}).status_code == 400


def test_public_endpoint_toggle(make_resolver):
    r, *_ = make_resolver()
    c = client(r, public_endpoint=False)
    assert get(c, q("a.example"), token=None).status_code == 404
    assert get(c, q("a.example")).status_code == 200


def test_health(setup):
    c, *_ = setup
    h = c.get("/health").json()
    assert h["ok"] and h["users"] == 1 and h["category_entries"] == 2


def test_padding_base64_variant_from_spec_post_body(setup):
    # RFC 8484 4.1.1 POST example body is the same message as the GET example.
    c, *_ = setup
    wire = base64.urlsafe_b64decode("AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB==")
    r = c.post(f"/u/{TOKEN}/dns-query", content=wire, headers={"Content-Type": CT})
    assert answer(r).q.qname == "www.example.com."
