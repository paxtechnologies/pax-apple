# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.25: DoH rate limits that survive carrier-grade NAT (pax_server/doh.py
RateLimits). A known account token is limited per token (all of its devices),
then by a loose per-address ceiling; no token or an unknown/retired token keeps
the strict per-address limit. Simulated clock, fake forwarder, no network."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pax_server import doh as doh_mod  # noqa: E402
from pax_server.config import Settings  # noqa: E402

CARRIER_IP = "203.0.113.50"           # one mobile-carrier NAT address
OK_WIRE = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00\x00\x01\x00\x01"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class FakeForwarder:
    """Echoes a NOERROR answer; never touches the network."""
    filters = None
    pax_filter_ok = True
    ready = True

    def handle(self, wire, policy):
        return wire[:2] + b"\x81\x80" + wire[4:]

    def status(self):
        return {}


def tok(i: int) -> str:
    return f"phone-account-token-{i:06d}-xxxxxxxxxxxx"


def make_service(tmp_path, n_tokens=0, retired=(), **limits):
    s = Settings()
    kw = dict(rate=s.doh_rate_per_ip, burst=s.doh_burst_per_ip,
              token_rate=s.doh_rate_per_token, token_burst=s.doh_burst_per_token,
              ceiling_rate=s.doh_ip_ceiling_rate, ceiling_burst=s.doh_ip_ceiling_burst)
    kw.update(limits)
    clock = Clock()
    svc = doh_mod.DohService(None, str(tmp_path), forwarder=FakeForwarder(), clock=clock, **kw)
    for lim in (svc.limits.per_ip, svc.limits.per_token, svc.limits.ip_ceiling):
        lim.clock = clock
    accounts = []
    for i in range(n_tokens):
        retire = (clock() - 1) if i in retired else None
        accounts.append({"account_id": f"acct-{i}", "tokens": [{"hash": doh_mod.hash_token(tok(i)),
                                                                   "retire_at": retire}]})
    svc.policies.apply({"full": True, "accounts": accounts})
    return svc, clock


def code(svc, token, ip=CARRIER_IP):
    return svc.answer(OK_WIRE, token, ip)[0]


def test_defaults_and_env(monkeypatch):
    s = Settings()
    assert (s.doh_rate_per_ip, s.doh_burst_per_ip) == (25.0, 400.0)
    assert (s.doh_rate_per_token, s.doh_burst_per_token) == (25.0, 400.0)
    assert (s.doh_ip_ceiling_rate, s.doh_ip_ceiling_burst) == (2000.0, 4000.0)
    for k, v in {"PAX_DOH_RATE_PER_TOKEN": "30", "PAX_DOH_BURST_PER_TOKEN": "500",
                 "PAX_DOH_IP_CEILING_RATE": "3000", "PAX_DOH_IP_CEILING_BURST": "6000",
                 "PAX_DOH_RATE_PER_IP": "20", "PAX_DOH_BURST_PER_IP": "300"}.items():
        monkeypatch.setenv(k, v)
    e = Settings.from_env()
    assert (e.doh_rate_per_token, e.doh_burst_per_token) == (30.0, 500.0)
    assert (e.doh_ip_ceiling_rate, e.doh_ip_ceiling_burst) == (3000.0, 6000.0)
    assert (e.doh_rate_per_ip, e.doh_burst_per_ip) == (20.0, 300.0)


def test_300_phones_on_one_carrier_ip_are_never_limited(tmp_path):
    svc, clock = make_service(tmp_path, n_tokens=300)
    old = doh_mod.RateLimiter(25.0, 400.0, clock=clock)   # the pre-0.8.25 per-IP limit
    old_limited = 0
    # 300 phones, distinct accounts, each 0.1 qps (one query every 10 s), staggered,
    # for 15 simulated minutes: 30 qps from one address.
    for step in range(90 * 300):
        clock.t = 1000.0 + step * (10.0 / 300)
        assert code(svc, tok(step % 300)) == 200, step
        old_limited += not old.allow(CARRIER_IP)
    assert svc.stats["rate_limited"] == 0 and svc.stats["queries"] == 90 * 300
    assert old_limited > 0          # the old per-IP limit would have throttled these phones


def test_one_token_flooding_is_limited_on_any_address(tmp_path):
    svc, clock = make_service(tmp_path, n_tokens=2)
    ok = 0
    for i in range(10_000):          # 1,000 qps for 10 s, from many addresses
        clock.t = 1000.0 + i / 1000
        ok += code(svc, tok(0), ip=f"198.51.100.{i % 200}") == 200
    assert 600 <= ok <= 700          # burst 400 + 25 qps x 10 s
    assert code(svc, tok(0)) == 429
    assert code(svc, tok(1)) == 200  # another account (same carrier address) is unaffected


def test_unknown_token_flood_keeps_the_strict_per_ip_limit(tmp_path):
    svc, clock = make_service(tmp_path, n_tokens=1, retired={0})
    for bad in ("u" * 40, None, "bad", tok(0)):          # unknown, none, malformed, retired
        svc2, clock2 = make_service(tmp_path / str(abs(hash(str(bad)))), n_tokens=1, retired={0})
        codes = [code(svc2, bad) for _ in range(1000)]   # instant flood from one address
        assert codes.count(200) == 400 and codes[400:] == [429] * 600, bad
        clock2.t += 2.0
        assert [code(svc2, bad) for _ in range(51)].count(200) == 50   # 25 qps refill
        assert code(svc2, bad, ip="198.51.100.77") == 200              # other address fine
    # An unknown-token flood on the carrier address doesn't use up real phones' limits.
    svc3, _c = make_service(tmp_path / "mix", n_tokens=5)
    for _ in range(1000):
        code(svc3, "u" * 40)
    assert all(code(svc3, tok(i)) == 200 for i in range(5))


def test_ip_ceiling_trips_at_its_limit(tmp_path):
    svc, clock = make_service(tmp_path, n_tokens=20)
    codes = [code(svc, tok(i % 20)) for i in range(4000)]   # 200 per token: under its burst
    assert codes == [200] * 4000
    assert code(svc, tok(0)) == 429                          # 4,001st from this address
    assert code(svc, tok(0), ip="198.51.100.9") == 200       # same token, other address
    clock.t += 1.0                                           # ceiling refills 2,000/s
    assert [code(svc, tok(i % 20)) for i in range(2001)].count(200) == 2000


def test_throttled_response_is_unchanged(tmp_path):
    svc, _c = make_service(tmp_path, rate=0.001, burst=1)
    assert code(svc, None) == 200
    assert svc.answer(OK_WIRE, None, CARRIER_IP) == (
        429, b"slow down", {"Retry-After": "2", "Content-Type": "text/plain"})
    assert svc.stats["rate_limited"] == 1


def test_buckets_stay_bounded():
    lim = doh_mod.RateLimits(max_keys=100)
    for i in range(1000):
        lim.allow(f"10.0.{i // 256}.{i % 256}", None)
        lim.allow(f"10.1.{i // 256}.{i % 256}", f"h{i}")
    assert len(lim.per_ip._b) == len(lim.per_token._b) == len(lim.ip_ceiling._b) == 100


def test_zero_rate_switches_a_limit_off(tmp_path):
    svc, _c = make_service(tmp_path, n_tokens=1, token_rate=0, ceiling_rate=0)
    assert all(code(svc, tok(0)) == 200 for _ in range(10_000))
    assert [code(svc, None) for _ in range(401)].count(429) == 1   # unknown still strict
