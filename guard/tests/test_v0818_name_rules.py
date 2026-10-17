# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.18: the name rules on every lookup inside pax-guard's lists and
forwarder. The restricted-content rule blocks even past a user's exception;
the web-proxy rule is part of the bypass category, so an exception frees it;
the Pax allowlist beats both. Matched words come from common/pax_restricted.py
at run time, never written here."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent
REPO = GUARD.parent
sys.path.insert(0, str(GUARD))
sys.path.insert(0, str(REPO / "common"))
import dns_forwarder as d  # noqa: E402
import filter_lists as fl  # noqa: E402
import pax_restricted as pr  # noqa: E402
from domain_matcher import SmallSuffixSet  # noqa: E402

_spec = importlib.util.spec_from_file_location("v08_lists", HERE / "test_v08_lists.py")
v08 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v08)

W = pr.data()["lookup_rule"]["words"][0]
NAMED = f"www.{W}tube.example"
PROXY_WORD = pr.data()["bypass_rule"]["contains"][0]
PROXY = f"free{PROXY_WORD}.example"


def test_store_load_attaches_both_rules(tmp_path):
    b, _ = v08.make_bundle(tmp_path, v08.BLOCK, bypass_lines=["vpn.example"])
    fs = v08.store(tmp_path, b).load()
    assert fs.restricted_by(NAMED) == "name-rule"
    assert fs.overridable_by(NAMED) is None
    assert fs.overridable_by(PROXY) == "bypass-name-rule"
    assert fs.restricted_by(PROXY) is None
    assert fs.blocked_by("bbc.co.uk") is None
    assert fs.info["name_rules"] is True
    # Lists still answer first, with the list entry.
    assert fs.restricted_by("www.bad7.example") == "bad7.example"


def _fwd(policy=None):
    fs = fl.FilterSet([], SmallSuffixSet(["allowed.example"]), {},
                      name_rules=[pr.lookup_rule()], bypass_rules=[pr.bypass_name_rule()])
    return d.Forwarder([], filters=fs, policy=policy or d.Policy(), log=lambda m: None)


def test_forwarder_blocks_rule_hits():
    f = _fwd()
    assert f.decide(NAMED) == ("block", "restricted:name-rule")
    assert f.decide(PROXY) == ("block", "list:bypass-name-rule")
    assert f.decide("bbc.co.uk")[0] == "forward"


def test_exception_frees_the_proxy_rule_but_never_the_restricted_rule():
    pol = d.Policy(exceptions=[NAMED.split(".", 1)[1], PROXY], never_except=pr.RestrictedCheck())
    f = _fwd(pol)
    assert f.decide(NAMED)[0] == "block"
    assert f.decide(PROXY) == ("forward", "exception")


def test_exception_request_is_refused_for_a_rule_hit():
    import pytest
    with pytest.raises(pr.RestrictedSite):
        pr.check_exception(NAMED.split(".", 1)[1])


def test_pax_allowlist_beats_the_rules():
    fs = fl.FilterSet([], SmallSuffixSet([f"{W}tube.example", PROXY]), {},
                      name_rules=[pr.lookup_rule()], bypass_rules=[pr.bypass_name_rule()])
    f = d.Forwarder([], filters=fs, policy=d.Policy(), log=lambda m: None)
    assert f.decide(NAMED)[0] == "forward"
    assert f.decide(PROXY)[0] == "forward"
