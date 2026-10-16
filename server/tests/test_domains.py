# SPDX-License-Identifier: GPL-3.0-only
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pax_server.domains import (DomainError, display_domain, matches,  # noqa: E402
                                normalise_domain, suffixes)


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("  Example.COM  ", "example.com"),
    ("https://www.Example.com/some/path?q=1#frag", "www.example.com"),
    ("http://user:pw@example.com:8443/x", "example.com"),
    ("example.com/path", "example.com"),
    ("example.com:443", "example.com"),
    ("example.com.", "example.com"),
    ("*.example.com", "example.com"),
    ("bücher.de", "xn--bcher-kva.de"),
    ("https://BÜCHER.de/", "xn--bcher-kva.de"),
    ("xn--bcher-kva.de", "xn--bcher-kva.de"),
    ("i.redd.it", "i.redd.it"),
    ("sub.example.co.uk", "sub.example.co.uk"),
    ("example.co.uk", "example.co.uk"),
    ("_dmarc.example.com", "_dmarc.example.com"),
])
def test_normalise_accepts(raw, expected):
    assert normalise_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "localhost", "com", ".com", "*", "*.com", "a.*.example.com", "ex*mple.com",
    "192.168.1.1", "http://10.0.0.1/", "::1", "[2001:db8::1]", "2001:db8::1", "1.2.3",
    "co.uk", "*.co.uk", "github.io", "exa mple.com", "-bad.example.com", "bad-.example.com",
    "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com", "example.123", "x" * 3000,
])
def test_normalise_rejects(raw):
    with pytest.raises(DomainError):
        normalise_domain(raw)


def test_display_and_suffix_matching():
    assert display_domain("xn--bcher-kva.de") == "bücher.de"
    assert list(suffixes("a.b.example.com")) == ["a.b.example.com", "b.example.com",
                                                "example.com", "com"]
    blocked = {"example.com"}
    assert matches("example.com", blocked) == "example.com"
    assert matches("deep.sub.example.com", blocked) == "example.com"
    assert matches("notexample.com", blocked) is None
    assert matches("example.com.evil.net", blocked) is None
