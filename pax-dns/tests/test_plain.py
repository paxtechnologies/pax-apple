# SPDX-License-Identifier: GPL-3.0-only
"""Plain DNS front end over real UDP/TCP sockets on localhost (fake upstream)."""
import socket

from conftest import TOKEN
from dnslib import DNSRecord

from pax_dns.config import DNSSettings
from pax_dns.plain import serve


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_plain_dns_udp_and_tcp(make_resolver):
    r, *_ = make_resolver(block=["bad.example"])
    port = free_port()
    servers, loop = serve(DNSSettings(), "127.0.0.1", port, TOKEN, resolver=r, start_sync=False)
    try:
        for tcp in (False, True):
            a = DNSRecord.parse(DNSRecord.question("www.bad.example").send(
                "127.0.0.1", port, tcp=tcp, timeout=5))
            assert str(a.rr[0].rdata) == "0.0.0.0"
            a = DNSRecord.parse(DNSRecord.question("ok.example").send(
                "127.0.0.1", port, tcp=tcp, timeout=5))
            assert str(a.rr[0].rdata) == "93.184.216.34"
    finally:
        for s in servers:
            s.stop()
        loop.call_soon_threadsafe(loop.stop)
