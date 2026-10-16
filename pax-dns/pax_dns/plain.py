# SPDX-License-Identifier: GPL-3.0-only
"""Plain DNS (UDP + TCP, port 53) front end for pax-dns.

Plain DNS carries no URL, so there is no per-user path. It serves either one
user's lists (--token, for a self-hosted single-user box or a home router) or
category filtering only. Same decisions and upstreams as the DoH server.

  python3 -m pax_dns.plain --port 5353 [--address 127.0.0.1] [--token TOKEN]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import threading
import time
from typing import Optional

from dnslib import RCODE, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from .config import DNSSettings
from .lists import CategoryList, load_builtin
from .policy import Store
from .resolver import Resolver, error_reply
from .sources import Syncer, make_source


class PlainResolver(BaseResolver):
    """dnslib resolver that runs Resolver coroutines on a private event loop."""

    def __init__(self, resolver: Resolver, token: Optional[str], loop: asyncio.AbstractEventLoop,
                 timeout: float = 8.0):
        self.resolver, self.token, self.loop, self.timeout = resolver, token, loop, timeout

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        fut = asyncio.run_coroutine_threadsafe(
            self.resolver.resolve_record(request, self.token), self.loop)
        try:
            return fut.result(self.timeout).reply
        except Exception:  # noqa: BLE001
            return error_reply(request, RCODE.SERVFAIL)


class _QuietLogger(DNSLogger):
    """No query logging."""

    def __init__(self):
        super().__init__(log="-request,-reply,-truncated,-data,-recv,-send", prefix=False)


def serve(settings: DNSSettings, address: str, port: int, token: Optional[str],
          resolver: Optional[Resolver] = None, start_sync: bool = True):
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True, name="pax-dns-loop").start()
    if resolver is None:
        store = Store()
        category = CategoryList.load(settings.category_file) if settings.category_file \
            else CategoryList()
        syncer = Syncer(store, make_source(settings.source, settings.internal_key), category,
                        settings.poll_seconds, builtin=load_builtin(settings.builtin_paths()))
        resolver = Resolver(settings, store, syncer)
    if start_sync:
        asyncio.run_coroutine_threadsafe(resolver.syncer.run(), loop)
    pr = PlainResolver(resolver, token, loop)
    servers = [DNSServer(pr, port=port, address=address, logger=_QuietLogger()),
               DNSServer(pr, port=port, address=address, tcp=True, logger=_QuietLogger())]
    for s in servers:
        s.start_thread()
    return servers, loop


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="pax-dns plain DNS server (UDP+TCP)")
    ap.add_argument("--address", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5353)
    ap.add_argument("--token", default=os.environ.get("PAX_DNS_PLAIN_TOKEN"),
                    help="serve this user's lists (default: category filtering only)")
    args = ap.parse_args(argv)
    servers, _ = serve(DNSSettings.from_env(), args.address, args.port, args.token)
    print(f"pax-dns plain DNS on {args.address}:{args.port} (udp+tcp)")
    try:
        while all(s.isAlive() for s in servers):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
