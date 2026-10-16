# SPDX-License-Identifier: GPL-3.0-only
"""pax-dns DoH server (RFC 8484), FastAPI/ASGI.

  GET  /u/<token>/dns-query?dns=<base64url DNS message, no padding>
  POST /u/<token>/dns-query   (Content-Type: application/dns-message)
  GET|POST /dns-query         category filtering only (PAX_DNS_PUBLIC_ENDPOINT)
  GET  /health

Run:
  PAX_DNS_SOURCE=sqlite:////var/lib/pax/pax.sqlite3 \\
  uvicorn --factory pax_dns.doh:create_app --host 127.0.0.1 --port 8053
behind an HTTPS reverse proxy for dns.paxmobile.org. No query is logged: the
access log is off by default in the run command in README (--no-access-log),
because the path holds the user's token.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import time
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from . import __version__
from .config import DNSSettings
from .lists import CategoryList, load_builtin
from .policy import Store
from .resolver import BadQuery, Resolver, min_ttl
from .sources import Syncer, make_source
from .upstream import DOH_CT

MAX_MESSAGE = 65535


def b64url_decode(s: str) -> bytes:
    if not s or len(s) > 2 * MAX_MESSAGE:
        raise BadQuery("missing or oversized dns parameter")
    # RFC 8484 4.1: base64url with padding omitted. Lenient about padding only.
    if "+" in s or "/" in s:
        raise BadQuery("dns parameter must be base64url")
    s = s.rstrip("=")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise BadQuery("dns parameter is not valid base64url") from None


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def create_app(settings: Optional[DNSSettings] = None, resolver: Optional[Resolver] = None,
               start_sync: bool = True) -> FastAPI:
    settings = settings or DNSSettings.from_env()
    if resolver is None:
        store = Store()
        category = CategoryList.load(settings.category_file) if settings.category_file \
            else CategoryList()
        syncer = Syncer(store, make_source(settings.source, settings.internal_key), category,
                        settings.poll_seconds, builtin=load_builtin(settings.builtin_paths()))
        resolver = Resolver(settings, store, syncer)
    syncer = resolver.syncer

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        task = None
        if start_sync:
            with contextlib.suppress(Exception):
                await syncer.sync_once()  # first load before serving, best effort
            task = asyncio.create_task(syncer.run())
        try:
            yield
        finally:
            if task:
                task.cancel()

    app = FastAPI(title="pax-dns", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.resolver = resolver

    async def answer(request: Request, token: Optional[str]) -> Response:
        if request.method == "GET":
            try:
                wire = b64url_decode(request.query_params.get("dns", ""))
            except BadQuery as exc:
                return Response(str(exc), status_code=400, media_type="text/plain")
        else:
            ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if ctype != DOH_CT:
                return Response(f"Content-Type must be {DOH_CT}", status_code=415,
                                media_type="text/plain")
            declared = request.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > MAX_MESSAGE:
                return Response("DNS message too large", status_code=413, media_type="text/plain")
            wire = await request.body()
            if len(wire) > MAX_MESSAGE:
                return Response("DNS message too large", status_code=413, media_type="text/plain")
        try:
            res = await resolver.resolve(wire, token)
        except BadQuery as exc:
            return Response(str(exc), status_code=400, media_type="text/plain")
        ttl = min_ttl(res.reply, settings.block_ttl)
        return Response(res.wire, media_type=DOH_CT,
                        headers={"Cache-Control": f"max-age={max(0, ttl)}"})

    @app.api_route("/u/{token}/dns-query", methods=["GET", "POST"])
    async def user_query(token: str, request: Request):
        return await answer(request, token)

    @app.api_route("/dns-query", methods=["GET", "POST"])
    async def public_query(request: Request):
        if not settings.public_endpoint:
            return Response(status_code=404)
        return await answer(request, None)

    @app.get("/health")
    def health():
        return JSONResponse({
            "ok": True,
            "version": __version__,
            "users": len(resolver.store),
            "category_entries": len(syncer.category),
            "builtin_entries": {k: len(v) for k, v in syncer.builtin.items()},
            "last_sync_age_seconds": (None if syncer.last_sync is None
                                      else round(time.time() - syncer.last_sync, 1)),
            "sync_failures": syncer.failures,
        })

    return app
