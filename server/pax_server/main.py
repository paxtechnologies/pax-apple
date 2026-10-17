# SPDX-License-Identifier: GPL-3.0-only
"""Pax escrow service (FastAPI).

Run:  PAX_SERVER_KEY=$(python3 -m pax_server.crypto --generate-key) \
      uvicorn --factory pax_server.main:create_app --host 127.0.0.1 --port 8080
Serve it behind HTTPS only (Caddy / nginx / a PaaS); tokens and revealed
passwords travel in request/response bodies.
"""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import sys
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

from . import __version__
from .config import HOUR, Settings
from .blocklist import Blocklist
from .sync import ListSync
from .db import Database
from .escrow import Clock, Escrow, EscrowError, NotFound, RateLimited
from .limits import client_ip
from . import replica as replica_mod
from .notify import CRISIS_LINES, EmailSender, LoggingEmailSender, SmtpEmailSender


def _pax_code(status: int, error: str, message: str):
    """v0.7.0: the PAX-ESCROW-… support code for an error response, from the shared
    table in common/pax_errors.py (None when that file isn't deployed)."""
    try:
        import pax_errors  # type: ignore
    except ImportError:
        root = Path(__file__).resolve().parents[2] / "common"
        if not (root / "pax_errors.py").is_file():
            return None
        sys.path.insert(0, str(root))
        import pax_errors  # type: ignore
    return pax_errors.escrow_code(status, error, message)


class AccountIn(BaseModel):
    email: EmailStr


class NotifyIn(BaseModel):
    kind: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=4000)
    partner_email: Optional[str] = Field(default=None, max_length=254)
    partner_body: Optional[str] = Field(default=None, max_length=4000)


class WaitIn(BaseModel):
    wait_hours: Optional[int] = Field(None, ge=1)
    wait_days: Optional[int] = Field(None, ge=1)


class PartnerIn(BaseModel):
    email: Optional[EmailStr] = None  # null removes the partner (after the wait)


class DeviceIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    platform: str = Field("ios", pattern="^(ios|ipados|macos|mac)$")
    profile_identifier: str = Field(..., min_length=3, max_length=255)
    removal_password: str = Field(..., min_length=20, max_length=256)
    # v0.8.15 "Allow verified support release": the app sends its set-up choice (on by
    # default). Left out (an older app) it is off: that device never agreed to it.
    support_release: bool = False


class SupportSettingIn(BaseModel):
    allowed: bool


class SupportCodeIn(BaseModel):
    code: str = Field(..., min_length=10, max_length=400)


class AdblockIn(BaseModel):
    enabled: bool


class CategoryIn(BaseModel):
    enabled: bool


class ConfirmIn(BaseModel):
    confirm: bool


class EmergencyIn(BaseModel):
    reason: str = Field(..., max_length=2000)


class DomainIn(BaseModel):
    domain: str = Field(..., min_length=1, max_length=2048)


class SyncLinkIn(BaseModel):
    """v0.8.9: link a Mac's pax-guard (local escrow) to this account's list."""
    device_name: str = Field("Mac", min_length=1, max_length=100)
    platform: str = Field("macos", pattern="^(macos|mac)$")


class SyncIn(BaseModel):
    add: list[str] = Field(default_factory=list, max_length=2000)
    since: int = Field(0, ge=0)
    wait_seconds: Optional[int] = Field(None, ge=0)
    partner_email: Optional[str] = Field(None, max_length=254)


class SigninStartIn(BaseModel):
    email: EmailStr


class SigninIn(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=4, max_length=12)
    label: str = Field("", max_length=100)


class DnsSettingsIn(BaseModel):
    """v0.8.8: Pax's own DNS filter (iPhone/iPad). Omit a key to leave it.
    v0.8.13: x_media / bluesky_media are accepted only as true (or left out);
    false is refused with 422 media_always_blocked (PAX-DNS-016)."""
    x_media: Optional[bool] = None
    bluesky_media: Optional[bool] = None
    youtube_restricted: Optional[bool] = None


log = logging.getLogger("pax.server")


def _add_doh_routes(app: FastAPI, doh, settings: Settings) -> None:
    """v0.8.8 DoH endpoints: /u/<token>/dns-query (the dns.paxpeace.com site)
    and /v1/doh/u/<token>/dns-query (the same through api.paxpeace.com)."""
    import anyio
    from fastapi.responses import Response
    from . import doh as doh_mod

    limiter = anyio.CapacityLimiter(max(1, settings.doh_max_inflight))

    async def answer(request: Request, token: str) -> Response:
        if not doh_mod.TOKEN_RE.match(token or ""):
            return Response(status_code=404)
        try:
            body = await request.body() if request.method == "POST" else None
            wire = doh_mod.wire_from_request(request.method, request.query_params.get("dns"),
                                             request.headers.get("content-type", ""), body)
        except doh_mod.BadQuery as exc:
            code = 415 if "Content-Type" in str(exc) else 400
            return Response(str(exc), status_code=code, media_type="text/plain")
        ip = client_ip(request.client.host if request.client else None,
                       request.headers.get("x-forwarded-for"))
        status, out, headers = await anyio.to_thread.run_sync(doh.answer, wire, token, ip,
                                                              limiter=limiter)
        return Response(out, status_code=status, headers=headers)

    for path in ("/u/{token}/dns-query", "/v1/doh/u/{token}/dns-query"):
        app.add_api_route(path, answer, methods=["GET", "POST"], include_in_schema=False)


def _make_doh(settings: Settings, blocklist=None):
    from . import doh as doh_mod
    doh_mod.install_log_filter()
    state = settings.resolved_doh_state_dir()
    if settings.role == "dns":
        import os
        os.makedirs(state, exist_ok=True)
        feed = doh_mod.ReplicaFeed(settings.replica_primary_url, settings.replica_key,
                                   cache_path=os.path.join(state, "replica-cache.json"))
    else:
        feed = doh_mod.LocalFeed(blocklist)
    return doh_mod.DohService(feed, state, role=settings.role, rate=settings.doh_rate_per_ip,
                              burst=settings.doh_burst_per_ip)


def create_dns_app(settings: Settings, doh=None) -> FastAPI:
    """v0.8.8 role "dns": a second server that answers DoH only. No accounts,
    no escrow, no email; nothing here writes user state."""
    doh = doh if doh is not None else _make_doh(settings)
    caddy = None
    if settings.caddy_acme_forward and settings.doh_enabled:
        # v0.8.17: hand the primary's ACME challenges on (see caddy_sync.py).
        from .caddy_sync import CaddySync
        caddy = CaddySync(settings.dns_host, settings.api_host, settings.caddy_admin_url,
                          mode="dns")

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        doh.start()
        if caddy is not None:
            caddy.start()
        try:
            yield
        finally:
            doh.stop()
            if caddy is not None:
                caddy.stop()

    app = FastAPI(title="Pax DNS", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.doh = doh
    app.state.caddy = caddy

    @app.get("/v1/health")
    def health():
        out = {"ok": True, "version": __version__, "role": "dns", "dns": doh.status()}
        if caddy is not None:
            out["dns_site"] = caddy.state     # v0.8.17 (informational)
        return out

    _add_doh_routes(app, doh, settings)
    return app


def create_app(settings: Optional[Settings] = None, clock: Optional[Clock] = None,
               sender: Optional[EmailSender] = None, doh=None) -> FastAPI:
    settings = settings or Settings.from_env()
    if settings.role == "dns":
        return create_dns_app(settings, doh)
    escrow = Escrow(
        db=Database(settings.db_path),
        settings=settings,
        clock=clock or Clock(),
        sender=sender or SmtpEmailSender.from_env() or LoggingEmailSender(),
    )
    blocklist = Blocklist(escrow)
    list_sync = ListSync(blocklist)
    if doh is None and settings.doh_enabled:
        doh = _make_doh(settings, blocklist)
    caddy = None
    if settings.caddy_sync and settings.doh_enabled:
        from .caddy_sync import CaddySync
        caddy = CaddySync(settings.dns_host, settings.api_host, settings.caddy_admin_url)

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        if doh is not None:
            doh.start()
        if caddy is not None:
            caddy.start()
        # Applies blocklist changes whose 72 h wait has ended (and emails about
        # them). pax-dns does not depend on this: the effective lists are computed
        # from the timestamps. v0.8.5: also lapses removal requests whose window
        # (or, for a grace request, the grace period) has passed.
        task = None
        if settings.blocklist_sweep_seconds > 0:
            async def sweep():
                while True:
                    try:
                        await asyncio.to_thread(blocklist.apply_due)
                    except Exception:  # noqa: BLE001
                        log.exception("blocklist sweep failed")
                    try:
                        await asyncio.to_thread(escrow.lapse_due)
                    except Exception:  # noqa: BLE001
                        log.exception("removal lapse sweep failed")
                    await asyncio.sleep(settings.blocklist_sweep_seconds)
            task = asyncio.create_task(sweep())
        try:
            yield
        finally:
            if task:
                task.cancel()
            if doh is not None:
                doh.stop()
            if caddy is not None:
                caddy.stop()

    app = FastAPI(title="Pax escrow", version=__version__, lifespan=lifespan,
                  description="Removal-password escrow with wait timers. GPL-3.0.")
    app.state.escrow = escrow
    app.state.blocklist = blocklist
    app.state.list_sync = list_sync
    app.state.doh = doh
    app.state.caddy = caddy

    @app.exception_handler(EscrowError)
    async def _escrow_error(_req: Request, exc: EscrowError):
        body = {"error": exc.code, "message": exc.message}
        body.update(exc.extra)
        code = _pax_code(exc.status, exc.code, exc.message)
        if code:
            body["pax_code"] = code   # v0.7.0 support code (docs/ERROR_CODES.md)
        return JSONResponse(status_code=exc.status, content=body)

    def current_account(authorization: Optional[str] = Header(None)):
        token = None
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        return escrow.authenticate(token)

    @app.post("/v1/notify", status_code=202)
    def notify_relay(body: NotifyIn, acct=Depends(current_account)):
        """v0.8.0 relay for a Mac using local escrow: pax-guard asks the server
        (Pax's or your own) to email its accountability partner, because the
        Mac has no mail server of its own. Account-authenticated, rate-limited."""
        return escrow.relay_notify(acct, body.kind, body.subject, body.body,
                                   body.partner_email, body.partner_body)

    @app.get("/v1/health")
    def health():
        out = {"ok": True, "version": __version__,
               # v0.8.9: what the app's wait picker may offer on this server.
               "wait_limits": {"min_wait_seconds": settings.min_wait_seconds,
                               "max_wait_seconds": settings.max_wait_seconds,
                               "default_wait_seconds": settings.default_wait_seconds}}
        if doh is not None:
            out["dns"] = doh.status()     # v0.8.8 (informational: never fails the update)
        if caddy is not None:
            out["dns_site"] = caddy.state
        # v0.8.10: which domain automated mail is sent from (no address, no secrets).
        dom = getattr(escrow.sender, "from_domain", None)
        if dom:
            out["mail_from_domain"] = dom
        return out

    @app.get("/v1/crisis-lines")
    def crisis_lines():
        return {"crisis_lines": CRISIS_LINES}

    @app.post("/v1/accounts", status_code=201)
    def register_account(body: AccountIn, request: Request,
                         x_forwarded_for: Optional[str] = Header(None)):
        """No token needed, so v0.8.5 limits it per client IP (X-Forwarded-For
        only from the local reverse proxy). The welcome email is best-effort:
        the account is created (201) even when it isn't sent."""
        ip = client_ip(request.client.host if request.client else None, x_forwarded_for)
        why = escrow.limits.check_signup(ip)
        if why:
            raise RateLimited(why)
        account_id, token = escrow.register_account(str(body.email))
        return {"account_id": account_id, "token": token}

    @app.get("/v1/accounts/me")
    def me(acct=Depends(current_account)):
        return escrow.account_status(acct)

    @app.put("/v1/accounts/me/wait")
    def set_wait(body: WaitIn, acct=Depends(current_account)):
        if (body.wait_hours is None) == (body.wait_days is None):
            raise EscrowError("give exactly one of wait_hours or wait_days")
        seconds = (body.wait_hours or 0) * HOUR + (body.wait_days or 0) * 24 * HOUR
        return escrow.set_wait(acct, seconds)

    @app.put("/v1/accounts/me/partner")
    def set_partner(body: PartnerIn, acct=Depends(current_account)):
        return escrow.set_partner(acct, str(body.email) if body.email else None)

    @app.put("/v1/accounts/me/adblock")
    def set_adblock(body: AdblockIn, acct=Depends(current_account)):
        """v0.4: ad/tracker blocking on self-locked Macs. Immediate both ways."""
        return escrow.set_adblock(acct, body.enabled)

    @app.post("/v1/devices", status_code=201)
    def register_device(body: DeviceIn, acct=Depends(current_account)):
        return escrow.register_device(acct, body.name, body.platform,
                                      body.profile_identifier, body.removal_password,
                                      support_release=body.support_release)

    @app.get("/v1/devices")
    def list_devices(acct=Depends(current_account)):
        return {"devices": escrow.list_devices(acct)}

    @app.post("/v1/devices/{device_id}/guard-token", status_code=201)
    def guard_token(device_id: str, acct=Depends(current_account)):
        """v0.4: a read-only token for pax-guard (root daemon on a self-locked Mac)."""
        return {"guard_token": escrow.issue_guard_token(acct, device_id)}

    @app.get("/v1/guard/config")
    def guard_config(x_pax_guard_token: Optional[str] = Header(None)):
        """What pax-guard enforces: the account's effective blocklist (a removal
        still waiting counts as blocked), its exceptions, ad blocking, and whether
        this Mac's password has been released (then pax-guard stops re-asserting)."""
        acct, d = escrow.guard_device(x_pax_guard_token)
        blocklist.apply_due(acct["id"])
        block, allow = blocklist.effective(acct["id"])
        return {
            "now": escrow.clock.now(),
            "device_id": d["id"],
            "blocked": block,
            "allowed": allow,
            "adblock": bool(acct["adblock"]),
            "released": d["released_at"] is not None,
            # v0.5: built-in categories pax-guard writes to /etc/hosts and pf.
            "categories": {"bypass": True,
                           "remote_desktop": blocklist.remote_desktop_blocked(acct["id"])},
        }

    @app.get("/v1/devices/{device_id}")
    def get_device(device_id: str, acct=Depends(current_account)):
        return escrow.device_status(acct, device_id)

    @app.post("/v1/devices/{device_id}/removal-request", status_code=201)
    def request_removal(device_id: str, acct=Depends(current_account)):
        return escrow.request_removal(acct, device_id)

    @app.post("/v1/devices/{device_id}/removal-request/cancel")
    def cancel_removal(device_id: str, acct=Depends(current_account)):
        return escrow.cancel_removal(acct, device_id)

    @app.post("/v1/devices/{device_id}/removal-request/confirm")
    def confirm(device_id: str, body: ConfirmIn, acct=Depends(current_account)):
        if not body.confirm:
            raise EscrowError("set confirm=true to reveal the removal password")
        return escrow.confirm_and_reveal(acct, device_id)

    @app.post("/v1/devices/{device_id}/emergency", status_code=201)
    def emergency(device_id: str, body: EmergencyIn, acct=Depends(current_account)):
        return escrow.emergency_release(acct, device_id, body.reason)

    @app.put("/v1/devices/{device_id}/support-release")
    def set_support_release(device_id: str, body: SupportSettingIn, acct=Depends(current_account)):
        """v0.8.15 "Allow verified support release": off at once; on after the wait,
        partner told first."""
        return escrow.set_support_release(acct, device_id, body.allowed)

    @app.post("/v1/devices/{device_id}/support-release/redeem")
    def redeem_support(device_id: str, body: SupportCodeIn, acct=Depends(current_account)):
        """v0.8.15: a one-time code from Pax support for this device. Partner emailed
        first (503 support_partner_unreachable otherwise), then the password is
        released at once, like confirming a finished request."""
        return escrow.redeem_support(acct, device_id, body.code)

    # ------------------------------------------------- blocklist (v0.3)
    @app.get("/v1/blocklist")
    def get_blocklist(acct=Depends(current_account)):
        return blocklist.view(acct)

    @app.post("/v1/blocklist", status_code=201)
    def add_block(body: DomainIn, acct=Depends(current_account)):
        """Immediate: more protection is never delayed."""
        return blocklist.add_block(acct, body.domain)

    @app.post("/v1/blocklist/remove", status_code=202)
    def remove_block(body: DomainIn, acct=Depends(current_account)):
        """A request: takes effect after the blocklist wait (default 72 h)."""
        return blocklist.request_unblock(acct, body.domain)

    @app.post("/v1/allowlist", status_code=202)
    def add_allow(body: DomainIn, acct=Depends(current_account)):
        """A request: an exception to the filter waits like a removal."""
        return blocklist.request_allow(acct, body.domain)

    @app.post("/v1/allowlist/remove")
    def remove_allow(body: DomainIn, acct=Depends(current_account)):
        """Immediate: dropping an exception is more protection."""
        return blocklist.remove_allow(acct, body.domain)

    @app.post("/v1/blocklist/requests/{request_id}/cancel")
    def cancel_blocklist_request(request_id: str, acct=Depends(current_account)):
        return blocklist.cancel_request(acct, request_id)

    # ------------------------------------------------ v0.8.9 list sync
    def sync_link(x_pax_sync_token: Optional[str] = Header(None)):
        return list_sync.authenticate(x_pax_sync_token)

    @app.post("/v1/sync/links", status_code=201)
    def create_sync_link(body: SyncLinkIn, acct=Depends(current_account)):
        """The app links this Mac's pax-guard to the account (a sync token)."""
        return list_sync.create_link(acct, body.device_name, "macos")

    @app.get("/v1/sync/links")
    def list_sync_links(acct=Depends(current_account)):
        return {"links": list_sync.links(acct)}

    @app.post("/v1/sync")
    def sync_now(body: SyncIn, link=Depends(sync_link)):
        """pax-guard: push additions (instant), report its wait and partner, pull the list."""
        acct, ln = link
        return list_sync.sync(acct, ln, body.add, since=body.since, wait_seconds=body.wait_seconds,
                              partner_email=body.partner_email)

    @app.post("/v1/sync/unblock", status_code=202)
    def sync_unblock(body: DomainIn, link=Depends(sync_link)):
        """The one removal rule: partner first (fail closed), then the wait."""
        acct, ln = link
        return list_sync.request_unblock(acct, ln, body.domain)

    @app.post("/v1/sync/requests/{request_id}/cancel")
    def sync_cancel(request_id: str, link=Depends(sync_link)):
        acct, ln = link
        return list_sync.cancel(acct, ln, request_id)

    @app.post("/v1/accounts/signin/start", status_code=202)
    def signin_start(body: SigninStartIn, request: Request,
                     x_forwarded_for: Optional[str] = Header(None)):
        """v0.8.9: a one-time code to the account's email, to sign another device in.
        The same answer whether or not the address has an account."""
        ip = client_ip(request.client.host if request.client else None, x_forwarded_for)
        why = escrow.limits.check_signup(ip)
        if why:
            raise RateLimited(why)
        list_sync.signin_start(str(body.email))
        return {"sent": True}

    @app.post("/v1/accounts/signin")
    def signin(body: SigninIn):
        return list_sync.signin_finish(str(body.email), body.code, body.label)

    # ------------------------------------------------ categories (v0.5)
    @app.get("/v1/categories")
    def get_categories(acct=Depends(current_account)):
        return blocklist.categories(acct)

    @app.put("/v1/categories/{category}")
    def set_category(category: str, body: CategoryIn, acct=Depends(current_account)):
        """On: immediate. Off (remote_desktop only): a request that waits like a
        removal (202), cancellable via /v1/blocklist/requests/{id}/cancel."""
        status, out = blocklist.set_category(acct, category.replace("-", "_"), body.enabled)
        return JSONResponse(out, status_code=status)

    @app.get("/v1/dns")
    def dns_info(acct=Depends(current_account)):
        return blocklist.dns_info(acct)

    @app.post("/v1/dns/rotate", status_code=202)
    def rotate_dns(acct=Depends(current_account)):
        return blocklist.rotate_token(acct)

    @app.get("/v1/dns/settings")
    def get_dns_settings(acct=Depends(current_account)):
        return blocklist.dns_settings(acct)

    @app.put("/v1/dns/settings")
    def put_dns_settings(body: DnsSettingsIn, acct=Depends(current_account)):
        """v0.8.8: YouTube Restricted Mode switches at once. v0.8.13: X and Bluesky
        media are always blocked; turning them off is refused (422, PAX-DNS-016)."""
        status, out = blocklist.set_dns_settings(acct, body.model_dump())
        return JSONResponse(out, status_code=status)

    # ------------------------------------------------ v0.8.8 replica feed
    @app.get("/v1/replica/dns/changes")
    def replica_changes(since: int = Query(0, ge=0),
                        x_pax_replica_key: Optional[str] = Header(None)):
        if not replica_mod.key_allowed(x_pax_replica_key, settings.replica_key_sha256):
            raise NotFound("not found")
        return blocklist.changes(since)

    if doh is not None:
        _add_doh_routes(app, doh, settings)

    # ------------------------------------------------ internal (pax-dns)
    def internal_auth(x_pax_internal_key: Optional[str] = Header(None)):
        key = settings.internal_api_key
        if not key or not x_pax_internal_key or not hmac.compare_digest(
                x_pax_internal_key.encode(), key.encode()):
            # 404, not 401: don't advertise the internal API.
            raise NotFound("not found")

    @app.get("/internal/v1/dns/changes", dependencies=[Depends(internal_auth)])
    def dns_changes(since: int = Query(0, ge=0)):
        return blocklist.changes(since)

    return app
