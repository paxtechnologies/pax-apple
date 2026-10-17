# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.8: give the already-running primary server the dns.paxpeace.com site
without a rebuild.

The primary (api.paxpeace.com) was provisioned by cloud-init, and its
Caddyfile only knows api.paxpeace.com. The self-updater swaps the code and
restarts pax-server; it can't edit /etc/caddy. So pax-server asks the local
Caddy, through Caddy's own admin API on 127.0.0.1:2019, to add:

  * a site for the DoH host (dns.paxpeace.com) that proxies only /u/* (the
    per-user DoH path) and /health to pax-server, and answers 404 to anything
    else (the escrow API is not exposed on that name); and
  * on port 80, for the DoH host only: ACME HTTP-01 challenges this server
    doesn't know are passed to the other DoH server(s), because with two A
    records the CA may ask either box (Caddy answers its own challenges first
    and falls through otherwise). A header stops the two from ping-ponging.
    TLS-ALPN challenges are turned off for that name for the same reason.

It is added only once the DoH host's public A records include this server's
address, so Caddy never burns certificate attempts before the DNS exists. The
change is checked: if https://api.paxpeace.com/v1/health no longer answers
through Caddy afterwards, the previous configuration is loaded back. Caddy's
admin API swaps a configuration atomically and refuses an invalid one.

A reload from the Caddyfile (a package upgrade) drops the addition; the next
check (every 2 minutes) puts it back. Rebuilt servers get the same thing from
the Caddyfile in deploy/cloud-init.yaml instead.

v0.8.17: two fixes for the primary never getting a dns.paxpeace.com
certificate.

  * Second server (role "dns", mode="dns"): its Caddyfile's port-80 block is a
    catch-all ("http://"), and Caddy puts its automatic HTTP->HTTPS redirects
    for dns.paxpeace.com in front of catch-all routes. So challenges for the
    primary that reached pax-dns2 were redirected instead of handed to the
    primary, and the CA's validation failed. pax-server on the second server
    now puts a forwarding route WITH a host matcher at the front of its own
    port-80 server (Caddy then puts its redirects after it). Same anti-loop
    header; checked against https://dns host/health and rolled back if that
    stops answering.
  * Primary: while the DoH site is in place but no certificate for the DoH
    host is served, ask Caddy to reload the same configuration (at most every
    20 minutes) so it starts a fresh certificate attempt instead of waiting
    out its back-off.
"""
from __future__ import annotations

import copy
import json
import logging
import socket
import ssl
import threading
import urllib.request
from typing import Callable, Optional

log = logging.getLogger("pax.caddy")

DNS_ROUTE_ID = "pax-doh-site"
FWD_ROUTE_ID = "pax-acme-forward"          # v0.8.17, second server
ACME_SERVER = "pax_acme_http"
FWD_HEADER = "X-Pax-Acme-Fwd"
METADATA_IPV4 = "http://169.254.169.254/hetzner/v1/metadata/public-ipv4"


def resolve_ipv4(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, socket.AF_INET)})
    except OSError:
        return []


def metadata_ipv4() -> Optional[str]:
    try:
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with direct.open(METADATA_IPV4, timeout=3) as r:
            return r.read().decode().strip() or None
    except Exception:  # noqa: BLE001
        return None


def dns_site_route(dns_host: str, upstream: str = "127.0.0.1:8080") -> dict:
    proxy = {"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]}
    return {
        "@id": DNS_ROUTE_ID,
        "match": [{"host": [dns_host]}],
        "terminal": True,
        "handle": [{"handler": "headers", "response": {"deferred": True, "delete": ["Server"]}},
                   {"handler": "subroute", "routes": [
            {"match": [{"path": ["/u/*"]}], "handle": [proxy], "terminal": True},
            {"match": [{"path": ["/health"]}],
             "handle": [{"handler": "rewrite", "uri": "/v1/health"}, proxy], "terminal": True},
            {"handle": [{"handler": "static_response", "status_code": 404}]},
        ]}],
    }


def acme_forward_server(dns_host: str, peers: list[str], http_port: int = 80) -> dict:
    """Port 80 for the DoH host: unknown challenges go to the peer(s); the rest
    keeps Caddy's automatic HTTP->HTTPS redirect (added by Caddy itself)."""
    routes = []
    if peers:
        routes.append({
            "match": [{"host": [dns_host], "path": ["/.well-known/acme-challenge/*"],
                       "not": [{"header": {FWD_HEADER: ["*"]}}]}],
            "handle": [{"handler": "reverse_proxy",
                        "upstreams": [{"dial": f"{p}:80"} for p in peers],
                        "headers": {"request": {"set": {FWD_HEADER: ["1"]}}}}],
            "terminal": True,
        })
    routes.append({"match": [{"host": [dns_host], "path": ["/.well-known/acme-challenge/*"]}],
                   "handle": [{"handler": "static_response", "status_code": 404}], "terminal": True})
    return {"listen": [f":{http_port}"], "routes": routes}


def acme_forward_route(dns_host: str, peers: list[str]) -> dict:
    """v0.8.17: an unknown challenge for the DoH host goes to the peer(s), once."""
    return {
        "@id": FWD_ROUTE_ID,
        "match": [{"host": [dns_host], "path": ["/.well-known/acme-challenge/*"],
                   "not": [{"header": {FWD_HEADER: ["*"]}}]}],
        "handle": [{"handler": "reverse_proxy",
                    "upstreams": [{"dial": f"{p}:80"} for p in peers],
                    "headers": {"request": {"set": {FWD_HEADER: ["1"]}}}}],
        "terminal": True,
    }


def peer_forward_config(current: dict, dns_host: str, peers: list[str]) -> dict:
    """v0.8.17 (second server): `current` with the challenge forwarder at the
    FRONT of the existing port-80 server. A route with a host matcher keeps
    Caddy's own redirects for that host behind it. Nothing else changes; with
    no port-80 server, a separate one is added (as on the primary)."""
    cfg = copy.deepcopy(current or {})
    http = cfg.setdefault("apps", {}).setdefault("http", {})
    servers = http.setdefault("servers", {})
    http_port = int(http.get("http_port", 80))
    target = None
    for name, srv in servers.items():
        if name == ACME_SERVER:
            continue
        if any(str(l).endswith(f":{http_port}") for l in srv.get("listen", [])):
            target = srv
            break
    if target is None:
        servers[ACME_SERVER] = acme_forward_server(dns_host, peers, http_port)
        return cfg
    routes = [r for r in target.get("routes", []) if r.get("@id") != FWD_ROUTE_ID]
    target["routes"] = ([acme_forward_route(dns_host, peers)] if peers else []) + routes
    return cfg


def https_get_local(host: str, path: str, timeout: float = 10) -> bytes:
    """GET https://<host><path> through the local Caddy (127.0.0.1:443), with
    real certificate checks. Raises on any TLS or connection error."""
    ctx = ssl.create_default_context()
    with socket.create_connection(("127.0.0.1", 443), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            t.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      "Connection: close\r\n\r\n".encode())
            data = b""
            while len(data) < 4096:
                chunk = t.recv(4096)
                if not chunk:
                    break
                data += chunk
    return data


def local_cert_ok(host: str) -> bool:
    """v0.8.17: does the local Caddy serve a valid certificate for `host`?"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except Exception:  # noqa: BLE001
        return False


ACME_NO_ALPN = {"module": "acme", "challenges": {"tls-alpn": {"disabled": True}}}


def tls_policy(dns_host: str, issuer: Optional[dict] = None) -> dict:
    return {"subjects": [dns_host], "issuers": [issuer or ACME_NO_ALPN]}


def desired_config(current: dict, dns_host: str, peers: list[str], issuer: Optional[dict] = None) -> dict:
    """`current` plus the DoH site, the port-80 challenge forwarder and the TLS
    policy. Everything else is left exactly as it was."""
    cfg = copy.deepcopy(current or {})
    http = cfg.setdefault("apps", {}).setdefault("http", {})
    servers = http.setdefault("servers", {})
    https_port = int(http.get("https_port", 443))
    http_port = int(http.get("http_port", 80))
    https_srv = None
    for name, srv in servers.items():
        if name == ACME_SERVER:
            continue
        if any(str(l).endswith(f":{https_port}") for l in srv.get("listen", [])):
            https_srv = srv
            break
    if https_srv is None:
        raise ValueError(f"no :{https_port} server in the Caddy configuration")
    routes = [r for r in https_srv.get("routes", []) if r.get("@id") != DNS_ROUTE_ID]
    https_srv["routes"] = [dns_site_route(dns_host)] + routes
    servers[ACME_SERVER] = acme_forward_server(dns_host, peers, http_port)
    tls = cfg["apps"].setdefault("tls", {})
    pols = [p for p in tls.setdefault("automation", {}).get("policies", [])
            if dns_host not in (p.get("subjects") or [])]
    tls["automation"]["policies"] = [tls_policy(dns_host, issuer)] + pols
    return cfg


def _strip_ids(x):
    return json.dumps(x, sort_keys=True)


class CaddySync:
    def __init__(self, dns_host: str, api_host: str, admin_url: str = "http://127.0.0.1:2019",
                 own_ip: Optional[str] = None, resolver: Callable[[str], list] = resolve_ipv4,
                 opener: Optional[Callable] = None, health: Optional[Callable[[], bool]] = None,
                 issuer: Optional[dict] = None, mode: str = "primary",
                 cert_probe: Optional[Callable[[str], bool]] = None,
                 kick_every: float = 1200.0, now: Optional[Callable[[], float]] = None):
        if mode not in ("primary", "dns"):
            raise ValueError("mode must be 'primary' or 'dns'")
        self.mode = mode
        self.dns_host, self.api_host = dns_host, api_host
        self.admin = admin_url.rstrip("/")
        self.own_ip = own_ip
        self.resolver = resolver
        # Never through an HTTP proxy: the admin API is on loopback.
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.opener = opener or (lambda req: direct.open(req, timeout=15))
        self.health = health or (self._dns_health if mode == "dns" else self._api_health)
        self.issuer = issuer
        self.cert_probe = cert_probe or local_cert_ok
        self.kick_every = kick_every
        import time as _time
        self.now = now or _time.monotonic
        self._last_kick: Optional[float] = None
        self.state = "idle"
        self._stop = threading.Event()

    # -------------------------------------------------------- admin API
    def _req(self, method: str, path: str, body: Optional[dict] = None,
             force: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if force:
            # Caddy skips a /load of an unchanged configuration unless asked.
            headers["Cache-Control"] = "must-revalidate"
        req = urllib.request.Request(self.admin + path, data=data, method=method,
                                     headers=headers)
        with self.opener(req) as r:
            raw = r.read()
        return json.loads(raw) if raw.strip() else None

    def _api_health(self) -> bool:
        """https://<api host>/v1/health through the local Caddy (real TLS)."""
        try:
            data = https_get_local(self.api_host, "/v1/health")
            return data.startswith(b"HTTP/1.1 200") and b'"ok":true' in data.replace(b" ", b"")
        except Exception:  # noqa: BLE001
            return False

    def _dns_health(self) -> bool:
        """v0.8.17 second server: https://<dns host>/health through the local Caddy."""
        try:
            data = https_get_local(self.dns_host, "/health")
            return data.startswith(b"HTTP/1.1 200") and b'"ok":true' in data.replace(b" ", b"")
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------ check
    def check_once(self) -> str:
        own = self.own_ip or metadata_ipv4()
        if not own:
            self.state = "no_own_ip"
            return self.state
        addrs = self.resolver(self.dns_host)
        if own not in addrs:
            self.state = "waiting_for_dns_record"
            return self.state
        peers = [a for a in addrs if a != own]
        current = self._req("GET", "/config/") or {}
        if self.mode == "dns":
            want = peer_forward_config(current, self.dns_host, peers)
        else:
            want = desired_config(current, self.dns_host, peers, self.issuer)
        if _strip_ids(want) == _strip_ids(current):
            self.state = self._in_place(current)
            return self.state
        if not self.health():
            # Caddy isn't serving the API right now: don't touch it.
            self.state = "api_unhealthy_skip"
            return self.state
        self._req("POST", "/load", want)
        if self.health():
            log.warning("Caddy: added %s (peers: %s)", self.dns_host, ", ".join(peers) or "none")
            self.state = "applied"
            return self.state
        log.error("Caddy: API unhealthy after adding %s; restoring the previous config", self.dns_host)
        self._req("POST", "/load", current)
        self.state = "rolled_back"
        return self.state

    def _in_place(self, current: dict) -> str:
        """The configuration is right. On the primary, also make sure Caddy is
        actually serving a certificate for the DoH host (v0.8.17)."""
        if self.mode == "dns" or self.cert_probe(self.dns_host):
            return "in_place"
        t = self.now()
        if self._last_kick is not None and t - self._last_kick < self.kick_every:
            return "waiting_for_certificate"
        if not self.health():
            return "api_unhealthy_skip"
        self._last_kick = t
        # Same configuration, forced: Caddy starts a fresh certificate attempt.
        self._req("POST", "/load", current, force=True)
        log.warning("Caddy: no certificate for %s yet; asked Caddy to try again", self.dns_host)
        return "certificate_retry"

    def run(self, every: float = 120.0, first_delay: float = 20.0) -> None:
        if self._stop.wait(first_delay):
            return
        while not self._stop.is_set():
            try:
                self.check_once()
            except Exception as exc:  # noqa: BLE001
                self.state = f"error:{type(exc).__name__}"
            if self._stop.wait(every):
                return

    def start(self) -> None:
        threading.Thread(target=self.run, daemon=True, name="pax-caddy-sync").start()

    def stop(self) -> None:
        self._stop.set()
