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
                 issuer: Optional[dict] = None):
        self.dns_host, self.api_host = dns_host, api_host
        self.admin = admin_url.rstrip("/")
        self.own_ip = own_ip
        self.resolver = resolver
        # Never through an HTTP proxy: the admin API is on loopback.
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.opener = opener or (lambda req: direct.open(req, timeout=15))
        self.health = health or self._api_health
        self.issuer = issuer
        self.state = "idle"
        self._stop = threading.Event()

    # -------------------------------------------------------- admin API
    def _req(self, method: str, path: str, body: Optional[dict] = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.admin + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        with self.opener(req) as r:
            raw = r.read()
        return json.loads(raw) if raw.strip() else None

    def _api_health(self) -> bool:
        """https://<api host>/v1/health through the local Caddy (real TLS)."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(("127.0.0.1", 443), timeout=10) as s:
                with ctx.wrap_socket(s, server_hostname=self.api_host) as t:
                    t.sendall(f"GET /v1/health HTTP/1.1\r\nHost: {self.api_host}\r\n"
                              "Connection: close\r\n\r\n".encode())
                    data = b""
                    while len(data) < 4096:
                        chunk = t.recv(4096)
                        if not chunk:
                            break
                        data += chunk
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
        want = desired_config(current, self.dns_host, peers, self.issuer)
        if _strip_ids(want) == _strip_ids(current):
            self.state = "in_place"
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
