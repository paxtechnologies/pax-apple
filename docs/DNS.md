# DNS on the Mac (v0.8.0)

(v0.8.9: blocked sites are shared between the Mac and iPhones by default; see [SYNC.md](SYNC.md).)

v0.8.0 replaces the v0.7 CleanBrowsing DoH profile payload on the Mac with **pax-guard's local forwarder**
on `127.0.0.1:53` (`guard/dns_forwarder.py`, standard library only). The iPhone/iPad is unchanged: its
profile sends DNS straight to CleanBrowsing Family over DoH.

Per query, in order:

1. SafeSearch rewrite (385 exact hosts: Google, YouTube Strict, Bing, DuckDuckGo) → CNAME + addresses.
   v0.8.6: with YouTube Restricted Mode switched off, YouTube's 7 names skip this rewrite and go to
   CleanBrowsing Adult DoH (no YouTube rewrite), then AdGuard Family (restricts again), else SERVFAIL.
2. The user's exceptions (only after their wait) → upstream.
3. The user's blocked sites and Pax categories (X/Bluesky media, bypass sites, remote desktop) → `0.0.0.0` / `::`.
4. Pax allowlist (tailscale.com, character.ai) → upstream.
5. Local lists (pax-block ~1.35M domains, pax-nrd, plug-ins) → blocked.
6. Upstream over DoH: **CleanBrowsing Family**, then **AdGuard Family** on failure or timeout. Both down →
   SERVFAIL. Never plain, unfiltered DNS.

Upstreams are reached at pinned IPs (TLS still checks the name). A health check runs every minute; Home shows
the active upstream. Until the lists load, the forwarder answers SERVFAIL (never open).

pax-guard points every network service's DNS at `127.0.0.1` each cycle and restores the previous settings on
removal. pf allows port 53 only to localhost and DoH (443) to the pinned upstreams only from root, with a
fallback rule set when pf's `user` matching is unavailable.

Why not dnscrypt-proxy, CoreDNS or Blocky: each is a 10-30 MB Go binary Pax would have to build universal,
sign and patch, and none does Pax's policy (user blocks, timed exceptions, categories) without a plug-in.

Tests: `guard/tests/test_v08_dns.py`, `guard/tests/test_e2e_mac.py`.

# DNS on the iPhone and iPad (v0.8.8): Pax's own filter

From 0.8.8, a new iPhone/iPad set-up locks the phone's encrypted DNS to **Pax's own DoH filter**:

    https://dns.paxpeace.com/u/<token>/dns-query        (RFC 8484, GET and POST)

The token is the account's DNS token: 192 random bits, stored as a SHA-256 hash for lookup and encrypted
at rest, the same token for every device of the account. Because the phone asks Pax for every name, a
site added in Pax (Blocked sites) is blocked on every phone within seconds, in every app and browser,
with no new profile. Removing one goes through the one removal rule (v0.8.9): the partner is emailed
**before** the request starts; if that email can't be sent, nothing starts (HTTP 503, PAX-ESCROW-010);
then the wait (`PAX_BLOCKLIST_DELAY`: by default the user's own wait, the longer of the account's and a
linked Mac's; `fixed` = `PAX_BLOCKLIST_DELAY_SECONDS`, 72 h, the 0.8.8 rule). An exception for a
restricted site is refused (PAX-DNS-010).

**v0.8.9: the Mac's list is the same list.** A Mac with its own key syncs its blocked sites with the
account (on by default), so a site added on the Mac reaches the phone's filter within seconds and the
other way round within about 15 s. See [SYNC.md](SYNC.md).

The resolver runs **inside pax-server** (`server/pax_server/doh.py`) with the **Mac's own engine**
(`guard/dns_forwarder.py` + `guard/filter_lists.py`), so an iPhone gets exactly the Mac's v2 lists and
rules. Per query, in order:

1. the user's own blocked sites (and their subdomains) → `0.0.0.0` / `::`
2. SafeSearch rewrites (Google, Bing, DuckDuckGo; YouTube unless the user turned Restricted Mode off)
3. restricted, never freed by an exception: pax-block (~1.34M names, includes Reddit's and Imgur's media
   hosts), pax-nrd, the name rule, media converters, remote AI browsers, and (v0.8.13) X's and Bluesky's
   media servers
4. the user's exceptions (after the wait)
5. Pax categories: cloud PCs / remote browsers / proxies (always), remote desktop (on unless switched off
   after the wait)
6. lists an exception may free (DoH / VPN / proxy names)
7. upstream: CleanBrowsing Family DoH, then AdGuard Family DoH; both down → SERVFAIL. Never open.
   With YouTube Restricted Mode off, YouTube's own names go to CleanBrowsing Adult, then AdGuard Family.

Unknown or retired tokens still get steps 2-7 (filtered, never open). Until the lists have loaded (about
10 s after a start), every answer is SERVFAIL.

**DNS settings** (`GET/PUT /v1/dns/settings`): `youtube_restricted`, chosen in "Choose what to block" and sent
just before the profile is made; instant both ways (as on the Mac). On Pax's filter the profile never carries
the per-domain YouTube bypass. v0.8.13: pictures and video on X and Bluesky are always blocked. `GET` reports
`x_media` and `bluesky_media` as true (and lists them in `always_blocked`); a `PUT` with either false is
refused with 422 `media_always_blocked` (PAX-DNS-016) before any request, wait or email, and nothing in that
request changes. The server forced older accounts back on at start-up and refuses any waiting
`x_media_off` / `bluesky_media_off` request.

**Second layer**: the profile still carries Apple's web filter with `DenyListURLs` (the sites typed at
set-up, X/Bluesky media, Reddit/Imgur media, media converters, remote AI browsers and the fallback list).
It only covers Safari and WebKit pages and is fixed at set-up; the DNS filter covers everything else.

**Before locking a phone** to the filter, the app checks `https://dns.paxpeace.com/health`. If it doesn't
answer, set-up stops with PAX-DNS-012 and nothing is changed on the phone (a supervised profile can't be
edited afterwards). **Advanced › "Use CleanBrowsing directly"** keeps the 0.8.7 behaviour (DNS straight to
CleanBrowsing Family); choosing the Core strength also uses the direct path.

**iPhones set up before 0.8.8 keep CleanBrowsing directly.** Their profile is locked and the supervision
key was deleted after set-up, so Pax can't change it. They only block the sites typed during their own
set-up (in Safari/WebKit) and never see later changes. To move one to Pax's filter, remove Pax with the
removal password (wait as usual), then set it up again with 0.8.8.

## Servers

| | Primary (`pax-api`) | Second (`pax-dns2`) |
|---|---|---|
| Hetzner | cx23, nbg1, server 170759416, 167.233.42.17 | cx23, hel1, server 170785748, 89.167.17.42 |
| Role | `all`: accounts, escrow, email, DoH | `dns`: DoH only |
| Names | api.paxpeace.com, dns.paxpeace.com | dns.paxpeace.com |
| User lists | the SQLite database | the primary's replica feed, polled every 3 s, full every 10 min, copy on disk |

Only the primary holds account state, so there is **no split brain**: the second server never writes. It
reads `GET https://api.paxpeace.com/v1/replica/dns/changes` with a shared key (its SHA-256 is in
`server/pax_server/replica.py`; the key itself is only in the second server's `/etc/pax/env`). The feed has
token hashes and effective lists, never a token, password or email. If the primary is down, the second
server keeps answering with every user's last known list (also after a restart, from
`/var/lib/pax/dns/replica-cache.json`); new edits wait until the primary is back.

**Failover**: `dns.paxpeace.com` has two A records (one per server). iOS connects by name through Network
framework, which resolves every address and races connection attempts, so an address that refuses or
times out is skipped and the other is used (Apple: WWDC18 "Introducing Network.framework"; the DNS
settings payload uses the host name when no server addresses are given). Not yet confirmed on a device.
A server that is up but answering errors (for example Caddy up, pax-server down) is not skipped, so the
self-updater rolls back any release whose `/v1/health` fails.

**Certificates with two A records**: either server may receive Let's Encrypt's HTTP-01 check, so each
passes a challenge it doesn't know to the other (port 80, `X-Pax-Acme-Fwd` stops loops) and TLS-ALPN is
off for this name. The second server's Caddyfile has this from cloud-init. The primary was built before
this, and the self-updater can't edit `/etc/caddy`, so pax-server adds the same site through Caddy's local
admin API (`server/pax_server/caddy_sync.py`), only once `dns.paxpeace.com` resolves to it, and loads the
previous configuration back if `https://api.paxpeace.com/v1/health` stops answering. A Caddy reload from
the Caddyfile drops it; the next check (every 2 minutes) adds it again. Since v0.8.9, `deploy/cloud-init.yaml` (outside the repo) has the `dns.paxpeace.com` site and the port-80
challenge hand-off in the primary's Caddyfile and sets `PAX_CADDY_SYNC=0`, so a rebuilt primary serves the
filter from its Caddyfile.

v0.8.17: the second server's catch-all `http://` block lost to Caddy's automatic HTTP->HTTPS redirect
for `dns.paxpeace.com` (Caddy puts that redirect before catch-all routes), so the primary's challenges
that reached it were redirected, not handed on, and the primary never got its certificate. pax-server on
the second server (role `dns`, `PAX_CADDY_ACME_FORWARD`, on by default) now puts a host-matched forwarding
route at the front of its port-80 server through the same admin API, checked against
`https://dns.paxpeace.com/health`. The primary, while its DoH site is in place but no certificate is served,
asks Caddy to reload the same configuration at most every 20 minutes so a fresh attempt starts.

**Privacy**: no query logging. Caddy has no access log; the primary drops uvicorn access-log lines for any
`dns-query` or replica path in-process, and the second server runs uvicorn with `--no-access-log`. Nothing
stores names or client addresses; the per-address rate-limit counters live in memory only.

**Abuse limits and sizing (cx23: 2 vCPU, 4 GB)**: 25 queries/s per client address with a burst of 400
(`PAX_DOH_RATE_PER_IP`, `PAX_DOH_BURST_PER_IP`; over it: HTTP 429), messages up to 4 KB, at most 48
queries resolving at once (`PAX_DOH_MAX_INFLIGHT`), answers cached (50,000 entries, TTLs capped). The lists
take ~60 MB of memory. One phone sends a few thousand queries a day, mostly answered from its own cache,
so one cx23 should carry a few thousand phones; above that, add servers behind the same name (estimate,
not load-tested).

## Risks (plainly)

* **Outage**: if both servers are unreachable, iPhones on Pax's filter can't resolve names, so browsing
  and most apps stop until one is back (SERVFAIL, never open). With one server, any outage of it did this.
* **Primary down**: DoH keeps working from the second server with the last known lists; adding/removing
  sites, removal requests and partner emails wait for the primary.
* **Privacy**: every name an iPhone looks up passes through Pax's servers (not stored). Users should know.
* **Load**: a busy day or abuse could hit the per-address limits or the box's CPU. The limits protect the
  box; a client over them gets errors.
* **Upstream**: unknown names still go to CleanBrowsing Family (then AdGuard Family). If both refuse Pax's
  servers, every answer is SERVFAIL.
* **Single DNS provider**: paxpeace.com's own DNS (Namecheap BasicDNS) has no health checks; a dead server
  stays in the answer and clients rely on connection racing to skip it.

**Mitigation in place**: the second cx23 in hel1 (another Hetzner site) behind the same name. Cost:
$6.49 + 20% backups $1.30 + IPv4 $0.60 = **$8.39 a month before VAT ($10.07 with 20% VAT)**, the same as
the primary. Further options, not bought: a third server in fsn1 or ash for the same price, or a DNS host
with health-checked failover.
