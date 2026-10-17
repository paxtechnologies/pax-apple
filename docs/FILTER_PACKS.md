# Filter packs (v0.8.19)

Pax's filter improves itself every night with no person and no outside service in the loop. The
workflow runs from this repository on GitHub Actions; anyone can read what it did and why.

## How the loop works

1. **03:00 UTC every night** (and on demand), `.github/workflows/filter-loop.yml` runs
   `lists/loop/run.py` on `main`.
2. **Refresh**: it downloads the sources Pax's lists are built from (see [FILTER_LISTS.md](FILTER_LISTS.md)),
   the newly registered domains and the Tranco top 1M.
3. **Check new candidates**: names that appeared in the two checked sources (restricted content and web
   proxies) and aren't covered yet are checked by their homepage, at most 8 requests a second and 1,000
   names a night (`lists/loop/homepage.py`). A name is added only when its own page labels itself for
   adults or shows restricted content, or is a working web proxy. Verdicts are remembered (30 days for a
   confirmed one, 90 days otherwise).
4. **Build** the lists with `lists/build.py` (gzip with mtime 0: the same inputs give the same bytes; the
   pack records the SHA-256 of every input and the commit it was built from).
5. **Gates** (all must pass):
   1. unit tests: `guard`, `common` and `lists` test suites;
   2. floors and max-drop: every block list keeps its bundled minimum size and shrinks by no more than its
      `max_drop` against the last published pack *and* the bundled lists;
   3. the 57 everyday UK sites (`lists/gates/everyday-uk.txt`) and the known-good set
      (`lists/gates/known-good.txt`, ~1,000 names): none blocked;
   4. Tranco top 10k: every name newly blocked against the last pack must be confirmed restricted or a
      proxy by its homepage. An unconfirmed one has its list entry *held back* from the pack (and from the
      next 30 nights' packs); more than 300 new blocks, more than 50 held back, or a new block from a code
      rule fails the run;
   5. benchmark: fresh held-out samples (adult names from sources Pax doesn't build from, each night
      different; a hand-kept proxy set; 250 ordinary sites from Tranco ranks 10,001-200,000) are scored by
      the new pack, the last pack and a reference resolver (at most 8 queries a second, 1,000 a night). The
      new pack must not lose more held-out names than it gains, beyond noise (1% of the set, at least 2),
      or block more ordinary sites the reference leaves open (0.5%, at least 1). The reference is a
      yardstick only: its answers are never copied into Pax's lists.
6. **Publish** (only if every gate passed): the pack is signed with the filter key (Actions secret `PAX_FILTER_SIGNING_KEY`, see Keys) and uploaded to the release tagged `filter-pack`, then mirrored to the orphan
   branch `filter-packs` (served by jsDelivr). The run then downloads and verifies what it published.
7. **Record**: the scoreboard (`scoreboard/history.csv`, `latest.md`, `latest.json`) and the loop's memory
   (`state/`) are committed to the `filter-loop` branch every night, published or not. Site names there are
   gzipped or encoded, never plain text.
8. **Refuse**: if any gate fails, nothing is published and the issue labelled `filter-loop` gets the reason.
   It closes itself when a later pack is published.

## What a Mac or server does with a pack

pax-guard (Mac) and the DoH servers check `filter-pack.json` every 6 hours (GitHub release first, jsDelivr
mirror second) and take a pack only if:

- it is signed with a key in `pax_signing.FILTER_PUBLIC_KEYS_HEX` (the app update key is never accepted
  for a pack, and the filter key never for an app update);
- its version is newer than the lists in use and the bundled lists, and wasn't refused before;
- it changes block lists only (the allowlist and SafeSearch rules change only with an app update), and the
  bundled manifest's floors, `max_drop` and `restricted` flags apply whatever the pack says;
- every changed file matches its signed SHA-256 (files are named by their hash), parses, and passes the floors;
- the canary self-test passes on the new lists before they are swapped in.

If a swapped-in pack later fails the canary, it is rolled back to the previous good lists at once and that
version is never taken again. If everything fails, the family-filter chain answers (never open). Refusals
and rollbacks are written to the tamper log; the version in use and the last check show in pax-guard's
status (`filter_pack`), in Settings › Advanced › Filter lists, and in the servers' `/v1/health`
(`dns.filter_pack`, `dns.lists_version`).

## Keys

- Filter key: Ed25519, its public half pinned in `guard/pax_signing.py` (`FILTER_PUBLIC_KEYS_HEX`). The
  private half (base64 of the 32-byte seed) exists only in the Actions secret `PAX_FILTER_SIGNING_KEY`;
  it was generated on the maintainer's own Mac and never shared. The sign step checks it against the
  pinned key before anything is published.
- The filter workflow never has the app update key (`PAX_UPDATE_SIGNING_KEY`, used by Build DMG only).
- Domain separation: a pack's signature covers `pax-filter-pack-v1` + a zero byte + the canonical payload;
  an app update's covers the canonical payload alone. So, besides being made with a different key, a pack
  signature can never verify as an app update, and an app update signature never as a pack.

Checking the secret: run the workflow by hand with `show_key` ticked; it prints the secret's public half
next to the pinned one and does nothing else.

Rotating the filter key: add the new public key to `FILTER_PUBLIC_KEYS_HEX`, ship an app release, then
change the secret.

## Web proxies and bypass sites (loop update, 2026-10-17)

Loop-only change: nothing in the app reads these files, so it ships through filter
packs with no app release.

- **More candidates, open sources only** (lists/loop/proxy.py). Besides the UT1
  redirector category, each night the loop reads up to 300 proxy pages it has already
  confirmed and queues the sites they link to (proxy pages and proxy directories link
  to more proxies; links not reached tonight wait in `state/proxy-frontier.json.gz`),
  takes newly registered names that read like a proxy, searches certificate
  transparency for a rotating handful of confirmed proxy brands, and tries those
  brands under the top-level domains mirrors use. Redirector names that read like a
  proxy are checked before the rest, and a DNS check drops names that no longer exist
  before any page is fetched ("gone", rechecked after 90 days). Every candidate still
  needs a homepage verdict of "proxy" before it is added, and the Tranco and
  known-good gates still apply.
- **Homepage check**: pages built on the common web-proxy engines, "web VPN",
  unblocker, mirror and translator-proxy titles count as proxies, and so do paid proxy
  networks (a browser set to use one resolves names at the proxy, so it gets round
  the filter like a VPN); parked or suspended
  pages are recognised from the page itself; a gambling page on an old proxy name is
  not a proxy; the site's own name in its title is not evidence. Tuned on redirector
  pages only.
- **Benchmark**: the hand-kept proxy set is scored on names that still resolve (a
  name that no longer exists counted as "blocked" by the reference). A fresh
  held-out proxy sample is added: two public circumvention lists Pax never builds
  from and never uses as a candidate source, re-checked every night (names that
  resolve and whose homepage is a working proxy today).
- **Proxy gate**: on both proxy sets the candidate pack may not lose a proxy the last
  pack blocked unless it gains at least as many (no noise allowance, since Pax's
  decisions are deterministic). The scoreboard shows both sets.
- Nightly homepage checks went from 1,000 to 1,500, half for proxy candidates when
  there are enough, so restricted-content candidates keep about 750 a night. A manual
  run can raise `verify_max` (up to 5,000) and `dns_max` (up to 40,000) to work
  through a backlog.

### Round 2 (2026-10-17 evening)

The proxies still missed were mostly sites the loop had never looked at (proxy
lists, proxy software, VPN services, proxies hosted on shared hosts), not sites it
judged wrongly. So round 2 widens discovery and tightens the judgement:

- **Ranked names**: Tranco names below the top 10k whose registrable label reads
  like a proxy or a VPN (the list is already downloaded for the gates).
- **Open-source proxy projects**: the GitHub search API (the workflow's own
  read-only token) finds repositories by topic and name (web proxy, unblocker,
  Ultraviolet, Rammerhead, Scramjet and similar engines) and takes their published
  sites: the homepage field and `<user>.github.io` sites. This is how proxies on
  shared hosts (github.io, pages.dev, vercel.app, netlify.app) are found, one host
  name at a time; the shared host itself is never blocked.
- New registrations that read like a VPN are candidates too, and the loop re-reads
  up to 800 confirmed proxy pages a night for links (was 300).
- **Candidate verdict** (`homepage.candidate_verdict`, new candidates and the
  top-10k gate only): consumer VPN services count as bypass sites (Pax already
  treats VPN apps as bypass), but not enterprise VPN gateways, VPN detection
  services, reviews or news; pages that use "proxy" for something else (developer
  and network tools, email security, game test servers, trading-card proxies,
  handle/DOI resolvers) and "unblocked games" sites without proxy code are not
  proxies; "unblock" inside another word is not evidence. Tuned on ranked names
  that read like a proxy or VPN, never on the held-out lists.
- The benchmark keeps labelling its fresh held-out sample with the unchanged
  `homepage.verdict`, so what counts as a working proxy there does not move.
- Round 3: the READMEs of the most recently updated of those repositories (up to 80
  a night) are read for the sites they link to (unblocker READMEs list their
  official mirrors), and ranked names are checked before new registrations, since
  they are sites people actually visit.
- Round 4 (precision): the UT1 "vpn" category (same maintainer and licence as the
  redirector category) is a candidate source. The candidate verdict no longer takes
  a handful of proxy words in the body (fewer than 10) as enough when the title says
  nothing about proxies, unblocking or hiding your IP (IP checkers, fingerprint
  tests and hosting lists were getting in), and a bot check or loading screen counts
  as "down", not as evidence. Each night up to 400 proxies the workflow confirmed
  earlier are re-judged, longest-unchecked first: one that is now plainly something
  else ("other") leaves the list; one that is down stays. The proxy gate still
  refuses a pack that loses more benchmark proxies than it gains.
- Round 5 (new sources): the remaining misses were in no source the loop read, so
  two kinds of source were added, both candidates only (DNS check, homepage
  verdict and every gate still apply, and nothing is copied into a list unchecked):
  - Chrome top sites: the Chrome UX Report top-sites lists (Google, CC BY 4.0;
    monthly CSV snapshots of the public data), worldwide and for 20 countries.
    Names whose registrable label reads like a proxy or VPN are checked right
    after the links and project sites, before the Tranco names. These lists rank
    sites by real visits, so they reach busy proxies and VPN services that never
    make Tranco. Five more countries are added each night in turn (60 more in
    all, every one within a fortnight).
  - Majestic Million (Majestic-12, CC BY 3.0; ranked by the number of linking
    sites): names below the top 10k that read like a proxy or VPN, checked after
    the Tranco names. Long-lived proxies collect links for years.
  - Curated lists other maintainers publish under open licences (Unlicense,
    CC0-1.0, Apache-2.0): VPN / proxy categories of public DNS blocklists, a
    per-engine list of web-proxy mirrors, and per-family lists of unblocker
    mirrors. Their addresses are kept encoded in lists/loop/proxy.py, like the
    held-out lists, and a test checks that none of them is, or comes from the same
    owner as, a held-out list.
  The candidate verdict also stops taking "unblock" alone in a title as evidence
  (drain services, a WordPress plugin, single re-hosted games, a news tracker) when
  there is no proxy code, fewer than 3 proxy words and no proxy or VPN word, and
  drain / plumbing services and organisations' own remote-access pages are not
  proxies. The loop's own bypass list already includes the encrypted-DNS / VPN /
  proxy bypass list it is built from, so that list is not a candidate source.

## Running it by hand

```sh
python3 lists/loop/run.py run --work /tmp/w --state /tmp/state --out /tmp/pack   # exit 0 = passed, 3 = refused
PAX_FILTER_SIGNING_KEY=... python3 lists/loop/run.py sign --out /tmp/pack
python3 lists/loop/run.py check-published                                         # verify the live pack
```
