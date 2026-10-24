# Filter lists (v0.8.1, name rules and checked additions since v0.8.18)

Built by `lists/build.py` (standard library, reproducible gzip), bundled in `guard/filters/`, described by
`guard/filters/filters.json`, loaded by `guard/filter_lists.py`.

| List | Contents | Restricted | Floor |
|---|---|---|---|
| pax-block | Restricted content: HaGeZi and OISD restricted-content lists, the UT1 restricted-content category (blogspot.* dropped), (v0.8.18) checked names from the ShadowWhisperer restricted-content list, Pax's hand list, pax-zones; minus pax-exclude and pax-allowlist; parent-collapsed | yes | ≥1,000,000 entries, max 10% drop |
| pax-bypass | HaGeZi Encrypted DNS/VPN/TOR/Proxy Bypass, plus (v0.8.18) checked web proxies from the UT1 "redirector" category, minus anything pax-block covers (v0.8.1: split out of pax-block) | no | ≥5,000, max 30% drop |
| pax-nrd | Newly registered domains (WhoisDS, 14 days) whose first label matches the name rule at a label edge, minus its allow words | yes | optional, ≥100 |
| pax-allow | character.ai (beats every block list; tailscale.com removed in 0.8.32) | — | — |
| safesearch | 385 exact-host rewrites | — | — |

**Restricted** (v0.8.1) means an exception never frees it: the forwarder blocks a restricted hit even when
the name is on the user's exception list, and pax-guard, the escrow server and make_profile.py refuse an
exception request for it with PAX-DNS-010 ("This site is in a category Pax always blocks, so it can't be
allowed.") before any wait or partner email. They also refuse a site CleanBrowsing Family blocks (a DoH
lookup through CleanBrowsing; NXDOMAIN, 0.0.0.0/:: or a block-page address counts as blocked, and a failed
lookup refuses). The flag comes from the bundled manifest; a signed update can't change it. An exception
can still free a VPN/proxy false positive (pax-bypass) or a Pax category such as remote desktop, and its
lookups still go through CleanBrowsing/AdGuard, so upstream filtering always applies.

The name-rule words, the single-label (whole top-level domain) entries, Pax's hand list, the iPhone
fallback sites and the restricted sources' addresses are kept encoded in `common/pax_restricted.py`
(gzip + base64, decoded at load time) so the repo reads calmly; `python3 common/pax_restricted.py --dump`
prints them.

## Name rules on every lookup (v0.8.18)

Lists only know names someone has already reported. Two name rules now run on **every** lookup, after the
lists, in pax-guard's forwarder and in the DoH server (both use `FilterStore.load()`, so the Mac and the
iPhone path get the same rules). Their words are kept encoded in `common/pax_restricted.py`
(`lookup_rule`, `bypass_rule`); `--dump` prints them.

| Rule | Reads | Counts a word when | Category |
|---|---|---|---|
| `lookup_rule` (restricted content) | the registrable label only (`www.example.co.uk` → `example`) | at the start or end of the label or next to `-` (not next to a digit); allow words skipped; names in or under `exclude` never match | restricted: an exception never frees it; an exception request is refused (PAX-DNS-010) |
| `bypass_rule` (web proxies, proxy lists) | the registrable label only | the label contains one of `contains`, or equals one of `labels`; `exclude` never matches | bypass: an exception can free it, like the rest of pax-bypass |

Why these limits:

* **Registrable label only.** Subdomain labels are often machine-made (CDN hashes, telemetry hosts, test
  hosts); judging them by their own labels produced the only false hits in testing.
* **No digit edge.** The new-registration rule also counts a word next to a digit; on every lookup that
  matched random hashes, so this rule doesn't.
* **Allow words and exclusions** come from reviewing every hit in the Tranco top 1M (list of 2026-10-14) and the
  Umbrella top 1M (2026-10-17) that no list already covered, with each homepage's title. Shop, place and
  brand names that contain a word by accident (a town, a furniture chain, a stock index, a DJ program, a
  tractor maker) are allow words; a few single sites are exclusions.
* **Web proxies by name, not "proxy" alone.** The bare word appears in many work services (application
  proxies, load balancers, developer tools, shareholder voting), so the rule only uses compound phrases
  that name a public web proxy or proxy list, and a short list of whole labels.

The Pax allowlist (`pax-allowlist.txt`) beats both rules, as it beats the lists. The rules ship with the code
(a signed app update), not with the list manifest, so a list update can't weaken them.

## Checked additions (v0.8.18)

Two inputs in `lists/verified/` (gzipped; one name per line; header says where each came from):

* `pax-block-extra.txt.gz`: names from the ShadowWhisperer restricted-content list (The Unlicense) that
  were live and whose homepage, fetched on the build date, either carried the standard adults-only
  self-label meta tag or showed restricted content in its title. Raw, that list also names mainstream
  sites (podcast apps, a university, a magazine, retailers), so it is never used unchecked.
* `pax-bypass-extra.txt.gz`: names from the UT1 "redirector" category (CC BY-SA 4.0) whose homepage, fetched
  on the build date, was a working web proxy or a public proxy list (not parked, not for sale, not a paid
  proxy network). Most of that category is dead or reused by unrelated sites, so it is never used unchecked.

Both are refreshed by hand with the maintainer's checking tools (not in the repo, as they hold the
matching words in plain text); `lists/build.py` fails if either file is missing.

## Measuring against a reference resolver

The filter is checked against a public family-filtering resolver used only as a benchmark: its answers
are never copied into Pax's lists. Test sets are drawn from sources Pax does not use, so a list is never
graded on itself. Results are kept with the release notes for the maintainer.

## Media converters (v0.8.1)

`pax-dns/lists/media-converters.txt` (~410 sites) and `pax-dns/lists/media-converter-keywords.txt` (a
label-edge name rule such as `ssstwitter`, `twittervideo`, `videodownloader`, `tomp4`, whole-label
`nitter`): sites that turn a link to a post on X, Instagram, TikTok, Reddit, YouTube or Facebook into a video
file, general file converters that also take video links, the embed and mirror sites that re-serve X,
Bluesky, Reddit, Instagram and TikTok media (fxtwitter, vxtwitter, fixupx, nitter instances, bskx, fxbsky,
rxddit, vxreddit and others), and three media file hosts. Always on, restricted (no exceptions), enforced by
pax-guard's forwarder and /etc/hosts block on the Mac and by pax-dns. Curated by Pax from known services
plus the name rule run over the Tranco top 1M (2026-10-15); no permissively licensed community list of
these exists that Pax could reuse. The name rule had 0 hits on Pax's UK false-positive set and 0 on the
Tranco top 1,000; in the Tranco top 1M every hit but one was a converter (the one, a software download
portal, was dropped from the rule).

**iPhone/iPad trade-off.** iOS has no Pax forwarder, so the full category only applies through pax-dns (the
per-user DoH address). Apple's web filter takes at most 500 DenyListURLs, so the profile carries the 60
most-visited converters and mirrors (`profile/media_converters.py`, one https URL each) and the custom block
cap drops from 496 to 376 (368 since the remote AI browsers below took 8 more). Custom sites past the cap
still apply through the synced list in pax-dns.

## Remote AI browsers (v0.8.1)

Project rule (2026-10-15): **an AI service that lets the user control a remote computer or browser is
blocked.** ChatGPT's "Work" cloud browser is a remote computer the user can take over, which goes round
every filter on the device. Its takeover stream couldn't be told apart from the rest of ChatGPT, so the whole
service is blocked. Manus (a cloud-computer agent) falls under the same rule.

`pax-dns/lists/remote-ai-browsers.txt`: chatgpt.com, chat.openai.com, ios.chat.openai.com,
android.chat.openai.com, desktop.chat.openai.com, oaiusercontent.com, oaistatic.com and manus.im, plus a
few exact subdomains for the Mac's /etc/hosts layer (ab.chatgpt.com, cdn.oaistatic.com,
files.oaiusercontent.com, api.manus.im). **openai.com itself (docs, API, platform) is not blocked**; only
its chat.* hosts are. Always on and restricted, like the media converters: an exception never frees it and
an exception request is refused with PAX-DNS-010.

| Where | How |
|---|---|
| Mac, DNS | pax-guard's forwarder (suffix match, so every subdomain) and pax-dns |
| Mac, /etc/hosts | every listed name and its www. name |
| Mac, browsers | Chrome/Edge/Brave/Chromium `URLBlocklist` and Firefox `WebsiteFilter` (profile) |
| Mac, apps | pax-guard kills and quarantines the ChatGPT desktop app (`com.openai.chat`, also matched as `ChatGPT.app`), `ChatGPT Atlas.app` and `Manus.app`, the same way as the unmanageable browsers |
| iPhone/iPad, web | the 8 domains above in the web filter's `DenyListURLs`, always (`profile/remote_ai_browsers.py`) |
| iPhone/iPad, apps | `blockedAppBundleIDs` (and the legacy key) in `com.apple.applicationaccess`: `com.openai.chat` (ChatGPT) and `tech.butterfly.app` (Manus), always, even without the default bypass-app list. Supervised devices only |
| iPhone/iPad, DNS | pax-dns, when the phone uses the per-user DoH address |

**Why the app block on iPhone.** Apple's web filter (`com.apple.webcontent-filter` DenyListURLs) covers
WebKit only: Safari and in-app web views. A native app such as ChatGPT makes its own connections and isn't
stopped by it, so the profile also blocks the app by bundle ID. Both bundle IDs were checked with Apple's
iTunes lookup API on 2026-10-15; `profile/refresh_bypass_apps.py` re-checks them.

**The 500 budget on iPhone/iPad:** 361 custom + 11 media hosts (4 Reddit/Imgur, and since v0.8.13 the 7
X/Bluesky media hosts, always) + 60 converters + 8 remote AI browsers + 60 fallback URLs = 500. Before 0.8.13
the app sent the X/Bluesky hosts as custom blocks (368 custom), so the room for the user's own sites is the same (`make_profile.MAX_CUSTOM_DENYLIST_URLS`,
`BulkSiteImport.iosCustomLimit` in the app).

**Chrome's limit on the Mac.** `URLBlocklist` holds up to 1,000 entries. Pax's list is the internal-page
blocks, up to 500 custom sites, the ~250 always-on bypass sites and the remote AI browsers, which stays
under 1,000 (tested); `mac_policies.chromium_policies` refuses to build a longer one.

Plug-in lists: one JSON descriptor per list in `/Library/PaxGuard/lists.d/` (root-owned, not group/world
writable), kinds `block|allow`, formats `domains|hosts|adblock|keywords`.

## Updates

Since v0.8.19 list updates are **filter packs**: built, tested and signed every night by the
filter workflow in this repo, with a key of their own, and checked again by every Mac and server
before use. See [FILTER_PACKS.md](FILTER_PACKS.md).

Rebuilding by hand:

```sh
cd lists
python3 build.py block --out /tmp/l && python3 build.py nrd --out /tmp/l && python3 build.py static --out /tmp/l
python3 build.py manifest --out /tmp/l --version 2026.1017.1   # unsigned: the bundled copy needs no signature
python3 build.py bundle --from /tmp/l        # into ../guard/filters (parts <85 KB)
```
