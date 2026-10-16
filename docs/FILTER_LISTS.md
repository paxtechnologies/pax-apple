# Filter lists (v0.8.1)

Built by `lists/build.py` (standard library, reproducible gzip), bundled in `guard/filters/`, described by
`guard/filters/filters.json`, loaded by `guard/filter_lists.py`.

| List | Contents | Restricted | Floor |
|---|---|---|---|
| pax-block | Restricted content: HaGeZi and OISD restricted-content lists, the UT1 restricted-content category (blogspot.* dropped), Pax's hand list, pax-zones; minus pax-exclude and pax-allowlist; parent-collapsed | yes | ≥1,000,000 entries, max 10% drop |
| pax-bypass | HaGeZi Encrypted DNS/VPN/TOR/Proxy Bypass, minus anything pax-block covers (v0.8.1: split out of pax-block) | no | ≥5,000, max 30% drop |
| pax-nrd | Newly registered domains (WhoisDS, 14 days) whose first label matches the name rule at a label edge, minus its allow words | yes | optional, ≥100 |
| pax-allow | tailscale.com, character.ai (beat every block list) | — | — |
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

Daily, pax-guard fetches `lists-manifest.json` from the GitHub release tagged `lists`
(`https://github.com/paxtechnologies/pax-apple/releases/download/lists/`), else jsDelivr
(`@pax-lists` branch). The manifest must be signed with the release key ([UPDATES.md](UPDATES.md)); every
changed file must match its signed SHA-256, parse, meet its floor and not shrink by more than `max_drop`.
Only then is it swapped in; the replaced copy is kept as "previous" and the bundled copy is the last
fallback. A failed update changes nothing. The Build DMG workflow republishes the bundled lists on every
`v*` tag; a scheduled list rebuild is future work.

Rebuilding by hand:

```sh
cd lists
python3 build.py block --out /tmp/l && python3 build.py nrd --out /tmp/l && python3 build.py static --out /tmp/l
PAX_UPDATE_SIGNING_KEY=... python3 build.py manifest --out /tmp/l --sign-key-env PAX_UPDATE_SIGNING_KEY
python3 build.py bundle --from /tmp/l        # into ../guard/filters (parts <85 KB)
```
