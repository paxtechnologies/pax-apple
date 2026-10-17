# Third-party notices

Pax Peace (Apple) is licensed under the GNU General Public License, version 3 only
(`GPL-3.0-only`, see `LICENSE`). It uses or credits the works below, each under its own licence.

## Method credit: attention awareness (no code copied)

Pax's "Keep my data" set-up for iOS 27 follows the method attention awareness documented and tested:
restore a seed backup holding only `CloudConfigurationDetails.plist` without system files
(`--skip-apps --remove --reboot`), then send `SetCloudConfiguration` over
`com.apple.mobile.MCInstall` while the phone is still in Setup Assistant, and read it back. Their write-up
also covers the on-phone steps, the re-pairing pitfalls and the iOS 26 path.

* Write-up: <https://attentionawareness.com/blog/supervise-iphone-ios-27-without-erasing>
* Source: <https://github.com/mertbuilds/attentionawareness> (read at commit
  `43b4f92c1fb1a00138ca4545bcd42df735a60918`, 2026-10-08)

**Licence note.** That repository has two licences. The site, extension and packages (including the
blog post) are MIT. The Mac app (`apps/mac`), which implements the method, is
**AGPL-3.0-only**, and it contains code adapted from Nugget (AGPL-3.0). So Pax copies **no** code from
`apps/mac`. Pax's implementation (`device/seed.py`, `device/pax_device.py`,
`mac-app/Sources/PaxCore/KeepDataSupervision.swift`) was written separately from the published
description, Apple's schema and the libraries below. The repository's MIT notice, which covers the
write-up, is reproduced here as a courtesy:

```
MIT License

Copyright (c) 2026 Mert Duzgun

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Code ported: TrollRestore (MIT)

`device/seed.py` ports the `Manifest.mbdb` record writer (`sparserestore/mbdb.py`) and the
`Status.plist` and `Manifest.plist` values, including the `BackupKeyBag` bytes
(`sparserestore/backup.py`), from TrollRestore, <https://github.com/JJTech0130/TrollRestore>, commit
`082f2520556b9aa8e2b8d6661b81a954ee35966b`. A test checks that the record bytes match.

```
Copyright 2024 James Gill (JJTech0130)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the “Software”), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Data: Apple device-management schema (MIT)

(v0.4 adds `com.apple.ManagedClient.preferences.yaml` from the same repository.)

`profile/apple-schema/` (including `skipkeys.yaml`, the Setup Assistant pane names Pax skips) comes
from <https://github.com/apple/device-management>, MIT, Copyright Apple Inc. See
`profile/apple-schema/LICENSE.txt`.

## iPhone helper (bundled in Pax.app since v0.8.6)

Pax.app contains a Python runtime with pymobiledevice3 for "Keep my data"
(`Contents/Resources/device/python`). Full list with versions and licences:
[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md#iphone-helper-runtime-bundled-since-v086). Licence texts
travel with it (`device/python/LICENSES/` and each package's `.dist-info`).

| Component | Licence | Used for |
|---|---|---|
| [CPython](https://www.python.org/) 3.12.15, built by [python-build-standalone](https://github.com/astral-sh/python-build-standalone) 20261009 | PSF-2.0; linked libraries: OpenSSL 3 (Apache-2.0), libffi, expat (MIT), mpdecimal, libedit, libuuid (BSD), liblzma (0BSD), bzip2, zlib, SQLite (public domain), ncurses (X11) | runs the helper and the iPhone profile generator |
| [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) 11.32.0 | GPL-3.0-or-later | lockdown, pairing, MCInstall (Get/SetCloudConfiguration, Escalate, InstallProfile[Silent], GetProfileList), restart, and since v0.8.6 the MobileBackup2 backup and seed restore |
| [cryptography](https://github.com/pyca/cryptography) 48.0.1 | Apache-2.0 or BSD-3-Clause | pairing, the PEM keybag for silent install |
| pyiosbackup, pygnuutils, ioregistry (GPL-3.0-or-later); requests (Apache-2.0); certifi, tqdm (MPL-2.0); pygments, click, idna, psutil, prompt-toolkit, pycparser, packaging (BSD); bpylist2, construct, cffi, charset-normalizer, hyperframe, ifaddr, questionary, urllib3, wcwidth (MIT / MIT-0); chardet (0BSD); backports-zstd, typing-extensions (PSF-2.0) | as listed | dependencies pymobiledevice3 imports |
| Apple Configurator `cfgutil` (Clean mode only, not bundled) | Apple licence | erase, prepare, install |

Source: every package is the unmodified release on PyPI (links in docs/DEPENDENCIES.md, each with an
sdist); the Python runtime is the unmodified python-build-standalone release, with files removed.
Pax's own code is GPL-3.0-only; the helper's Python files ship as source.

Up to v0.8.5 Pax also needed libimobiledevice's `idevicebackup2` (LGPL-2.1-or-later), installed by the
user with Homebrew. Pax no longer uses or ships it; developers can still point `PAX_IDEVICEBACKUP2` at
their own copy.

### pax-dns and server (v0.3)

| Component | Licence | Used for |
|---|---|---|
| [dnslib](https://github.com/paulc/dnslib) | BSD-2-Clause | DNS wire format, plain DNS server |
| [FastAPI](https://github.com/fastapi/fastapi) / [Starlette](https://github.com/encode/starlette) / [uvicorn](https://github.com/encode/uvicorn) | MIT / BSD-3-Clause / BSD-3-Clause | HTTP (escrow API, DoH) |
| [httpx](https://github.com/encode/httpx) | BSD-3-Clause | DoH upstream client |
| [idna](https://github.com/kjd/idna) | BSD-3-Clause | IDNA domain normalisation |

### Block lists and DNS services (downloaded or queried at run time, not shipped)

* **HaGeZi DNS blocklists**, <https://github.com/hagezi/dns-blocklists>, GPL-3.0. Fetched by
  `pax-dns/scripts/load_lists.py` (restricted-content and DoH/VPN/proxy-bypass lists), and since v0.4 by
  `guard/pax_guard.py` on a protected Mac: Multi LIGHT (legacy hosts build,
  <https://github.com/hagezi/dns-blocklists-legacy>, GPL-3.0), "Encrypted DNS servers" names and
  DoH server IPs. Downloaded daily to `/Library/PaxGuard/state`, never shipped in the app.
* **uBlock Origin Lite / uBlock Origin** (Raymond Hill, GPL-3.0), force-installed from the Chrome Web
  Store, Edge Add-ons and addons.mozilla.org by the Mac profile when ad blocking is on. Pax ships
  only their store IDs.
* **OISD**, <https://oisd.nl>, GPL-3.0 (<https://github.com/sjhgvr/oisd>). Fetched by the same script
  (restricted-content list).
* **CleanBrowsing** Family and Security Filter DoH endpoints, used as pax-dns's development
  upstreams and as the profile default. A service, not a dependency; its free tier is for families,
  not organisations.

If you redistribute a generated category list, keep its GPL-3.0 notice and say where it came from.

If a future release bundles any of these, ship their licence texts and source offers with the app.

**Upstream names and addresses.** So the repo reads calmly, this file names upstream lists and projects in
neutral terms. Their exact names, list names, repository addresses and the verbatim notices as published up
to v0.8.0 are in `licenses/upstream-notices.txt.gz` (gzip text; `gzip -dc` to read).


## Bundled in v0.5: Pax Image Blur (extension/)

Pax Image Blur ships these inside the extension (`extension/src/vendor`, `extension/src/model`), and so
inside `Pax.app/Contents/Resources/extensions/pax-image-blur.xpi`:

| Component | Licence | What |
|---|---|---|
| [TensorFlow.js](https://github.com/tensorflow/tfjs) 4.22.0: `@tensorflow/tfjs-core`, `tfjs-layers`, `tfjs-backend-cpu`, `tfjs-backend-webgl` | Apache-2.0 (compatible with GPL-3.0) | runs the model; bundled with esbuild into `vendor/pax-ml.min.js`, which keeps the original licence comments at the end of the file. Source: the npm packages at those versions (`extension/scripts/update-vendor.sh` rebuilds it). |
| Infinite Red's open-source MobileNetV2 image-classification model (`models/mobilenet_v2/model.json` + `group1-shard1of1`, from Infinite Red's GitHub repository, `master`, fetched 2026-10-14; the npm package 4.4.0 is MIT; exact names and addresses in `licenses/upstream-notices.txt.gz`) | MIT, Copyright (c) 2019 Infinite Red, Inc. | the classifier weights. Pax uses the model files only, not the library code (preprocessing is re-implemented: resize to 224×224, divide by 255, five output classes mapped to neutral names in `extension/src/core.js`). |
| The model's training project (GantMan's model repository on GitHub; address in `licenses/upstream-notices.txt.gz`) | MIT, Copyright (c) 2020 the model's developers (exact holder line in `licenses/upstream-notices.txt.gz`) | credited as the origin of the weights. Its LICENSE notes the project "contains third-party copyrighted material under different licenses" (the training images were scraped); the weights themselves are published under MIT. |

```
MIT License

Copyright (c) 2019 Infinite Red, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

(The training project's MIT notice is identical apart from its 2020 copyright line, quoted verbatim in
`licenses/upstream-notices.txt.gz`.)
The Apache-2.0 text applies to the TensorFlow.js code; see
<https://www.apache.org/licenses/LICENSE-2.0>. Test-only dependency (not shipped): jsdom (MIT).

## v0.5 block lists

* `pax-dns/lists/cloud-pc-bypass.txt` and `remote-desktop.txt` are Pax's own curated lists
  (GPL-3.0-only), written for v0.5; they copy no third-party list.
* **HaGeZi "Encrypted DNS/VPN/Tor/Proxy Bypass"**
  (`wildcard/doh-vpn-proxy-bypass-onlydomains.txt`, GPL-3.0, ~15,500 domains on 2026-10-14) is now
  downloaded at run time by `pax-dns/scripts/load_lists.py` (default) and by pax-guard. Not shipped.

## v0.8.0: block lists bundled with pax-guard

From v0.8.0 the Mac app **ships** compiled lists (`guard/filters/pax-block.txt.gz` and, from v0.8.1,
`pax-bypass.txt.gz`, also published signed under the `lists` release) built by `lists/build.py` from:

* **HaGeZi** restricted-content list and "Encrypted DNS/VPN/Tor/Proxy Bypass" list,
  <https://github.com/hagezi/dns-blocklists>, GPL-3.0 (same licence as Pax; source: that repository).
* **OISD** restricted-content list, <https://oisd.nl>, GPL-3.0.
* **UT1 blacklists**, restricted-content category, Université Toulouse Capitole,
  <https://dsi.ut-capitole.fr/blacklists/>, CC BY-SA 4.0. The bundled list is an adaptation (merged, trimmed,
  parent-collapsed); it is shared under the same terms and credited here.
* **WhoisDS** newly registered domains (filtered by Pax's name rule, `pax-nrd.txt.gz`), <https://www.whoisds.com>.

v0.8.18 adds two checked inputs (`lists/verified/`, see docs/FILTER_LISTS.md):

* **ShadowWhisperer BlockLists**, restricted-content list (`Lists/Adult`),
  <https://github.com/ShadowWhisperer/BlockLists>, released into the public domain (The Unlicense). Only names
  that were live and whose homepage was checked on the build date are used (`pax-block-extra.txt.gz`).
* **UT1 blacklists**, "redirector" category, Université Toulouse Capitole, <https://dsi.ut-capitole.fr/blacklists/>,
  CC BY-SA 4.0. Only names whose homepage was a working web proxy or proxy list on the build date are used
  (`pax-bypass-extra.txt.gz`, part of `pax-bypass.txt.gz`). The selection is an adaptation; it is shared under the
  same terms and credited here.

The exact list names and download addresses are in `licenses/upstream-notices.txt.gz` and, encoded, in
`common/pax_restricted.py` (`sources`).

## v0.8.1: media converters

`pax-dns/lists/media-converters.txt` and `media-converter-keywords.txt` are Pax's own curated lists
(GPL-3.0-only): known services, their mirrors and TLD variants, the name rule's hits in the Tranco top 1M
(Tranco list, used only to find and rank candidates; no Tranco data is shipped) and domains the maintainer supplied.
Public sources were checked for a reusable list; none was found under a permissive licence that covers this
category, so no third-party list is included.

The build is reproducible from these sources with `lists/build.py`, which is the corresponding source.

## v0.8.16: brand fonts bundled in Pax.app (SIL Open Font License 1.1)

Static instances of three OFL fonts, made with fontTools' `varLib.instancer` and renamed as the OFL
asks of modified versions. They ship in `mac-app/Resources/fonts` and in `Pax.app/Contents/Resources/Fonts`,
with the full licence text and copyright notices in `OFL.txt` beside them.

* **Fraunces** (Copyright 2020 The Fraunces Project Authors, github.com/undercasetype/Fraunces):
  `PaxFrauncesSoft-Regular.ttf` (opsz 72, wght 420, SOFT 100, WONK 0). Headings.
* **Inter** (Copyright 2016 The Inter Project Authors, github.com/rsms/inter): `PaxInter-Regular`,
  `-Medium`, `-SemiBold.ttf`. Body and UI text.
* **Playfair Display Italic** (Copyright 2017 The Playfair Display Project Authors,
  github.com/clauseggers/Playfair-Display, Reserved Font Name "Playfair Display"): `PaxAccent-Italic.ttf`,
  renamed "Pax Accent" so the Reserved Font Name isn't used. One accent word on the welcome screen.

The logo and app icon images in `mac-app/Resources/branding` are Pax Peace's own artwork.
