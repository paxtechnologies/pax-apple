# Pax Image Blur

Part of Pax (GPL-3.0-only). A Chrome/Edge/Brave (MV3) and Firefox (MV3) extension that blurs pictures
and video on every page until an on-device classifier says they're fine. Restricted pictures stay hidden
with no reveal; borderline or uncheckable ones reveal on click. Nothing leaves the browser.

```bash
python3 build.py          # dist/chrome (load unpacked), dist/pax-image-blur-chrome.zip (Web Store),
                          # dist/firefox, dist/pax-image-blur.xpi (unsigned; sign via AMO unlisted)
npm install && npm test   # node --test: core logic, build, content script in jsdom
sh scripts/update-vendor.sh   # rebuild TensorFlow.js bundle + re-fetch the model (Node, network)
```

| File | Role |
|---|---|
| `src/core.js` | pure logic: verdict thresholds, states, video rules, allowlist, LRU, queue |
| `src/content.js`, `src/content.css` | blur at `document_start`, classify near the viewport, click to reveal |
| `src/background.js` | Chrome service worker (owns the offscreen document) / Firefox background page; caches verdicts by URL |
| `src/classifier.js` | loads the model, fetches/decodes the picture, runs MobileNetV2 (224×224, /255) |
| `src/offscreen.html`, `src/offscreen.js` | Chrome only: hosts the classifier (WebGL) |
| `src/options.html`, `src/options.js` | allowlist editor and toolbar popup |
| `src/vendor/pax-ml.min.js.gz.part-*` | TensorFlow.js 4.22 (core, layers, CPU, WebGL), Apache-2.0 |
| `src/model/mobilenet_v2/*.gz.part-*` | MobileNetV2 image model (Infinite Red), MIT |
| `src/manifest.chrome.json`, `src/manifest.firefox.json` | per-browser manifests (`build.py` writes `manifest.json`) |

How it's installed on a protected Mac, and why Chrome needs an unlisted Chrome Web Store listing, is in
the main README ("Pax Image Blur"). Firefox ID: `pax-image-blur@paxmobile.org`.
