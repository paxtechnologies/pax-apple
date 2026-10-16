// SPDX-License-Identifier: GPL-3.0-only
// Pax Image Blur background. Chrome: an MV3 service worker that keeps one
// offscreen document running the classifier. Firefox: an MV3 background page
// that runs the classifier itself (classifier.js is loaded before this file).
if (typeof importScripts === "function" && !globalThis.PaxBlurCore) importScripts("core.js");

const Core = globalThis.PaxBlurCore;
const cache = new Core.LRU(3000);            // verdicts by image URL
const OFFSCREEN = "offscreen.html";
let creating = null;

async function ensureOffscreen() {
  if (chrome.runtime.getContexts) {
    const found = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
    if (found.length) return;
  }
  if (!creating) {
    creating = chrome.offscreen.createDocument({
      url: OFFSCREEN,
      reasons: ["BLOBS"],
      justification: "Runs Pax's on-device image classifier (TensorFlow.js) on page images.",
    }).catch((e) => { if (!String(e).includes("single offscreen")) throw e; })
      .finally(() => { creating = null; });
  }
  await creating;
}

async function classify(msg) {
  const key = msg.url && !msg.url.startsWith("data:") ? msg.url : null;
  if (key) {
    const hit = cache.get(key);
    if (hit) return hit;
  }
  let result;
  if (globalThis.PaxClassifier) {
    result = await globalThis.PaxClassifier.classify(msg);           // Firefox
  } else {
    await ensureOffscreen();                                          // Chrome
    result = await chrome.runtime.sendMessage(Object.assign({}, msg, { target: "pax-offscreen" }));
  }
  if (key && result && !result.error) cache.set(key, result);
  return result || { error: "no classifier" };
}

// v0.8.12: is Pax Max switched off on this Mac? Only Firefox has the dns API
// (it reads /etc/hosts first, where pax-guard writes the off signal). Chrome, an
// error or no answer: on (keep blurring). Asked at most every 20 s.
let paxMaxCheck = { at: 0, off: false };
async function paxMaxOff() {
  const now = Date.now();
  if (now - paxMaxCheck.at < 20000) return paxMaxCheck.off;
  let off = false;
  try {
    const dns = globalThis.browser && globalThis.browser.dns;
    if (dns && typeof dns.resolve === "function") {
      const r = await dns.resolve(Core.PAX_MAX_OFF_NAME, ["bypass_cache", "disable_ipv6"]);
      off = Core.paxMaxOff(r && r.addresses);
    }
  } catch (_) {
    off = false;
  }
  paxMaxCheck = { at: now, off };
  return off;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.target !== "pax-background") return false;
  if (msg.type === "paxmax") {
    paxMaxOff().then((off) => sendResponse({ off }), () => sendResponse({ off: false }));
    return true;
  }
  if (msg.type !== "classify") return false;
  classify(msg).then(sendResponse, (e) => sendResponse({ error: String(e) }));
  return true;
});
