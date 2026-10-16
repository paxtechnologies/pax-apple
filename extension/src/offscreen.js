// SPDX-License-Identifier: GPL-3.0-only
// Chrome only: the offscreen document hosts the classifier (a service worker
// has no WebGL or DOM). It answers messages addressed to "pax-offscreen".
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.target !== "pax-offscreen") return false;
  globalThis.PaxClassifier.classify(msg).then(sendResponse);
  return true;
});
