// SPDX-License-Identifier: GPL-3.0-only
// Pax Image Blur: pure logic shared by the content script, the background and
// the tests (node --test). No DOM, no extension APIs in here.
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PaxBlurCore = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // Output order of the bundled MobileNetV2 model (the upstream classes file;
  // see THIRD_PARTY_NOTICES.md), under neutral names: two restricted classes
  // (photographic and drawn), a borderline class, and two neutral ones.
  const CLASSES = ["Drawing", "RestrictedDrawn", "Neutral", "Restricted", "Borderline"];

  // Deliberately cautious: a false "locked" only means a picture stays blurred
  // with no reveal; a false "safe" shows something unwanted.
  const THRESHOLDS = Object.freeze({
    locked: 0.5,        // Restricted alone
    drawn: 0.6,         // RestrictedDrawn alone
    combined: 0.6,      // Restricted + RestrictedDrawn together
    veiled: 0.5,        // Borderline alone -> blurred, click to reveal
    anyFlag: 0.5,       // Restricted + RestrictedDrawn + Borderline -> at least "veiled"
  });

  // Images smaller than this (rendered AND natural, both sides) are icons and
  // UI chrome: never blurred, never classified.
  const MIN_SIZE = 48;
  const INPUT_SIZE = 224;

  // Element states (data-pax-state on the <img>/<video>):
  //   pending   blurred, waiting for the classifier
  //   safe      shown
  //   veiled    blurred, click to reveal
  //   unknown   blurred, click to reveal (couldn't classify: cross-origin video,
  //             decode error, classifier unavailable)
  //   locked    blurred, NO reveal
  //   revealed  shown because the user clicked (never for locked)
  //   skip      too small to matter
  const STATES = ["pending", "safe", "veiled", "unknown", "locked", "revealed", "skip"];

  function softmax(values) {
    const max = Math.max(...values);
    const exps = values.map((v) => Math.exp(v - max));
    const sum = exps.reduce((a, b) => a + b, 0);
    return exps.map((e) => e / sum);
  }

  /** Model output (5 numbers) -> {Drawing, RestrictedDrawn, Neutral, Restricted, Borderline}. The
   *  model ends in a softmax; anything that isn't a distribution is softmaxed. */
  function toProbabilities(values) {
    const arr = Array.from(values || []).map(Number);
    if (arr.length !== CLASSES.length || arr.some((v) => !Number.isFinite(v))) {
      throw new Error("expected " + CLASSES.length + " finite model outputs");
    }
    const sum = arr.reduce((a, b) => a + b, 0);
    const probs = arr.every((v) => v >= 0 && v <= 1) && Math.abs(sum - 1) < 0.02 ? arr : softmax(arr);
    const out = {};
    CLASSES.forEach((c, i) => { out[c] = probs[i]; });
    return out;
  }

  /** "locked" | "veiled" | "safe" */
  function verdict(p, t) {
    t = t || THRESHOLDS;
    const restricted = p.Restricted || 0, drawn = p.RestrictedDrawn || 0, borderline = p.Borderline || 0;
    if (restricted >= t.locked || drawn >= t.drawn || restricted + drawn >= t.combined) return "locked";
    if (borderline >= t.veiled || restricted + drawn + borderline >= t.anyFlag) return "veiled";
    return "safe";
  }

  /** Can a click show this element? Never for locked. */
  function canReveal(state) {
    return state === "veiled" || state === "unknown";
  }

  /** State after a classification result for a still image. */
  function stateForVerdict(v) {
    if (v === "locked" || v === "veiled" || v === "safe") return v;
    return "unknown";
  }

  /** Video: every sampled frame can only make things stricter, except that a
   *  video still waiting for its first frame becomes safe on a clean one.
   *  A locked frame locks the video (no reveal) even if it was revealed. */
  function nextVideoState(current, frameVerdict) {
    if (current === "locked" || frameVerdict === "locked") return "locked";
    if (frameVerdict === "veiled") return current === "revealed" ? "revealed" : "veiled";
    if (frameVerdict === "safe") return current === "pending" || current === "unknown" ? "safe" : current;
    return current === "pending" ? "unknown" : current;
  }

  function isSmall(renderedW, renderedH, naturalW, naturalH, min) {
    min = min || MIN_SIZE;
    const rendered = renderedW > 0 && renderedH > 0 && (renderedW < min || renderedH < min);
    const natural = naturalW > 0 && naturalH > 0 && (naturalW < min || naturalH < min);
    // Small only if it is small however it's measured (a 40px thumbnail of a
    // 2000px photo still shows the photo when opened, but not here).
    if (renderedW > 0 && naturalW > 0) return rendered && natural;
    return rendered || natural;
  }

  /** How the background can get the pixels: "url" (fetch it, with the
   *  extension's host permissions), "canvas" (the page must draw it: blob:,
   *  page-scoped), or "none". */
  function sourceKind(url) {
    if (!url || typeof url !== "string") return "none";
    const u = url.trim().toLowerCase();
    if (u.startsWith("http://") || u.startsWith("https://")) return "url";
    if (u.startsWith("data:image/")) return u.length <= 2_000_000 ? "url" : "canvas";
    if (u.startsWith("blob:")) return "canvas";
    return "none";
  }

  // ------------------------------------------------------------- allowlist
  const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/;

  /** "https://www.Example.com/x" -> "example.com"; null if not a domain. */
  function normalizeDomain(input) {
    if (!input || typeof input !== "string") return null;
    let s = input.trim().toLowerCase();
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
    s = s.split(/[/?#]/)[0];
    s = s.replace(/^\*\./, "").replace(/:\d+$/, "").replace(/\.$/, "");
    if (s.startsWith("www.")) s = s.slice(4);
    return DOMAIN_RE.test(s) ? s : null;
  }

  /** Text area / list -> clean, de-duplicated domains (bad lines dropped). */
  function parseAllowlist(input) {
    const lines = Array.isArray(input) ? input : String(input || "").split(/[\s,]+/);
    const out = [];
    for (const line of lines) {
      const d = normalizeDomain(line);
      if (d && !out.includes(d)) out.push(d);
    }
    return out;
  }

  /** Does `host` (a page's hostname) fall under an allow-listed domain? */
  function hostAllowed(host, allowlist) {
    const h = (host || "").toLowerCase().replace(/\.$/, "");
    if (!h) return false;
    return (allowlist || []).some((d) => h === d || h.endsWith("." + d));
  }

  // ------------------------------------------------------------ utilities
  /** Tiny LRU cache (verdicts by image URL in the background). */
  class LRU {
    constructor(limit) { this.limit = limit || 2000; this.map = new Map(); }
    get(k) {
      if (!this.map.has(k)) return undefined;
      const v = this.map.get(k);
      this.map.delete(k);
      this.map.set(k, v);
      return v;
    }
    set(k, v) {
      if (this.map.has(k)) this.map.delete(k);
      this.map.set(k, v);
      while (this.map.size > this.limit) this.map.delete(this.map.keys().next().value);
    }
    get size() { return this.map.size; }
  }

  /** Run async jobs with at most `limit` in flight (content script -> background). */
  function createQueue(limit) {
    let active = 0;
    const waiting = [];
    function pump() {
      while (active < limit && waiting.length) {
        const { job, resolve, reject } = waiting.shift();
        active++;
        Promise.resolve().then(job).then(resolve, reject).finally(() => { active--; pump(); });
      }
    }
    return {
      push(job) { return new Promise((resolve, reject) => { waiting.push({ job, resolve, reject }); pump(); }); },
      get active() { return active; },
      get pending() { return waiting.length; },
    };
  }

  // v0.8.12: Pax Max switched off after set-up. pax-guard writes this name with
  // this address into /etc/hosts only once the hour to turn Pax Max off is over
  // (guard_config.PAX_MAX_OFF_NAME / PAX_MAX_OFF_ADDR). Anything else (no
  // answer, an error, another address, an extra address) keeps the blur on.
  const PAX_MAX_OFF_NAME = "pax-max-off.guard.paxpeace.com";
  const PAX_MAX_OFF_ADDR = "127.80.77.0";

  function paxMaxOff(addresses) {
    return Array.isArray(addresses) && addresses.length === 1 && addresses[0] === PAX_MAX_OFF_ADDR;
  }

  return {
    PAX_MAX_OFF_NAME, PAX_MAX_OFF_ADDR, paxMaxOff,
    CLASSES, THRESHOLDS, MIN_SIZE, INPUT_SIZE, STATES,
    softmax, toProbabilities, verdict, canReveal, stateForVerdict, nextVideoState,
    isSmall, sourceKind, normalizeDomain, parseAllowlist, hostAllowed, LRU, createQueue,
  };
});
