// SPDX-License-Identifier: GPL-3.0-only
// Pax Image Blur content script. Runs at document_start in every frame.
//
// Every <img> and <video> starts blurred (content.css, keyed on the
// html.pax-blur-armed class this script sets immediately, so nothing unwanted
// flashes up). Images are sent to the extension's on-device classifier as they
// come near the viewport; safe ones are un-blurred, "veiled" ones stay blurred
// until clicked, "locked" ones stay blurred with no way to reveal them. Videos are
// sampled about once a second while they play. No image or frame ever leaves
// the browser: the classifier runs in the extension (offscreen document in
// Chrome, background page in Firefox).
//
// Written as start(env) so the tests can drive it with jsdom and fakes.
(function (root) {
  "use strict";
  const Core = root.PaxBlurCore || (typeof require === "function" ? require("./core.js") : null);
  const STATE = "data-pax-state";
  const ARMED = "pax-blur-armed";       // blur everything not yet known to be safe
  const RELAXED = "pax-blur-relaxed";   // allow-listed site: only locked stays hidden
  const VIDEO_SAMPLE_MS = 1200;
  const CLASSIFY_TIMEOUT_MS = 20000;

  function start(env) {
    const doc = env.document;
    const win = env.window;
    const send = env.sendMessage;            // (msg) => Promise<response>
    const getAllowlist = env.getAllowlist;   // () => Promise<string[]>
    // v0.8.12: () => Promise<bool>, true only when Pax Max is switched off on this
    // Mac (after its hour). Missing, failing or slow: keep blurring.
    const getPaxMaxOff = env.getPaxMaxOff || (() => Promise.resolve(false));
    const html = doc.documentElement;
    if (!html || html.hasAttribute("data-pax-blur")) return null;   // once per document
    html.setAttribute("data-pax-blur", "1");
    html.classList.add(ARMED);

    const queue = Core.createQueue(env.concurrency || 3);
    const known = new WeakMap();      // element -> {src, timer}
    let relaxed = false;
    let stopped = false;
    let off = false;                  // v0.8.12: Pax Max switched off

    function state(el) { return el.getAttribute(STATE) || ""; }
    function setState(el, s) {
      if (off || state(el) === s) return;
      el.setAttribute(STATE, s);
      if (s === "locked") el.setAttribute("title", "Hidden by Pax");
      else if (Core.canReveal(s)) el.setAttribute("title", "Hidden by Pax. Click to show.");
      else if (el.getAttribute("title") && el.getAttribute("title").startsWith("Hidden by Pax")) {
        el.removeAttribute("title");
      }
      if (s === "locked" && el.tagName === "VIDEO" && typeof el.pause === "function") {
        try { el.pause(); } catch (_) { /* ignore */ }
      }
    }

    function withTimeout(p, ms) {
      return Promise.race([p, new Promise((_, rej) => win.setTimeout(() => rej(new Error("timeout")), ms))]);
    }

    function classify(msg) {
      return queue.push(() => withTimeout(send(Object.assign({ target: "pax-background", type: "classify" }, msg)),
        CLASSIFY_TIMEOUT_MS));
    }

    // Draw an element onto a small canvas. Throws on a tainted canvas
    // (cross-origin without CORS), which is the browser keeping its promise.
    function snapshot(el) {
      const canvas = doc.createElement("canvas");
      canvas.width = Core.INPUT_SIZE;
      canvas.height = Core.INPUT_SIZE;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("no 2d context");
      ctx.drawImage(el, 0, 0, Core.INPUT_SIZE, Core.INPUT_SIZE);
      return canvas.toDataURL("image/jpeg", 0.9);
    }

    function measure(el) {
      const r = el.getBoundingClientRect ? el.getBoundingClientRect() : { width: 0, height: 0 };
      const nw = el.tagName === "VIDEO" ? el.videoWidth : el.naturalWidth;
      const nh = el.tagName === "VIDEO" ? el.videoHeight : el.naturalHeight;
      return [r.width || el.width || 0, r.height || el.height || 0, nw || 0, nh || 0];
    }

    async function processImage(img) {
      const src = img.currentSrc || img.src || "";
      const info = known.get(img) || {};
      if (info.src === src && state(img) && state(img) !== "pending") return;
      known.set(img, Object.assign(info, { src }));
      if (!src) return;
      const [rw, rh, nw, nh] = measure(img);
      if ((nw || rw) && Core.isSmall(rw, rh, nw, nh)) { setState(img, "skip"); return; }
      setState(img, "pending");
      let result = null;
      const kind = Core.sourceKind(src);
      try {
        if (kind === "url") result = await classify({ url: src });
        if ((!result || result.error) && (kind === "canvas" || kind === "url")) {
          if (!img.complete) await new Promise((res) => img.addEventListener("load", res, { once: true }));
          result = await classify({ dataUrl: snapshot(img) });
        }
      } catch (_) {
        result = null;
      }
      if (known.get(img) && known.get(img).src !== (img.currentSrc || img.src || "")) return; // changed meanwhile
      if (state(img) === "revealed" && !(result && result.verdict === "locked")) return;
      setState(img, result && !result.error ? Core.stateForVerdict(result.verdict) : "unknown");
    }

    async function sampleVideo(video) {
      if (stopped || !video.isConnected) return stopVideo(video);
      if (video.paused || video.ended || video.readyState < 2) return;
      let frame;
      try {
        frame = snapshot(video);
      } catch (_) {
        // Cross-origin video without CORS: the page won't let anyone read it.
        setState(video, Core.nextVideoState(state(video) || "pending", null));
        return stopVideo(video);
      }
      try {
        const r = await classify({ dataUrl: frame, video: true });
        if (r && !r.error) setState(video, Core.nextVideoState(state(video), r.verdict));
      } catch (_) { /* keep the current state */ }
    }

    function stopVideo(video) {
      const info = known.get(video);
      if (info && info.timer) { win.clearInterval(info.timer); info.timer = null; }
    }

    function watchVideo(video) {
      if (known.has(video)) return;
      const info = { src: video.currentSrc || video.src || "", timer: null };
      known.set(video, info);
      if (!state(video)) setState(video, "pending");
      const begin = () => {
        if (info.timer || stopped) return;
        sampleVideo(video);
        info.timer = win.setInterval(() => sampleVideo(video), VIDEO_SAMPLE_MS);
      };
      video.addEventListener("playing", begin);
      video.addEventListener("loadeddata", () => sampleVideo(video));
      video.addEventListener("pause", () => stopVideo(video));
      video.addEventListener("ended", () => stopVideo(video));
      if (!video.paused) begin();
    }

    // Only classify images near the viewport (lazy pages load hundreds).
    const io = typeof win.IntersectionObserver === "function"
      ? new win.IntersectionObserver((entries) => {
        for (const e of entries) {
          if (e.isIntersecting) { io.unobserve(e.target); scheduleImage(e.target); }
        }
      }, { rootMargin: "200% 0px" })
      : null;

    function scheduleImage(img) {
      if (stopped) return;
      if (img.complete || img.naturalWidth) processImage(img);
      else img.addEventListener("load", () => processImage(img), { once: true });
      img.addEventListener("error", () => { if (state(img) === "pending") setState(img, "unknown"); },
        { once: true });
    }

    function track(el) {
      if (el.tagName === "IMG") {
        if (!state(el)) setState(el, "pending");
        if (io) io.observe(el); else scheduleImage(el);
      } else if (el.tagName === "VIDEO") {
        watchVideo(el);
      }
    }

    function scan(node) {
      if (!node || node.nodeType !== 1) return;
      if (node.tagName === "IMG" || node.tagName === "VIDEO") track(node);
      if (node.querySelectorAll) node.querySelectorAll("img, video").forEach(track);
    }

    const mo = new win.MutationObserver((records) => {
      for (const r of records) {
        if (r.type === "childList") r.addedNodes.forEach(scan);
        else if (r.type === "attributes" && r.target.tagName === "IMG") {
          // A new src/srcset is a new picture: blur it and check it again.
          setState(r.target, "pending");
          if (io) io.observe(r.target); else scheduleImage(r.target);
        }
      }
    });
    mo.observe(doc, { childList: true, subtree: true, attributes: true, attributeFilter: ["src", "srcset"] });

    // Click to reveal (veiled / unknown only). Capture phase, so the page's own
    // handlers and links don't fire for the click that reveals.
    function onClick(ev) {
      const el = ev.target && ev.target.closest ? ev.target.closest(`[${STATE}]`) : null;
      if (!el || relaxed) return;
      if (Core.canReveal(state(el))) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        setState(el, "revealed");
      }
    }
    win.addEventListener("click", onClick, true);

    if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", () => scan(doc.documentElement));
    scan(doc.documentElement);

    // Allow-listed site: stop pre-blurring; locked verdicts still hide pictures.
    Promise.resolve(getAllowlist()).then((list) => {
      if (Core.hostAllowed(win.location.hostname, list)) {
        relaxed = true;
        html.classList.remove(ARMED);
        html.classList.add(RELAXED);
      }
    }).catch(() => { /* keep blurring */ });

    function stop() {
      stopped = true;
      mo.disconnect();
      if (io) io.disconnect();
      win.removeEventListener("click", onClick, true);
    }

    // v0.8.12: Pax Max is off on this Mac: stop, and undo everything on this page.
    function switchOff() {
      if (off) return;
      stop();
      off = true;
      html.classList.remove(ARMED);
      html.classList.remove(RELAXED);
      doc.querySelectorAll(`[${STATE}]`).forEach((el) => {
        el.removeAttribute(STATE);
        const t = el.getAttribute("title");
        if (t && t.startsWith("Hidden by Pax")) el.removeAttribute("title");
      });
    }
    Promise.resolve().then(getPaxMaxOff).then((isOff) => { if (isOff === true) switchOff(); })
      .catch(() => { /* keep blurring */ });

    return {
      stop,
      get relaxed() { return relaxed; },
      get off() { return off; },
      processImage, sampleVideo, scan,
    };
  }

  const api = { start, STATE, ARMED, RELAXED };
  if (typeof module === "object" && module.exports) module.exports = api;
  root.PaxBlurContent = api;

  // In the browser: start for real.
  const ext = root.chrome && root.chrome.runtime && root.chrome.runtime.id ? root.chrome : null;
  if (ext && typeof document !== "undefined") {
    start({
      document, window,
      sendMessage: (msg) => ext.runtime.sendMessage(msg),
      getPaxMaxOff: () => Promise.resolve(ext.runtime.sendMessage({ target: "pax-background", type: "paxmax" }))
        .then((r) => !!(r && r.off === true), () => false),
      getAllowlist: () => new Promise((resolve) => {
        try {
          ext.storage.local.get({ allowlist: [] }, (v) => resolve((v && v.allowlist) || []));
        } catch (_) { resolve([]); }
      }),
    });
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
