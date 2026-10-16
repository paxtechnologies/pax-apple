// SPDX-License-Identifier: GPL-3.0-only
// Content-script behaviour in jsdom (npm install, then node --test tests/*.test.js).
// Skipped, not failed, when jsdom isn't installed.
const test = require("node:test");
const assert = require("node:assert/strict");

let JSDOM = null;
try { ({ JSDOM } = require("jsdom")); } catch (_) { /* optional */ }
const skip = JSDOM ? false : "jsdom not installed (cd extension && npm install)";

const VERDICTS = {
  "https://cdn.example/cat.jpg": "safe",
  "https://cdn.example/beach.jpg": "veiled",
  "https://cdn.example/x.jpg": "locked",
};

function setup({ host = "news.example", allowlist = [], verdicts = VERDICTS, failUrls = false, paxMaxOff } = {}) {
  const { VirtualConsole } = require("jsdom");
  const virtualConsole = new VirtualConsole();   // jsdom has no canvas: silence "not implemented"
  const dom = new JSDOM("<!doctype html><html><head></head><body></body></html>",
    { url: `https://${host}/`, pretendToBeVisual: true, virtualConsole });
  const { window } = dom;
  global.window = window;
  global.document = window.document;
  global.PaxBlurCore = require("../src/core.js");
  delete require.cache[require.resolve("../src/content.js")];
  const Content = require("../src/content.js");
  const sent = [];
  const ctl = Content.start({
    document: window.document, window,
    sendMessage: async (msg) => {
      sent.push(msg);
      if (msg.url && failUrls) return { error: "HTTP 403" };
      if (msg.url) return verdicts[msg.url] ? { verdict: verdicts[msg.url] } : { error: "unknown url" };
      return { verdict: "safe" };
    },
    getAllowlist: async () => allowlist,
    ...(paxMaxOff === undefined ? {} : { getPaxMaxOff: paxMaxOff }),
  });
  return { window, doc: window.document, ctl, sent };
}

function addImg(doc, src, natural = 800) {
  const img = doc.createElement("img");
  Object.defineProperty(img, "naturalWidth", { value: natural });
  Object.defineProperty(img, "naturalHeight", { value: natural });
  Object.defineProperty(img, "complete", { value: true });
  img.src = src;
  doc.body.appendChild(img);
  return img;
}

const settle = () => new Promise((r) => setTimeout(r, 30));

test("arms the page and blurs until classified", { skip }, async () => {
  const { doc, sent } = setup();
  assert.ok(doc.documentElement.classList.contains("pax-blur-armed"));
  const cat = addImg(doc, "https://cdn.example/cat.jpg");
  const beach = addImg(doc, "https://cdn.example/beach.jpg");
  const x = addImg(doc, "https://cdn.example/x.jpg");
  await settle();
  assert.equal(cat.getAttribute("data-pax-state"), "safe");
  assert.equal(beach.getAttribute("data-pax-state"), "veiled");
  assert.equal(x.getAttribute("data-pax-state"), "locked");
  assert.equal(x.getAttribute("title"), "Hidden by Pax");
  assert.ok(sent.every((m) => m.target === "pax-background" && m.type === "classify"));
});

test("click reveals veiled, never locked, and stops the link", { skip }, async () => {
  const { window, doc } = setup();
  const a = doc.createElement("a");
  a.href = "https://elsewhere.example/";
  doc.body.appendChild(a);
  const beach = addImg(doc, "https://cdn.example/beach.jpg");
  a.appendChild(beach);
  const x = addImg(doc, "https://cdn.example/x.jpg");
  await settle();
  let linkFired = 0;
  a.addEventListener("click", () => linkFired++);
  const ev = new window.MouseEvent("click", { bubbles: true, cancelable: true });
  beach.dispatchEvent(ev);
  assert.equal(beach.getAttribute("data-pax-state"), "revealed");
  assert.equal(ev.defaultPrevented, true);
  assert.equal(linkFired, 0);
  x.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(x.getAttribute("data-pax-state"), "locked");
});

test("tiny images are skipped without asking the classifier", { skip }, async () => {
  const { doc, sent } = setup();
  const icon = addImg(doc, "https://cdn.example/icon.png", 24);
  await settle();
  assert.equal(icon.getAttribute("data-pax-state"), "skip");
  assert.equal(sent.length, 0);
});

test("unreadable image stays blurred but can be revealed", { skip }, async () => {
  const { doc } = setup({ failUrls: true });
  const img = addImg(doc, "https://cdn.example/cat.jpg");
  await settle();
  // URL fetch failed and jsdom has no canvas: unknown, click to reveal
  assert.equal(img.getAttribute("data-pax-state"), "unknown");
});

test("changing src re-checks the picture", { skip }, async () => {
  const { doc } = setup();
  const img = addImg(doc, "https://cdn.example/cat.jpg");
  await settle();
  assert.equal(img.getAttribute("data-pax-state"), "safe");
  img.src = "https://cdn.example/x.jpg";
  await settle();
  assert.equal(img.getAttribute("data-pax-state"), "locked");
});

test("allow-listed site is relaxed but locked is still hidden", { skip }, async () => {
  const { doc, ctl } = setup({ host: "photos.example.org", allowlist: ["example.org"] });
  await settle();
  assert.equal(ctl.relaxed, true);
  assert.ok(!doc.documentElement.classList.contains("pax-blur-armed"));
  assert.ok(doc.documentElement.classList.contains("pax-blur-relaxed"));
  const x = addImg(doc, "https://cdn.example/x.jpg");
  await settle();
  assert.equal(x.getAttribute("data-pax-state"), "locked");
});

test("video whose frames can't be read stays blurred (unknown)", { skip }, async () => {
  const { window, doc, ctl } = setup();
  const v = doc.createElement("video");
  Object.defineProperty(v, "paused", { value: false });
  Object.defineProperty(v, "ended", { value: false });
  Object.defineProperty(v, "readyState", { value: 4 });
  doc.body.appendChild(v);
  await settle();
  await ctl.sampleVideo(v);
  assert.equal(v.getAttribute("data-pax-state"), "unknown");
  ctl.stop();
  window.close();
});

test("css never blurs safe/revealed and always hides locked", () => {
  const css = require("fs").readFileSync(require("path").join(__dirname, "../src/content.css"), "utf8");
  assert.match(css, /:not\(\[data-pax-state="safe"\]\)/);
  assert.match(css, /:not\(\[data-pax-state="revealed"\]\)/);
  assert.match(css, /html \[data-pax-state="locked"\]/);
});

test("manifests: MV3, on-device only, Firefox ID and signing-ready", () => {
  const read = (n) => JSON.parse(require("fs").readFileSync(require("path").join(__dirname, "../src", n), "utf8"));
  const c = read("manifest.chrome.json"), f = read("manifest.firefox.json");
  for (const m of [c, f]) {
    assert.equal(m.manifest_version, 3);
    assert.equal(m.content_scripts[0].run_at, "document_start");
    assert.equal(m.content_scripts[0].all_frames, true);
    assert.ok(!m.permissions.includes("webRequest"));
    assert.ok(!JSON.stringify(m).includes("http://") && !("externally_connectable" in m));
  }
  assert.ok(c.permissions.includes("offscreen") && c.background.service_worker);
  assert.equal(f.browser_specific_settings.gecko.id, "pax-image-blur@paxmobile.org");
  assert.deepEqual(f.browser_specific_settings.gecko.data_collection_permissions, { required: ["none"] });
  assert.ok(f.background.scripts.includes("classifier.js"));
});

// v0.8.12: Pax Max switched off after set-up (pax-guard's signal, read by the background).
const tick = () => new Promise((r) => setTimeout(r, 20));

test("Pax Max off: the page is left alone", { skip }, async () => {
  const { doc, ctl, sent } = setup({ paxMaxOff: async () => true });
  const img = addImg(doc, "https://cdn.example/x.jpg");
  await tick();
  assert.equal(ctl.off, true);
  assert.ok(!doc.documentElement.classList.contains("pax-blur-armed"));
  assert.equal(img.getAttribute("data-pax-state"), null);
  const later = addImg(doc, "https://cdn.example/beach.jpg");
  await tick();
  assert.equal(later.getAttribute("data-pax-state"), null);
  assert.ok(!sent.some((m) => m.url === "https://cdn.example/beach.jpg"));
});

for (const [name, fn] of [["no answer", undefined], ["false", async () => false],
  ["an error", async () => { throw new Error("no dns"); }], ["not exactly true", async () => "yes"]]) {
  test(`Pax Max stays on with ${name}`, { skip }, async () => {
    const { doc, ctl } = setup({ paxMaxOff: fn });
    await tick();
    assert.equal(ctl.off, false);
    assert.ok(doc.documentElement.classList.contains("pax-blur-armed"));
  });
}
