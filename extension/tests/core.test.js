// SPDX-License-Identifier: GPL-3.0-only
// node --test tests/*.test.js   (no dependencies)
const test = require("node:test");
const assert = require("node:assert/strict");
const C = require("../src/core.js");

const P = (Drawing, RestrictedDrawn, Neutral, Restricted, Borderline) => ({ Drawing, RestrictedDrawn, Neutral, Restricted, Borderline });

test("probabilities keep a distribution and softmax logits", () => {
  const p = C.toProbabilities([0.1, 0.0, 0.8, 0.05, 0.05]);
  assert.equal(p.Neutral, 0.8);
  const q = C.toProbabilities([1, 2, 3, 4, 5]);
  assert.ok(Math.abs(Object.values(q).reduce((a, b) => a + b, 0) - 1) < 1e-9);
  assert.ok(q.Borderline > q.Restricted);
  assert.throws(() => C.toProbabilities([1, 2]));
  assert.throws(() => C.toProbabilities([1, 2, NaN, 4, 5]));
});

test("verdicts are cautious", () => {
  assert.equal(C.verdict(P(0.1, 0, 0.88, 0.01, 0.01)), "safe");
  assert.equal(C.verdict(P(0, 0, 0.3, 0.6, 0.1)), "locked");
  assert.equal(C.verdict(P(0.2, 0.65, 0.1, 0.0, 0.05)), "locked");
  assert.equal(C.verdict(P(0.2, 0.35, 0.1, 0.3, 0.05)), "locked");   // combined restricted
  assert.equal(C.verdict(P(0.1, 0, 0.35, 0.05, 0.5)), "veiled");
  assert.equal(C.verdict(P(0.2, 0.2, 0.3, 0.1, 0.2)), "veiled");     // any flagged class >= 0.5
  assert.equal(C.verdict(P(0.6, 0.1, 0.2, 0.05, 0.05)), "safe");
});

test("reveal is never possible for locked", () => {
  assert.equal(C.canReveal("locked"), false);
  assert.equal(C.canReveal("pending"), false);
  assert.equal(C.canReveal("veiled"), true);
  assert.equal(C.canReveal("unknown"), true);
  assert.equal(C.stateForVerdict(undefined), "unknown");
  assert.equal(C.stateForVerdict("locked"), "locked");
});

test("video frames only get stricter; locked locks even after a reveal", () => {
  assert.equal(C.nextVideoState("pending", "safe"), "safe");
  assert.equal(C.nextVideoState("safe", "veiled"), "veiled");
  assert.equal(C.nextVideoState("revealed", "veiled"), "revealed");
  assert.equal(C.nextVideoState("revealed", "locked"), "locked");
  assert.equal(C.nextVideoState("locked", "safe"), "locked");
  assert.equal(C.nextVideoState("veiled", "safe"), "veiled");
  assert.equal(C.nextVideoState("pending", null), "unknown");
  assert.equal(C.nextVideoState("unknown", "safe"), "safe");
});

test("small images are skipped, thumbnails of big pictures are not", () => {
  assert.equal(C.isSmall(32, 32, 32, 32), true);
  assert.equal(C.isSmall(40, 40, 2000, 1500), false);
  assert.equal(C.isSmall(300, 200, 1200, 800), false);
  assert.equal(C.isSmall(0, 0, 24, 24), true);
  assert.equal(C.isSmall(120, 16, 0, 0), true);
});

test("source kinds", () => {
  assert.equal(C.sourceKind("https://cdn.example/a.jpg"), "url");
  assert.equal(C.sourceKind("data:image/png;base64,AAAA"), "url");
  assert.equal(C.sourceKind("blob:https://example.com/1234"), "canvas");
  assert.equal(C.sourceKind("javascript:alert(1)"), "none");
  assert.equal(C.sourceKind(""), "none");
});

test("allowlist parsing and matching", () => {
  assert.deepEqual(C.parseAllowlist("https://www.Example.com/path\nfoo.org, *.bar.co.uk  nonsense ftp://x"),
    ["example.com", "foo.org", "bar.co.uk"]);
  assert.deepEqual(C.parseAllowlist(["a.com", "A.com", "a.com."]), ["a.com"]);
  assert.equal(C.normalizeDomain("localhost"), null);
  assert.equal(C.normalizeDomain("192.168.1.1"), null);
  const list = ["example.com"];
  assert.equal(C.hostAllowed("example.com", list), true);
  assert.equal(C.hostAllowed("img.example.com", list), true);
  assert.equal(C.hostAllowed("notexample.com", list), false);
  assert.equal(C.hostAllowed("example.com.evil.net", list), false);
  assert.equal(C.hostAllowed("", list), false);
});

test("LRU evicts the least recently used", () => {
  const l = new C.LRU(2);
  l.set("a", 1); l.set("b", 2); l.get("a"); l.set("c", 3);
  assert.equal(l.get("b"), undefined);
  assert.equal(l.get("a"), 1);
  assert.equal(l.size, 2);
});

test("queue caps concurrency", async () => {
  const q = C.createQueue(2);
  let running = 0, peak = 0;
  const job = () => new Promise((r) => { running++; peak = Math.max(peak, running);
    setTimeout(() => { running--; r(1); }, 5); });
  const results = await Promise.all(Array.from({ length: 7 }, () => q.push(job)));
  assert.equal(peak, 2);
  assert.equal(results.length, 7);
});

test("Pax Max is off only on the exact signal (v0.8.12)", () => {
  assert.equal(C.PAX_MAX_OFF_NAME, "pax-max-off.guard.paxpeace.com");
  assert.equal(C.paxMaxOff(["127.80.77.0"]), true);
  for (const a of [undefined, null, [], ["0.0.0.0"], ["127.80.77.1"], ["127.80.77.0", "1.2.3.4"], "127.80.77.0"]) {
    assert.equal(C.paxMaxOff(a), false, String(a));
  }
});
