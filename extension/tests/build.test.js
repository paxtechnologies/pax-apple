// SPDX-License-Identifier: GPL-3.0-only
// build.py reassembles the split vendor/model files and produces both packages.
const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");

test("build.py makes the Chrome zip and Firefox xpi with the model inside", () => {
  execFileSync("python3", ["build.py"], { cwd: ROOT, stdio: "pipe" });
  for (const b of ["chrome", "firefox"]) {
    const dir = path.join(ROOT, "dist", b);
    const mf = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
    assert.equal(mf.name, "Pax Image Blur");
    const model = JSON.parse(fs.readFileSync(path.join(dir, "model/mobilenet_v2/model.json"), "utf8"));
    assert.deepEqual(model.weightsManifest[0].paths, ["group1-shard1of1"]);
    assert.ok(fs.statSync(path.join(dir, "model/mobilenet_v2/group1-shard1of1")).size > 2_000_000);
    assert.ok(fs.readFileSync(path.join(dir, "vendor/pax-ml.min.js"), "utf8").includes("paxTf"));
  }
  assert.ok(fs.existsSync(path.join(ROOT, "dist/chrome/offscreen.html")));
  assert.ok(!fs.existsSync(path.join(ROOT, "dist/firefox/offscreen.html")));
  assert.ok(fs.statSync(path.join(ROOT, "dist/pax-image-blur.xpi")).size > 2_000_000);
});

test("every file in src/ is under 90 KB (the uploader's limit)", () => {
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true })
    .flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
  for (const f of walk(path.join(ROOT, "src"))) {
    assert.ok(fs.statSync(f).size < 90_000, `${f} is ${fs.statSync(f).size} bytes`);
  }
});

test("vendor bundle never evaluates strings (MV3 CSP)", () => {
  const js = fs.readFileSync(path.join(ROOT, "dist/chrome/vendor/pax-ml.min.js"), "utf8");
  assert.ok(!/new Function\(/.test(js) && !/\beval\(/.test(js));
});
