// SPDX-License-Identifier: GPL-3.0-only
// On-device classifier: Infinite Red's MobileNetV2 image model (MIT, bundled in
// model/mobilenet_v2) on TensorFlow.js (Apache-2.0, vendor/pax-ml.min.js).
// Runs in Chrome's offscreen document or Firefox's background page. Images are
// fetched with the extension's own host permissions or handed over as a small
// data: URL drawn by the page; nothing is sent anywhere else.
(function (root) {
  "use strict";
  const Core = root.PaxBlurCore;
  const SIZE = Core.INPUT_SIZE;
  const MAX_BYTES = 15 * 1024 * 1024;
  let modelPromise = null;
  let chain = Promise.resolve();   // one inference at a time (WebGL)

  function modelUrl() {
    const rt = (root.chrome && root.chrome.runtime) || (root.browser && root.browser.runtime);
    return rt.getURL("model/mobilenet_v2/model.json");
  }

  function loadModel() {
    if (!modelPromise) {
      modelPromise = (async () => {
        const { tf, loadLayersModel } = root.paxTf;
        try { await tf.setBackend("webgl"); } catch (_) { await tf.setBackend("cpu"); }
        await tf.ready();
        const model = await loadLayersModel(modelUrl());
        tf.tidy(() => model.predict(tf.zeros([1, SIZE, SIZE, 3])));   // warm up
        return model;
      })();
      modelPromise.catch(() => { modelPromise = null; });
    }
    return modelPromise;
  }

  async function bitmapFor(msg) {
    const src = msg.url || msg.dataUrl;
    const resp = await fetch(src, { credentials: "include", cache: "force-cache" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const blob = await resp.blob();
    if (blob.size > MAX_BYTES) throw new Error("image too large");
    if (blob.type && !blob.type.startsWith("image/")) throw new Error("not an image: " + blob.type);
    return createImageBitmap(blob);
  }

  function pixels(bitmap) {
    const canvas = typeof OffscreenCanvas === "function"
      ? new OffscreenCanvas(SIZE, SIZE)
      : Object.assign(document.createElement("canvas"), { width: SIZE, height: SIZE });
    const ctx = canvas.getContext("2d");
    ctx.drawImage(bitmap, 0, 0, SIZE, SIZE);
    if (bitmap.close) bitmap.close();
    return ctx.getImageData(0, 0, SIZE, SIZE);
  }

  async function run(msg) {
    const model = await loadModel();
    const { tf } = root.paxTf;
    const data = pixels(await bitmapFor(msg));
    const out = tf.tidy(() => {
      const x = tf.browser.fromPixels(data).toFloat().div(tf.scalar(255)).expandDims(0);
      return model.predict(x);
    });
    const values = await out.data();
    out.dispose();
    const probs = Core.toProbabilities(values);
    return { verdict: Core.verdict(probs), probs };
  }

  function classify(msg) {
    const next = chain.then(() => run(msg));
    chain = next.catch(() => {});
    return next.catch((e) => ({ error: String((e && e.message) || e) }));
  }

  root.PaxClassifier = { classify, loadModel };
})(typeof globalThis !== "undefined" ? globalThis : this);
