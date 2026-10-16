// SPDX-License-Identifier: GPL-3.0-only
// Entry point for src/vendor/pax-ml.min.js (TensorFlow.js core + layers +
// CPU/WebGL backends, Apache-2.0). Rebuilt by scripts/update-vendor.sh.
import * as tf from "@tensorflow/tfjs-core";
import { loadLayersModel } from "@tensorflow/tfjs-layers";
import "@tensorflow/tfjs-backend-cpu";
import "@tensorflow/tfjs-backend-webgl";
globalThis.paxTf = { tf, loadLayersModel };
