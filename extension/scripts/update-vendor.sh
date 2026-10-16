#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Rebuild the bundled TensorFlow.js (src/vendor/pax-ml.min.js) and re-download
# the MobileNetV2 image model (src/model/mobilenet_v2), then store both as
# gzipped parts under 85 KB (python3 build.py pack). Needs Node 18+ and network.
# Versions are pinned in package.json "vendorDependencies".
set -eu
cd "$(dirname "$0")/.."
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp scripts/vendor-entry.js "$WORK/entry.js"
(cd "$WORK" && npm init -y >/dev/null && npm install --silent \
  @tensorflow/tfjs-core@4.22.0 @tensorflow/tfjs-layers@4.22.0 \
  @tensorflow/tfjs-backend-cpu@4.22.0 @tensorflow/tfjs-backend-webgl@4.22.0 esbuild@0.24.2 && \
  npx esbuild entry.js --bundle --minify --format=iife --legal-comments=eof \
    --target=chrome110,firefox115 --outfile=pax-ml.min.js)
python3 build.py pack "$WORK/pax-ml.min.js" vendor/pax-ml.min.js
# The model's address is kept encoded in common/pax_restricted.py (sources.model_url).
MODEL="$(python3 ../common/pax_restricted.py --source model_url)"
curl -fsSL -o "$WORK/model.json" "$MODEL/model.json"
curl -fsSL -o "$WORK/group1-shard1of1" "$MODEL/group1-shard1of1"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); open(sys.argv[1],"w").write(json.dumps(d,separators=(",",":")))' "$WORK/model.json"
python3 build.py pack "$WORK/model.json" model/mobilenet_v2/model.json
python3 build.py pack "$WORK/group1-shard1of1" model/mobilenet_v2/group1-shard1of1
echo "vendor and model updated; run python3 build.py and the tests"
