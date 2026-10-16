#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# CI/dev aid for machines without macOS: type-checks PaxCore and runs the PaxCore
# XCTests through the Swift interpreter on Linux (no linker needed), then
# parse-checks the SwiftUI sources (SwiftUI itself only exists on macOS).
#   SWIFT=/path/to/swift-toolchain/usr/bin SDK=/path/to/sysroot ./scripts/linux-xctest.sh
set -euo pipefail
SWIFT_BIN="${SWIFT:-$(dirname "$(command -v swift)")}"
SDK_ARGS=()
[[ -n "${SDK:-}" ]] && SDK_ARGS=(-sdk "$SDK")
MAC_APP="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

"$SWIFT_BIN/swiftc" -typecheck "${SDK_ARGS[@]}" -module-name PaxCore "$MAC_APP"/Sources/PaxCore/*.swift
echo "PaxCore type-checks"

for f in "$MAC_APP"/Tests/PaxCoreTests/*.swift; do
  sed -e 's/^@testable import PaxCore//' "$f" > "$WORK/T_$(basename "$f")"
done
cp "$MAC_APP"/Sources/PaxCore/*.swift "$WORK/"
python3 - "$WORK" <<'PY'
import glob, os, re, sys
out = sys.argv[1]
cases = []
for f in sorted(glob.glob(os.path.join(out, "T_*.swift"))):
    for cls, body in re.findall(r"final class (\w+): XCTestCase \{(.*?)\n\}\n", open(f).read(), re.S):
        entries = []
        for m in re.finditer(r"func (test\w+)\(\)\s*(async)?", body):
            call = f"{{ (c: {cls}) in c.{m.group(1)} }}"
            entries.append(f'("{m.group(1)}", asyncTest({call}))' if m.group(2) else f'("{m.group(1)}", {call})')
        cases.append(f"    testCase([{', '.join(entries)}]),")
open(os.path.join(out, "zz_main.swift"), "w").write("XCTMain([\n" + "\n".join(cases) + "\n])\n")
PY
# The interpreter takes a single file: concatenate with imports first.
{
  cat "$WORK"/*.swift | grep -E '^import ' | sort -u
  echo "import XCTest"
  for f in "$WORK"/*.swift; do grep -vE '^import ' "$f"; done
} > "$WORK/all.swift.txt"
mv "$WORK/all.swift.txt" "$WORK/all.swift"
"$SWIFT_BIN/swift" "${SDK_ARGS[@]}" "$WORK/all.swift"

for f in "$MAC_APP"/Sources/Pax/*.swift "$MAC_APP"/Sources/Pax/Views/*.swift; do
  "$SWIFT_BIN/swiftc" -parse "$f"
done
echo "SwiftUI sources parse"
