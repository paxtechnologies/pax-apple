#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# Build the iPhone helper runtime that Pax.app bundles (v0.8.6): a relocatable,
# universal2 (arm64 + x86_64) CPython from python-build-standalone with pymobiledevice3
# and the packages it needs, so "Keep my data" works on a Mac with no Python, no
# Command Line Tools and no Homebrew.
#
#   ./scripts/build-device-helper.sh OUT_DIR       # creates OUT_DIR/python
#
# Everything downloaded is pinned: the two CPython archives by sha256
# (device/helper-runtime.json) and every wheel by sha256 (device/requirements-bundle.txt,
# pip --require-hashes). The result is ad-hoc signed so it runs here; build-dmg.sh signs
# every Mach-O again with the Developer ID (hardened runtime) before notarisation.
#
# Environment:
#   PAX_HELPER_CACHE   where downloads are kept (default mac-app/.build/helper-cache)
#
# Needs macOS (lipo, codesign, shasum). Run by build-dmg.sh; developers rarely run it
# directly.
set -euo pipefail

die() { echo "build-device-helper: $*" >&2; exit 1; }
[[ $# -eq 1 ]] || die "usage: $0 OUT_DIR"
[[ "$(uname -s)" == "Darwin" ]] || die "run this on macOS (it needs lipo and codesign)"
for tool in lipo codesign shasum curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found"
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAC_APP="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO="$(cd "$MAC_APP/.." && pwd)"
OUT="$1"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
[[ ! -e "$OUT/python" ]] || die "$OUT/python already exists"
CACHE="${PAX_HELPER_CACHE:-$MAC_APP/.build/helper-cache}"
mkdir -p "$CACHE"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
HR="$SCRIPT_DIR/helper_runtime.py"
LOCK="$REPO/device/requirements-bundle.txt"
[[ -f "$LOCK" ]] || die "missing $LOCK"

case "$(uname -m)" in
  arm64) HOST=arm64 ;;
  x86_64) HOST=x86_64 ;;
  *) die "unsupported build machine $(uname -m)" ;;
esac

json() { /usr/bin/plutil -extract "$1" raw -o - "$REPO/device/helper-runtime.json"; }
# helper_runtime.py and pip run on an untouched copy of this Mac's runtime, so the
# build needs no other Python either.
hr() { "$WORK/host-python/bin/python3.12" -I "$HR" "$@"; }

echo "==> Python runtime (python-build-standalone)"
for arch in arm64 x86_64; do
  url="$(json "archives.$arch.url")"
  sum="$(json "archives.$arch.sha256")"
  file="$CACHE/$(basename "${url//%2B/+}")"
  if [[ ! -f "$file" ]] || [[ "$(shasum -a 256 "$file" | cut -d' ' -f1)" != "$sum" ]]; then
    echo "   downloading $(basename "$file")"
    curl -fsSL --retry 4 --retry-delay 5 -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  got="$(shasum -a 256 "$file" | cut -d' ' -f1)"
  [[ "$got" == "$sum" ]] || die "$(basename "$file"): sha256 $got, expected $sum"
  echo "   $arch: sha256 OK"
  mkdir -p "$WORK/$arch"
  tar -xzf "$file" -C "$WORK/$arch"
  [[ -x "$WORK/$arch/python/bin/python3.12" ]] || die "$arch archive has no bin/python3.12"
done
cp -R "$WORK/$HOST/python" "$WORK/host-python"
PYVER="$("$WORK/host-python/bin/python3.12" -I -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
WANT="$(json python_version)"
[[ "$PYVER" == "$WANT" ]] || die "runtime is Python $PYVER, expected $WANT"

echo "==> Packages (pinned with hashes, --no-deps)"
for arch in arm64 x86_64; do
  plat="$(json "wheel_platform.$arch")"
  "$WORK/host-python/bin/python3.12" -I -m pip install --disable-pip-version-check --no-input \
    --no-deps --require-hashes --only-binary=:all: --no-compile \
    --platform "$plat" --python-version 3.12 --implementation cp \
    --cache-dir "$CACHE/pip" --target "$WORK/site-$arch" -r "$LOCK"
  rm -rf "$WORK/site-$arch/bin"   # console scripts point at the build machine's python
done

echo "==> Pruning and assembling"
for arch in arm64 x86_64; do
  hr prune "$WORK/$arch/python"
  cp -R "$WORK/site-$arch/." "$WORK/$arch/python/lib/python3.12/site-packages/"
done

echo "==> Universal2 (lipo)"
hr merge "$WORK/arm64/python" "$WORK/x86_64/python" "$OUT/python"
hr verify-universal "$OUT/python"

echo "==> Ad-hoc signing (Developer ID signing happens in build-dmg.sh)"
while IFS= read -r -d '' f; do
  codesign --force --sign - --timestamp=none "$f"
done < <(hr list-macho "$OUT/python")

echo "==> Precompiling (unchecked-hash .pyc: the helper runs with -B and never writes into Pax.app)"
"$OUT/python/bin/python3.12" -I -m compileall -q -j 0 --invalidation-mode unchecked-hash \
  "$OUT/python/lib/python3.12" >/dev/null

echo "==> Self-test"
PIN="$(hr pin pymobiledevice3)"
"$OUT/python/bin/python3.12" -I -B "$REPO/device/pax_device.py" selftest \
  --expect-pymobiledevice3 "$PIN" --expect-arch "$HOST"
if arch -x86_64 /usr/bin/true 2>/dev/null && [[ "$HOST" == "arm64" ]]; then
  arch -x86_64 "$OUT/python/bin/python3.12" -I -B "$REPO/device/pax_device.py" selftest \
    --expect-pymobiledevice3 "$PIN" --expect-arch x86_64
else
  echo "   (no Rosetta here: the x86_64 slice is checked for presence only)"
fi
# Licence texts for the runtime and for packages whose wheels carry none.
cp -R "$REPO/licenses/helper-runtime" "$OUT/python/LICENSES"
du -sh "$OUT/python" | sed 's/^/   size: /'
