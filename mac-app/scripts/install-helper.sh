#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# FOR DEVELOPERS ONLY. Users never run this: since v0.8.6 Pax.app bundles its own Python
# with pymobiledevice3 (scripts/build-device-helper.sh), and this script is not shipped.
#
# It makes a developer venv with pymobiledevice3 in ~/Library/Application Support/Pax/venv,
# which a `swift run` build (no app bundle) falls back to. Since v0.8.6 the helper does
# backups and the seed restore with pymobiledevice3 itself, so idevicebackup2 is optional:
# it's only used when PAX_IDEVICEBACKUP2 points at it.
#
#   mac-app/scripts/install-helper.sh
set -euo pipefail

SUPPORT="$HOME/Library/Application Support/Pax"
VENV="$SUPPORT/venv"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ="$HERE/../../device/requirements.txt"
[[ -f "$REQ" ]] || { echo "can't find device/requirements.txt" >&2; exit 1; }

PY=""
for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if [[ -x "$candidate" ]] && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    PY="$candidate"; break
  fi
done
[[ -n "$PY" ]] || { echo "Python 3.9+ not found. Run: xcode-select --install (or brew install python)" >&2; exit 1; }

echo "==> Creating $VENV with $PY"
mkdir -p "$SUPPORT"
"$PY" -m venv "$VENV"
"$VENV/bin/python3" -m pip install --upgrade pip >/dev/null
"$VENV/bin/python3" -m pip install -r "$REQ"

"$VENV/bin/python3" "$HERE/../../device/pax_device.py" selftest || true
echo "==> Done. A \`swift run\` build uses this venv (or set PAX_PYTHON=$VENV/bin/python3)."
