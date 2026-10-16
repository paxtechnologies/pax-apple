#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
#
# pax-guard's launcher (v0.8.6): the program in
# /Library/LaunchDaemons/org.paxpeace.pax-guard.plist. It picks the Python that
# runs /Library/PaxGuard/bin/pax_guard.py:
#
#   1. Pax's own runtime, /Library/PaxGuard/runtime (a checked copy of the signed
#      CPython inside Pax.app; see guard/guard_runtime.py), unless it has failed
#      to start 3 times in a row (state/runtime-starts, cleared by pax-guard after
#      a healthy cycle);
#   2. otherwise /usr/bin/python3, if Apple's Command Line Tools are installed;
#   3. otherwise the runtime anyway (there is nothing else to run).
#
# Root-owned, in /Library/PaxGuard/bin, and hashed by pax-guard's tamper checks.
# No PATH lookups: every program is named by its full path.
BASE=/Library/PaxGuard
RT="$BASE/runtime/bin/python3.12"
GUARD="$BASE/bin/pax_guard.py"
STARTS="$BASE/state/runtime-starts"
MAX=3

# The bundled CPython doesn't know where macOS keeps its CA bundle (OpenSSL reads this).
if [ -f /etc/ssl/cert.pem ]; then SSL_CERT_FILE=/etc/ssl/cert.pem; export SSL_CERT_FILE; fi

n=0
if [ -f "$STARTS" ]; then n="$(/bin/cat "$STARTS" 2>/dev/null)"; fi
case "$n" in ''|*[!0-9]*) n=0 ;; esac

if [ -x "$RT" ] && [ "$n" -lt "$MAX" ]; then
  if [ "${1:-run}" = "run" ]; then echo "$((n + 1))" > "$STARTS" 2>/dev/null; fi
  exec "$RT" -I -B "$GUARD" "$@"
fi
if /usr/bin/xcode-select -p >/dev/null 2>&1 && /usr/bin/python3 -I -c 'import ssl' >/dev/null 2>&1; then
  exec /usr/bin/python3 -I -B "$GUARD" "$@"
fi
if [ -x "$RT" ]; then
  exec "$RT" -I -B "$GUARD" "$@"
fi
echo "pax-guard-launch: PAX-GUARD-002 no Python to run pax-guard (runtime missing, no Command Line Tools)" >&2
exit 78
