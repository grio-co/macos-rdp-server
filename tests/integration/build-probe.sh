#!/bin/bash
# Builds tests/integration/rdp_probe against Homebrew FreeRDP (brew install freerdp)
# and signs it with Developer ID (hardened runtime; library validation off for the
# Homebrew dylibs). Output: build/probe/rdp_probe
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FRDP="$(brew --prefix freerdp)"
OUT="$ROOT/build/probe"; mkdir -p "$OUT"
clang -O1 -Wall -Wextra -Wno-unused-parameter \
    -I"$FRDP/include/freerdp3" -I"$FRDP/include/winpr3" \
    "$ROOT/tests/integration/rdp_probe.c" -L"$FRDP/lib" \
    -lfreerdp-client3 -lfreerdp3 -lwinpr3 -Wl,-rpath,"$FRDP/lib" -o "$OUT/rdp_probe"
codesign --force --options runtime --timestamp \
    --entitlements "$ROOT/tests/integration/probe.entitlements" \
    --sign "${RDP_CODESIGN_IDENTITY:-Developer ID Application: Grioghar Thomas-Baldwin (FQKL8883DP)}" \
    "$OUT/rdp_probe"
echo "built $OUT/rdp_probe"
