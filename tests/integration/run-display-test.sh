#!/bin/bash
# Display-protocol integration test: starts a loopback-only, no-auth test daemon
# on a spare port and drives it with the headless rdp_probe (initial output,
# resize to 1600x900, two-monitor layout).
#
#   tests/integration/run-display-test.sh [--virtual]
#
# Default mode serves from the main display (RDP_VIRTUAL_DISPLAY=0): nothing on
# the Mac's screens changes, and the two-monitor request collapses to one.
# --virtual creates real virtual displays (they briefly become the main display,
# then the arrangement is restored) and expects two monitors.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${RDP_TEST_PORT:-33899}"
BIN="${RDP_TEST_BIN:-$ROOT/build/release/macos-rdp-daemon}"
PROBE="$ROOT/build/probe/rdp_probe"
LOG="${RDP_TEST_LOG:-$ROOT/build/probe/daemon-test.log}"
[[ -x "$PROBE" ]] || "$ROOT/tests/integration/build-probe.sh" >/dev/null

VD=0; EXPECT=1
[[ "${1:-}" == "--virtual" ]] && { VD=1; EXPECT=2; }

env RDP_CERT_DIR="${RDP_CERT_DIR:-$HOME/.macos-rdp}" RDP_ALLOW_NO_AUTH=1 RDP_NLA=off RDP_VIRTUAL_DISPLAY=$VD RDP_SHARED_MODE=1 \
    RDP_NO_TCC_PROMPT=1 RDP_CURSOR_SHAPES=0 RDP_UPDATE_ENABLED=0 \
    "$BIN" --port "$PORT" --bind 127.0.0.1 --log-level verbose >"$LOG" 2>&1 &
DPID=$!
trap 'kill $DPID 2>/dev/null; wait $DPID 2>/dev/null' EXIT

for _ in $(seq 1 50); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.1; done

"$PROBE" --expect-monitors "$EXPECT" -- /v:127.0.0.1:"$PORT" /u:probe /p:probe \
    /cert:ignore /size:1280x720 -clipboard /audio-mode:2 /gfx:AVC420 /log-level:ERROR
RC=$?
kill $DPID 2>/dev/null; wait $DPID 2>/dev/null
echo "--- daemon log (display/gfx/disp lines): $LOG"
grep -E "GFX|DISP|disp:|monitor|layout|ResetGraphics|display [0-9]|error|ERROR" "$LOG" | sed 's/^/  /' | head -60
exit $RC
