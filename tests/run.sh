#!/bin/bash
# Builds and runs the standalone clipboard tests (plain clang, nothing is linked
# into the daemon; the real pasteboard is never touched).
#
#   test_clipboard   pure pieces: CF_HTML, DIB <-> PNG/TIFF, FILEDESCRIPTORW, file
#                    sets, >4 GB ranges, chunked folder download
#   test_engine      protocol/RDPClipboard.c against a mock cliprdr server context
#                    (both directions, locks, threading, teardown while waiting)
#   test_pasteboard  NSPasteboard promise assumptions on a PRIVATE pasteboard
#                    (pasteboardWithUniqueName, released globally at the end)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${RDP_DEPS_DIR:-$ROOT/build/deps}"
FI="$DEPS/freerdp-install/include"
OUT="$ROOT/build/tests"
mkdir -p "$OUT/tmp"
export TEST_TMP="$OUT/tmp"
WARN=(-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)
FW=(-framework CoreFoundation -framework CoreGraphics -framework ImageIO)

clang -std=gnu11 -O1 -g "${WARN[@]}" -I"$ROOT" \
    "$ROOT/tests/test_clipboard.c" \
    "$ROOT/protocol/RDPClipboardCodec.c" "$ROOT/protocol/RDPClipboardFiles.c" \
    "$ROOT/protocol/RDPClipboardImage.c" "${FW[@]}" -o "$OUT/test_clipboard"
"$OUT/test_clipboard"

clang -std=gnu11 -O1 -g "${WARN[@]}" -I"$ROOT" -I"$FI/freerdp3" -I"$FI/winpr3" -I"$FI" \
    "$ROOT/tests/test_engine.c" "$ROOT/protocol/RDPClipboard.c" \
    "$ROOT/protocol/RDPClipboardCodec.c" "$ROOT/protocol/RDPClipboardFiles.c" \
    "$ROOT/logging/RDPLog.c" -o "$OUT/test_engine"
perl -e 'alarm 180; exec @ARGV' "$OUT/test_engine"

clang -std=gnu11 -fobjc-arc -O1 -g "${WARN[@]}" -I"$ROOT" \
    "$ROOT/tests/test_pasteboard.m" -framework Foundation -framework AppKit \
    -o "$OUT/test_pasteboard"
perl -e 'alarm 90; exec @ARGV' "$OUT/test_pasteboard"

# daemon/main.m shutdown pattern (dispatch signal sources + main run loop), isolated.
clang -fobjc-arc "${WARN[@]}" "$ROOT/tests/test_runloop.m" -framework Foundation -o "$OUT/test_runloop"
perl -e 'alarm 30; exec @ARGV' "$OUT/test_runloop"

clang -std=c11 -O1 -g "${WARN[@]}" -I"$ROOT" "$ROOT/tests/test_security_core.c" \
    "$ROOT/daemon/SecurityCore.c" -o "$OUT/test_security_core"
"$OUT/test_security_core"

clang -std=gnu11 -O1 -g "${WARN[@]}" -I"$ROOT" "$ROOT/tests/test_input_logic.c" \
    -o "$OUT/test_input_logic"
"$OUT/test_input_logic"

clang -std=c11 -O1 -g "${WARN[@]}" -I"$ROOT" "$ROOT/tests/test_update_version.c" \
    -o "$OUT/test_update_version"
"$OUT/test_update_version"

clang -fobjc-arc -O1 -g "${WARN[@]}" -I"$ROOT" "$ROOT/tests/test_update_verify.m" \
    "$ROOT/daemon/UpdateVerify.m" -framework Foundation -framework Security \
    -o "$OUT/test_update_verify"
"$OUT/test_update_verify"

clang -std=gnu11 -O1 -g "${WARN[@]}" -I"$ROOT" "$ROOT/tests/test_flowcontrol.c" \
    "$ROOT/protocol/RDPFlowControl.c" -o "$OUT/test_flowcontrol"
"$OUT/test_flowcontrol"

clang -std=gnu11 -O1 -g "${WARN[@]}" -I"$ROOT" "$ROOT/tests/test_ima.c" \
    "$ROOT/audio/ImaAdpcm.c" -lm -o "$OUT/test_ima"
"$OUT/test_ima"
