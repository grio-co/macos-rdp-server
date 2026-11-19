#!/bin/bash
# install-user.sh — durable, sudo-free install of macos-rdp-daemon as a per-user
# LaunchAgent in the Aqua (GUI) session.
#
# Why this exists instead of install.sh's LaunchDaemon:
#   * Screen capture requires the daemon to run inside the user's GUI (Aqua) session
#     so it has a WindowServer connection. A system LaunchDaemon does NOT, which is why
#     the daemon rendered a black screen under the old install.
#   * macOS TCC pins the Screen-Recording / Accessibility grant to the binary's code
#     signature. The binary must already be signed with the Developer ID certificate
#     (scripts/build-local.sh does this), so TCC pins to a stable requirement and the
#     grant SURVIVES rebuilds. This script never signs or re-signs anything; it refuses
#     a binary that is not Developer ID signed with identifier com.macosrdp.daemon.
#   * Everything lives under $HOME, so no sudo is ever required.
#
# Usage:
#   scripts/install-user.sh [path-to-macos-rdp-daemon]
#     If no path is given, falls back to ./build/macos-rdp-daemon.
#
# NOTE: This codifies the exact sequence validated manually over SSH. Verify end-to-end
# on a real Mac after any change.

set -euo pipefail

if [[ $EUID -eq 0 ]]; then
    echo "Run as your normal user, NOT root — this installs a per-user LaunchAgent." >&2
    exit 1
fi

PORT="${RDP_PORT:-3389}"
ROOT="$HOME/.macos-rdp"
BIN_DIR="$ROOT/bin"
BIN="$BIN_DIR/macos-rdp-daemon"
PLIST="$HOME/Library/LaunchAgents/com.macosrdp.agent.plist"
LABEL="com.macosrdp.agent"
GUI="gui/$(id -u)"

# 1. Locate the binary to install ------------------------------------------------------
SRC="${1:-}"
if [[ -z "$SRC" ]]; then
    if [[ -x "./build/macos-rdp-daemon" ]]; then
        SRC="./build/macos-rdp-daemon"
    else
        echo "No binary given and ./build/macos-rdp-daemon not found." >&2
        echo "Build first, or: scripts/install-user.sh /path/to/macos-rdp-daemon" >&2
        exit 1
    fi
fi
[[ -f "$SRC" ]] || { echo "Binary not found: $SRC" >&2; exit 1; }

mkdir -p "$BIN_DIR" "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"

# 2. Verify the signature (never re-sign) ---------------------------------------------
REQ='anchor apple generic and certificate leaf[subject.OU] = "FQKL8883DP" and identifier "com.macosrdp.daemon"'
if ! codesign --verify --strict -R="$REQ" "$SRC" 2>/dev/null; then
    echo "Refusing to install: $SRC is not signed with the Developer ID certificate" >&2
    echo "(team FQKL8883DP, identifier com.macosrdp.daemon). Build it with scripts/build-local.sh." >&2
    exit 1
fi

# 3. Install ---------------------------------------------------------------------------
echo "==> Installing binary..."
cp "$SRC" "$BIN"
chmod 755 "$BIN"
codesign -d -r- "$BIN" 2>&1 | grep -i "designated" || true

# 4. RDP TLS certificate (self-signed) into the user cert dir ---------------------------
if [[ ! -f "$ROOT/server.crt" || ! -f "$ROOT/server.key" ]]; then
    echo "==> Generating RDP TLS certificate..."
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$ROOT/server.key" -out "$ROOT/server.crt" \
        -subj "/CN=$(hostname)"
    chmod 600 "$ROOT/server.key"
fi

# 5. Per-user LaunchAgent (Aqua session => WindowServer => capture works) ---------------
echo "==> Writing LaunchAgent..."
cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array><string>$BIN</string><string>--port</string><string>$PORT</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RDP_CERT_DIR</key><string>$ROOT</string>
        <key>RDP_LOG_LEVEL</key><string>info</string>
    </dict>
    <key>StandardOutPath</key><string>$HOME/Library/Logs/macos-rdp-agent.log</string>
    <key>StandardErrorPath</key><string>$HOME/Library/Logs/macos-rdp-agent.error.log</string>
    <key>ThrottleInterval</key><integer>5</integer>
    <key>ProcessType</key><string>Interactive</string>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict>
</plist>
PL

# 7. (Re)load the agent -----------------------------------------------------------------
launchctl bootout "$GUI/$LABEL" 2>/dev/null || true
launchctl enable "$GUI/$LABEL" 2>/dev/null || true   # clear any prior `disable` override
launchctl bootstrap "$GUI" "$PLIST"

cat <<EOF

Installed and running as $LABEL on port $PORT (user: $USER).

ONE-TIME permission grant (durable afterwards — survives rebuilds):
  1. Connect once from your RDP client to this Mac.
  2. Approve the Screen Recording + Accessibility prompts, or enable
     "macos-rdp-daemon" under System Settings > Privacy & Security.
  3. Reconnect — the desktop will render.

To deploy a new build later (no sudo, grant stays valid):
  scripts/install-user.sh /path/to/new/macos-rdp-daemon
EOF
