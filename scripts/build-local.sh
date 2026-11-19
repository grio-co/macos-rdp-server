#!/bin/bash
# build-local.sh — local, reproducible build of macos-rdp-daemon, signed with the
# Developer ID identity (hardened runtime + secure timestamp + minimal entitlements).
#
#   1. Builds the pinned FreeRDP fork (.github/freerdp-version, branch
#      build/<ver>-patched) as STATIC libraries into build/deps/freerdp-install.
#      Cached: rebuilt only when the version or the configure flags change.
#   2. Builds the daemon statically against it + Homebrew's static OpenSSL, so the
#      binary links only macOS system frameworks (no Homebrew dylibs — hardened
#      runtime library validation would refuse those).
#   3. Signs it with Developer ID and verifies the signature.
#
# Usage:  scripts/build-local.sh [--clean-deps] [--universal]
# Output: build/release/macos-rdp-daemon
#
# Environment overrides:
#   RDP_BUILD_VERSION      release tag to stamp (e.g. v0.1.7); the updater needs a tag
#   RDP_CODESIGN_IDENTITY  signing identity (default: Developer ID Application, FQKL8883DP)
#   RDP_DEPS_DIR           FreeRDP build cache (default build/deps; share it across worktrees)
#   RDP_BUILD_DIR          daemon build dir (default build/release)
#   OPENSSL_ROOT           OpenSSL prefix with lib/libssl.a + lib/libcrypto.a
#   FREERDP_REPO / FREERDP_BRANCH   FreeRDP source to build
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${RDP_DEPS_DIR:-$ROOT/build/deps}"
OUT="${RDP_BUILD_DIR:-$ROOT/build/release}"
JOBS="$(sysctl -n hw.logicalcpu)"

FREERDP_VER="$(tr -d '[:space:]' < "$ROOT/.github/freerdp-version")"
FREERDP_REPO="${FREERDP_REPO:-https://github.com/grio-co/FreeRDP.git}"
FREERDP_BRANCH="${FREERDP_BRANCH:-build/${FREERDP_VER}-patched}"
FREERDP_SRC="$DEPS/freerdp-src"
FREERDP_INSTALL="$DEPS/freerdp-install"
OPENSSL_ROOT="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
SIGN_ID="${RDP_CODESIGN_IDENTITY:-Developer ID Application: Grioghar Thomas-Baldwin (FQKL8883DP)}"
ENTITLEMENTS="$ROOT/entitlements/daemon.runtime.entitlements"

ARCHS="$(uname -m)"
for arg in "$@"; do
    case "$arg" in
        --clean-deps) rm -rf "$FREERDP_INSTALL" "$FREERDP_SRC/build" ;;
        --universal)  ARCHS="arm64;x86_64" ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

[[ -f "$OPENSSL_ROOT/lib/libssl.a" && -f "$OPENSSL_ROOT/lib/libcrypto.a" ]] || {
    echo "Static OpenSSL not found under $OPENSSL_ROOT (brew install openssl@3)" >&2; exit 1; }

# ── 1. FreeRDP (static) ──────────────────────────────────────────────────────
# Server-only, every optional dependency off. Notes on the non-obvious flags:
#   WITH_JSON_DISABLED  Homebrew json-c is auto-detected otherwise and leaks an
#                       undeclared dynamic dependency into WinPR (server never uses JSON).
#   WITH_KRB5=OFF       same, for Homebrew/system krb5.
#   WITH_INTERNAL_MD4/RC4  NTLM (NLA) needs MD4/RC4, which OpenSSL 3 only ships in
#                       the legacy provider; WinPR's built-in versions avoid that.
#   CMAKE_POLICY_VERSION_MINIMUM  CMake 4 rejects some bundled 3.x-era modules.
FREERDP_FLAGS=(
    -G Ninja
    -DCMAKE_BUILD_TYPE=MinSizeRel
    -DCMAKE_C_FLAGS=-Os -DCMAKE_CXX_FLAGS=-Os
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    -DCMAKE_INSTALL_PREFIX="$FREERDP_INSTALL"
    -DCMAKE_OSX_ARCHITECTURES="$ARCHS"
    -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0
    -DCMAKE_PREFIX_PATH="$OPENSSL_ROOT"
    -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT" -DOPENSSL_USE_STATIC_LIBS=TRUE
    -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DWITH_MANPAGES=OFF
    -DWITH_SERVER=ON -DWITH_PLATFORM_SERVER=OFF -DWITH_SERVER_CHANNELS=ON
    -DWITH_CLIENT=OFF -DWITH_CLIENT_COMMON=OFF -DWITH_PROXY=OFF
    -DWITH_SHADOW=OFF -DWITH_SAMPLE=OFF -DWITH_WINPR_TOOLS=OFF
    -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DWITH_DSP_FFMPEG=OFF
    -DWITH_CAIRO=OFF -DWITH_OPUS=OFF -DWITH_RDTK=OFF -DWITH_FAAD2=OFF -DWITH_FAAC=OFF
    -DWITH_SOXR=OFF -DWITH_LAME=OFF -DWITH_GSM=OFF
    -DWITH_WAYLAND=OFF -DWITH_X11=OFF -DWITH_CUPS=OFF -DWITH_PCSC=OFF
    -DWITH_JPEG=OFF -DWITH_WEBP=OFF -DWITH_OSS=OFF -DWITH_ALSA=OFF -DWITH_PULSE=OFF
    -DWITH_CHANNELS=ON -DWITH_RDPSND=ON -DWITH_CLIPRDR=ON -DWITH_RDPGFX=ON
    -DWITH_RDPEI=OFF -DWITH_RDPDR=ON -DWITH_PRINTER=OFF -DWITH_SMARTCARD=OFF
    -DWITH_SERIAL=OFF -DWITH_PARALLEL=OFF -DWITH_URBDRC=OFF
    -DWITH_VIDEO_ENCODER=OFF -DWITH_NEON=OFF
    -DWITH_JSON_DISABLED=ON -DWITH_KRB5=OFF
    -DWITH_INTERNAL_MD4=ON -DWITH_INTERNAL_RC4=ON
)
STAMP_WANT="$(printf '%s\n' "$FREERDP_REPO" "$FREERDP_BRANCH" "${FREERDP_FLAGS[@]}" | shasum -a 256 | cut -c1-16)"
STAMP_FILE="$FREERDP_INSTALL/.build-stamp"

if [[ -f "$STAMP_FILE" && "$(cat "$STAMP_FILE")" == "$STAMP_WANT" ]]; then
    echo "==> FreeRDP $FREERDP_BRANCH: cached ($FREERDP_INSTALL)"
else
    echo "==> Building FreeRDP $FREERDP_BRANCH (static, $ARCHS)"
    mkdir -p "$DEPS"
    if [[ ! -d "$FREERDP_SRC/.git" ]]; then
        git clone --depth 1 --branch "$FREERDP_BRANCH" "$FREERDP_REPO" "$FREERDP_SRC"
    fi
    rm -rf "$FREERDP_SRC/build" "$FREERDP_INSTALL"
    cmake -S "$FREERDP_SRC" -B "$FREERDP_SRC/build" "${FREERDP_FLAGS[@]}" > "$DEPS/freerdp-configure.log"
    cmake --build "$FREERDP_SRC/build" --parallel "$JOBS" > "$DEPS/freerdp-build.log"
    cmake --install "$FREERDP_SRC/build" > /dev/null
    echo "$STAMP_WANT" > "$STAMP_FILE"
fi

# ── 2. Daemon (static link) ──────────────────────────────────────────────────
mkdir -p "$OUT"
echo "==> Building macos-rdp-daemon ($ARCHS)"
cmake -S "$ROOT" -B "$OUT" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES="$ARCHS" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
    -DMACOS_RDP_STATIC=ON ${RDP_BUILD_VERSION:+-DMACOS_RDP_BUILD_VERSION=$RDP_BUILD_VERSION} \
    -DFREERDP_STATIC_INSTALL="$FREERDP_INSTALL" \
    -DCMAKE_PREFIX_PATH="$FREERDP_INSTALL;$OPENSSL_ROOT" \
    -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT" -DOPENSSL_USE_STATIC_LIBS=TRUE > "$OUT.configure.log"
cmake --build "$OUT" --parallel "$JOBS" 2>&1 | grep -E "error|warning: (unused|incompatible)|FAILED|Linking" || true
BIN="$OUT/macos-rdp-daemon"
[[ -x "$BIN" ]] || { echo "build failed — see output above" >&2; exit 1; }

EXTERNAL="$(otool -L "$BIN" | grep -E '^[[:space:]]' | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/|@)' || true)"
if [[ -n "$EXTERNAL" ]]; then echo "Non-system dylib dependencies: $EXTERNAL" >&2; exit 1; fi

# ── 3. Sign (Developer ID, hardened runtime, timestamp) ──────────────────────
echo "==> Signing with: $SIGN_ID"
strip -x "$BIN"
codesign --force --options runtime --timestamp \
    --identifier com.macosrdp.daemon \
    --entitlements "$ENTITLEMENTS" \
    --sign "$SIGN_ID" "$BIN"
codesign --verify --strict --verbose=2 "$BIN" 2>&1 | sed 's/^/    /'
codesign -d -r- "$BIN" 2>&1 | grep -i designated | sed 's/^/    /'
echo "==> Built $(du -h "$BIN" | cut -f1) $(lipo -archs "$BIN"): $BIN"
