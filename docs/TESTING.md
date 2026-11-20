# macOS RDP Server — Feature & Stability Test Plan

Goal: parity with the Windows Remote Desktop (mstsc) experience, and rock-solid stability.

Status legend: ✅ working · ⚠️ partial / needs work · ❌ not implemented · ❓ untested

Test client: Windows `mstsc` → macOS Tahoe 26 arm64. Release binaries are built with `scripts/build-local.sh` (Developer ID) and uploaded by the owner; the updater rejects anything else.

---

## 1. Connection & Security
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 1.1 | TCP connect on 3389 | `mstsc /v:192.168.1.152` | Session opens | ✅ |
| 1.2 | TLS negotiation | Connect; accept cert | Encrypted session | ✅ |
| 1.3 | Self-signed cert prompt | First connect | Cert warning, then connects | ✅ |
| 1.4 | Auth — correct creds | Enter Mac username+password | Authenticates, session starts | ✅ |
| 1.5 | Auth — wrong creds | Enter wrong password | Rejected, no session | ✅ |
| 1.6 | Auth — session takeover | Connect 2nd client with correct creds | 2nd client takes over | ✅ |
| 1.7 | Auth — takeover with wrong creds | Connect 2nd client with bad creds | Rejected, 1st session undisturbed | ❓ |
| 1.8 | NLA disabled | Try NLA-required client | NLA is off server-side (document) | ⚠️ |
| 1.9 | Durable TCC grant across rebuilds | Auto-update reloads daemon | Screen Recording still granted | ✅ |
| 1.10 | Grant across reboot | Reboot Mac, reconnect | TBD — non-notarized binary | ❓ |
| 1.11 | Multi-monitor client | Connect mstsc with "Use all my monitors" | Single combined virtual display | ❓ |

## 2. Display
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 2.1 | Desktop renders (AVC420/H.264) | Connect | Live desktop, correct content | ✅ |
| 2.2 | Virtual display at client resolution | Connect at 3440×1440 | No pillarbox, native 1:1 | ✅ |
| 2.3 | Correct colors | View photos / gradients | Accurate color | ❓ |
| 2.4 | Refresh on minimize/restore | Minimize then restore mstsc | Repaints cleanly | ✅ (SuppressOutput + IDR) |
| 2.5 | Frame rate / smoothness | Drag a window, scroll | Fluid ~30 fps | ❓ |
| 2.6 | Dynamic resolution change | Resize mstsc window | Session adapts | ❓ |
| 2.7 | Non-ultrawide client (1920×1080) | Connect from 16:9 | Correct proportions | ❓ |
| 2.7a | Dynamic resolution (MS-RDPEDISP) | Resize the client window; watch the log | `disp: client requested monitor …` appears | ⚠️ observe-only — channel receives, resize NOT applied (blocked on RESET_GRAPHICS) |
| 2.8 | Privacy blank on connect | Set RDP_PRIVACY_BLANK=1 | Local display dims/blanks | ⚠️ (DisplayServices brightness only) |
| 2.8a | Automatic brightness after a dimmed session | With System Settings › Displays › "Automatically adjust brightness" on, connect, then disconnect (or touch the Mac) | Log shows "automatic brightness paused" at connect and "automatic brightness back on for display N" after; the setting is on again and the screen follows the room light | ❓ needs a real session |
| 2.9 | Shared mode | Set RDP_SHARED_MODE=1 | Remote + local see same screen | ❓ |
| 2.10 | Wake Mac on connect | Mac display asleep, then connect | Display wakes, capture starts | ✅ (IOPMAssertion) |

## 3. Input
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 3.1 | Mouse move (1:1 position) | Move across whole screen | Tracks accurately | ✅ |
| 3.2 | Cursor shapes (I-beam, resize, spinner) | Hover text / window edge | Shows correct cursor | ✅ (24bpp; default on, `RDP_CURSOR_SHAPES=0` opts out) |
| 3.3 | Left/right/middle click | Click around | Registers correctly | ❓ |
| 3.4 | Click-drag | Drag a window / select text | Works | ❓ |
| 3.5 | Scroll wheel (vert/horiz) | Scroll a page | Scrolls correct direction | ❓ |
| 3.6 | Keyboard — letters/numbers/symbols | Type in TextEdit | Correct chars | ❓ |
| 3.7 | Modifiers (⌘ ⌥ ⌃ ⇧) + shortcuts | ⌘C / ⌘V / ⌘Tab / ⌘Space | Work | ❓ |
| 3.8 | Special keys (F1-F12, Esc, arrows, Del) | Press them | Work | ❓ |

## 4. Clipboard (CLIPRDR)
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 4.1 | Text Mac → Windows | Copy on Mac, paste on Win | Pastes correctly | ✅ |
| 4.2 | Text Windows → Mac | Copy on Win, paste on Mac | Pastes correctly | ✅ |
| 4.3 | Unicode / emoji / RTL text | Copy/paste 非ASCII 🎉 | Preserved | ✅ |
| 4.4 | Large text | Copy a large block | No truncation | ✅ |
| 4.5 | Image (PNG) Mac → Windows | Copy a screenshot on Mac, paste in Paint | Image appears | ❓ (0xC004 named format) |
| 4.6 | Image Windows → Mac | Copy image on Win, paste in Preview | Image appears | ❓ |
| 4.7 | File drag/drop | Drag a file | Not implemented (HDROP) | ❌ |

## 5. Audio
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 5.1 | System audio out (Mac → client) | Play music on Mac | Hear it on Windows headphones | ✅ (CATap, 44.1 kHz) |
| 5.2 | Audio pitch / rate | Play a 440 Hz tone | Correct pitch | ✅ |
| 5.3 | Audio + local speakers | RDP_AUDIO_LOCAL=1 | Plays on both Mac+client | ✅ |
| 5.4 | Audio quality / sync | Play a video | Clear, in sync | ❓ |
| 5.5 | Mic input (Windows → Mac speakers) | RDP_AUDIO_INPUT=1, Win "Record from this computer" | Mac plays Windows mic | ✅ (MS-RDPEAI, 16kHz PCM) |

## 6. Drive Redirection (RDPDR / WebDAV)
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 6.1 | Channel open | Connect with Drives enabled in mstsc | Log shows "rdpdr: channel open" | ✅ |
| 6.2 | Drive enumeration | Connect with C: shared | Log shows "rdpdr: client drive C" | ✅ |
| 6.3 | WebDAV server starts | See above | Log shows "webdav: accept loop started on port N" (a free port) | ❓ needs test |
| 6.4 | Volume mounts in Finder | See above | ~/RDP-Drives/C mounts (Finder volume RDP-C) | ❓ needs hardware test |
| 6.5 | Browse files (PROPFIND) | Open ~/RDP-Drives/C in Finder | Windows files visible | ❓ |
| 6.6 | Read file (GET) | Open a text file | Contents correct | ❓ |
| 6.7 | Write file (PUT) | Save a file to ~/RDP-Drives/C | File appears on Windows | ❓ |
| 6.8 | Delete file | Trash a file | Deleted on Windows | ❓ |
| 6.9 | Unmount on disconnect | Disconnect mstsc | ~/RDP-Drives/C unmounts | ❓ |
| 6.9a | Drive needs its password | During a session, `curl -X PROPFIND http://127.0.0.1:<port>/` (port from 6.3) | HTTP 401 with `WWW-Authenticate: Basic`; the Finder mount keeps working | ✅ (FreeRDP drive client) |
| 6.10 | Printer / serial / USB | — | Not built | ❌ |

**How to enable:** `RDP_RDPDR_ENABLED=1` must be in the LaunchAgent plist (set by default).  
**mstsc setup:** Options → Local Resources → More → Drives → check your Windows drives.

## 7. Auto-Update
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 7.1 | Polls GitHub releases | Check daemon log | "up to date (version XXXXXXX)" every 5 min | ✅ |
| 7.2 | Updates on a newer release | Owner uploads a Developer-ID-signed `vX.Y.Z` build (`RDP_BUILD_VERSION=vX.Y.Z scripts/build-local.sh`) | Daemon swaps and restarts within 5 min | ⚠️ needs a signed release; CI builds are rejected |
| 7.3 | Defers while client connected | Be connected when update is available | Log "deferring: client active" | ✅ |
| 7.4 | Verifies signature, never re-signs | Offer a release asset that is unsigned, ad-hoc, or not team FQKL8883DP / `com.macosrdp.daemon` / hardened runtime | Log "verify: rejected: ...", live binary untouched | ✅ |
| 7.6 | Refuses downgrade / same version | Release tag <= running `vX.Y.Z` | Log "no update: ..." | ✅ (`tests/test_update_version.c`) |
| 7.5 | SHA-256 integrity check | — | Daemon verifies hash before applying | ✅ |

## 8. Session management
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 8.1 | Clean disconnect | Close mstsc | Server tears down, no leak | ✅ |
| 8.2 | Reconnect after disconnect | Reconnect | Fresh session works | ✅ |
| 8.3 | Negotiation watchdog | Half-open connection stuck | Drops after 20s | ✅ |
| 8.4 | Multiple sequential sessions | Connect/disconnect ×10 | Each works, no leak | ❓ |
| 8.5 | Two simultaneous clients | Connect from 2 machines | 2nd must auth; takeover or reject | ✅ |
| 8.6 | Idle session (10 min) | Leave idle | Stays up, low CPU | ❓ |
| 8.7 | Display restore on disconnect | Disconnect | Built-in display restored | ❓ |

## 9. Performance
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 9.1 | Idle CPU | Connected, static screen | Low (heartbeat ~4 fps) | ❓ |
| 9.2 | Active CPU | Drag windows / play video | Reasonable | ❓ |
| 9.3 | Input latency | Move mouse / type | Snappy (<50ms) | ✅ (cursor) / ❓ (keys) |
| 9.4 | Memory (no leak) | Watch RSS over 1h | Flat | ❓ |

## 10. Stability / soak
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 10.1 | Long soak (1–8 h) | Keep session open | No drop, no leak, no crash | ❓ |
| 10.2 | Rapid reconnect ×20 | Connect/disconnect fast | No crash / port stuck | ❓ |
| 10.3 | Network blip | Briefly drop Wi-Fi | Recovers or clean fail | ❓ |
| 10.4 | Mac sleep/wake | Sleep the Mac, wake, reconnect | Recovers (IOPMAssertion prevents sleep during session) | ❓ |
| 10.5 | Agent auto-restart | `launchctl kill -TERM gui/501/com.macosrdp.agent.user` | launchd restarts it in 5s | ✅ |

## 11. Install & configuration
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 11.1 | User installer | Run scripts/install-user.sh on Mac | Verifies the Developer ID signature, installs, loads | ⚠️ untested end-to-end |
| 11.2 | GUI config app | Open the menu-bar app | Toggle all options, start/stop | ✅ (gui/build.sh) |
| 11.3 | Grant permissions | scripts/grant-permissions.sh | Screen Recording + Accessibility granted | ⚠️ |
| 11.4 | Uninstall | scripts/uninstall.sh | Clean removal | ❓ |
| 11.5 | Remote install (fresh Mac) | scripts/remote-install.sh | Binary + plist + cert installed | ⚠️ untested |

---

### Environment variable reference

| Variable | Default | Description |
|---|---|---|
| `RDP_LOG_LEVEL` | info | Log verbosity: error / info / verbose / debug |
| `RDP_CERT_DIR` | *required* | Directory containing server.crt + server.key |
| `RDP_CURSOR_SHAPES` | 1 | Send real Mac cursor shapes (24bpp) |
| `RDP_SHOW_CURSOR` | 0 | Overlay Mac cursor in the video stream |
| `RDP_SHARED_MODE` | 0 | Allow local+remote to interact simultaneously |
| `RDP_PRIVACY_BLANK` | 0 | Dim built-in display brightness on connect |
| `RDP_RDPDR_ENABLED` | 1 | Enable Windows drive redirection |
| `RDP_AUDIO_LOCAL` | 1 | Also play audio on local Mac speakers |
| `RDP_AUDIO_INPUT` | 0 | Receive Windows mic → Mac speakers (MS-RDPEAI) |
| `RDP_ALLOW_IDLE_SLEEP` | 0 | Allow Mac to idle-sleep (breaks remote access) |
| `RDP_UPDATE_ENABLED` | 1 | Enable auto-update |
| `RDP_UPDATE_INTERVAL_MIN` | 5 | Auto-update check interval in minutes |
| `RDP_UPDATE_REPO` | `grioghar/macos-rdp-server` | GitHub `owner/repo` the updater polls |
| `RDP_UPDATE_TOKEN` | — | Optional bearer token for a private repo |
| `RDP_VIRTUAL_DISPLAY` | 1 | `0` serves the main display instead of creating virtual displays |
| `RDP_GFX_RESET` | 1 | `0` = legacy GFX: one fixed-size surface, no dynamic resolution, no multi-monitor |
| `RDP_HIDPI` | 1 | `0` forces a 1x (non-Retina) desktop, ignoring `RDP_SCALE` and the client scale |
| `RDP_SCALE` | unset (follow client) | Desktop scale in percent (>= 100); capped so the desktop stays at least 800x600 points |
| `RDP_PHYSICAL_DISPLAYS` | aside | While a virtual display is active: `aside` moves physical displays to the right of it, `mirror` mirrors them. Restored on disconnect |
| `RDP_NO_TCC_PROMPT` | 0 | `1` does not pop the Screen Recording / Accessibility prompts (headless and test runs) |
| `RDP_DISPLAY_MODE_HELPER` | the daemon itself | Path of the executable run as `--set-display-mode id w h pw` to change a virtual display's mode (tests) |

Security variables (`RDP_NLA`, `RDP_TLS_MIN`, `RDP_LEGACY_SECURITY`, `RDP_IDLE_TIMEOUT_MIN`, lockout, allow-lists, audit log) are documented in [security.md](security.md).

## Parity with Microsoft RDP

Windows host = Remote Desktop Services on Windows 10/11 or Server, with `mstsc` as client.

| Feature | Windows host behaviour | macos-rdp status | How to test |
|---|---|---|---|
| NLA / CredSSP | Offered and usually required | Done: NTLM via a SAM file learned at first logon (`RDP_NLA=auto\|off\|require`) | Connect with mstsc; see [security.md](security.md) |
| TLS minimum | TLS 1.2 on current builds | Done: 1.2 default, `RDP_TLS_MIN` to lower or raise | `openssl s_client -tls1_1 -connect host:3389` must fail; `-tls1_2` succeeds |
| Legacy RDP security | Disabled by default on current builds | Done: off by default, opt in with `RDP_LEGACY_SECURITY=1` (never with `RDP_NLA=require`) | mstsc with "security: RDP" fails by default, connects with the variable set |
| Dynamic resolution | Resize window, session resizes (DISP) | Done: DISP + GFX ResetGraphics; `RDP_GFX_RESET=0` falls back to a fixed size | Resize the mstsc window or toggle smart sizing; `tests/integration/run-display-test.sh` |
| Multi-monitor | Up to 16 monitors in RDP; mstsc `/multimon` | Done: up to 15, one virtual display per monitor, arranged like the client | mstsc `/multimon` with 2+ screens; `run-display-test.sh --virtual` |
| HiDPI / scale | Client scale factor applied to the session | Done: scale taken from the client; `RDP_HIDPI=0` or `RDP_SCALE=n` override | mstsc at 150% display scaling; check the Mac's resolution in Displays |
| Clipboard | Text, HTML, RTF, images, files | Done: `RDPClipboard` engine with delayed rendering; files up to >4 GB | Copy each type both ways; `tests/run.sh` covers the engine |
| Audio out | RDPSND to the client | Done | mstsc "play on this computer"; `RDP_AUDIO_LOCAL=0` for remote only |
| Audio in | Microphone redirection | Done, opt in: `RDP_AUDIO_INPUT=1` | mstsc "record from this computer" |
| Drive redirection | RDPDR, client drives appear in the session | Done: RDPDR through a WebDAV bridge; `RDP_RDPDR_ENABLED=0` disables | mstsc Local Resources > Drives |
| Frame-ack flow control | Server paces frames on client acks | In progress | Watch the verbose log under a throttled link |
| Adaptive bitrate | Bitrate follows measured bandwidth and RTT | In progress | Throttle the link (Network Link Conditioner) and watch quality |
| Reconnect | Auto-reconnect after a network blip, session kept | Not implemented: a dropped connection starts a new session | Drop Wi-Fi briefly (section 10.3) |
| Idle timeout | Session limits from policy | Done: `RDP_IDLE_TIMEOUT_MIN`, default off | Set it to 1, leave the session idle |
| Lockout | Account lockout policy | Done: per IP and user, `RDP_LOCKOUT_*` | Five bad passwords, then connect; see [security.md](security.md) |
| Audit log | Security event log (4624/4625) | Done: `~/Library/Logs/macos-rdp-connections.log` | Connect and disconnect, read the log |
| Auto-update | Windows Update | Done: Developer-ID-signed, strictly newer `vX.Y.Z` releases only; `RDP_UPDATE_ENABLED=0` disables | Section 7 |

## Running the tests

Unit tests (no display or network changes; the clipboard tests use a private pasteboard):

```bash
RDP_DEPS_DIR=/path/to/deps tests/run.sh   # default $ROOT/build/deps; needs $RDP_DEPS_DIR/freerdp-install/include
```

Integration (headless `rdp_probe` client against a loopback, no-auth test daemon on port 33899, `RDP_TEST_PORT` to change):

```bash
tests/integration/run-display-test.sh            # serves the main display; nothing on screen changes
tests/integration/run-display-test.sh --virtual  # real virtual displays; expects 2 monitors
```

`--virtual` temporarily moves the physical displays aside and restores them afterwards, so the screen flickers and windows may jump; do not run it while someone is working on the Mac. Variables: `RDP_PROBE_ARGS` adds client options (word-split, e.g. `RDP_PROBE_ARGS=/sec:rdp`), `RDP_TEST_LOG_LEVEL` sets the daemon log level (default `verbose`), `RDP_TEST_BIN` the binary, `RDP_TEST_LOG` the log path.

### Known issues / in progress
1. **Drive mounting needs hardware test** — WebDAV bridge is built; test by connecting mstsc with Drives enabled.
2. **Image clipboard** — PNG support is wired (0xC004), but needs verification against real mstsc.
3. **Stability soak** — §10 scenarios not run yet.
4. **Multi-monitor per-display** — span mode works (one big virtual display); per-display virtual displays not built.
5. **Printer/USB redirection** — out of scope for personal use.
6. **Upstream FreeRDP PRs** — 1 PERF + 2 MEDIUM fixes ready to file (commands in docs/security-audit-2026-06-02.md).
