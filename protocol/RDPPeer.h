#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#include "protocol/RDPFlowControl.h"
#include "audio/ImaAdpcm.h"
#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/server/rdpgfx.h>
#include <freerdp/server/disp.h>
#include <freerdp/server/cliprdr.h>
#include <freerdp/server/rdpsnd.h>
#include <freerdp/channels/wtsvc.h>
#include <winpr/wtsapi.h>
#include "protocol/RDPClipboard.h"

typedef struct rdp_peer_context RDPPeerContext;
typedef struct RDPWebDAVServer  RDPWebDAVServer;

typedef void (*RDPPeerInputCallback)(void *userdata, uint16_t flags, uint16_t code);
typedef void (*RDPPeerMouseCallback)(void *userdata, uint16_t flags, uint16_t x, uint16_t y);
typedef void (*RDPPeerReadyCallback)(void *userdata, uint32_t width, uint32_t height, uint32_t colorDepth);
/* monitorIndex: the monitor whose encoder must emit an IDR, or -1 for all. */
typedef void (*RDPPeerKeyframeCallback)(void *userdata, int32_t monitorIndex);

/* ── Monitor layout ─────────────────────────────────────────────────────────
 * The client's monitors in DESKTOP coordinates: client pixels, origin at the
 * top-left of the bounding box of all monitors (so x/y are never negative).
 * That is the space RDP pointer events and GFX MapSurfaceToOutput use. Each
 * monitor gets its own Mac virtual display, capture, encoder and GFX surface. */
/* MS-RDPEGFX allows 16 monitors in ResetGraphics, but FreeRDP's serializer
 * rejects monitorCount >= 16, so 15 is the real ceiling. */
#define RDP_MAX_MONITORS 15

typedef struct {
    int32_t  x, y;           /* top-left in desktop coordinates */
    uint32_t width, height;  /* client pixels (what we capture and encode) */
    uint32_t scale;          /* desktop scale factor, percent (100 = 1:1) */
    uint32_t physicalWidthMm, physicalHeightMm; /* 0 if the client didn't say */
    bool     primary;
} RDPMonitor;

typedef struct {
    uint32_t   count;
    uint32_t   desktopWidth, desktopHeight;   /* bounding box */
    RDPMonitor monitors[RDP_MAX_MONITORS];
} RDPMonitorLayout;

/* Normalizes a layout in place: clamps sizes to what GFX/RDPEDISP allow, makes
 * widths even, ensures exactly one primary (first monitor if none), shifts the
 * coordinates so the bounding box starts at (0,0), and fills desktopWidth/Height.
 * Returns false if the layout is unusable (no monitors, or too many). */
bool rdp_layout_normalize(RDPMonitorLayout *layout);
bool rdp_layout_equal(const RDPMonitorLayout *a, const RDPMonitorLayout *b);
/* Keyboard lock-key sync; flags use KBD_SYNC_* bits (caps 0x4). */
typedef void (*RDPPeerSyncCallback)(void *userdata, uint32_t flags);

/* Called from FreeRDP's Logon hook right after security negotiation. `nla` is
 * true when CredSSP completed, in which case user/domain/password are the
 * cleartext credentials the client delegated (FreeRDP stores them in the
 * settings, which the later Client Info PDU overwrites, so they are only valid
 * here). `selectedProtocol` is the negotiated PROTOCOL_* mask. The pointers are
 * owned by FreeRDP and must be copied, never retained or logged. Return false to
 * reject the client; the session then tears the connection down. */
typedef bool (*RDPPeerLogonCallback)(void *userdata, bool nla,
                                     uint32_t selectedProtocol,
                                     const char *user, const char *domain,
                                     const char *password);

/* Per-connection transport-security configuration (NLA). `nlaMode`: 0 = TLS
 * only, 1 = offer NLA and TLS, 2 = NLA only. `samPath` is WinPR's SAM file used
 * by the NTLM server to look up NT hashes; copied during rdp_peer_create. */
typedef struct {
    int         nlaMode;
    const char *samPath;
} RDPPeerSecurity;

/* IRP async completion callback type.  Invoked on the peer run-loop thread
 * when a PAKID_CORE_DEVICE_IOCOMPLETION arrives for the matching CompletionId.
 * ioStatus — NT status code (0 = success).
 * payload/payloadLen — bytes following the 12-byte completion header (may be 0).
 * userdata — opaque pointer supplied to rdpdr_alloc_request. */
typedef void (*RDPIrpCallback)(uint32_t ioStatus,
                               const uint8_t *payload, uint32_t payloadLen,
                               void *userdata);

typedef struct {
    RDPPeerInputCallback     onKeyboard;
    /* MS-RDPBCGR 2.2.8.1.1.3.1.1.2 — code is a UTF-16 code unit, not a scancode.
     * Sent by clients for characters the scancode layout can't express. */
    RDPPeerInputCallback     onUnicodeKeyboard;
    RDPPeerMouseCallback     onMouse;
    RDPPeerMouseCallback     onMouseEx;
    RDPPeerSyncCallback      onSynchronize;
    RDPPeerReadyCallback     onReady;
    /* Asks an encoder (or all, monitorIndex -1) to emit an IDR keyframe ASAP.
     * Invoked when GFX surfaces are (re)created, when output resumes after a
     * minimize, or when a delta arrives before that surface's first keyframe.
     * Called with xportLock held, from the run loop or an encoder thread: it must
     * only set a flag, never block or call back into the peer. */
    RDPPeerKeyframeCallback  onKeyframeRequest;
    RDPPeerLogonCallback     onLogon;
    RDPPeerSecurity          security;
    void *userdata;
} RDPPeerCallbacks;

/* Maximum number of redirected drives we track simultaneously. */
#define RDPDR_MAX_DEVICES 8

struct rdp_peer_context {
    rdpContext          base;       /* MUST be first */
    RDPPeerCallbacks    callbacks;
    HANDLE              vcm;        /* WTSOpenServerA handle — owns gfx/cliprdr/rdpsnd */
    RdpgfxServerContext *gfx;
    /* MS-RDPEDISP DISPLAY_CONTROL DVC: the client asks for a new monitor layout
     * when its window is resized, it goes full screen, or monitors change.
     * FreeRDP runs this channel on its OWN thread, so the callback only records
     * the request (pendingLayout, under xportLock); the session loop applies it
     * after a short debounce. */
    DispServerContext   *disp;
    RdpsndServerContext  *rdpsnd;
    uint32_t             frameId;    /* monotonic GFX frame id for StartFrame/EndFrame */
    RDPFlowControl       fc;         /* GFX FrameAcknowledge window + adaptive bitrate */
    /* Current layout and one GFX surface per monitor (surfaceCount == 0 until
     * both a layout is set and the client's GFX caps arrived). Frames tagged
     * with an older layoutEpoch are dropped. All guarded by xportLock. */
    RDPMonitorLayout     layout;
    bool                 layoutSet;          /* session supplied a layout */
    uint32_t             layoutEpoch;        /* bumped by rdp_peer_set_layout */
    bool                 legacyGfx;          /* RDP_GFX_RESET=0: no ResetGraphics,
                                                one surface, DISP not offered */
    uint16_t             nextSurfaceId;
    uint16_t             surfaceIds[RDP_MAX_MONITORS];
    uint32_t             surfaceCount;
    bool                 surfaceKeyframeSent[RDP_MAX_MONITORS];
    bool                 surfaceKeyframeRequested[RDP_MAX_MONITORS];
    /* DISP caps go out once the client confirms the DVC is open (MS-RDPEDYC:
     * no data before the Create Response); then it may send layouts. */
    uint32_t             dispChannelId;
    bool                 dispCapsPending;
    /* Client-requested layout (DISP) awaiting the session loop. */
    RDPMonitorLayout     pendingLayout;
    bool                 pendingLayoutValid;
    uint64_t             pendingLayoutTimeMs;
    /* Serializes ALL writes to the single RDP transport (TLS socket). FreeRDP is
     * NOT thread-safe for concurrent sends: the encoder thread (GFX SurfaceCommand),
     * the run-loop thread (CheckFileDescriptor + VCM pump + GFX handle_messages),
     * the clipboard poll thread (cliprdr ServerFormatList) and the audio thread
     * (rdpsnd SendSamples) all write the same socket. Unsynchronized, their bytes
     * interleave and the GFX bytestream desyncs -> mstsc decodes a "packet of type
     * Unknown" and drops the session (Reason 3334). Every transport write MUST hold
     * this lock. RECURSIVE so a run-loop callback (e.g. cliprdr) can re-enter while
     * the loop already holds it. */
    pthread_mutex_t      xportLock;
    bool                 gfxOpened;  /* GFX DVC Open() succeeded (drdynvc ready) */
    bool                 dispOpened; /* DISP DVC Open() succeeded (drdynvc ready) */
    bool                 gfxReady;   /* client sent GFX caps; surfaces mapped */
    bool                 outputSuppressed; /* client minimized: Suppress Output PDU -> pause sends */
    bool                 activated;
    bool                 channelsStarted; /* static-channel hellos sent (first activation) */
    bool                 logonInfoSent;   /* Save Session Info logon notification sent */
    bool                 gfxOutputReady;  /* first ResetGraphics + surfaces sent */
    bool                 audioReady; /* set by rdpsnd Activated callback */
    uint32_t             audioSendFailures; /* rdpsnd sends rejected, for the log */
    /* Wave Confirms from the client: one per audio PDU it has played. Bumped on
     * the rdpsnd thread (atomic builtins); the rest is audio-thread only. */
    uint32_t             audioConfirms;
    uint64_t             audioFirstSendMs;  /* 0 until the first successful send */
    bool                 audioConfirmChecked;
    /* Negotiated IMA ADPCM (RDP_AUDIO_CODEC=ima): our own encoder, blocks sent
     * with SendSamples2. Used only from the audio thread after audioReady. */
    bool                 imaActive;
    ImaEncoder           ima;
    uint8_t             *imaBuf;
    size_t               imaCap;
    /* Clipboard (MS-RDPECLIP): the whole protocol engine, state and threading rules
     * live in protocol/RDPClipboard.c. Created in peer_post_connect, pumped from
     * rdp_peer_run_once (under xportLock), destroyed in context_free. The host
     * (input/ClipboardSync.m) attaches via rdp_peer_get_clipboard(). */
    RDPClipboard        *clip;
    /* RDPDR (MS-RDPEFS) drive-redirection static VC. Non-NULL only when
     * RDP_RDPDR_ENABLED=1. Raw WTS channel; protocol state machine runs in C. */
    HANDLE               rdpdrChannel;   /* WTSVirtualChannelOpen handle */
    HANDLE               rdpdrEvent;     /* WTSVirtualEventHandle for the run loop */
    int                  rdpdrState;     /* RdpdrHandshakeState enum (int for C compat) */
    bool                 rdpdrHeard;     /* the client has sent any rdpdr PDU */
    bool                 rdpdrLoggedOnSent; /* Server User Logged On sent */
    int                  rdpdrHelloTries;/* SERVER_ANNOUNCE sends so far */
    uint64_t             rdpdrHelloMs;   /* when the last one went out */
    uint16_t             rdpdrClientId;  /* client-assigned id from ANNOUNCE_REPLY */
    uint32_t             rdpdrNextReqId; /* monotonic IRP request id counter */
    /* Pending IRP request table — up to RDPDR_MAX_PENDING in-flight requests.
     * Each slot carries an optional async callback + userdata so callers on
     * other threads (WebDAV handlers) can be woken when the completion arrives. */
#define RDPDR_MAX_PENDING 64
    struct {
        uint32_t       requestId;  /* 0 = slot free */
        uint32_t       deviceId;
        char           path[64];   /* requested path, for logging */
        RDPIrpCallback callback;   /* NULL = fire-and-forget */
        void          *userdata;
    } rdpdrPending[RDPDR_MAX_PENDING];
    /* WebDAV servers — one per redirected drive (RDPDR_MAX_DEVICES slots).
     * Created in DEVICE_LIST_ANNOUNCE; destroyed in context_free. */
    RDPWebDAVServer     *webdavServers[RDPDR_MAX_DEVICES];
    /* AUDIO_INPUT (MS-RDPEAI) mic-redirection channel. Non-NULL only when
     * RDP_AUDIO_INPUT=1. Stored as void* so this C header stays ObjC-free;
     * RDPPeer.c casts it through __bridge when handing it to AudioInput.m.
     * ARC ownership is maintained by the ObjC object itself; the void* here is
     * a non-owning reference — lifetime is managed by context_free calling
     * rdp_peer_close_audio_input(), which releases the ObjC object. */
    void                *audioInput;   /* __strong RDPAudioInput * under ARC */
};

freerdp_peer *rdp_peer_create(int fd, const RDPPeerCallbacks *callbacks);
void          rdp_peer_destroy(freerdp_peer *peer);
bool          rdp_peer_run_once(freerdp_peer *peer);

/* Read the logon credentials the client supplied in the RDP info packet (valid
 * once the peer has activated — i.e. inside/after the onReady callback). The
 * out-pointers receive pointers OWNED by the FreeRDP peer settings (do not free;
 * valid for the peer's lifetime). Any out value may be NULL if the client sent
 * none. Pass NULL for fields you don't need. NEVER log the returned password. */
void rdp_peer_get_credentials(freerdp_peer *peer,
                              const char **username,
                              const char **password,
                              const char **domain);

/* ── Display layout (multi-monitor, dynamic resolution) ─────────────────────
 *
 * The session serves one GFX surface per client monitor. The flow is:
 *   activation   rdp_peer_get_client_layout() -> session builds displays ->
 *                rdp_peer_set_layout()
 *   resize/      the client sends an MS-RDPEDISP layout; the session polls
 *   monitor      rdp_peer_take_pending_layout(), rebuilds its displays and calls
 *   change       rdp_peer_set_layout() again.
 * rdp_peer_set_layout() sends ResetGraphics + CreateSurface/MapSurfaceToOutput
 * per monitor (or defers that until the client's GFX caps arrive) and returns a
 * new layout epoch. Frames carry the epoch they were encoded for; frames from an
 * older layout reference surfaces that no longer exist and are dropped. */

/* The layout the client announced at connect: its monitor list (Client Monitor
 * Data, plus Monitor Ex for per-monitor scale/physical size) or, for a single-
 * monitor client, DesktopWidth x DesktopHeight at its desktop scale factor.
 * Normalized. Valid once activated. */
void     rdp_peer_get_client_layout(freerdp_peer *peer, RDPMonitorLayout *out);

/* Installs the layout the session now serves (normalized copy) and returns its
 * epoch. Thread-safe (takes xportLock). */
uint32_t rdp_peer_set_layout(freerdp_peer *peer, const RDPMonitorLayout *layout);

/* Takes the client's latest layout request (MS-RDPEDISP) once no newer request
 * has arrived for debounceMs (a window drag sends a burst). Returns false when
 * there is none, it is too fresh, or it equals the layout being served. */
bool     rdp_peer_take_pending_layout(freerdp_peer *peer, RDPMonitorLayout *out,
                                      uint32_t debounceMs);

/*
 * Send an AVC420 (H.264) frame for one monitor's surface.
 *
 * epoch is the value rdp_peer_set_layout() returned for the layout this frame
 * was encoded for; a stale epoch or an out-of-range monitorIndex drops the frame
 * (returns true: not an error). width/height are the encoded picture size, which
 * must equal the monitor's.
 *
 * The H.264 bitstream always encodes the full surface, so the surface-command
 * destination is the full surface. The damage region goes in the AVC420
 * metablock regionRects: keyframe -> full surface, interframe -> dirty rect
 * (surface pixels; ignored for keyframes). A valid quantQualityVals array is
 * always supplied - FreeRDP's serializer dereferences it unconditionally.
 */
bool rdp_peer_send_h264_frame(freerdp_peer *peer,
                               uint32_t epoch, uint32_t monitorIndex,
                               const uint8_t *data, size_t len,
                               uint32_t width, uint32_t height,
                               bool isKeyFrame,
                               uint16_t dirtyX, uint16_t dirtyY,
                               uint16_t dirtyW, uint16_t dirtyH);

/* Flow control (see RDPFlowControl.h). can_send is called by capture BEFORE
 * encoding; false = skip this frame. Safe from any thread, takes no xportLock. */
bool rdp_peer_gfx_can_send(freerdp_peer *peer);
/* Rate step, every ~500 ms. Returns the bitrate scale in permille of the target. */
uint32_t rdp_peer_gfx_rate_step(freerdp_peer *peer, bool *changed,
                                uint32_t *maxInFlight, double *latencyMs, uint32_t *skips);

bool rdp_peer_send_bitmap(freerdp_peer *peer,
                           const uint8_t *bgra, uint32_t x, uint32_t y,
                           uint32_t width, uint32_t height);

bool rdp_peer_send_audio(freerdp_peer *peer,
                          const int16_t *samples, uint32_t frame_count);

/* Negotiated client audio playback sample rate in Hz, or 0 if audio is not yet
 * activated (rdpsnd Activated callback has not fired, or no compatible format).
 *
 * rdpsnd does NOT resample: the client plays the PCM bytes we send at the rate
 * of the format IT selected. AudioCapture polls this to drive its resampler so
 * the captured/sent rate equals the client's playback rate (otherwise the audio
 * is pitch-shifted). Safe to call from any thread. */
uint32_t rdp_peer_get_audio_rate(freerdp_peer *peer);

/* The peer's clipboard engine (see protocol/RDPClipboard.h), RETAINED: balance
 * with rdp_clip_release(). NULL if the clipboard channel did not open. */
RDPClipboard *rdp_peer_get_clipboard(freerdp_peer *peer);

/* Tell the client to render the default system pointer CLIENT-SIDE, so the cursor
 * tracks the local mouse smoothly instead of being tied to the (30fps) video. */
void rdp_peer_send_default_cursor(freerdp_peer *peer);

/* Largest pointer edge in pixels the client accepts: 96 with the RDP
 * large-pointer capability, else 32. Valid after activation. */
uint32_t rdp_peer_max_pointer_dim(freerdp_peer *peer);

/* Tell the client the user is logged on (Save Session Info, logon notification),
 * as a Windows host does after logon. Once per session; holds xportLock. */
void rdp_peer_send_logon_info(freerdp_peer *peer);

/*
 * RDPDR (drive redirection) channel support.
 *
 * rdp_peer_open_rdpdr  — open the "rdpdr" WTS static virtual channel. Called
 *   from peer_post_connect; SERVER_ANNOUNCE goes out at activation and is
 *   resent while the client stays silent. Returns true on success.
 *
 * rdp_peer_pump_rdpdr  — drain inbound rdpdr data and advance the MS-RDPEFS
 *   state machine. Call from the peer run loop whenever the rdpdr channel event
 *   is signaled, under xportLock.
 *
 * Both are no-ops when RDP_RDPDR_ENABLED != "1".
 */
bool rdp_peer_open_rdpdr(freerdp_peer *peer);
void rdp_peer_pump_rdpdr(freerdp_peer *peer);

/*
 * IRP send helpers — each sends one MS-RDPEFS IRP to the Windows client and
 * registers an optional async callback that fires (on the peer run-loop thread)
 * when the matching IOCOMPLETION arrives.  cb may be NULL for fire-and-forget.
 * All helpers MUST be called under xportLock.
 */

/* IRP_MJ_CREATE — open a file or directory on the client drive.
 * desiredAccess: specific rights, e.g. FILE_GENERIC_READ=0x00120089,
 *   FILE_GENERIC_WRITE=0x00120116, FILE_LIST_DIRECTORY=0x1, DELETE=0x10000, each with
 *   SYNCHRONIZE=0x100000. Not GENERIC_READ/GENERIC_WRITE: mstsc refused a read on a
 *   file opened with GENERIC_READ.
 * createDisposition: FILE_OPEN=1, FILE_CREATE=2, FILE_OPEN_IF=3, FILE_OVERWRITE_IF=5
 * createOptions: FILE_DIRECTORY_FILE=0x1, FILE_NON_DIRECTORY_FILE=0x40
 * path: UTF-8 relative to the drive root, "" for the root, else "\\a\\b". */
bool rdpdr_send_create_req(RDPPeerContext *ctx, uint32_t deviceId,
                           const char *path,
                           uint32_t desiredAccess,
                           uint32_t createDisposition,
                           uint32_t createOptions,
                           RDPIrpCallback cb, void *userdata);

/* IRP_MJ_CLOSE — close a file handle returned by CREATE. */
bool rdpdr_send_close_req(RDPPeerContext *ctx, uint32_t deviceId,
                          uint32_t fileId,
                          RDPIrpCallback cb, void *userdata);

/* IRP_MJ_READ — read bytes from an open file. */
bool rdpdr_send_read_req(RDPPeerContext *ctx, uint32_t deviceId,
                         uint32_t fileId, uint64_t offset, uint32_t length,
                         RDPIrpCallback cb, void *userdata);

/* IRP_MJ_WRITE — write bytes to an open file. */
bool rdpdr_send_write_req(RDPPeerContext *ctx, uint32_t deviceId,
                          uint32_t fileId, uint64_t offset,
                          const uint8_t *data, uint32_t length,
                          RDPIrpCallback cb, void *userdata);

/* IRP_MJ_DIRECTORY_CONTROL / IRP_MN_QUERY_DIRECTORY — one directory entry
 * (FileFullDirectoryInformation) per call. The first call passes the pattern,
 * a path relative to the drive root ("\\*", "\\dir\\*" or an exact
 * "\\dir\\name"); each next call passes NULL, until STATUS_NO_MORE_FILES. */
bool rdpdr_send_query_dir_req(RDPPeerContext *ctx, uint32_t deviceId,
                              uint32_t fileId, const char *pattern,
                              RDPIrpCallback cb, void *userdata);

/* IRP_MJ_SET_INFORMATION (FileRenameInformation) — rename or move an open
 * file or directory to newPath (relative to the drive root, like CREATE). */
bool rdpdr_send_rename_req(RDPPeerContext *ctx, uint32_t deviceId,
                           uint32_t fileId, const char *newPath,
                           bool replaceIfExists,
                           RDPIrpCallback cb, void *userdata);

/* IRP_MJ_SET_INFORMATION (FileDispositionInformation) — mark file for deletion. */
bool rdpdr_send_delete_req(RDPPeerContext *ctx, uint32_t deviceId,
                           uint32_t fileId,
                           RDPIrpCallback cb, void *userdata);

/* Create Desktop placeholder folders for each redirected client drive and
 * register an NSFileProviderDomain (macOS 12+) for the drive.
 * Implemented in protocol/RDPDriveMount.m (ObjC/Foundation).
 * deviceId — the RDPDR device id from DEVICE_LIST_ANNOUNCE. */
void rdp_drive_mount_placeholder(const char *driveName, uint32_t deviceId);

/* Send the ACTUAL current cursor shape as an RDP color-pointer PDU so mstsc
 * renders the correct shape (I-beam, resize, hand, ...) client-side, lag-free.
 *
 * `bgra` is a 32-bit BGRA premultiplied, TOP-LEFT-origin, tightly packed
 * (stride == w*4) bitmap; w/h are in pixels (capped ~96; >96 uses the Large
 * pointer PDU). hotX/hotY are the hotspot in bitmap pixels. Internally builds a
 * bottom-up xor mask + a 1bpp AND mask from the alpha channel.
 *
 * Holds xportLock (transport write). No-op if the peer is not yet activated or
 * output is suppressed. Safe to call repeatedly; the caller should de-dupe
 * (only call when the shape actually changes). */
void rdp_peer_send_cursor_shape(freerdp_peer *peer,
                                const uint8_t *bgra, uint32_t w, uint32_t h,
                                uint16_t hotX, uint16_t hotY);
