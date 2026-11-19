#import "daemon/RDPSession.h"
#import "daemon/DisplayControl.h"
#import "daemon/Authenticator.h"
#import "protocol/RDPPeer.h"
#import "display/VirtualDisplay.h"
#import "display/DisplayArrangement.h"
#import "display/ScreenCapture.h"
#import "display/FrameEncoder.h"
#import "display/CursorCapture.h"
#import "input/InputInjector.h"
#import "input/ClipboardSync.h"
#import "audio/AudioCapture.h"
#import "audio/AudioRedirect.h"
#import <os/lock.h>
#import <unistd.h>
#include <freerdp/freerdp.h>
#define RDP_LOG_COMPONENT "session"
#include "logging/RDPLog.h"

/* H.264 bitrate for a 1080p monitor; other sizes scale with their area. */
static const uint32_t kBitrate1080pKbps = 8000;
/* A window drag sends a burst of layout requests; act once they settle. */
static const uint32_t kLayoutDebounceMs = 350;

static uint32_t bitrate_for(uint32_t w, uint32_t h) {
    double kbps = kBitrate1080pKbps * ((double)w * h) / (1920.0 * 1080.0);
    return (uint32_t)MIN(MAX(kbps, 3000.0), 25000.0);
}

/* One client monitor: the Mac display serving it, its capture and its encoder. */
@interface RDPMonitorPipeline : NSObject
@property (nonatomic, strong) VirtualDisplay *display;
@property (nonatomic, strong) ScreenCapture  *capture;
@property (nonatomic, strong) FrameEncoder   *encoder;
@end
@implementation RDPMonitorPipeline
@end

@interface RDPSession () {
    /* Guards _pipelines for the keyframe callback, which runs on encoder and
     * run-loop threads; the session queue is the only writer. */
    os_unfair_lock _pipeLock;
    NSArray<RDPMonitorPipeline *> *_pipelines;
    RDPMonitorLayout _layout;          /* what the client is being served */
}
@property (nonatomic, assign) int fd;
@property (nonatomic, assign) RDPSessionState sessionState;
@property (nonatomic, strong) NSString *address;
@property (nonatomic, assign) freerdp_peer *peer;
@property (nonatomic, strong) DisplayArrangement *arrangement;
@property (nonatomic, strong) DisplayControl  *displayControl;
@property (nonatomic, strong) InputInjector   *injector;
@property (nonatomic, strong) ClipboardSync   *clipboard;
@property (nonatomic, strong) AudioCapture    *audio;
@property (nonatomic, strong) CursorCapture   *cursor;
@property (nonatomic, strong) dispatch_queue_t sessionQueue;
/* Signaled exactly once when teardown completes; lets the takeover path wait
 * for this session's display to be released without touching the main queue. */
@property (nonatomic, strong) dispatch_semaphore_t teardownSem;
/* Set once this session has authenticated + become the active session, so we
 * skip re-authenticating / re-activating on a subsequent Activate (mstsc may
 * re-activate on a resize). Guarded by the serial session queue. */
@property (nonatomic, assign) BOOL activated;
@end

@implementation RDPSession

- (instancetype)initWithFileDescriptor:(int)fd clientAddress:(NSString *)address {
    if ((self = [super init])) {
        _fd             = fd;
        _address        = [address copy];
        _sessionState   = RDPSessionStateConnecting;
        _sessionQueue   = dispatch_queue_create("com.macosrdp.session",
                                                DISPATCH_QUEUE_SERIAL);
        _teardownSem    = dispatch_semaphore_create(0);
        _pipeLock       = OS_UNFAIR_LOCK_INIT;
        _pipelines      = @[];
    }
    return self;
}

- (NSArray<RDPMonitorPipeline *> *)pipelineSnapshot {
    os_unfair_lock_lock(&_pipeLock);
    NSArray<RDPMonitorPipeline *> *p = _pipelines;
    os_unfair_lock_unlock(&_pipeLock);
    return p;
}

- (void)publishPipelines:(NSArray<RDPMonitorPipeline *> *)pipelines {
    NSArray<RDPMonitorPipeline *> *copy = [pipelines copy], *old;
    os_unfair_lock_lock(&_pipeLock);
    old = _pipelines;
    _pipelines = copy;
    os_unfair_lock_unlock(&_pipeLock);
    (void)old;   /* the previous pipelines are released at scope exit, unlocked */
}

- (int)clientFd             { return _fd; }
- (RDPSessionState)state    { return _sessionState; }
- (NSString *)clientAddress { return _address; }

- (void)start {
    rdp_info("starting session for %s", _address.UTF8String);
    dispatch_async(_sessionQueue, ^{ [self setupAndRun]; });
}

- (void)setupAndRun {
    rdp_verbose("creating RDP peer for fd=%d", _fd);
    RDPPeerCallbacks cb = {
        .onKeyboard  = rdp_on_keyboard,
        .onUnicodeKeyboard = rdp_on_unicode_keyboard,
        .onMouse     = rdp_on_mouse,
        .onMouseEx   = rdp_on_mouse_ex,
        .onSynchronize = rdp_on_synchronize,
        .onClipboard = rdp_on_clipboard,
        .onReady     = rdp_on_ready,
        .onKeyframeRequest = rdp_on_keyframe_request,
        .userdata    = (__bridge void *)self,
    };

    _peer = rdp_peer_create(_fd, &cb);
    if (!_peer) {
        rdp_error("rdp_peer_create failed for %s", _address.UTF8String);
        [self endWithError:[NSError errorWithDomain:@"RDPError" code:1
                            userInfo:@{NSLocalizedDescriptionKey: @"peer_create failed"}]];
        return;
    }

    _sessionState = RDPSessionStateNegotiating;
    rdp_verbose("RDP negotiation started with %s", _address.UTF8String);

    /* Negotiation watchdog: if the client doesn't complete RDP activation within
     * kNegotiationTimeoutSecs, drop the connection. Without this, a half-open or
     * stalled TLS handshake holds the peer for FreeRDP's full 2-minute read timeout,
     * making every reconnect attempt appear dead to the user. */
    static const NSTimeInterval kNegotiationTimeoutSecs = 20.0;
    NSDate *negoDeadline = [NSDate dateWithTimeIntervalSinceNow:kNegotiationTimeoutSecs];

    uint32_t lastAudioRate = 0;
    while (_sessionState != RDPSessionStateDisconnecting &&
           _sessionState != RDPSessionStateDisconnected) {
        if (!rdp_peer_run_once(_peer)) {
            rdp_verbose("peer loop ended for %s", _address.UTF8String);
            break;
        }
        /* Abort if still negotiating past the deadline. */
        if (_sessionState == RDPSessionStateNegotiating &&
            [[NSDate date] compare:negoDeadline] == NSOrderedDescending) {
            rdp_info("negotiation timeout (%gs) for %s — dropping stale connection",
                     kNegotiationTimeoutSecs, _address.UTF8String);
            break;
        }
        /* The client resized its window or changed monitors (MS-RDPEDISP). */
        if (_sessionState == RDPSessionStateActive) {
            RDPMonitorLayout req;
            if (rdp_peer_take_pending_layout(_peer, &req, kLayoutDebounceMs)) {
                rdp_info("client requested a new layout: %u monitor(s), desktop %ux%u",
                         req.count, req.desktopWidth, req.desktopHeight);
                [self applyLayout:&req];
            }
        }
        /* rdpsnd format negotiation completes asynchronously (Activated callback)
         * AFTER audio capture starts. The client plays our PCM at the rate IT
         * selected — rdpsnd does not resample — so the tap must be resampled to
         * that exact rate or the audio is pitch-shifted. Poll the negotiated rate
         * and push it to AudioCapture once known/changed. Cheap; the setter
         * no-ops when unchanged. */
        if (_audio) {
            uint32_t rate = rdp_peer_get_audio_rate(_peer);
            if (rate && rate != lastAudioRate) {
                _audio.outputSampleRate = rate;
                rdp_info("audio playback rate negotiated: %u Hz — "
                         "tap resampled to match (no pitch shift)", (unsigned)rate);
                lastAudioRate = rate;
            }
        }
    }

    [self teardown];
}

static void rdp_on_ready(void *ud, uint32_t w, uint32_t h, uint32_t depth) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_info("client activated: %ux%u @%ubpp", w, h, depth);
    /* Called from peer_activate INSIDE the peer loop, which already runs on the
     * serial sessionQueue. dispatch_async back onto that same queue would starve
     * this behind the blocking loop — it would only run after the loop exits and
     * teardown has freed _peer (use-after-free crash), and media would never be
     * set up during a live session. Run it inline: the peer is alive here. */
    [self activateSession];
}

static void rdp_on_keyboard(void *ud, uint16_t flags, uint16_t code) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("key flags=0x%04x code=0x%02x", flags, code);
    [self.injector injectKeyEvent:flags scanCode:code];
}

static void rdp_on_unicode_keyboard(void *ud, uint16_t flags, uint16_t code) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("unicode key flags=0x%04x code=U+%04X", flags, code);
    [self.injector injectUnicodeKeyEvent:flags code:code];
}

static void rdp_on_mouse(void *ud, uint16_t flags, uint16_t x, uint16_t y) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("mouse flags=0x%04x x=%u y=%u", flags, x, y);
    if (flags & (RDP_PTR_WHEEL | RDP_PTR_HWHEEL))
        [self.injector injectMouseWheelEvent:flags x:x y:y];
    else
        [self.injector injectMouseEvent:flags x:x y:y];
}

static void rdp_on_mouse_ex(void *ud, uint16_t flags, uint16_t x, uint16_t y) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("mouse_ex flags=0x%04x x=%u y=%u", flags, x, y);
    [self.injector injectMouseExEvent:flags x:x y:y];
}

static void rdp_on_synchronize(void *ud, uint32_t flags) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("sync flags=0x%x", flags);
    [self.injector synchronizeLockKeys:flags];
}

static void rdp_on_clipboard(void *ud, const uint8_t *data, size_t len,
                              uint32_t format) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_verbose("clipboard from client: format=0x%08x len=%zu", format, len);
    [self.clipboard receiveFromClient:data length:len format:format];
}

/* Runs with xportLock held, on the run loop or an encoder thread: only flags. */
static void rdp_on_keyframe_request(void *ud, int32_t monitorIndex) {
    RDPSession *self = (__bridge RDPSession *)ud;
    NSArray<RDPMonitorPipeline *> *pipes = [self pipelineSnapshot];
    rdp_debug("keyframe requested for monitor %d", monitorIndex);
    if (monitorIndex < 0) {
        for (RDPMonitorPipeline *p in pipes) [p.encoder forceKeyframe];
    } else if ((NSUInteger)monitorIndex < pipes.count) {
        [pipes[(NSUInteger)monitorIndex].encoder forceKeyframe];
    }
}

- (void)activateSession {
    /* mstsc can re-activate (e.g. on a client-side resize). We only authenticate
     * and bring the display up once — re-entry after we're active is a no-op. */
    if (_activated || _sessionState == RDPSessionStateActive) {
        rdp_verbose("re-activation ignored (session already active) for %s",
                    _address.UTF8String);
        return;
    }
    if (![self authenticateClient]) return;
    if (![self claimActiveSession]) return;
    [self startMedia];
}

/* Validate the client's credentials. Returns NO (and marks the session
 * Disconnecting) when the client must be rejected. */
- (BOOL)authenticateClient {
    /* ── Authenticate BEFORE creating any virtual display ─────────────────────
     * Credentials arrived in the RDP logon (peer_activate captured them). Validate
     * against the local macOS account. Fail-closed: bad/missing creds → tear the
     * connection down. This runs inline on the serial session queue (inside the
     * peer loop), so a synchronous check is safe. NEVER log the password. */
    const char *cuser = NULL, *cpass = NULL, *cdomain = NULL;
    rdp_peer_get_credentials(_peer, &cuser, &cpass, &cdomain);
    NSString *user   = cuser   ? [NSString stringWithUTF8String:cuser]   : nil;
    NSString *pass   = cpass   ? [NSString stringWithUTF8String:cpass]   : nil;
    NSString *domain = cdomain ? [NSString stringWithUTF8String:cdomain] : nil;

    if (![Authenticator validateUsername:user password:pass domain:domain]) {
        rdp_error("authentication FAILED for %s (user='%s') — rejecting connection",
                  _address.UTF8String, user.length ? user.UTF8String : "(none)");
        _sessionState = RDPSessionStateDisconnecting;
        return NO;  /* peer loop sees Disconnecting and exits → teardown, no display */
    }
    rdp_info("authentication OK for %s (user='%s')",
             _address.UTF8String, user.length ? user.UTF8String : "(none)");
    return YES;
}

/* Become the single active session, superseding any other. Returns NO (and
 * marks the session Disconnecting) if activation was refused. */
- (BOOL)claimActiveSession {
    /* ── Become the single active session (takeover) ──────────────────────────
     * Ask the server to make us active. It signals any currently-active session
     * to disconnect and BLOCKS here until that old session has released its
     * virtual display, so we never have two virtual displays / two main displays
     * fighting. If it returns NO we were superseded (or the server is stopping)
     * and must abort. */
    if ([self.delegate respondsToSelector:@selector(sessionDidAuthenticateAndRequestActivation:)]) {
        if (![self.delegate sessionDidAuthenticateAndRequestActivation:self]) {
            rdp_info("activation refused for %s — aborting session", _address.UTF8String);
            _sessionState = RDPSessionStateDisconnecting;
            return NO;
        }
    }
    _activated = YES;
    return YES;
}

/* Bring up the displays, capture, encoders, input, clipboard, audio and cursor
 * streaming for an authenticated, active session. */
- (void)startMedia {
    RDPMonitorLayout layout;
    rdp_peer_get_client_layout(_peer, &layout);
    rdp_info("client layout: %u monitor(s), desktop %ux%u, for %s", layout.count,
             layout.desktopWidth, layout.desktopHeight, _address.UTF8String);

    _arrangement = [[DisplayArrangement alloc] init];   /* remembers physical displays */
    _injector = [[InputInjector alloc] initWithDisplayID:CGMainDisplayID()
                                             sourceWidth:layout.desktopWidth
                                            sourceHeight:layout.desktopHeight];
    if (![self applyLayout:&layout]) {
        rdp_error("no display could be set up for %s — disconnecting", _address.UTF8String);
        _sessionState = RDPSessionStateDisconnecting;
        return;
    }

    /* Wake the Mac + keep it awake for the whole session (replaces caffeinate),
     * and privacy-dim the BUILT-IN panel (brightness -> 0) so a bystander can't
     * watch the remote session. The session's virtual displays are never dimmed.
     * RDP_SHARED_MODE=1 skips dimming. */
    _displayControl = [[DisplayControl alloc]
        initWithVirtualDisplayID:[self primaryDisplayID]];
    [_displayControl start];

    __weak typeof(self) weak = self;
    _clipboard = [[ClipboardSync alloc] init];
    _clipboard.sendToClientBlock = ^(const uint8_t *data, size_t len, uint32_t fmt) {
        rdp_verbose("sending clipboard to client: format=0x%08x len=%zu", fmt, len);
        rdp_peer_send_clipboard(weak.peer, data, len, fmt);
    };
    [_clipboard start];

    /* Only start audio capture if the client actually declared audio support.
       Saves a CoreAudio IO proc registration for clients that don't want audio. */
    BOOL clientWantsAudio = freerdp_settings_get_bool(
        _peer->context->settings, FreeRDP_AudioPlayback);
    if (clientWantsAudio) {
        _audio = [[AudioCapture alloc] init];
        _audio.captureBlock = ^(const int16_t *samples, uint32_t frameCount) {
            /* No per-buffer logging here: buffers arrive ~100x/sec and flooded the
             * log. AudioCapture itself logs a throttled frame total. */
            rdp_peer_send_audio(weak.peer, samples, frameCount);
        };
        NSError *audioErr = nil;
        if (![_audio startWithError:&audioErr]) {
            rdp_verbose("audio capture unavailable: %s",
                        audioErr.localizedDescription.UTF8String);
        } else {
            rdp_verbose("audio capture started");
        }
    } else {
        rdp_verbose("client did not request audio — capture skipped");
    }

    _sessionState = RDPSessionStateActive;
    rdp_info("session active for %s", _address.UTF8String);

    /* Advertise a client-side system cursor first so the very first pointer the
     * client gets is valid (and the cursor is smooth, decoupled from the video
     * frame rate) before the real shapes start streaming. */
    rdp_peer_send_default_cursor(_peer);

    /* Stream the REAL Mac cursor shapes (I-beam, resize, hand, …) as RDP
     * color-pointer PDUs. Default ON; opt OUT with RDP_CURSOR_SHAPES=0, which
     * falls back to the client-side SYSPTR_DEFAULT arrow advertised above.
     *
     * This was default-off while the pointer was encoded 32bpp/alpha, which
     * mstsc renders invisible. rdp_peer_send_cursor_shape now emits a 24bpp BGR
     * XOR + 1bpp AND mask, which mstsc renders reliably, so the gate no longer
     * has anything to protect against. */
    const char *curShapes = getenv("RDP_CURSOR_SHAPES");
    if (!curShapes || strcmp(curShapes, "0") != 0) {
        _cursor = [[CursorCapture alloc] init];
        _cursor.handler = ^(const uint8_t *bgra, uint32_t cw, uint32_t ch,
                            uint16_t hotX, uint16_t hotY) {
            rdp_peer_send_cursor_shape(weak.peer, bgra, cw, ch, hotX, hotY);
        };
        [_cursor start];
        rdp_info("cursor-shape streaming ON (default) — real Mac cursor shapes, "
                 "24bpp; set RDP_CURSOR_SHAPES=0 to fall back to the system arrow");
    } else {
        rdp_info("cursor-shape streaming OFF (RDP_CURSOR_SHAPES=0) — client draws "
                 "the system arrow");
    }
}

- (CGDirectDisplayID)primaryDisplayID {
    NSArray<RDPMonitorPipeline *> *pipes = [self pipelineSnapshot];
    for (NSUInteger i = 0; i < pipes.count && i < _layout.count; i++)
        if (_layout.monitors[i].primary) return pipes[i].display.displayID;
    return pipes.firstObject ? pipes.firstObject.display.displayID : CGMainDisplayID();
}

/* Serves `requested` to the client: one Mac display per monitor (resized in
 * place where possible), arranged like the client's monitors, then ResetGraphics
 * + new surfaces on the client, then fresh capture + encoder per monitor.
 * Session queue only. Returns NO if no display at all could be provided. */
- (BOOL)applyLayout:(const RDPMonitorLayout *)requested {
    RDPMonitorLayout layout = *requested;
    if (!rdp_layout_normalize(&layout)) return NO;
    NSArray<RDPMonitorPipeline *> *old = [self pipelineSnapshot];

    /* Quiesce: no new frames, then flush the encoders (their last frames still
     * belong to the current surfaces, which exist until rdp_peer_set_layout). */
    for (RDPMonitorPipeline *p in old) [p.capture stop];
    for (RDPMonitorPipeline *p in old) [p.encoder stop];

    NSMutableArray<VirtualDisplay *> *displays = [NSMutableArray array];
    BOOL allVirtual = YES;
    for (uint32_t i = 0; i < layout.count; i++) {
        const RDPMonitor *m = &layout.monitors[i];
        VirtualDisplay *vd = i < old.count ? old[i].display
                                           : [[VirtualDisplay alloc] initWithSerial:i + 1];
        [vd configureWidth:m->width height:m->height scalePercent:m->scale
           physicalWidthMm:m->physicalWidthMm physicalHeightMm:m->physicalHeightMm];
        [displays addObject:vd];
        if (!vd.isVirtual) { allVirtual = NO; break; }
    }
    for (NSUInteger i = layout.count; i < old.count; i++) [old[i].display destroy];

    if (!allVirtual) {
        /* No virtual displays on this Mac: serve the client's primary monitor
         * only, from the main display (letterboxed). */
        for (VirtualDisplay *vd in displays) [vd destroy];
        RDPMonitor primary = layout.monitors[0];
        for (uint32_t i = 0; i < layout.count; i++)
            if (layout.monitors[i].primary) primary = layout.monitors[i];
        primary.x = primary.y = 0;
        layout.count = 1;
        layout.monitors[0] = primary;
        rdp_layout_normalize(&layout);
        VirtualDisplay *fallback = displays.firstObject ?: [[VirtualDisplay alloc] initWithSerial:1];
        if (![fallback configureWidth:primary.width height:primary.height scalePercent:100
                      physicalWidthMm:0 physicalHeightMm:0])
            return NO;
        displays = [NSMutableArray arrayWithObject:fallback];
        allVirtual = fallback.isVirtual;
    }

    NSMutableArray<NSNumber *> *ids = [NSMutableArray array];
    for (VirtualDisplay *vd in displays) [ids addObject:@(vd.displayID)];
    if (allVirtual) [_arrangement arrangeDisplays:ids layout:&layout];

    /* Client side: ResetGraphics + one surface per monitor. Frames must carry the
     * returned epoch; anything encoded for the previous layout is dropped. */
    uint32_t epoch = rdp_peer_set_layout(_peer, &layout);
    _layout = layout;

    __weak typeof(self) weak = self;
    NSMutableArray<RDPMonitorPipeline *> *pipes = [NSMutableArray array];
    for (uint32_t i = 0; i < layout.count; i++) {
        const RDPMonitor *m = &layout.monitors[i];
        uint32_t fw = m->width, fh = m->height, idx = i;
        RDPMonitorPipeline *p = [RDPMonitorPipeline new];
        p.display = displays[i];

        p.encoder = [[FrameEncoder alloc] initWithWidth:fw height:fh
                                                bitrate:bitrate_for(fw, fh)];
        p.encoder.outputHandler = ^(const uint8_t *data, size_t len, BOOL keyFrame,
                                    uint16_t dx, uint16_t dy, uint16_t dw, uint16_t dh) {
            freerdp_peer *peer = weak.peer;
            if (peer)
                rdp_peer_send_h264_frame(peer, epoch, idx, data, len, fw, fh,
                                         keyFrame ? true : false, dx, dy, dw, dh);
        };
        [p.encoder start];

        p.capture = [[ScreenCapture alloc] initWithDisplayID:p.display.displayID];
        __weak FrameEncoder *wenc = p.encoder;
        p.capture.frameHandler = ^(IOSurfaceRef surface, uint32_t cw, uint32_t ch,
                                   CGRect dirty) {
            (void)cw; (void)ch;
            uint16_t dx = (uint16_t)MAX(0.0, dirty.origin.x);
            uint16_t dy = (uint16_t)MAX(0.0, dirty.origin.y);
            uint16_t dw = (uint16_t)MIN((double)fw, dirty.size.width);
            uint16_t dh = (uint16_t)MIN((double)fh, dirty.size.height);
            [wenc encodeFrame:surface dirtyX:dx dirtyY:dy dirtyW:dw dirtyH:dh];
        };
        if (![p.capture startWithWidth:fw height:fh])
            rdp_error("screen capture FAILED on display %u — monitor %u will be black "
                      "until Screen Recording is granted", p.display.displayID, i);
        [pipes addObject:p];
        rdp_info("monitor %u: %ux%u px at (%d,%d), %u kbps, display %u (%ux%u pt%s)%s",
                 i, fw, fh, m->x, m->y, bitrate_for(fw, fh), p.display.displayID,
                 p.display.pointsWide, p.display.pointsHigh,
                 p.display.hiDPI ? " HiDPI" : "", m->primary ? " primary" : "");
    }
    [self publishPipelines:pipes];

    if (allVirtual) {
        CGRect rects[RDP_MAX_MONITORS];
        CGDirectDisplayID dids[RDP_MAX_MONITORS];
        for (uint32_t i = 0; i < layout.count; i++) {
            const RDPMonitor *m = &layout.monitors[i];
            rects[i] = CGRectMake(m->x, m->y, m->width, m->height);
            dids[i]  = displays[i].displayID;
        }
        [_injector setMonitorRects:rects displays:dids count:layout.count];
    } else {
        [_injector setSingleDisplay:displays[0].displayID
                        sourceWidth:layout.desktopWidth
                       sourceHeight:layout.desktopHeight];
    }
    return YES;
}

- (void)disconnect {
    rdp_info("disconnecting %s", _address.UTF8String);
    /* The peer loop polls this state every <=50ms and exits when it sees
     * Disconnecting, after which teardown runs on the session queue. */
    _sessionState = RDPSessionStateDisconnecting;
}

- (BOOL)waitForTeardown:(NSTimeInterval)timeout {
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW,
                                             (int64_t)(timeout * NSEC_PER_SEC));
    long rc = dispatch_semaphore_wait(_teardownSem, deadline);
    if (rc != 0)
        rdp_error("timed out after %.0fs waiting for %s to release its display",
                  timeout, _address.UTF8String);
    return rc == 0;
}

- (void)teardown {
    rdp_verbose("tearing down session for %s", _address.UTF8String);
    [_injector releaseAll];   /* never leave Cmd or a mouse button held */
    [_cursor stop];
    NSArray<RDPMonitorPipeline *> *pipes = [self pipelineSnapshot];
    for (RDPMonitorPipeline *p in pipes) [p.capture stop];
    for (RDPMonitorPipeline *p in pipes) [p.encoder stop];
    [_audio stop];
    [_clipboard stop];
    [_displayControl stop];
    NSMutableArray<NSNumber *> *virtualIDs = [NSMutableArray array];
    for (RDPMonitorPipeline *p in pipes) {
        if (p.display.isVirtual) [virtualIDs addObject:@(p.display.displayID)];
        [p.display destroy];
    }
    [self publishPipelines:@[]];
    [_arrangement restoreAfterRemoving:virtualIDs];

    if (_peer) { rdp_peer_destroy(_peer); _peer = NULL; }
    if (_fd >= 0) { close(_fd); _fd = -1; }

    _sessionState = RDPSessionStateDisconnected;
    rdp_info("session torn down for %s", _address.UTF8String);

    /* Signal anyone waiting on takeover that our display is now released. Done
     * here (on the session queue, after destroy) rather than via the main-queue
     * delegate hop below — the main run loop does not run in this daemon, so the
     * semaphore is the reliable cross-thread completion signal. */
    dispatch_semaphore_signal(_teardownSem);

    [self endWithError:nil];
}

- (void)endWithError:(NSError *)error {
    /* Notify on a background queue, NOT the main queue: this daemon's main thread
     * blocks in kevent() with no running main run loop, so a main-queue async
     * would never fire and the server would never remove this session. */
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        [self.delegate sessionDidEnd:self error:error];
    });
}

@end
