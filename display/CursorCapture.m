#import "display/CursorCapture.h"
#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>
#include <time.h>

#define RDP_LOG_COMPONENT "cursor"
#include "logging/RDPLog.h"

/*
 * HEADLESS CURSOR CAPTURE (read before changing the timer or read path)
 * ---------------------------------------------------------------------
 * Capture runs on a dispatch_source timer on its own serial queue, never on
 * the main thread.
 *
 * The shape comes from +[NSCursor currentSystemCursor]: the cursor the window
 * server is showing, whichever app set it. It works from a background thread
 * in a process without NSApplication. Its image is resolution-independent
 * (a point size plus 1x/2x representations), so it is rendered at the remote
 * display's pixel scale.
 *
 * The private CGSGetGlobalCursorData used to supply the pixels. On current
 * macOS it still reports success, with the right size and hotspot, but hands
 * back an all-zero bitmap. That went out as a fully transparent pointer, so
 * mstsc drew no pointer at all. Only the private CGSCurrentCursorSeed is still
 * used, as a cheap hint that the shape changed.
 */

/* Bumps whenever the system cursor changes. Only a hint: the shape is also
 * re-read every kRecheckNanos in case the seed ever stops moving. */
extern int CGSCurrentCursorSeed(void);

/* ~12 Hz seed check: a shape change (I-beam, resize, hand) feels immediate. */
static const uint64_t kPollIntervalNanos = (uint64_t)(NSEC_PER_SEC / 12);
/* Forced re-read when the seed hasn't moved. The hash stops duplicate sends. */
static const uint64_t kRecheckNanos = (uint64_t)(NSEC_PER_SEC / 4);

@interface CursorCapture ()
@property (nonatomic, strong, nullable) dispatch_queue_t queue;
@property (nonatomic, strong, nullable) dispatch_source_t timer;
@property (nonatomic, assign) uint64_t lastHash;      /* 0 == nothing sent yet */
@property (nonatomic, assign) int      lastSeed;      /* CGS cursor seed last read */
@property (nonatomic, assign) BOOL     haveSeed;
@property (nonatomic, assign) uint64_t lastReadNanos;
@property (nonatomic, assign) BOOL     loggedFirst;
@property (nonatomic, assign) BOOL     loggedBlank;
@end

@implementation CursorCapture

- (instancetype)init {
    if ((self = [super init])) {
        _pixelsPerPoint = 1.0;
        _maxDimension = 96;
    }
    return self;
}

- (void)start {
    if (_timer) return;
    _lastHash = 0;
    _haveSeed = NO;
    _lastReadNanos = 0;

    _queue = dispatch_queue_create("com.macos-rdp.cursor-capture",
                                    DISPATCH_QUEUE_SERIAL);

    __weak typeof(self) weak = self;
    dispatch_source_t t =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    dispatch_source_set_timer(t,
                              dispatch_time(DISPATCH_TIME_NOW, 0),  /* fire promptly */
                              kPollIntervalNanos,
                              kPollIntervalNanos / 4);              /* leeway */
    dispatch_source_set_event_handler(t, ^{ [weak poll]; });
    _timer = t;
    dispatch_resume(t);

    rdp_verbose("cursor capture started (~12 Hz, NSCursor, %.0fx, max %u px)",
                self.pixelsPerPoint, self.maxDimension);
}

- (void)stop {
    dispatch_queue_t q = _queue;
    if (_timer) {
        dispatch_source_cancel(_timer);
        _timer = nil;
    }
    /* Cancelling doesn't wait for a poll already running. Wait for it, so the
     * handler can't run after the caller has freed what it sends to. */
    if (q) dispatch_sync(q, ^{});
    _queue = nil;
    rdp_verbose("cursor capture stopped");
}

/* FNV-1a over the bitmap bytes + dimensions + hotspot, to detect shape changes. */
static uint64_t fnv1a(const uint8_t *p, size_t n, uint64_t seed) {
    uint64_t h = seed ? seed : 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

/* True if any pixel is at least half opaque, the threshold the RDP AND mask
 * uses: anything less would reach the client as an invisible pointer. */
static bool has_visible_pixel(const uint8_t *bgra, uint32_t w, uint32_t h) {
    for (size_t i = 0, n = (size_t)w * h; i < n; i++)
        if (bgra[i * 4 + 3] >= 128) return true;
    return false;
}

- (void)poll {
    uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    int seed = CGSCurrentCursorSeed();
    if (_haveSeed && seed == _lastSeed && now - _lastReadNanos < kRecheckNanos) return;
    _lastSeed = seed;
    _haveSeed = YES;
    _lastReadNanos = now;

    uint32_t w = 0, h = 0;
    uint16_t hotX = 0, hotY = 0;
    uint8_t *bgra = [self copyCursorBGRA:&w height:&h hotX:&hotX hotY:&hotY];
    if (!bgra) return;

    uint64_t hash = fnv1a(bgra, (size_t)w * h * 4, 0);
    hash = fnv1a((const uint8_t *)&w, sizeof(w), hash);
    hash = fnv1a((const uint8_t *)&h, sizeof(h), hash);
    hash = fnv1a((const uint8_t *)&hotX, sizeof(hotX), hash);
    hash = fnv1a((const uint8_t *)&hotY, sizeof(hotY), hash);
    if (hash == _lastHash) { free(bgra); return; }
    _lastHash = hash;

    if (!has_visible_pixel(bgra, w, h)) {
        /* Keep the client's current pointer rather than hide it. */
        if (!_loggedBlank) {
            rdp_info("cursor image is blank (%ux%u) — not sent", w, h);
            _loggedBlank = YES;
        }
        free(bgra);
        return;
    }

    if (!_loggedFirst) {
        rdp_info("cursor: first shape %ux%u px, hotspot (%u,%u)", w, h, hotX, hotY);
        _loggedFirst = YES;
    } else {
        rdp_verbose("cursor shape changed: %ux%u hot=(%u,%u) — sending", w, h, hotX, hotY);
    }
    if (self.handler) self.handler(bgra, w, h, hotX, hotY);
    free(bgra);
}

/* Render the current system cursor as a freshly malloc'd 32-bit BGRA
 * premultiplied, top-down, tightly packed buffer (stride == w*4) at
 * pixelsPerPoint, scaled down to fit maxDimension. The hotspot is in the same
 * pixels. Returns NULL if there is no cursor to read. Caller frees. */
- (uint8_t *)copyCursorBGRA:(uint32_t *)outW height:(uint32_t *)outH
                       hotX:(uint16_t *)outHotX hotY:(uint16_t *)outHotY {
    @autoreleasepool {
        NSCursor *cursor = [NSCursor currentSystemCursor];
        NSImage *image = cursor.image;
        NSSize pt = image.size;
        if (!cursor || !image || pt.width < 1 || pt.height < 1) return NULL;

        double ppp = self.pixelsPerPoint;
        if (!(ppp > 0.0)) ppp = 1.0;              /* also rejects NaN */
        double tw = pt.width * ppp, th = pt.height * ppp;
        uint32_t maxDim = self.maxDimension ? self.maxDimension : 32;
        double longest = tw > th ? tw : th;
        if (longest > maxDim) {
            double s = (double)maxDim / longest;
            tw *= s;
            th *= s;
        }
        long lw = llround(tw), lh = llround(th);
        uint32_t w = (uint32_t)(lw < 1 ? 1 : lw);
        uint32_t h = (uint32_t)(lh < 1 ? 1 : lh);

        /* Let AppKit pick the representation closest to the target size. */
        NSRect proposed = NSMakeRect(0, 0, w, h);
        CGImageRef cg = [image CGImageForProposedRect:&proposed context:nil hints:nil];
        if (!cg) return NULL;

        size_t stride = (size_t)w * 4;
        uint8_t *buf = calloc(h, stride);
        if (!buf) return NULL;
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        /* PremultipliedFirst + ByteOrder32Little == B,G,R,A in memory. */
        CGContextRef ctx = cs ? CGBitmapContextCreate(
            buf, w, h, 8, stride, cs,
            kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little) : NULL;
        if (cs) CGColorSpaceRelease(cs);
        if (!ctx) { free(buf); return NULL; }
        /* No flip: a bitmap context keeps the top image row in the first
         * buffer row, which is the top-down order the RDP encoder expects. */
        CGContextSetInterpolationQuality(ctx, kCGInterpolationHigh);
        CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), cg);
        CGContextRelease(ctx);

        /* NSCursor's hotspot is in image points with a top-left origin. */
        NSPoint hs = cursor.hotSpot;
        long hx = llround(hs.x * (double)w / pt.width);
        long hy = llround(hs.y * (double)h / pt.height);
        if (hx < 0) hx = 0;
        if (hy < 0) hy = 0;
        if (hx >= (long)w) hx = (long)w - 1;
        if (hy >= (long)h) hy = (long)h - 1;
        *outW = w;
        *outH = h;
        *outHotX = (uint16_t)hx;
        *outHotY = (uint16_t)hy;
        return buf;
    }
}

@end
