#import "display/VirtualDisplay.h"
#import <CoreGraphics/CoreGraphics.h>
#import <unistd.h>
#import <spawn.h>
#import <signal.h>
#import <sys/wait.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <pthread.h>
#define RDP_LOG_COMPONENT "display"
#include "logging/RDPLog.h"

/* Pixel budget fixed at creation. Mode changes within it happen in place (same
 * displayID, no flicker of the arrangement); beyond it the display is recreated.
 * 8K covers a HiDPI 4K desktop, so ordinary resizes never recreate. */
static const uint32_t kMaxPixelsWide = 7680;
static const uint32_t kMaxPixelsHigh = 4320;
static const uint32_t kVendorID = 0x5244500u;   /* "RDP" */

@interface VirtualDisplay ()
@property (nonatomic, assign) uint32_t serial;
@property (nonatomic, assign) CGDirectDisplayID did;
@property (nonatomic, assign) uint32_t w, h, ptsW, ptsH;
@property (nonatomic, assign) uint32_t maxW, maxH;
@property (nonatomic, assign) BOOL retina, virt;
/* CGVirtualDisplay and its private listener thread keep using the descriptor,
 * mode and settings after applySettings: returns, so all of them are retained
 * for the display's lifetime (releasing them early was a use-after-free). */
@property (nonatomic, strong) id vdObject;
@property (nonatomic, strong) id vdDescriptor;
@property (nonatomic, strong) id vdMode;
@property (nonatomic, strong) id vdSettings;
@end

@implementation VirtualDisplay

+ (void)prepareOnMainThread {
    if (!pthread_main_np()) rdp_error("prepareOnMainThread called off the main thread");
    /* The window-server connection is created lazily by whichever thread needs
     * it first, and its notification port is serviced on that thread's run loop.
     * Create it here (private, looked up so its absence only costs this). */
    typedef int (*ConnFn)(void);
    ConnFn conn = (ConnFn)dlsym(RTLD_DEFAULT, "CGSMainConnectionID");
    if (!conn) conn = (ConnFn)dlsym(RTLD_DEFAULT, "SLSMainConnectionID");
    if (conn) (void)conn();
    else rdp_error("no window-server connection symbol — display changes may be seen late");
    (void)CGMainDisplayID();
}

/* ── Explicit mode switch, out of process ─────────────────────────────────
 * applySettings: replaces the display's mode list, but macOS keeps the
 * display's remembered resolution whenever it is still offered — and it
 * offers smaller same-aspect modes it generates from ours — so e.g. 1280x720 ->
 * 1600x900 silently stays at 1280x720. The display-mode APIs that would select
 * the mode return nothing for a virtual display inside the process that owns
 * it, but work from any other process (both measured). So the daemon runs
 * itself as a helper: `--set-display-mode <id> <ptsW> <ptsH> <pixelsW>`. */
+ (int)runSetModeHelperWithArgc:(int)argc argv:(char **)argv {
    if (argc < 4) return 2;
    CGDirectDisplayID did = (CGDirectDisplayID)strtoul(argv[0], NULL, 10);
    size_t w = strtoul(argv[1], NULL, 10), h = strtoul(argv[2], NULL, 10);
    size_t pw = strtoul(argv[3], NULL, 10);
    NSDictionary *opts = @{ (__bridge NSString *)kCGDisplayShowDuplicateLowResolutionModes: @YES };
    CFArrayRef all = CGDisplayCopyAllDisplayModes(did, (__bridge CFDictionaryRef)opts);
    int rc = 1;
    for (CFIndex i = 0; all && i < CFArrayGetCount(all); i++) {
        CGDisplayModeRef m = (CGDisplayModeRef)CFArrayGetValueAtIndex(all, i);
        if (CGDisplayModeGetWidth(m) != w || CGDisplayModeGetHeight(m) != h ||
            CGDisplayModeGetPixelWidth(m) != pw) continue;
        CGDisplayConfigRef cfg = NULL;
        if (CGBeginDisplayConfiguration(&cfg) == kCGErrorSuccess) {
            CGConfigureDisplayWithDisplayMode(cfg, did, m, NULL);
            rc = CGCompleteDisplayConfiguration(cfg, kCGConfigureForSession) == kCGErrorSuccess ? 0 : 1;
        }
        break;
    }
    if (all) CFRelease(all);
    return rc;
}

static BOOL set_mode_via_helper(CGDirectDisplayID did, uint32_t w, uint32_t h, uint32_t pw) {
    char path[PATH_MAX];
    uint32_t size = sizeof path;
    const char *override = getenv("RDP_DISPLAY_MODE_HELPER");   /* tests */
    if (override && *override) strlcpy(path, override, sizeof path);
    else if (_NSGetExecutablePath(path, &size) != 0) return NO;
    char a[4][16];
    snprintf(a[0], 16, "%u", did); snprintf(a[1], 16, "%u", w);
    snprintf(a[2], 16, "%u", h);   snprintf(a[3], 16, "%u", pw);
    char *args[] = { path, "--set-display-mode", a[0], a[1], a[2], a[3], NULL };
    extern char **environ;
    pid_t pid;
    if (posix_spawn(&pid, path, NULL, NULL, args, environ) != 0) return NO;
    int status = 0;
    for (int i = 0; i < 60; i++) {                     /* <= 3 s */
        if (waitpid(pid, &status, WNOHANG) == pid)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        usleep(50000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return NO;
}

- (instancetype)initWithSerial:(uint32_t)serial {
    if ((self = [super init])) _serial = serial ?: 1;
    return self;
}

- (CGDirectDisplayID)displayID { return _did; }
- (uint32_t)width      { return _w; }
- (uint32_t)height     { return _h; }
- (uint32_t)pointsWide { return _ptsW; }
- (uint32_t)pointsHigh { return _ptsH; }
- (BOOL)hiDPI          { return _retina; }
- (BOOL)isVirtual      { return _virt; }

+ (void)pointsForWidth:(uint32_t)width height:(uint32_t)height
          scalePercent:(uint32_t)scale
                 outW:(uint32_t *)outW outH:(uint32_t *)outH
              outHiDPI:(BOOL *)outHiDPI {
    const char *hd = getenv("RDP_HIDPI");
    const char *sc = getenv("RDP_SCALE");
    if (sc && atoi(sc) >= 100) scale = (uint32_t)atoi(sc);
    if (hd && strcmp(hd, "0") == 0) scale = 100;
    /* A tiny Mac desktop is unusable (menu bar, dialogs); cap the scale so the
     * desktop stays at least 800x600 points. */
    uint32_t maxScale = MIN(width * 100 / 800, height * 100 / 600);
    if (scale > maxScale) scale = MAX(100u, maxScale);
    if (scale <= 100) {
        *outW = width; *outH = height; *outHiDPI = NO;
        return;
    }
    *outW = (uint32_t)lround((double)width  * 100.0 / scale);
    *outH = (uint32_t)lround((double)height * 100.0 / scale);
    *outHiDPI = YES;
}

- (BOOL)configureWidth:(uint32_t)width height:(uint32_t)height
          scalePercent:(uint32_t)scalePercent
       physicalWidthMm:(uint32_t)mmW
      physicalHeightMm:(uint32_t)mmH {
    uint32_t pw, ph; BOOL retina;
    [VirtualDisplay pointsForWidth:width height:height scalePercent:scalePercent
                              outW:&pw outH:&ph outHiDPI:&retina];
    uint32_t backW = retina ? pw * 2 : pw, backH = retina ? ph * 2 : ph;

    if (_virt && _vdObject && backW <= _maxW && backH <= _maxH) {
        if (pw == _ptsW && ph == _ptsH && retina == _retina) {
            _w = width; _h = height;          /* capture size only */
            return YES;
        }
        if ([self applyModeWidth:pw height:ph hiDPI:retina]) {
            _w = width; _h = height; _ptsW = pw; _ptsH = ph; _retina = retina;
            [self settleModeWidth:pw height:ph];
            rdp_info("display %u resized in place: %ux%u px -> %ux%u pt%s",
                     _did, width, height, pw, ph, retina ? " (HiDPI)" : "");
            return YES;
        }
        rdp_error("display %u: in-place mode change failed — recreating", _did);
    }

    [self destroy];
    _w = width; _h = height; _ptsW = pw; _ptsH = ph; _retina = retina;
    const char *vdEnv = getenv("RDP_VIRTUAL_DISPLAY");   /* 0: always use the main display */
    if (!(vdEnv && strcmp(vdEnv, "0") == 0) &&
        [self createWithPhysicalWidthMm:mmW heightMm:mmH]) return YES;

    /* No virtual display: capture the main display, letterboxed into the
     * client size. Only meaningful for a single monitor; the session collapses
     * the layout accordingly. */
    _did = CGMainDisplayID();
    _virt = NO;
    CGRect b = CGDisplayBounds(_did);
    _ptsW = (uint32_t)b.size.width; _ptsH = (uint32_t)b.size.height;
    _retina = NO;
    if (vdEnv && strcmp(vdEnv, "0") == 0)
        rdp_verbose("RDP_VIRTUAL_DISPLAY=0: serving the main display %u", _did);
    else
        rdp_error("virtual display unavailable — capturing the main display %u "
                  "(letterboxed, single monitor)", _did);
    return _did != 0;
}

- (void)destroy {
    if (!_vdObject && !_virt) { _did = 0; return; }
    CGDirectDisplayID old = _did;
    /* Release in reverse dependency order: the display first (stops its listener
     * thread), then the settings/mode/descriptor it referenced. */
    _vdObject     = nil;
    _vdSettings   = nil;
    _vdMode       = nil;
    _vdDescriptor = nil;
    _did  = 0;
    _virt = NO;
    if (old) rdp_verbose("virtual display %u released", old);
}

#pragma mark - CGVirtualDisplay

- (BOOL)createWithPhysicalWidthMm:(uint32_t)mmW heightMm:(uint32_t)mmH {
    @try {
        Class descClass = NSClassFromString(@"CGVirtualDisplayDescriptor");
        Class dispClass = NSClassFromString(@"CGVirtualDisplay");
        Class modeClass = NSClassFromString(@"CGVirtualDisplayMode");
        Class setClass  = NSClassFromString(@"CGVirtualDisplaySettings");
        if (!descClass || !dispClass || !modeClass || !setClass) {
            rdp_error("CGVirtualDisplay classes unavailable on this macOS");
            return NO;
        }

        uint32_t backW = _retina ? _ptsW * 2 : _ptsW, backH = _retina ? _ptsH * 2 : _ptsH;
        _maxW = MAX(kMaxPixelsWide, MAX(backW, _w));
        _maxH = MAX(kMaxPixelsHigh, MAX(backH, _h));

        id desc = [[descClass alloc] init];
        [desc setValue:[NSString stringWithFormat:@"RDP Display %u", _serial] forKey:@"name"];
        [desc setValue:@(_maxW) forKey:@"maxPixelsWide"];
        [desc setValue:@(_maxH) forKey:@"maxPixelsHigh"];
        /* Physical size: ~96 dpi of the whole pixel budget, NOT the client's
         * monitor. macOS refuses (keeps the old mode) a 1x mode whose density
         * against this fixed size is too high — measured: a display created at
         * 1280x720 with a matching size would not switch to 1600x900 at 1x — so a
         * low density keeps every later resize possible. */
        (void)mmW; (void)mmH;
        CGSize mm = CGSizeMake(_maxW / 96.0 * 25.4, _maxH / 96.0 * 25.4);
        [desc setValue:[NSValue valueWithBytes:&mm objCType:@encode(CGSize)]
                forKey:@"sizeInMillimeters"];
        @try { [desc setValue:@(kVendorID) forKey:@"productID"]; } @catch (id e) {}
        @try { [desc setValue:@(kVendorID) forKey:@"vendorID"];  } @catch (id e) {}
        @try { [desc setValue:@(_serial)   forKey:@"serialNum"]; } @catch (id e) {}
        @try { [desc setValue:dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0)
                       forKey:@"queue"]; } @catch (id e) {}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id vd = [[dispClass alloc] performSelector:@selector(initWithDescriptor:)
                                         withObject:desc];
#pragma clang diagnostic pop
        if (!vd) { rdp_error("CGVirtualDisplay init failed"); return NO; }

        _vdObject = vd;
        _vdDescriptor = desc;
        if (![self applyModeWidth:_ptsW height:_ptsH hiDPI:_retina]) {
            rdp_error("CGVirtualDisplay applySettings failed");
            _vdObject = nil; _vdDescriptor = nil;
            return NO;
        }

        CGDirectDisplayID vdid = 0;
        @try { vdid = (CGDirectDisplayID)[[vd valueForKey:@"displayID"] unsignedIntValue]; }
        @catch (id e) {}
        if (!vdid) {
            rdp_error("virtual display has no displayID");
            [self destroy];
            return NO;
        }
        _did = vdid;
        _virt = YES;
        [self settleModeWidth:_ptsW height:_ptsH];
        rdp_info("virtual display %u created: %ux%u px client, %ux%u pt%s",
                 _did, _w, _h, _ptsW, _ptsH, _retina ? " (HiDPI 2x)" : "");
        return YES;
    } @catch (NSException *e) {
        rdp_error("virtual display creation threw (%s)", e.reason.UTF8String ?: "?");
        [self destroy];
        return NO;
    }
}

/* Builds a one-mode settings object and applies it. With hiDPI the mode size is
 * in points and macOS renders it at 2x (backing must fit maxPixels). */
- (BOOL)applyModeWidth:(uint32_t)pw height:(uint32_t)ph hiDPI:(BOOL)retina {
    Class modeClass = NSClassFromString(@"CGVirtualDisplayMode");
    Class setClass  = NSClassFromString(@"CGVirtualDisplaySettings");
    if (!_vdObject || !modeClass || !setClass) return NO;

    /* initWithWidth:height:refreshRate: is init-family: it initialises the
     * alloc'd receiver in place. Keep the single strong `m` (bridging the
     * invocation's return value as well over-released it). */
    SEL modeSel = @selector(initWithWidth:height:refreshRate:);
    if (![modeClass instancesRespondToSelector:modeSel]) return NO;
    id m = [modeClass alloc];
    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:
                            [m methodSignatureForSelector:modeSel]];
    inv.target = m; inv.selector = modeSel;
    unsigned int w = pw, h = ph; double rr = 60.0;
    [inv setArgument:&w atIndex:2];
    [inv setArgument:&h atIndex:3];
    [inv setArgument:&rr atIndex:4];
    [inv invoke];

    id settings = [[setClass alloc] init];
    [settings setValue:@[m] forKey:@"modes"];
    @try { [settings setValue:@(retina ? 1 : 0) forKey:@"hiDPI"]; } @catch (id e) {}

    BOOL applied = NO;
    SEL applySel = @selector(applySettings:);
    if (![_vdObject respondsToSelector:applySel]) return NO;
    NSInvocation *inv2 = [NSInvocation invocationWithMethodSignature:
                             [_vdObject methodSignatureForSelector:applySel]];
    inv2.target = _vdObject; inv2.selector = applySel;
    [inv2 setArgument:&settings atIndex:2];
    [inv2 retainArguments];
    [inv2 invoke];
    [inv2 getReturnValue:&applied];
    if (applied) { _vdMode = m; _vdSettings = settings; }
    return applied;
}

/* A new display or mode takes a moment to reach the window server. */
- (BOOL)waitForBoundsWidth:(uint32_t)pw height:(uint32_t)ph timeoutMs:(int)ms {
    for (int t = 0; t <= ms; t += 50) {
        CGRect b = CGDisplayBounds(_did);
        if ((uint32_t)b.size.width == pw && (uint32_t)b.size.height == ph) return YES;
        usleep(50000);
    }
    return NO;
}

/* Waits for the requested mode; if macOS kept a remembered one instead, selects
 * ours explicitly (see runSetModeHelperWithArgc). */
- (BOOL)settleModeWidth:(uint32_t)pw height:(uint32_t)ph {
    if (!_did) return NO;
    if ([self waitForBoundsWidth:pw height:ph timeoutMs:400]) return YES;
    uint32_t backW = _retina ? pw * 2 : pw;
    BOOL helped = set_mode_via_helper(_did, pw, ph, backW);
    if ([self waitForBoundsWidth:pw height:ph timeoutMs:2000]) {
        rdp_verbose("display %u: selected %ux%u pt explicitly", _did, pw, ph);
        return YES;
    }
    CGRect b = CGDisplayBounds(_did);
    rdp_error("display %u stuck at %gx%g pt (wanted %ux%u%s; helper %s)", _did,
              b.size.width, b.size.height, pw, ph, _retina ? " HiDPI" : "",
              helped ? "ran" : "failed");
    return NO;
}

@end
