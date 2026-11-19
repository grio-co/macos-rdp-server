#import "display/VirtualDisplay.h"
#import <CoreGraphics/CoreGraphics.h>
#import <unistd.h>
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
            [self waitForBoundsWidth:pw height:ph];
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
        /* Physical size from the client when it is plausible, else ~96 dpi of the
         * client's pixels. macOS uses it for the display's DPI, not for layout. */
        CGSize mm = (mmW >= 10 && mmW <= 10000 && mmH >= 10 && mmH <= 10000)
                        ? CGSizeMake(mmW, mmH)
                        : CGSizeMake(_w / 96.0 * 25.4, _h / 96.0 * 25.4);
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
        [self waitForBoundsWidth:_ptsW height:_ptsH];
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

/* A new display or mode takes a moment to reach the window server; capture and
 * arrangement must not run against the old geometry. Bounded wait. */
- (void)waitForBoundsWidth:(uint32_t)pw height:(uint32_t)ph {
    for (int i = 0; i < 40; i++) {
        if (_did) {
            CGRect b = CGDisplayBounds(_did);
            if ((uint32_t)b.size.width == pw && (uint32_t)b.size.height == ph) return;
        }
        usleep(50000);
    }
    CGRect b = CGDisplayBounds(_did);
    rdp_verbose("display %u: bounds %gx%g after 2s (wanted %ux%u pt)",
                _did, b.size.width, b.size.height, pw, ph);
}

@end
