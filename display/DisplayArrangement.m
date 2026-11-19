#import "display/DisplayArrangement.h"
#import <unistd.h>
#define RDP_LOG_COMPONENT "display"
#include "logging/RDPLog.h"

#define MAX_DISPLAYS 32

@implementation DisplayArrangement {
    CGDirectDisplayID _saved[MAX_DISPLAYS];
    CGPoint           _savedOrigin[MAX_DISPLAYS];
    uint32_t          _savedCount;
    BOOL              _mirrored;      /* we made physical displays mirror */
}

- (instancetype)init {
    if ((self = [super init])) {
        CGDirectDisplayID ids[MAX_DISPLAYS];
        uint32_t n = 0;
        if (CGGetActiveDisplayList(MAX_DISPLAYS, ids, &n) == kCGErrorSuccess) {
            for (uint32_t i = 0; i < n; i++) {
                if (CGDisplayMirrorsDisplay(ids[i]) != kCGNullDirectDisplay) continue;
                _saved[_savedCount] = ids[i];
                _savedOrigin[_savedCount] = CGDisplayBounds(ids[i]).origin;
                _savedCount++;
            }
        }
    }
    return self;
}

static BOOL contains_id(NSArray<NSNumber *> *ids, CGDirectDisplayID did) {
    for (NSNumber *n in ids) if (n.unsignedIntValue == did) return YES;
    return NO;
}

static BOOL near(int32_t a, int32_t b) { return a - b <= 2 && b - a <= 2; }

- (void)arrangeDisplays:(NSArray<NSNumber *> *)displayIDs
                 layout:(const RDPMonitorLayout *)layout {
    uint32_t n = MIN((uint32_t)displayIDs.count, layout->count);
    if (n == 0) return;

    /* Points per client pixel, per monitor (HiDPI monitors are < 1). */
    CGSize pts[RDP_MAX_MONITORS];
    double f[RDP_MAX_MONITORS];
    for (uint32_t i = 0; i < n; i++) {
        pts[i] = CGDisplayBounds(displayIDs[i].unsignedIntValue).size;
        f[i] = layout->monitors[i].width ? pts[i].width / layout->monitors[i].width : 1.0;
    }

    uint32_t primary = 0;
    for (uint32_t i = 0; i < n; i++) if (layout->monitors[i].primary) { primary = i; break; }

    /* Place the primary at the origin, then grow outward through shared edges so
     * adjacency survives differing scales. Monitors that touch nothing keep
     * their client offset (scaled by the primary); macOS snaps them to an edge. */
    CGPoint org[RDP_MAX_MONITORS];
    bool placed[RDP_MAX_MONITORS] = { false };
    org[primary] = CGPointZero;
    placed[primary] = true;
    for (bool progress = true; progress;) {
        progress = false;
        for (uint32_t j = 0; j < n; j++) {
            if (placed[j]) continue;
            const RDPMonitor *mj = &layout->monitors[j];
            for (uint32_t k = 0; k < n && !placed[j]; k++) {
                if (!placed[k]) continue;
                const RDPMonitor *mk = &layout->monitors[k];
                int32_t kr = mk->x + (int32_t)mk->width, kb = mk->y + (int32_t)mk->height;
                int32_t jr = mj->x + (int32_t)mj->width, jb = mj->y + (int32_t)mj->height;
                double offY = (mj->y - mk->y) * f[k], offX = (mj->x - mk->x) * f[k];
                if (near(mj->x, kr))      org[j] = CGPointMake(org[k].x + pts[k].width,  org[k].y + offY);
                else if (near(jr, mk->x)) org[j] = CGPointMake(org[k].x - pts[j].width,  org[k].y + offY);
                else if (near(mj->y, kb)) org[j] = CGPointMake(org[k].x + offX, org[k].y + pts[k].height);
                else if (near(jb, mk->y)) org[j] = CGPointMake(org[k].x + offX, org[k].y - pts[j].height);
                else continue;
                placed[j] = true;
                progress = true;
            }
        }
    }
    const RDPMonitor *mp = &layout->monitors[primary];
    double maxX = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (!placed[i])
            org[i] = CGPointMake((layout->monitors[i].x - mp->x) * f[primary],
                                 (layout->monitors[i].y - mp->y) * f[primary]);
        maxX = MAX(maxX, org[i].x + pts[i].width);
    }

    const char *pd = getenv("RDP_PHYSICAL_DISPLAYS");
    BOOL mirror = pd && strcasecmp(pd, "mirror") == 0;
    CGDirectDisplayID primaryID = displayIDs[primary].unsignedIntValue;

    /* Physical displays, as a group, go to the right of the virtual desktop. */
    double minPX = INFINITY, minPY = INFINITY;
    for (uint32_t i = 0; i < _savedCount; i++) {
        if (contains_id(displayIDs, _saved[i])) continue;
        minPX = MIN(minPX, _savedOrigin[i].x);
        minPY = MIN(minPY, _savedOrigin[i].y);
    }

    CGDisplayConfigRef cfg = NULL;
    if (CGBeginDisplayConfiguration(&cfg) != kCGErrorSuccess) {
        rdp_error("CGBeginDisplayConfiguration failed — displays left as macOS placed them");
        return;
    }
    for (uint32_t i = 0; i < n; i++)
        CGConfigureDisplayOrigin(cfg, displayIDs[i].unsignedIntValue,
                                 (int32_t)lround(org[i].x), (int32_t)lround(org[i].y));
    for (uint32_t i = 0; i < _savedCount; i++) {
        if (contains_id(displayIDs, _saved[i]) || !CGDisplayIsOnline(_saved[i])) continue;
        if (mirror)
            CGConfigureDisplayMirrorOfDisplay(cfg, _saved[i], primaryID);
        else
            CGConfigureDisplayOrigin(cfg, _saved[i],
                                     (int32_t)lround(maxX + _savedOrigin[i].x - minPX),
                                     (int32_t)lround(_savedOrigin[i].y - minPY));
    }
    CGError ce = CGCompleteDisplayConfiguration(cfg, kCGConfigureForSession);
    if (ce != kCGErrorSuccess) {
        rdp_error("display arrangement failed (%d)", ce);
        return;
    }
    if (mirror) _mirrored = YES;
    for (uint32_t i = 0; i < n; i++) {
        CGRect b = CGDisplayBounds(displayIDs[i].unsignedIntValue);
        rdp_info("monitor %u -> display %u at (%g,%g) %gx%g pt%s", i,
                 displayIDs[i].unsignedIntValue, b.origin.x, b.origin.y,
                 b.size.width, b.size.height, i == primary ? " (main)" : "");
    }
    if (_savedCount && !(_savedCount == 1 && contains_id(displayIDs, _saved[0])))
        rdp_info("physical displays %s", mirror ? "mirror the primary monitor"
                                                : "moved to the right of the session");
}

- (void)restoreAfterRemoving:(NSArray<NSNumber *> *)virtualIDs {
    for (int i = 0; i < 40; i++) {           /* <= 2 s for removal to land */
        BOOL anyOnline = NO;
        for (NSNumber *v in virtualIDs) if (CGDisplayIsOnline(v.unsignedIntValue)) anyOnline = YES;
        if (!anyOnline) break;
        usleep(50000);
    }
    CGDisplayConfigRef cfg = NULL;
    if (CGBeginDisplayConfiguration(&cfg) != kCGErrorSuccess) return;
    uint32_t restored = 0;
    for (uint32_t i = 0; i < _savedCount; i++) {
        if (contains_id(virtualIDs, _saved[i]) || !CGDisplayIsOnline(_saved[i])) continue;
        if (_mirrored) CGConfigureDisplayMirrorOfDisplay(cfg, _saved[i], kCGNullDirectDisplay);
        CGConfigureDisplayOrigin(cfg, _saved[i], (int32_t)_savedOrigin[i].x,
                                 (int32_t)_savedOrigin[i].y);
        restored++;
    }
    CGError ce = CGCompleteDisplayConfiguration(cfg, kCGConfigureForSession);
    if (restored)
        rdp_info("restored the arrangement of %u physical display(s) (rc=%d)", restored, ce);
}

@end
