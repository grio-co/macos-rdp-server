#import "daemon/DisplayControl.h"
#import <CoreGraphics/CoreGraphics.h>
#import <IOKit/pwr_mgt/IOPMLib.h>
#import <dlfcn.h>
#import <unistd.h>
#define RDP_LOG_COMPONENT "displayctl"
#include "logging/RDPLog.h"

/*
 * RUN-LOOP / THREADING NOTE (important — read before changing blanking strategy)
 * ----------------------------------------------------------------------------
 * main.m runs the MAIN run loop on the main thread for the daemon's whole life
 * (it also services the main dispatch queue); there is no NSApplication event
 * loop. The input monitor's CGEventTap lives on that main run loop. A dispatch
 * worker thread's run loop is never run and goes away with the thread, so a tap
 * put there never fired, and removing it at disconnect crashed the daemon before
 * the panel brightness was restored.
 *
 * start/stop run on the session queue while the tap callback runs on the main
 * thread, so every entry point takes @synchronized(self), and the tap is only
 * ever removed on the main thread.
 *
 * BLANKING STRATEGY — panel brightness, NOT display capture
 * ----------------------------------------------------------------------------
 * Privacy "blanking" here means dimming the BUILT-IN physical panel to black by
 * driving its backlight brightness to 0 via the private DisplayServices
 * framework. This is a pure side-channel to the panel hardware: it does NOT
 * change the display topology and does NOT trigger a WindowServer
 * reconfiguration, so the virtual/remote display keeps compositing normally and
 * the remote view is UNAFFECTED.
 *
 * This replaces the old CGDisplayCapture()+black-fill approach. Capturing a
 * display raised a privacy shield BUT the capture caused a WindowServer
 * reconfiguration that also stopped compositing to the virtual display, so the
 * remote went all-black. We must never do that again — there is no fallback to
 * CGDisplayCapture anywhere in this file.
 *
 * DisplayServices is a private framework. We resolve its symbols at runtime
 * with dlopen/dlsym (no hard link dependency); if the framework or symbols are
 * unavailable on this hardware we log clearly and fall back to NO blanking —
 * the remote keeps working and we never crash.
 *
 *   extern int DisplayServicesSetBrightness(CGDirectDisplayID, float);
 *   extern int DisplayServicesGetBrightness(CGDirectDisplayID, float *);
 *
 * AUTOMATIC BRIGHTNESS. While a panel is dimmed, its "Automatically adjust
 * brightness" setting is turned off (when it was on), so the room light can't
 * raise the dimmed panel. Undim puts the saved level back and then turns it on
 * again, so macOS goes back to following the room light instead of holding
 * the restored level as a manual setting. Optional: without these symbols
 * dimming works as before.
 *
 *   extern bool DisplayServicesHasAmbientLightCompensation(CGDirectDisplayID);
 *   extern int  DisplayServicesAmbientLightCompensationEnabled(CGDirectDisplayID, bool *);
 *   extern int  DisplayServicesEnableAmbientLightCompensation(CGDirectDisplayID, bool);
 *
 * macOS single-session constraint: macOS has ONE GUI login session. This is
 * privacy DIMMING of the local panel, not a true session lock — we can't show
 * the login window locally while the remote keeps the unlocked desktop.
 *
 * Input monitoring uses a CGEventTap on the main run loop (see above). NSEvent
 * global monitors are avoided: they need an NSApplication event loop.
 *
 * Everything here is best-effort: if dimming or the tap fails we log and keep
 * going. Remote video is the priority; we must never crash the session.
 */

/* DisplayServices private API signatures, resolved at runtime via dlsym. */
typedef int  (*DSSetBrightnessFn)(CGDirectDisplayID, float);
typedef int  (*DSGetBrightnessFn)(CGDirectDisplayID, float *);
/* Automatic brightness: System Settings › Displays › "Automatically adjust
 * brightness", which DisplayServices calls ambient light compensation. The
 * argument shapes were read from the framework's code: the getter stores a bool
 * through its pointer and returns 0, the setter takes the new value. */
typedef bool (*DSHasAutoBrightnessFn)(CGDirectDisplayID);
typedef int  (*DSGetAutoBrightnessFn)(CGDirectDisplayID, bool *);
typedef int  (*DSSetAutoBrightnessFn)(CGDirectDisplayID, bool);

#define DS_FRAMEWORK_PATH \
    "/System/Library/PrivateFrameworks/DisplayServices.framework/DisplayServices"

/* Below this the panel counts as dark; a restore never goes back to dark. */
static const float kDarkBrightness = 0.05f;
static const float kRestoreFloorBrightness = 0.5f;

/* While a panel is dimmed, what the dim changed is also kept on disk, so a run
 * that dies mid-session can't leave the Mac's own screen dark or on manual
 * brightness: the next start restores it (+restoreBrightnessLeftDimmed), and the
 * next dim comes back to the saved values rather than to the dark panel.
 *
 * Format: display id (string) -> { brightness: float, autoBrightness: bool },
 * where autoBrightness means "it was on and the dim turned it off". A bare
 * number (the brightness-only format of earlier builds) is still read. */
static NSString *saved_brightness_path(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@".macos-rdp/dimmed-brightness.plist"];
}

static NSDictionary *read_saved_brightness(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:saved_brightness_path()];
    return [d isKindOfClass:[NSDictionary class]] ? d : nil;
}

/* One saved entry; NO if it's missing or unreadable. */
static BOOL saved_entry(id value, float *brightness, BOOL *autoWasOn) {
    *autoWasOn = NO;
    if ([value isKindOfClass:[NSNumber class]]) {
        *brightness = [value floatValue];
        return YES;
    }
    if (![value isKindOfClass:[NSDictionary class]]) return NO;
    id b = value[@"brightness"], a = value[@"autoBrightness"];
    if (![b isKindOfClass:[NSNumber class]]) return NO;
    *brightness = [b floatValue];
    *autoWasOn = [a isKindOfClass:[NSNumber class]] && [a boolValue];
    return YES;
}

static void write_saved_brightness(NSDictionary<NSNumber *, NSNumber *> *saved,
                                   NSSet<NSNumber *> *autoPaused) {
    NSMutableDictionary<NSString *, NSDictionary *> *out = [NSMutableDictionary dictionary];
    for (NSNumber *did in saved)
        out[did.stringValue] = @{ @"brightness": saved[did],
                                  @"autoBrightness": @([autoPaused containsObject:did]) };
    NSString *path = saved_brightness_path();
    [[NSFileManager defaultManager] createDirectoryAtPath:path.stringByDeletingLastPathComponent
                              withIntermediateDirectories:YES attributes:nil error:NULL];
    if (![out writeToFile:path atomically:YES])
        rdp_error("could not save the original brightness to %s — if the daemon dies "
                  "during this session, raise the brightness and turn automatic "
                  "brightness back on by hand", path.UTF8String);
}

static void clear_saved_brightness(void) {
    [[NSFileManager defaultManager] removeItemAtPath:saved_brightness_path() error:NULL];
}

/* Turn automatic brightness back on and read it back. Run after the saved level
 * is restored, so macOS adjusts from there to the room light instead of keeping
 * the restored level as a manual setting. */
static BOOL resume_auto_brightness(DSSetAutoBrightnessFn set, DSGetAutoBrightnessFn get,
                                   CGDirectDisplayID did) {
    int r = set ? set(did, true) : -1;
    bool on = (r == 0);
    if (on && get) {
        bool now = false;
        if (get(did, &now) == 0) on = now;
    }
    if (on) {
        rdp_info("automatic brightness back on for display %u", did);
        return YES;
    }
    rdp_error("turning automatic brightness back on for display %u failed (%d%s) — "
              "the next start tries again", did, r, r == 0 ? ", it still reads off" : "");
    return NO;
}

/* The tap's refcon. The callback reaches the DisplayControl only through this
 * weak reference, so a callout already queued when the session ends finds nil
 * instead of a freed object. */
@interface RDPTapTarget : NSObject
@property (atomic, weak) DisplayControl *owner;
@property (atomic, assign) CFMachPortRef tap;   /* valid while the source is installed */
@end

@implementation RDPTapTarget
@end

@interface DisplayControl ()
@property (nonatomic, assign) CGDirectDisplayID virtualDisplayID;
@property (nonatomic, assign) BOOL started;
@property (nonatomic, assign) BOOL sharedMode;

/* Power management. */
@property (nonatomic, assign) IOPMAssertionID displaySleepAssertion;
@property (nonatomic, assign) IOPMAssertionID systemSleepAssertion;

/* DisplayServices brightness control, resolved lazily at runtime. */
@property (nonatomic, assign) void *displayServicesHandle;
@property (nonatomic, assign) DSSetBrightnessFn dsSetBrightness;
@property (nonatomic, assign) DSGetBrightnessFn dsGetBrightness;
/* Automatic brightness; all NULL when this macOS lacks them (dimming still works). */
@property (nonatomic, assign) DSHasAutoBrightnessFn dsHasAutoBrightness;
@property (nonatomic, assign) DSGetAutoBrightnessFn dsGetAutoBrightness;
@property (nonatomic, assign) DSSetAutoBrightnessFn dsSetAutoBrightness;

/* Blanking state: maps each dimmed built-in display id -> its saved brightness
 * (to restore), plus the dimmed displays whose automatic brightness the dim
 * turned off (to turn back on). Empty when nothing is dimmed. */
@property (nonatomic, assign) BOOL displaysDimmed;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSNumber *> *savedBrightness;
@property (nonatomic, strong) NSMutableSet<NSNumber *> *autoBrightnessPaused;

/* Input monitor (CGEventTap on the main run loop). */
@property (nonatomic, assign) CFMachPortRef eventTap;
@property (nonatomic, assign) CFRunLoopSourceRef eventTapSource;
@property (nonatomic, strong) RDPTapTarget *tapTarget;

- (void)handleLocalUserActivity;
@end

/* CGEventTap callback (main thread): any physical interaction by the desk user
 * un-dims. */
static CGEventRef rdp_event_tap_cb(CGEventTapProxy proxy, CGEventType type,
                                   CGEventRef event, void *ud) {
    (void)proxy;
    RDPTapTarget *target = (__bridge RDPTapTarget *)ud;
    if (type == kCGEventTapDisabledByTimeout ||
        type == kCGEventTapDisabledByUserInput) {
        /* The system can disable a tap that is too slow; re-enable it. */
        CFMachPortRef tap = target.tap;
        if (tap) CGEventTapEnable(tap, true);
        return event;
    }
    DisplayControl *owner = target.owner;   /* strong until this call returns */
    [owner handleLocalUserActivity];
    return event;   /* never swallow the user's real input */
}

@implementation DisplayControl

- (instancetype)initWithVirtualDisplayID:(CGDirectDisplayID)virtualDisplayID {
    if ((self = [super init])) {
        _virtualDisplayID      = virtualDisplayID;
        _displaySleepAssertion = kIOPMNullAssertionID;
        _systemSleepAssertion  = kIOPMNullAssertionID;
        _savedBrightness       = [NSMutableDictionary dictionary];
        _autoBrightnessPaused  = [NSMutableSet set];
        const char *shared     = getenv("RDP_SHARED_MODE");
        _sharedMode            = (shared && strcmp(shared, "1") == 0);
    }
    return self;
}

- (void)start {
    @synchronized (self) {
        if (_started) return;
        _started = YES;

        [self takePowerAssertions];

        if (_sharedMode) {
            rdp_info("RDP_SHARED_MODE=1 — privacy blanking SKIPPED (desk user and "
                     "remote user share the screen)");
            return;
        }

        /* Privacy DIMMING is the DEFAULT. We drive the built-in panel brightness
         * to 0 (a pure backlight change) so a bystander at the Mac can't watch the
         * remote session. This does NOT change the display topology, so the
         * virtual/remote display keeps compositing — the remote view is
         * unaffected. Set RDP_SHARED_MODE=1 to skip dimming entirely. If
         * brightness control is unavailable we fall back to NO dimming (never the
         * old capture path). */
        [self dimBuiltInDisplays];
        [self installInputMonitor];
    }
}

- (void)stop {
    @synchronized (self) {
        if (!_started) return;
        _started = NO;

        [self removeInputMonitor];
        [self undimDisplays];
        [self releasePowerAssertions];
        [self closeDisplayServices];
    }
    rdp_verbose("display control stopped");
}

#pragma mark - Power management (replaces `caffeinate -d`)

- (void)takePowerAssertions {
    /* Wake the display NOW if it was asleep when the client connected. */
    IOPMAssertionID activityID = kIOPMNullAssertionID;
    IOReturn ar = IOPMAssertionDeclareUserActivity(CFSTR("rdp-connect"),
                                                   kIOPMUserActiveLocal,
                                                   &activityID);
    if (ar == kIOReturnSuccess)
        rdp_info("declared user activity — display woken for incoming session");
    else
        rdp_error("IOPMAssertionDeclareUserActivity failed (0x%x)", ar);

    /* Hold the display awake for the whole session. */
    IOReturn dr = IOPMAssertionCreateWithName(
        kIOPMAssertionTypePreventUserIdleDisplaySleep,
        kIOPMAssertionLevelOn,
        CFSTR("macos-rdp: remote session active (display)"),
        &_displaySleepAssertion);
    if (dr == kIOReturnSuccess)
        rdp_info("holding PreventUserIdleDisplaySleep for session");
    else {
        _displaySleepAssertion = kIOPMNullAssertionID;
        rdp_error("PreventUserIdleDisplaySleep assertion failed (0x%x)", dr);
    }

    /* Also keep the system from idle-sleeping so capture/encode keep running. */
    IOReturn sr = IOPMAssertionCreateWithName(
        kIOPMAssertionTypePreventUserIdleSystemSleep,
        kIOPMAssertionLevelOn,
        CFSTR("macos-rdp: remote session active (system)"),
        &_systemSleepAssertion);
    if (sr == kIOReturnSuccess)
        rdp_verbose("holding PreventUserIdleSystemSleep for session");
    else {
        _systemSleepAssertion = kIOPMNullAssertionID;
        rdp_error("PreventUserIdleSystemSleep assertion failed (0x%x)", sr);
    }
}

- (void)releasePowerAssertions {
    if (_displaySleepAssertion != kIOPMNullAssertionID) {
        IOPMAssertionRelease(_displaySleepAssertion);
        _displaySleepAssertion = kIOPMNullAssertionID;
        rdp_verbose("released display-sleep assertion");
    }
    if (_systemSleepAssertion != kIOPMNullAssertionID) {
        IOPMAssertionRelease(_systemSleepAssertion);
        _systemSleepAssertion = kIOPMNullAssertionID;
        rdp_verbose("released system-sleep assertion");
    }
}

#pragma mark - DisplayServices (private) brightness control

/* Resolve DisplayServicesSet/GetBrightness lazily via dlopen+dlsym. Returns YES
 * if both symbols are available. We deliberately do NOT hard-link the private
 * framework: if it's missing or renamed on some macOS build we simply skip
 * dimming instead of failing to launch. */
- (BOOL)ensureDisplayServices {
    if (_dsSetBrightness && _dsGetBrightness) return YES;

    if (!_displayServicesHandle) {
        _displayServicesHandle = dlopen(DS_FRAMEWORK_PATH, RTLD_LAZY | RTLD_LOCAL);
        if (!_displayServicesHandle) {
            const char *e = dlerror();
            rdp_error("DisplayServices unavailable (dlopen: %s) — privacy dimming "
                      "DISABLED, remote unaffected", e ? e : "unknown");
            return NO;
        }
    }

    _dsSetBrightness = (DSSetBrightnessFn)dlsym(_displayServicesHandle,
                                                "DisplayServicesSetBrightness");
    _dsGetBrightness = (DSGetBrightnessFn)dlsym(_displayServicesHandle,
                                                "DisplayServicesGetBrightness");
    if (!_dsSetBrightness || !_dsGetBrightness) {
        rdp_error("DisplayServices brightness symbols missing (set=%p get=%p) — "
                  "privacy dimming DISABLED, remote unaffected",
                  (void *)_dsSetBrightness, (void *)_dsGetBrightness);
        _dsSetBrightness = NULL;
        _dsGetBrightness = NULL;
        return NO;
    }

    /* Optional: without these, dimming still works but automatic brightness
     * stays on through the session. */
    _dsHasAutoBrightness = (DSHasAutoBrightnessFn)dlsym(_displayServicesHandle,
                               "DisplayServicesHasAmbientLightCompensation");
    _dsGetAutoBrightness = (DSGetAutoBrightnessFn)dlsym(_displayServicesHandle,
                               "DisplayServicesAmbientLightCompensationEnabled");
    _dsSetAutoBrightness = (DSSetAutoBrightnessFn)dlsym(_displayServicesHandle,
                               "DisplayServicesEnableAmbientLightCompensation");
    if (!_dsHasAutoBrightness || !_dsGetAutoBrightness || !_dsSetAutoBrightness) {
        rdp_info("automatic brightness control unavailable — it is left as it is "
                 "during sessions");
        _dsHasAutoBrightness = NULL;
        _dsGetAutoBrightness = NULL;
        _dsSetAutoBrightness = NULL;
    }
    return YES;
}

- (void)closeDisplayServices {
    _dsSetBrightness = NULL;
    _dsGetBrightness = NULL;
    _dsHasAutoBrightness = NULL;
    _dsGetAutoBrightness = NULL;
    _dsSetAutoBrightness = NULL;
    if (_displayServicesHandle) {
        dlclose(_displayServicesHandle);
        _displayServicesHandle = NULL;
    }
}

#pragma mark - Privacy dimming of the built-in display

/* Enumerate active displays and dim every BUILT-IN one that is not the virtual
 * display to brightness 0. This is a backlight change only — no display-config
 * change — so the virtual/remote display keeps compositing normally. The
 * original brightness of each affected display is saved for restore. */
- (void)dimBuiltInDisplays {
    /* Without Screen Recording the remote sees nothing anyway, and whoever is at
     * the Mac may need the screen to answer the permission prompt. */
    if (!CGPreflightScreenCaptureAccess()) {
        rdp_info("privacy dimming skipped — Screen Recording isn't granted, so the "
                 "remote can't see the screen and the Mac's own screen stays usable");
        return;
    }
    if (![self ensureDisplayServices]) {
        rdp_info("privacy dimming skipped — DisplayServices brightness control "
                 "unavailable on this hardware; remote view works normally");
        return;
    }

    CGDirectDisplayID active[16];
    uint32_t count = 0;
    CGError ce = CGGetActiveDisplayList(16, active, &count);
    if (ce != kCGErrorSuccess) {
        rdp_error("CGGetActiveDisplayList failed (%d) — cannot dim, continuing", ce);
        return;
    }

    NSDictionary *earlier = read_saved_brightness();
    for (uint32_t i = 0; i < count; i++) {
        CGDirectDisplayID did = active[i];
        if (did == _virtualDisplayID) {
            rdp_verbose("display %u is the virtual/remote display — left lit", did);
            continue;
        }
        /* Only dim the physical built-in panel(s); leave any external monitors
         * alone, and never touch the display the remote captures. */
        if (!CGDisplayIsBuiltin(did)) {
            rdp_verbose("display %u is not built-in — left lit", did);
            continue;
        }

        /* Save the current brightness so we can restore it later. */
        float original = 1.0f;
        int gr = _dsGetBrightness(did, &original);
        if (gr != 0) {
            rdp_error("DisplayServicesGetBrightness(%u) failed (%d) — "
                      "display NOT dimmed (can't safely restore)", did, gr);
            continue;
        }
        /* A panel that is still dark because an earlier run died while it was
         * dimmed comes back to the saved brightness, not to dark; automatic
         * brightness that run turned off goes back on at the end of this one. */
        float earlierBrightness = 0;
        BOOL earlierAuto = NO;
        BOOL haveEarlier = saved_entry(earlier[@(did).stringValue],
                                       &earlierBrightness, &earlierAuto);
        if (haveEarlier && original < kDarkBrightness) {
            rdp_info("display %u is still dark (%.2f) from an earlier session — "
                     "will restore it to %.2f", did, original, earlierBrightness);
            original = earlierBrightness;
        }
        /* With no saved value either (say, a build without the file crashed
         * mid-session), restoring "dark" would leave the desk user a black
         * screen: come back at a usable level instead. */
        if (original < kDarkBrightness) {
            rdp_info("display %u is dark (%.2f) with nothing saved — will restore "
                     "it to %.2f", did, original, kRestoreFloorBrightness);
            original = kRestoreFloorBrightness;
        }

        /* Automatic brightness goes off for the session, so the room light can't
         * raise the dimmed panel and macOS doesn't take the dim (or the restore)
         * as a manual brightness setting. Undim turns it back on. */
        BOOL autoPaused = haveEarlier && earlierAuto && _dsSetAutoBrightness;
        bool autoOn = false;
        if (_dsSetAutoBrightness && _dsHasAutoBrightness(did) &&
            _dsGetAutoBrightness(did, &autoOn) == 0 && autoOn) {
            int ar = _dsSetAutoBrightness(did, false);
            if (ar == 0)
                autoPaused = YES;
            else
                rdp_error("couldn't pause automatic brightness on display %u (%d) — "
                          "it stays on through the session", did, ar);
        }

        int sr = _dsSetBrightness(did, 0.0f);
        if (sr != 0) {
            rdp_error("DisplayServicesSetBrightness(%u, 0) failed (%d) — "
                      "display NOT dimmed", did, sr);
            if (autoPaused)
                resume_auto_brightness(_dsSetAutoBrightness, _dsGetAutoBrightness, did);
            continue;
        }

        _savedBrightness[@(did)] = @(original);
        if (autoPaused) [_autoBrightnessPaused addObject:@(did)];
        rdp_info("privacy-dimmed built-in display %u (brightness %.2f -> 0%s)",
                 did, original, autoPaused ? ", automatic brightness paused" : "");
    }

    if (_savedBrightness.count == 0) {
        rdp_info("no built-in display to dim (only the virtual/remote display "
                 "is active, or none accepted brightness control) — nothing to do");
        return;
    }
    write_saved_brightness(_savedBrightness, _autoBrightnessPaused);
    _displaysDimmed = YES;
}

/* Restore every dimmed display to its saved brightness, then turn automatic
 * brightness back on where the dim paused it. In that order: macOS then adjusts
 * from the restored level to the room light, rather than keeping it as a manual
 * setting. */
- (void)undimDisplays {
    if (!_displaysDimmed) return;

    BOOL allRestored = YES;
    for (NSNumber *key in _savedBrightness) {
        CGDirectDisplayID did = (CGDirectDisplayID)key.unsignedIntValue;
        float original = _savedBrightness[key].floatValue;
        int sr = _dsSetBrightness ? _dsSetBrightness(did, original) : -1;
        if (sr == 0) {
            rdp_info("restored brightness %.2f on display %u", original, did);
        } else {
            allRestored = NO;
            rdp_error("DisplayServicesSetBrightness(%u, %.2f) restore failed (%d)",
                      did, original, sr);
        }
        if ([_autoBrightnessPaused containsObject:key] &&
            !resume_auto_brightness(_dsSetAutoBrightness, _dsGetAutoBrightness, did))
            allRestored = NO;
    }
    [_savedBrightness removeAllObjects];
    [_autoBrightnessPaused removeAllObjects];
    _displaysDimmed = NO;
    if (allRestored) clear_saved_brightness();   /* otherwise the next start retries */
}

#pragma mark - Return control to the local user

/* Re-dim policy: once the desk user physically interacts we restore brightness
 * and DO NOT re-dim for the rest of this session. Rationale: re-dimming under
 * the user's hands would fight an actively-present person at the keyboard, which
 * is worse than the small privacy window of a present, deliberate user. Privacy
 * is fully restored on the next session connect. */
- (void)installInputMonitor {
    if (!_displaysDimmed || _eventTap) return;   /* nothing to give back */

    CGEventMask mask = CGEventMaskBit(kCGEventMouseMoved)   |
                       CGEventMaskBit(kCGEventLeftMouseDown) |
                       CGEventMaskBit(kCGEventRightMouseDown)|
                       CGEventMaskBit(kCGEventKeyDown)       |
                       CGEventMaskBit(kCGEventScrollWheel);

    /* Listen-only tap (we never modify/drop events) on the main run loop, which
     * main.m runs for the daemon's whole life. */
    RDPTapTarget *target = [[RDPTapTarget alloc] init];
    target.owner = self;
    CFMachPortRef tap = CGEventTapCreate(kCGHIDEventTap, kCGTailAppendEventTap,
                                         kCGEventTapOptionListenOnly, mask,
                                         rdp_event_tap_cb, (__bridge void *)target);
    if (!tap) {
        rdp_error("CGEventTapCreate failed — desk user cannot auto-restore brightness "
                  "(needs Accessibility/Input Monitoring). Dim stays until disconnect.");
        return;
    }
    CFRunLoopSourceRef src = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0);
    if (!src) {
        CFMachPortInvalidate(tap);
        CFRelease(tap);
        rdp_error("input monitor: no run loop source — dim stays until disconnect");
        return;
    }
    target.tap = tap;
    CFRunLoopAddSource(CFRunLoopGetMain(), src, kCFRunLoopCommonModes);
    CGEventTapEnable(tap, true);
    _eventTap       = tap;
    _eventTapSource = src;
    _tapTarget      = target;
    rdp_verbose("input monitor armed — desk user can reclaim the screen");
}

/* The tap is removed on the main thread, where its callback runs, so removal can
 * never overlap a callout; the target (the refcon) lives until then. */
- (void)removeInputMonitor {
    CFMachPortRef tap      = _eventTap;
    CFRunLoopSourceRef src = _eventTapSource;
    RDPTapTarget *target   = _tapTarget;
    _eventTap       = NULL;
    _eventTapSource = NULL;
    _tapTarget      = nil;
    if (!tap) return;

    target.owner = nil;   /* a callout already queued now finds nobody */
    dispatch_async(dispatch_get_main_queue(), ^{
        CGEventTapEnable(tap, false);
        if (src) {
            CFRunLoopRemoveSource(CFRunLoopGetMain(), src, kCFRunLoopCommonModes);
            CFRelease(src);
        }
        target.tap = NULL;
        CFMachPortInvalidate(tap);
        CFRelease(tap);
    });
}

- (void)handleLocalUserActivity {
    @synchronized (self) {
        if (!_displaysDimmed) return;   /* already handed back */
        rdp_info("local user activity detected — restoring the screen to the desk user");
        [self undimDisplays];
        /* Tear down the tap; we won't re-dim this session. */
        [self removeInputMonitor];
    }
}

#pragma mark - Recovery after an unclean exit

+ (void)restoreBrightnessLeftDimmed {
    NSDictionary *saved = read_saved_brightness();
    if (saved.count == 0) return;

    void *h = dlopen(DS_FRAMEWORK_PATH, RTLD_LAZY | RTLD_LOCAL);
    DSSetBrightnessFn set = h ? (DSSetBrightnessFn)dlsym(h, "DisplayServicesSetBrightness")
                              : NULL;
    DSSetAutoBrightnessFn setAuto = h ? (DSSetAutoBrightnessFn)dlsym(h,
                                        "DisplayServicesEnableAmbientLightCompensation") : NULL;
    DSGetAutoBrightnessFn getAuto = h ? (DSGetAutoBrightnessFn)dlsym(h,
                                        "DisplayServicesAmbientLightCompensationEnabled") : NULL;
    if (!set) {
        rdp_error("an earlier run left the built-in display dimmed, and DisplayServices "
                  "isn't available to restore it — raise the brightness by hand");
        if (h) dlclose(h);
        return;
    }
    BOOL allRestored = YES;
    for (NSString *key in saved) {
        float b = 0;
        BOOL autoWasOn = NO;
        if (![key isKindOfClass:[NSString class]] || !saved_entry(saved[key], &b, &autoWasOn))
            continue;
        CGDirectDisplayID did = (CGDirectDisplayID)key.longLongValue;
        int r = set(did, b);
        if (r == 0) {
            rdp_info("restored brightness %.2f on display %u (an earlier run ended "
                     "while it was dimmed)", b, did);
        } else {
            allRestored = NO;
            rdp_error("restoring brightness %.2f on display %u failed (%d) — the next "
                      "session will try again", b, did, r);
        }
        if (autoWasOn && !resume_auto_brightness(setAuto, getAuto, did))
            allRestored = NO;
    }
    if (allRestored) clear_saved_brightness();
    dlclose(h);
}

@end
