#import "input/InputInjector.h"
#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/hidsystem/IOHIDLib.h>
#import <IOKit/hidsystem/IOHIDParameter.h>
#import <syslog.h>
#include "input/InputLogic.h"
#define RDP_LOG_COMPONENT "input"
#include "logging/RDPLog.h"

/* "No mapping" sentinel. NOT 0 — macOS virtual keycode 0 is the letter 'A'. */
#define kVKNone 0xFFFF

/* RDP scan code → macOS virtual key code mapping.
   Scan codes follow MS-RDPBCGR (IBM PC/AT set 1); VK values are Carbon
   kVK_* constants from HIToolbox/Events.h. */
static const uint16_t kScanToVK[256] = {
    [0x01] = 53,  /* Esc */
    [0x02] = 18,  /* 1 */  [0x03] = 19,  /* 2 */  [0x04] = 20,  /* 3 */
    [0x05] = 21,  /* 4 */  [0x06] = 23,  /* 5 */  [0x07] = 22,  /* 6 */
    [0x08] = 26,  /* 7 */  [0x09] = 28,  /* 8 */  [0x0A] = 25,  /* 9 */
    [0x0B] = 29,  /* 0 */  [0x0C] = 27,  /* - */  [0x0D] = 24,  /* = */
    [0x0E] = 51,  /* BS */
    [0x0F] = 48,  /* Tab */
    [0x10] = 12,  /* Q */  [0x11] = 13,  /* W */  [0x12] = 14,  /* E */
    [0x13] = 15,  /* R */  [0x14] = 17,  /* T */  [0x15] = 16,  /* Y */
    [0x16] = 32,  /* U */  [0x17] = 34,  /* I */  [0x18] = 31,  /* O */
    [0x19] = 35,  /* P */  [0x1A] = 33,  /* [ */  [0x1B] = 30,  /* ] */
    [0x1C] = 36,  /* Return */
    [0x1D] = 59,  /* LCtrl */
    [0x1E] = 0,   /* A */  [0x1F] = 1,   /* S */  [0x20] = 2,   /* D */
    [0x21] = 3,   /* F */  [0x22] = 5,   /* G */  [0x23] = 4,   /* H */
    [0x24] = 38,  /* J */  [0x25] = 40,  /* K */  [0x26] = 37,  /* L */
    [0x27] = 41,  /* ; */  [0x28] = 39,  /* ' */  [0x29] = 50,  /* ` */
    [0x2A] = 56,  /* LShift */
    [0x2B] = 42,  /* \ */
    [0x2C] = 6,   /* Z */  [0x2D] = 7,   /* X */  [0x2E] = 8,   /* C */
    [0x2F] = 9,   /* V */  [0x30] = 11,  /* B */  [0x31] = 45,  /* N */
    [0x32] = 46,  /* M */  [0x33] = 43,  /* , */  [0x34] = 47,  /* . */
    [0x35] = 44,  /* / */
    [0x36] = 60,  /* RShift */
    [0x37] = 67,  /* KP* */
    [0x38] = 58,  /* LAlt */
    [0x39] = 49,  /* Space */
    [0x3A] = 57,  /* CapsLk */
    [0x3B] = 122, /* F1 */  [0x3C] = 120, /* F2 */  [0x3D] = 99, /* F3 */
    [0x3E] = 118, /* F4 */  [0x3F] = 96,  /* F5 */  [0x40] = 97, /* F6 */
    [0x41] = 98,  /* F7 */  [0x42] = 100, /* F8 */  [0x43] = 101,/* F9 */
    [0x44] = 109, /* F10 */ [0x57] = 103, /* F11 */ [0x58] = 111,/* F12 */

    /* F13–F24. mstsc sends these for the top-row keys on full-size keyboards;
     * macOS only defines through F20. */
    [0x64] = 105, /* F13 */ [0x65] = 107, /* F14 */ [0x66] = 113, /* F15 */
    [0x67] = 106, /* F16 */ [0x68] = 64,  /* F17 */ [0x69] = 79,  /* F18 */
    [0x6A] = 80,  /* F19 */ [0x6B] = 90,  /* F20 */

    /* Numeric keypad. These scan codes ARE the keypad in PC/AT set 1 — the
     * dedicated nav cluster (Home/arrows/PgUp/Ins/Del) arrives 0xE0-prefixed and
     * is handled in kExtScanToVK below. Mapping them to keypad VKs is what makes
     * the numpad type digits; macOS has no NumLock, so the keypad is always
     * numeric and the NumLock-off aliasing a PC would apply does not exist here. */
    [0x45] = 71,  /* NumLock -> Clear (the Mac keypad's NumLock position) */
    [0x47] = 89,  /* KP7 */ [0x48] = 91,  /* KP8 */ [0x49] = 92,  /* KP9 */
    [0x4A] = 78,  /* KP-  */
    [0x4B] = 86,  /* KP4 */ [0x4C] = 87,  /* KP5 */ [0x4D] = 88,  /* KP6 */
    [0x4E] = 69,  /* KP+  */
    [0x4F] = 83,  /* KP1 */ [0x50] = 84,  /* KP2 */ [0x51] = 85,  /* KP3 */
    [0x52] = 82,  /* KP0 */ [0x53] = 65,  /* KP.  */
    [0x59] = 81,  /* KP=  */

    /* International. 0x56 is the extra key left of Z on ISO layouts; the 0x7x
     * block is JIS. */
    [0x56] = 10,  /* ISO section/backslash */
    [0x73] = 94,  /* JIS underscore */
    [0x7D] = 93,  /* JIS yen */
    [0x70] = 104, /* JIS kana */
};

/* Extended scan codes (prefixed 0xE0 in RDP) → macOS VK */
static const uint16_t kExtScanToVK[256] = {
    [0x1C] = 76,  /* KP Enter */
    [0x1D] = 62,  /* RCtrl */
    [0x35] = 75,  /* KP/ */
    [0x38] = 61,  /* RAlt */
    [0x47] = 115, /* Home */
    [0x48] = 126, /* Up */
    [0x49] = 116, /* PgUp */
    [0x4B] = 123, /* Left */
    [0x4D] = 124, /* Right */
    [0x4F] = 119, /* End */
    [0x50] = 125, /* Down */
    [0x51] = 121, /* PgDn */
    [0x52] = 114, /* Insert */
    [0x53] = 117, /* Delete */
    [0x5B] = 55,  /* LCmd */
    [0x5C] = 54,  /* RCmd — kVK_RightCommand, not 55 */
};

/* Mouse button slots (bit index in _buttonMask). */
enum { kBtnLeft = 0, kBtnRight = 1, kBtnMiddle = 2, kBtnBack = 3, kBtnForward = 4, kBtnCount = 5 };

@interface InputInjector () {
    CGEventSourceRef _source;      /* one source for every event */
    uint64_t _modBits;             /* held modifier device bits (IL_DEV_*) */
    BOOL _caps;                    /* Caps Lock state as the client sees it */
    BOOL _windowsKeymap;           /* RDP_KEYMAP=windows: Ctrl->Cmd, Win->Ctrl */
    uint32_t _buttonMask;          /* held mouse buttons, bit = kBtn* */
    ILClickTracker _click;
    double _wheelAccV, _wheelAccH;
    CGPoint _lastPos;
    NSMutableIndexSet *_heldKeys;  /* non-modifier VKs currently down */
    io_connect_t _hid;             /* IOHIDSystem connection for Caps Lock */
    ILRect _monRects[16];          /* multi-monitor map (desktop coords) */
    CGDirectDisplayID _monDisplays[16];
    uint32_t _monCount;
}
@property (nonatomic, assign) CGDirectDisplayID displayID;
@property (nonatomic, assign) uint32_t srcW;   /* RDP desktop width  (pointer coord space) */
@property (nonatomic, assign) uint32_t srcH;   /* RDP desktop height */
/* High surrogate awaiting its pair; 0 when not mid-pair. */
@property (nonatomic, assign) uint16_t pendingHighSurrogate;
@end

@implementation InputInjector

- (instancetype)initWithDisplayID:(CGDirectDisplayID)did
                      sourceWidth:(uint32_t)sourceWidth
                     sourceHeight:(uint32_t)sourceHeight {
    if ((self = [super init])) {
        _displayID = did;
        _srcW = sourceWidth;
        _srcH = sourceHeight;
        _source = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
        _heldKeys = [NSMutableIndexSet indexSet];
        il_click_init(&_click);
        const char *km = getenv("RDP_KEYMAP");
        _windowsKeymap = (km && strcasecmp(km, "windows") == 0);
        if (_windowsKeymap) rdp_info("keymap: windows (Ctrl->Command, Win->Control)");
        /* Prompt for Accessibility (required for CGEventPost) and register the
         * binary in the Privacy list. In the GUI session this pops the system
         * dialog the first time; thereafter it just reports the trust state. */
        const char *np = getenv("RDP_NO_TCC_PROMPT");   /* headless/test runs */
        BOOL prompt = !(np && strcmp(np, "1") == 0);
        NSDictionary *opts = @{ (__bridge id)kAXTrustedCheckOptionPrompt: @(prompt) };
        if (!AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)opts))
            rdp_error("Accessibility not granted — input injection will not work "
                      "until enabled (grant the prompt or System Settings > Privacy "
                      "& Security > Accessibility)");
    }
    return self;
}

- (void)dealloc {
    if (_hid) IOServiceClose(_hid);
    if (_source) CFRelease(_source);
}

- (CGKeyCode)keyCodeForScanCode:(uint16_t)code extended:(BOOL)ext {
    const uint16_t *table = ext ? kExtScanToVK : kScanToVK;
    if (code >= 256) return kVKNone;
    uint16_t vk = table[code];
    /* Unlisted entries default to 0, and macOS VK 0 is the letter 'A' — so a bare
     * `return table[code]` injects an 'A' for every key we don't map. Scancode
     * 0x1E (non-extended) is the only one that legitimately resolves to 0. */
    if (vk == 0 && !(!ext && code == 0x1E)) return kVKNone;
    if (_windowsKeymap) {
        switch (vk) {
        case IL_VK_CTRL_L: vk = IL_VK_CMD_L;  break;
        case IL_VK_CTRL_R: vk = IL_VK_CMD_R;  break;
        case IL_VK_CMD_L:  vk = IL_VK_CTRL_L; break;
        case IL_VK_CMD_R:  vk = IL_VK_CTRL_R; break;
        }
    }
    return (CGKeyCode)vk;
}

- (CGEventFlags)currentFlags {
    return (CGEventFlags)il_event_flags(_modBits, _caps);
}

/* ── Caps Lock hardware state ─────────────────────────────────────────── */

- (void)setHardwareCapsLock:(BOOL)on {
    if (!_hid) {
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                                                       IOServiceMatching(kIOHIDSystemClass));
        if (!svc) { rdp_error("IOHIDSystem not found"); return; }
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), kIOHIDParamConnectType, &_hid);
        IOObjectRelease(svc);
        if (kr != KERN_SUCCESS) { _hid = 0; rdp_error("IOServiceOpen(IOHIDSystem) failed: 0x%x", kr); return; }
    }
    IOHIDSetModifierLockState(_hid, kIOHIDCapsLockState, on);
}

- (void)synchronizeLockKeys:(uint32_t)flags {
    BOOL caps = (flags & 0x4 /* KBD_SYNC_CAPS_LOCK */) != 0;
    _caps = caps;
    [self setHardwareCapsLock:caps];
}

/* ── Keyboard ─────────────────────────────────────────────────────────── */

- (void)postFlagsChangedForVK:(CGKeyCode)vk {
    CGEventRef e = CGEventCreate(_source);
    if (!e) return;
    CGEventSetType(e, kCGEventFlagsChanged);
    CGEventSetIntegerValueField(e, kCGKeyboardEventKeycode, vk);
    CGEventSetFlags(e, [self currentFlags]);
    CGEventPost(kCGSessionEventTap, e);
    CFRelease(e);
}

- (void)injectKeyEvent:(uint16_t)flags scanCode:(uint16_t)code {
    BOOL isRelease = (flags & RDP_KBD_RELEASE) != 0;
    BOOL isExtended = (flags & RDP_KBD_EXTENDED) != 0;
    CGKeyCode vk = [self keyCodeForScanCode:code extended:isExtended];
    if (vk == 0xFFFF) return;

    /* Caps Lock: a press toggles the lock (on both the Mac hardware state and our
     * flag); the release is ignored. No key event is posted — a synthetic one does
     * not reliably toggle the HID lock. */
    if (vk == IL_VK_CAPS) {
        if (!isRelease && !(flags & RDP_KBD_DOWN)) {
            _caps = !_caps;
            [self setHardwareCapsLock:_caps];
        }
        return;
    }

    uint64_t bit = il_modifier_device_bit(vk);
    if (bit) {
        uint64_t before = _modBits;
        if (isRelease) _modBits &= ~bit; else _modBits |= bit;
        if (_modBits != before) [self postFlagsChangedForVK:vk];
        return;
    }

    CGEventRef event = CGEventCreateKeyboardEvent(_source, vk, !isRelease);
    if (!event) return;
    CGEventSetFlags(event, [self currentFlags]);
    if (!isRelease && (flags & RDP_KBD_DOWN))   /* "already down" = autorepeat */
        CGEventSetIntegerValueField(event, kCGKeyboardEventAutorepeat, 1);
    if (isRelease) [_heldKeys removeIndex:vk]; else [_heldKeys addIndex:vk];

    /* Post to the session event stream so it reaches the frontmost app. */
    CGEventPost(kCGSessionEventTap, event);
    CFRelease(event);
}

- (void)injectUnicodeKeyEvent:(uint16_t)flags code:(uint16_t)code {
    /* The client sends a press and a release carrying the same code. A character
     * has no key identity to hold down, so the release is dropped and the press
     * emits a complete down/up pair. */
    if (flags & RDP_KBD_RELEASE) return;

    UniChar buf[2];
    CFIndex len = 0;

    if (code >= 0xD800 && code <= 0xDBFF) {   /* high surrogate — wait for the low */
        _pendingHighSurrogate = code;
        return;
    }
    if (code >= 0xDC00 && code <= 0xDFFF) {   /* low surrogate */
        if (!_pendingHighSurrogate) return;   /* unpaired — nothing to compose */
        buf[len++] = _pendingHighSurrogate;
        buf[len++] = code;
        _pendingHighSurrogate = 0;
    } else {
        _pendingHighSurrogate = 0;            /* an unpaired high is stale now */
        buf[len++] = code;
    }

    /* Virtual keycode 0 is ignored by the system when a unicode string is
     * attached, so the character is delivered verbatim regardless of the Mac's
     * active keyboard layout. */
    for (int down = 1; down >= 0; down--) {
        CGEventRef event = CGEventCreateKeyboardEvent(_source, 0, down != 0);
        if (!event) return;
        CGEventKeyboardSetUnicodeString(event, len, buf);
        CGEventSetFlags(event, [self currentFlags]);
        CGEventPost(kCGSessionEventTap, event);
        CFRelease(event);
    }
}

/* ── Mouse ────────────────────────────────────────────────────────────── */

- (void)setMonitorRects:(const CGRect *)rects
               displays:(const CGDirectDisplayID *)displays
                  count:(uint32_t)count {
    _monCount = MIN(count, 16u);
    for (uint32_t i = 0; i < _monCount; i++) {
        _monRects[i] = (ILRect){ rects[i].origin.x, rects[i].origin.y,
                                 rects[i].size.width, rects[i].size.height };
        _monDisplays[i] = displays[i];
    }
}

- (void)setSingleDisplay:(CGDirectDisplayID)displayID
             sourceWidth:(uint32_t)sourceWidth
            sourceHeight:(uint32_t)sourceHeight {
    _monCount = 0;
    self.displayID = displayID;
    self.srcW = sourceWidth;
    self.srcH = sourceHeight;
}

- (CGPoint)globalPointForDesktopX:(uint16_t)x y:(uint16_t)y {
    if (_monCount > 0) {
        int i = il_monitor_at(_monRects, (int)_monCount, x, y);
        CGRect b = CGDisplayBounds(_monDisplays[i]);
        double gx, gy;
        il_map_into(_monRects[i],
                    (ILRect){ b.origin.x, b.origin.y, b.size.width, b.size.height },
                    x, y, &gx, &gy);
        return CGPointMake(gx, gy);
    }
    /* The client sends pointer coords in the RDP desktop space (0..srcW, 0..srcH).
     * The capture preserves the Mac's aspect ratio inside that surface, so the Mac
     * image occupies a CENTERED sub-rectangle with letterbox/pillarbox bars when the
     * client and Mac aspect ratios differ. Map the pointer into that content rect
     * (not the whole surface), then to the Mac display's point bounds — otherwise the
     * bars throw off the cursor position. */
    CGRect bounds = CGDisplayBounds(_displayID);
    double macAspect  = bounds.size.width / bounds.size.height;
    double surfAspect = (_srcH > 0) ? (double)_srcW / (double)_srcH : macAspect;
    double contentW, contentH, offX, offY;
    if (macAspect < surfAspect) {            /* pillarbox: content fits the height */
        contentH = _srcH; contentW = (double)_srcH * macAspect;
        offX = ((double)_srcW - contentW) / 2.0; offY = 0;
    } else {                                  /* letterbox: content fits the width */
        contentW = _srcW; contentH = (double)_srcW / macAspect;
        offX = 0; offY = ((double)_srcH - contentH) / 2.0;
    }
    double fx = (contentW > 0) ? ((double)x - offX) / contentW : 0;  /* 0..1 in content */
    double fy = (contentH > 0) ? ((double)y - offY) / contentH : 0;
    if (fx < 0) fx = 0; else if (fx > 1) fx = 1;
    if (fy < 0) fy = 0; else if (fy > 1) fy = 1;
    return CGPointMake(bounds.origin.x + fx * bounds.size.width,
                       bounds.origin.y + fy * bounds.size.height);
}

static void btnTypes(int btn, CGEventType *down, CGEventType *up, CGEventType *drag,
                     CGMouseButton *cgButton) {
    switch (btn) {
    case kBtnLeft:  *down = kCGEventLeftMouseDown;  *up = kCGEventLeftMouseUp;
                    *drag = kCGEventLeftMouseDragged;  *cgButton = kCGMouseButtonLeft; break;
    case kBtnRight: *down = kCGEventRightMouseDown; *up = kCGEventRightMouseUp;
                    *drag = kCGEventRightMouseDragged; *cgButton = kCGMouseButtonRight; break;
    default:        *down = kCGEventOtherMouseDown; *up = kCGEventOtherMouseUp;
                    *drag = kCGEventOtherMouseDragged;
                    /* middle = 2, back = 3, forward = 4 */
                    *cgButton = (CGMouseButton)btn; break;
    }
}

- (void)postMouseType:(CGEventType)type button:(CGMouseButton)button at:(CGPoint)pos
           clickState:(int)clickState {
    CGEventRef event = CGEventCreateMouseEvent(_source, type, pos, button);
    if (!event) return;
    CGEventSetFlags(event, [self currentFlags]);
    if (button >= kCGMouseButtonCenter)
        CGEventSetIntegerValueField(event, kCGMouseEventButtonNumber, button);
    if (clickState > 0)
        CGEventSetIntegerValueField(event, kCGMouseEventClickState, clickState);
    CGEventPost(kCGSessionEventTap, event);
    CFRelease(event);
    _lastPos = pos;
}

/* Press/release of button slot `btn`, or (btn < 0) a move/drag. */
- (void)handleButton:(int)btn down:(BOOL)down x:(uint16_t)x y:(uint16_t)y {
    CGPoint pos = [self globalPointForDesktopX:x y:y];
    CGEventType tDown, tUp, tDrag; CGMouseButton cgb;
    if (btn >= 0) {
        btnTypes(btn, &tDown, &tUp, &tDrag, &cgb);
        if (down) {
            double now = NSProcessInfo.processInfo.systemUptime;
            int cs = il_click_down(&_click, btn, now, NSEvent.doubleClickInterval, x, y);
            _buttonMask |= (1u << btn);
            [self postMouseType:tDown button:cgb at:pos clickState:cs];
        } else {
            _buttonMask &= ~(1u << btn);
            [self postMouseType:tUp button:cgb at:pos
                     clickState:(_click.button == btn ? _click.count : 1)];
        }
        return;
    }
    /* Move: with a button held it's a drag — macOS needs the dragged event type
     * or the gesture (selection, window move) is dropped. */
    for (int b = 0; b < kBtnCount; b++) {
        if (_buttonMask & (1u << b)) {
            btnTypes(b, &tDown, &tUp, &tDrag, &cgb);
            [self postMouseType:tDrag button:cgb at:pos
                     clickState:(_click.button == b ? _click.count : 1)];
            return;
        }
    }
    [self postMouseType:kCGEventMouseMoved button:kCGMouseButtonLeft at:pos clickState:0];
}

- (void)injectMouseEvent:(uint16_t)flags x:(uint16_t)x y:(uint16_t)y {
    BOOL down = (flags & RDP_PTR_DOWN) != 0;
    if      (flags & RDP_PTR_BUTTON1) [self handleButton:kBtnLeft   down:down x:x y:y];
    else if (flags & RDP_PTR_BUTTON2) [self handleButton:kBtnRight  down:down x:x y:y];
    else if (flags & RDP_PTR_BUTTON3) [self handleButton:kBtnMiddle down:down x:x y:y];
    else if (flags & RDP_PTR_MOVE)    [self handleButton:-1         down:NO   x:x y:y];
}

- (void)injectMouseExEvent:(uint16_t)flags x:(uint16_t)x y:(uint16_t)y {
    BOOL down = (flags & RDP_XFLAGS_DOWN) != 0;
    if      (flags & RDP_XFLAGS_BUTTON1) [self handleButton:kBtnBack    down:down x:x y:y];
    else if (flags & RDP_XFLAGS_BUTTON2) [self handleButton:kBtnForward down:down x:x y:y];
    else if (flags & RDP_PTR_MOVE)       [self handleButton:-1          down:NO   x:x y:y];
}

/* Direction mapping:
 *   RDP vertical wheel: positive rotation = wheel rotated away from the user =
 *     scroll UP (content moves down). CGEvent wheel1 positive = scroll up too.
 *     -> pass through unchanged.
 *   RDP horizontal wheel: positive = scroll RIGHT (Windows convention).
 *     CGEvent wheel2 positive = scroll LEFT (content moves right), so negate.
 * Units: 120 RDP units (one Windows notch) = IL_PIXELS_PER_NOTCH pixels; smaller
 * touchpad deltas accumulate in _wheelAcc* and are emitted once they reach a pixel. */
- (void)injectMouseWheelEvent:(uint16_t)flags x:(uint16_t)x y:(uint16_t)y {
    (void)x; (void)y;
    BOOL horizontal = (flags & RDP_PTR_HWHEEL) != 0;
    int rotation = il_wheel_rotation(flags);
    if (rotation == 0) return;

    int px = il_wheel_accumulate(horizontal ? &_wheelAccH : &_wheelAccV, rotation);
    if (px == 0) return;

    int32_t v = horizontal ? 0 : px;
    int32_t h = horizontal ? -px : 0;
    CGEventRef event = CGEventCreateScrollWheelEvent(_source, kCGScrollEventUnitPixel, 2, v, h);
    if (!event) return;
    CGEventSetFlags(event, [self currentFlags]);
    CGEventPost(kCGSessionEventTap, event);
    CFRelease(event);
}

/* ── Cleanup ──────────────────────────────────────────────────────────── */

- (void)releaseAll {
    [_heldKeys enumerateIndexesUsingBlock:^(NSUInteger vk, BOOL *stop) {
        CGEventRef e = CGEventCreateKeyboardEvent(self->_source, (CGKeyCode)vk, false);
        if (!e) return;
        CGEventSetFlags(e, [self currentFlags]);
        CGEventPost(kCGSessionEventTap, e);
        CFRelease(e);
    }];
    [_heldKeys removeAllIndexes];

    for (int b = 0; b < kBtnCount; b++) {
        if (!(_buttonMask & (1u << b))) continue;
        CGEventType tDown, tUp, tDrag; CGMouseButton cgb;
        btnTypes(b, &tDown, &tUp, &tDrag, &cgb);
        _buttonMask &= ~(1u << b);
        [self postMouseType:tUp button:cgb at:_lastPos clickState:1];
    }

    static const unsigned mods[] = { IL_VK_CTRL_L, IL_VK_CTRL_R, IL_VK_SHIFT_L, IL_VK_SHIFT_R,
                                     IL_VK_ALT_L, IL_VK_ALT_R, IL_VK_CMD_L, IL_VK_CMD_R };
    for (size_t i = 0; i < sizeof mods / sizeof mods[0]; i++) {
        uint64_t bit = il_modifier_device_bit(mods[i]);
        if (_modBits & bit) {
            _modBits &= ~bit;
            [self postFlagsChangedForVK:(CGKeyCode)mods[i]];
        }
    }
}

@end
