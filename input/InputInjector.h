#pragma once
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

/* RDP keyboard flags (MS-RDPBCGR 2.2.8.1.1.3.1.1.1) */
#define RDP_KBD_RELEASE   0x8000   /* KBDFLAGS_RELEASE */
#define RDP_KBD_EXTENDED  0x0100   /* KBDFLAGS_EXTENDED */

/* RDP pointer flags (MS-RDPBCGR 2.2.8.1.1.3.1.1.3). Button press vs release is
 * the DOWN bit — NOT separate values; identity is the BUTTONn bit. */
#define RDP_PTR_MOVE              0x0800
#define RDP_PTR_DOWN              0x8000
#define RDP_PTR_BUTTON1           0x1000   /* left   */
#define RDP_PTR_BUTTON2           0x2000   /* right  */
#define RDP_PTR_BUTTON3           0x4000   /* middle */
#define RDP_PTR_WHEEL             0x0200
#define RDP_PTR_HWHEEL            0x0400
#define RDP_PTR_WHEEL_NEGATIVE    0x0100
#define RDP_PTR_WHEEL_ROTATION    0x01FF
/* Extended pointer flags (PTR_XFLAGS_*) */
#define RDP_XFLAGS_DOWN           0x8000
#define RDP_XFLAGS_BUTTON1        0x0001   /* back    */
#define RDP_XFLAGS_BUTTON2        0x0002   /* forward */
/* Keyboard "key was already down" (autorepeat) */
#define RDP_KBD_DOWN              0x4000

@interface InputInjector : NSObject

/* sourceWidth/Height are the RDP desktop dimensions the client sends pointer
 * coordinates in (the negotiated/captured size). They are scaled to the Mac
 * display's actual point bounds so clicks land correctly when the remote
 * resolution differs from the Mac's (e.g. a Retina display). */
- (instancetype)initWithDisplayID:(CGDirectDisplayID)displayID
                      sourceWidth:(uint32_t)sourceWidth
                     sourceHeight:(uint32_t)sourceHeight;

- (void)injectKeyEvent:(uint16_t)flags scanCode:(uint16_t)code;
/* code is a UTF-16 code unit. Surrogate pairs are buffered across two calls and
 * posted once the low surrogate arrives. */
- (void)injectUnicodeKeyEvent:(uint16_t)flags code:(uint16_t)code;
- (void)injectMouseEvent:(uint16_t)flags x:(uint16_t)x y:(uint16_t)y;
/* Extended mouse (X buttons: back/forward) — PTR_XFLAGS_* in flags. */
- (void)injectMouseExEvent:(uint16_t)flags x:(uint16_t)x y:(uint16_t)y;
/* Wheel rotation is encoded entirely within flags; decoded internally. */
- (void)injectMouseWheelEvent:(uint16_t)flags x:(uint16_t)x y:(uint16_t)y;
/* Make the Mac's Caps Lock match the client (KBD_SYNC_* flags). */
- (void)synchronizeLockKeys:(uint32_t)flags;
/* The single place RDP desktop coordinates are mapped to global Mac points. */
- (CGPoint)globalPointForDesktopX:(uint16_t)x y:(uint16_t)y;
/* Post key-up / button-up for everything still held (call on session end). */
- (void)releaseAll;

@end

NS_ASSUME_NONNULL_END
