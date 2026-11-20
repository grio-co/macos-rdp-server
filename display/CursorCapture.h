#pragma once
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/* Delivers the current system cursor as a 32-bit BGRA (premultiplied),
 * top-left-origin bitmap plus its hotspot, in surface pixels. The bytes are
 * only valid for the duration of the block — copy if you need them longer.
 * Rows are tightly packed: stride == width * 4. */
typedef void (^CursorCaptureBlock)(const uint8_t *bgra,
                                   uint32_t width, uint32_t height,
                                   uint16_t hotX, uint16_t hotY);

/* Polls the system cursor on a background dispatch_source timer and invokes
 * `handler` only when the shape changes (CGS cursor seed as a hint, plus a
 * re-read every 250 ms and a content hash). The image comes from
 * +[NSCursor currentSystemCursor], rendered at `pixelsPerPoint` and capped at
 * `maxDimension`. Blank images are never delivered.
 *
 * The handler is invoked on the capture's background serial queue. */
@interface CursorCapture : NSObject

@property (nonatomic, copy, nullable) CursorCaptureBlock handler;

/* Pixels per point of the display the remote user sees: 1 for a 1x virtual
 * display, 2 for HiDPI. Cursors are rendered at this scale so the remote
 * pointer matches the desktop. Default 1. */
@property (atomic, assign) double pixelsPerPoint;

/* Longest pointer edge, in pixels, the client accepts: 32 without the RDP
 * large-pointer capability, 96 with it. Larger cursors are scaled to fit.
 * Default 96. */
@property (atomic, assign) uint32_t maxDimension;

/* Start polling at ~12 Hz. The first shape fires almost immediately. Safe to
 * call from any thread. */
- (void)start;
/* Stop polling and tear down the timer. Safe to call from any thread. */
- (void)stop;

@end

NS_ASSUME_NONNULL_END
