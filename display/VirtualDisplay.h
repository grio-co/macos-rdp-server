#pragma once
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

/*
 * VirtualDisplay: one Mac display for one client monitor.
 *
 * Backed by CGVirtualDisplay (private CoreGraphics API, reached through
 * NSClassFromString/KVC so a missing class or changed ABI degrades instead of
 * crashing). If it is unavailable, the display falls back to the main display
 * and `isVirtual` is NO; the session then serves a single, letterboxed monitor.
 *
 * Sizes: `width` x `height` are CLIENT pixels, which is what gets captured and
 * encoded. When the client runs above 100% scale (and HiDPI is not disabled),
 * the display is a HiDPI ("Retina") display whose desktop is the client size
 * divided by the scale, in points, rendered at 2x and captured down to client
 * pixels — so text and UI appear at the size the client's user chose, exactly
 * like a Windows session honouring the client's DPI.
 */
@interface VirtualDisplay : NSObject

@property (nonatomic, readonly) CGDirectDisplayID displayID;
@property (nonatomic, readonly) uint32_t width;        /* client pixels */
@property (nonatomic, readonly) uint32_t height;
@property (nonatomic, readonly) uint32_t pointsWide;   /* Mac desktop size, points */
@property (nonatomic, readonly) uint32_t pointsHigh;
@property (nonatomic, readonly) BOOL hiDPI;
@property (nonatomic, readonly) BOOL isVirtual;

/* serial makes each of a session's displays a distinct monitor to macOS (which
 * keys remembered arrangement and settings by vendor/product/serial). */
- (instancetype)initWithSerial:(uint32_t)serial;

/* Creates the display, or changes its mode in place (same displayID) when it
 * already exists and the new size fits its pixel budget; otherwise recreates
 * it. scalePercent is the client's desktop scale (100 = 1:1). Returns NO only
 * when no display at all could be provided. */
- (BOOL)configureWidth:(uint32_t)width height:(uint32_t)height
          scalePercent:(uint32_t)scalePercent
       physicalWidthMm:(uint32_t)physicalWidthMm
      physicalHeightMm:(uint32_t)physicalHeightMm;

- (void)destroy;

/* The points size a client monitor gets: honours RDP_HIDPI=0 (always 1:1) and
 * RDP_SCALE=<percent> (override the client's scale), and never shrinks the Mac
 * desktop below 800x600 points. Pure; exposed for logging and tests. */
+ (void)pointsForWidth:(uint32_t)width height:(uint32_t)height
          scalePercent:(uint32_t)scalePercent
                 outW:(uint32_t *)outW outH:(uint32_t *)outH
              outHiDPI:(BOOL *)outHiDPI;

@end

NS_ASSUME_NONNULL_END
