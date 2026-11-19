#pragma once
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <IOSurface/IOSurface.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^ScreenCaptureFrameBlock)(IOSurfaceRef surface,
                                        uint32_t width, uint32_t height,
                                        CGRect dirtyRect);

@interface ScreenCapture : NSObject

@property (nonatomic, readonly) BOOL isCapturing;
@property (nonatomic, copy, nullable) ScreenCaptureFrameBlock frameHandler;

- (instancetype)initWithDisplayID:(CGDirectDisplayID)displayID;
/* Frame-rate cap (RDP_FPS, default 30, clamped 5..60). Shared by capture and
 * encoder so both agree. */
+ (uint32_t)configuredFPS;
/* Re-deliver the latest captured frame to frameHandler after `ms`, on the capture
 * queue; coalesced. Used after a throttled capture so the skipped content is sent
 * as soon as the link has room, even if the screen has gone static. */
- (void)refeedLastFrameAfterMs:(uint32_t)ms;
- (BOOL)startWithWidth:(uint32_t)width height:(uint32_t)height;
- (void)stop;

@end

NS_ASSUME_NONNULL_END
